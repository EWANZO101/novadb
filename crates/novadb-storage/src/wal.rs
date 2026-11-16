//! Write-ahead log.
//!
//! The WAL is a redo-only physical log. A transaction logs, for every page it modified, either a
//! full page image (first modification of that page since the last checkpoint) or a byte-range
//! delta against the previously logged state, followed by a `Commit` record; the WAL is fsynced
//! before commit returns. Uncommitted pages are never written to the data file (no-steal), so no
//! undo is needed. Replaying the WAL from the start therefore reconstructs every page touched
//! since the last checkpoint, which also repairs torn data-page writes.
//!
//! ```text
//! file header (40 bytes):
//!   0 magic "NOVAWAL\x01" | 8 version u32 | 12 salt u32 | 16 start_lsn u64 | 24 db_id u64
//!  32 reserved u32 | 36 crc32c([0..36]) u32
//! record:
//!   0 payload_len u32 | 4 crc32c(salt ‖ rec[8..20] ‖ payload) u32 | 8 lsn u64 | 16 kind u8
//!  17 reserved [3] | 20 payload
//! ```
//!
//! The per-generation random `salt` makes records from an older WAL generation (e.g. stale
//! bytes after a truncate) fail the CRC, and LSNs must be strictly consecutive. `db_id` ties
//! the WAL to its data file (recovery refuses to replay a WAL from another database).

use crate::crc32c::Crc32c;
use crate::error::{Error, Result};
use crate::page::{self, PAGE_SIZE, PageId, get_u16, get_u32, get_u64};
use crate::vfs::VfsFile;
use std::io;

/// File magic.
pub const WAL_MAGIC: [u8; 8] = *b"NOVAWAL\x01";
/// WAL format version.
pub const WAL_VERSION: u32 = 1;
/// File header size.
pub const WAL_HEADER_SIZE: usize = 40;
/// Record header size.
pub const REC_HEADER_SIZE: usize = 20;
/// LSNs must stay below this (2^62): ~146 years at 10^9 records/s.
pub const MAX_LSN: u64 = 1 << 62;
/// Largest legal payload (a full page image).
pub const MAX_PAYLOAD: usize = 8 + PAGE_SIZE;

/// Record kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordKind {
    /// `page_id u64 ‖ page bytes` (checksum field zero).
    PageImage = 1,
    /// `page_id u64 ‖ count u16 ‖ (offset u16 ‖ len u16 ‖ bytes)*`.
    PageDelta = 2,
    /// Empty payload; makes all preceding records of the transaction durable.
    Commit = 3,
}

impl RecordKind {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::PageImage),
            2 => Some(Self::PageDelta),
            3 => Some(Self::Commit),
            _ => None,
        }
    }
}

/// Parsed WAL file header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalHeader {
    /// Random per-generation salt.
    pub salt: u32,
    /// LSN of the first record.
    pub start_lsn: u64,
    /// Random id of the database this WAL belongs to (also stored in the meta page).
    pub db_id: u64,
}

impl WalHeader {
    /// Serialise.
    pub fn encode(&self) -> [u8; WAL_HEADER_SIZE] {
        let mut b = [0u8; WAL_HEADER_SIZE];
        b[0..8].copy_from_slice(&WAL_MAGIC);
        page::put_u32(&mut b, 8, WAL_VERSION);
        page::put_u32(&mut b, 12, self.salt);
        page::put_u64(&mut b, 16, self.start_lsn);
        page::put_u64(&mut b, 24, self.db_id);
        let mut h = Crc32c::new();
        h.update(&b[..36]);
        page::put_u32(&mut b, 36, h.finish());
        b
    }

    /// Parse and validate.
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() < WAL_HEADER_SIZE {
            return Err(Error::corrupt("WAL header truncated"));
        }
        if b[0..8] != WAL_MAGIC {
            return Err(Error::corrupt("WAL: bad magic"));
        }
        let mut h = Crc32c::new();
        h.update(&b[..36]);
        if h.finish() != get_u32(b, 36) {
            return Err(Error::corrupt("WAL: header checksum mismatch"));
        }
        let v = get_u32(b, 8);
        if v != WAL_VERSION {
            return Err(Error::corrupt(format!("WAL: unsupported version {v}")));
        }
        let start_lsn = get_u64(b, 16);
        // Leave LSN headroom so arithmetic on LSNs can never overflow.
        if start_lsn == 0 || start_lsn >= MAX_LSN {
            return Err(Error::corrupt(format!(
                "WAL: start LSN {start_lsn} out of range"
            )));
        }
        Ok(WalHeader {
            salt: get_u32(b, 12),
            start_lsn,
            db_id: get_u64(b, 24),
        })
    }
}

fn record_crc(salt: u32, hdr_tail: &[u8], payload: &[u8]) -> u32 {
    let mut h = Crc32c::new();
    h.update(&salt.to_le_bytes());
    h.update(hdr_tail);
    h.update(payload);
    h.finish()
}

/// Encode one record (header + payload) into `out`.
pub fn encode_record(out: &mut Vec<u8>, salt: u32, lsn: u64, kind: RecordKind, payload: &[u8]) {
    debug_assert!(payload.len() <= MAX_PAYLOAD);
    let mut hdr = [0u8; REC_HEADER_SIZE];
    page::put_u32(&mut hdr, 0, payload.len() as u32);
    page::put_u64(&mut hdr, 8, lsn);
    hdr[16] = kind as u8;
    let crc = record_crc(salt, &hdr[8..], payload);
    page::put_u32(&mut hdr, 4, crc);
    out.extend_from_slice(&hdr);
    out.extend_from_slice(payload);
}

/// Compute byte ranges where `new` differs from `old`, ignoring the checksum field.
/// Nearby ranges are merged (gaps under 8 bytes) to reduce per-range overhead.
pub fn diff_pages(old: &[u8; PAGE_SIZE], new: &[u8; PAGE_SIZE]) -> Vec<(u16, u16)> {
    const GAP: usize = 8;
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut i = 4;
    while i < PAGE_SIZE {
        if old[i] == new[i] {
            i += 1;
            continue;
        }
        let start = i;
        let mut end = i + 1;
        while end < PAGE_SIZE && old[end] != new[end] {
            end += 1;
        }
        if let Some(last) = ranges.last_mut()
            && start - last.1 < GAP
        {
            last.1 = end;
        } else {
            ranges.push((start, end));
        }
        i = end;
    }
    // PAGE_SIZE (16384) fits in u16, so the casts are lossless.
    ranges
        .into_iter()
        .map(|(s, e)| (s as u16, (e - s) as u16))
        .collect()
}

/// Build a delta payload; `None` if it would be larger than a full image.
pub fn encode_delta(id: PageId, ranges: &[(u16, u16)], new: &[u8; PAGE_SIZE]) -> Option<Vec<u8>> {
    let size: usize = 10 + ranges.iter().map(|&(_, l)| 4 + l as usize).sum::<usize>();
    if size >= MAX_PAYLOAD || ranges.len() > u16::MAX as usize {
        return None;
    }
    let mut p = Vec::with_capacity(size);
    p.extend_from_slice(&id.to_le_bytes());
    p.extend_from_slice(&(ranges.len() as u16).to_le_bytes());
    for &(off, len) in ranges {
        p.extend_from_slice(&off.to_le_bytes());
        p.extend_from_slice(&len.to_le_bytes());
        p.extend_from_slice(&new[off as usize..off as usize + len as usize]);
    }
    Some(p)
}

/// Apply a delta payload to `page`. Validates every bound; never panics on hostile input.
pub fn apply_delta(payload: &[u8], page: &mut [u8; PAGE_SIZE]) -> Result<PageId> {
    let bad = |m: &str| Error::corrupt(format!("WAL delta: {m}"));
    if payload.len() < 10 {
        return Err(bad("payload too short"));
    }
    let id = get_u64(payload, 0);
    let n = get_u16(payload, 8) as usize;
    let mut pos = 10usize;
    for _ in 0..n {
        if payload.len() < pos + 4 {
            return Err(bad("truncated range header"));
        }
        let off = get_u16(payload, pos) as usize;
        let len = get_u16(payload, pos + 2) as usize;
        pos += 4;
        if off < 4 || off + len > PAGE_SIZE {
            return Err(bad("range outside page"));
        }
        let data = payload
            .get(pos..pos + len)
            .ok_or_else(|| bad("truncated range data"))?;
        page[off..off + len].copy_from_slice(data);
        pos += len;
    }
    if pos != payload.len() {
        return Err(bad("trailing bytes"));
    }
    Ok(id)
}

/// Appends records and makes them durable.
pub struct WalWriter {
    file: Box<dyn VfsFile>,
    salt: u32,
    next_lsn: u64,
    end: u64,
    buf: Vec<u8>,
}

impl WalWriter {
    /// Writer positioned after the header of a fresh, synced WAL file.
    pub fn new(file: Box<dyn VfsFile>, header: WalHeader) -> Self {
        WalWriter {
            file,
            salt: header.salt,
            next_lsn: header.start_lsn,
            end: WAL_HEADER_SIZE as u64,
            buf: Vec::new(),
        }
    }

    /// LSN the next appended record will get.
    pub fn next_lsn(&self) -> u64 {
        self.next_lsn
    }

    /// Bytes in the WAL (including unflushed buffer).
    pub fn size(&self) -> u64 {
        self.end + self.buf.len() as u64
    }

    /// Buffer a record; returns its LSN.
    pub fn append(&mut self, kind: RecordKind, payload: &[u8]) -> u64 {
        let lsn = self.next_lsn;
        encode_record(&mut self.buf, self.salt, lsn, kind, payload);
        self.next_lsn += 1;
        lsn
    }

    /// Write the buffered records and fsync. On error the caller must poison the database.
    pub fn flush_sync(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            self.file.write_all_at(&self.buf, self.end)?;
            self.end += self.buf.len() as u64;
            self.buf.clear();
        }
        self.file.sync()
    }
}

/// One record yielded by [`WalScanner`].
#[derive(Debug)]
pub struct Record<'a> {
    /// Record kind.
    pub kind: RecordKind,
    /// Record LSN.
    pub lsn: u64,
    /// Payload bytes.
    pub payload: &'a [u8],
    /// File offset just past this record.
    pub end: u64,
}

/// Sequential reader. Stops (returns `None`) at end of file or at the first torn/invalid record.
pub struct WalScanner<'f> {
    file: &'f mut dyn VfsFile,
    len: u64,
    pos: u64,
    salt: u32,
    expected_lsn: u64,
    payload: Vec<u8>,
    /// Set when scanning stopped before end of file (torn or stale tail).
    pub stopped_early: bool,
}

impl<'f> WalScanner<'f> {
    /// Read and validate the header, position at the first record.
    pub fn open(file: &'f mut dyn VfsFile) -> Result<(Self, WalHeader)> {
        let len = file.size()?;
        let mut hb = [0u8; WAL_HEADER_SIZE];
        if len < WAL_HEADER_SIZE as u64 {
            return Err(Error::corrupt("WAL file shorter than its header"));
        }
        file.read_exact_at(&mut hb, 0)?;
        let h = WalHeader::decode(&hb)?;
        Ok((
            WalScanner {
                file,
                len,
                pos: WAL_HEADER_SIZE as u64,
                salt: h.salt,
                expected_lsn: h.start_lsn,
                payload: Vec::new(),
                stopped_early: false,
            },
            h,
        ))
    }

    /// Next valid record, or `None` at the end of the valid prefix.
    pub fn next_record(&mut self) -> Result<Option<Record<'_>>> {
        if self.pos == self.len {
            return Ok(None);
        }
        let stop = |s: &mut Self| {
            s.stopped_early = true;
            Ok(None)
        };
        if self.len - self.pos < REC_HEADER_SIZE as u64 {
            return stop(self);
        }
        let mut hdr = [0u8; REC_HEADER_SIZE];
        self.file.read_exact_at(&mut hdr, self.pos)?;
        let plen = get_u32(&hdr, 0) as usize;
        // Check the length before allocating anything based on it.
        if plen > MAX_PAYLOAD || self.len - self.pos - (REC_HEADER_SIZE as u64) < plen as u64 {
            return stop(self);
        }
        self.payload.resize(plen, 0);
        self.file
            .read_exact_at(&mut self.payload, self.pos + REC_HEADER_SIZE as u64)?;
        if record_crc(self.salt, &hdr[8..], &self.payload) != get_u32(&hdr, 4) {
            return stop(self);
        }
        let lsn = get_u64(&hdr, 8);
        if lsn != self.expected_lsn || lsn >= MAX_LSN {
            return stop(self);
        }
        // CRC matched: anything structurally wrong from here on is real corruption or a bug,
        // not a torn write, so it is reported instead of silently truncating the log.
        let kind = RecordKind::from_u8(hdr[16])
            .ok_or_else(|| Error::corrupt(format!("WAL record {lsn}: unknown kind {}", hdr[16])))?;
        self.expected_lsn = lsn
            .checked_add(1)
            .ok_or_else(|| Error::corrupt("WAL: LSN overflow"))?;
        self.pos += (REC_HEADER_SIZE + plen) as u64;
        Ok(Some(Record {
            kind,
            lsn,
            payload: &self.payload,
            end: self.pos,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page::{PageType, init_page, new_page_buf};
    use crate::vfs::MemFile;

    #[test]
    fn header_roundtrip_and_rejects_garbage() {
        let h = WalHeader {
            salt: 0xDEAD_BEEF,
            start_lsn: 77,
            db_id: 99,
        };
        let b = h.encode();
        assert_eq!(WalHeader::decode(&b).unwrap(), h);
        for i in 0..WAL_HEADER_SIZE {
            let mut c = b;
            c[i] ^= 1;
            assert!(WalHeader::decode(&c).is_err(), "flip {i}");
        }
        assert!(WalHeader::decode(&b[..10]).is_err());
    }

    #[test]
    fn diff_and_apply_roundtrip() {
        let mut a = new_page_buf();
        init_page(&mut a, 3, PageType::Leaf);
        let mut b = a.clone();
        b[0] = 9; // checksum bytes are ignored
        b[40] = 1;
        b[45] = 2; // merged with previous range (gap < 8)
        b[1000..1100].fill(7);
        b[PAGE_SIZE - 1] = 5;
        let r = diff_pages(&a, &b);
        assert_eq!(r.len(), 3);
        let p = encode_delta(3, &r, &b).unwrap();
        let mut c = a.clone();
        assert_eq!(apply_delta(&p, &mut c).unwrap(), 3);
        assert_eq!(c[4..], b[4..]);
        assert!(diff_pages(&a, &a).is_empty());
    }

    #[test]
    fn apply_delta_rejects_bad_ranges() {
        let mut pg = new_page_buf();
        let mut p = 1u64.to_le_bytes().to_vec();
        p.extend_from_slice(&1u16.to_le_bytes());
        p.extend_from_slice(&0u16.to_le_bytes()); // offset 0 = checksum field
        p.extend_from_slice(&1u16.to_le_bytes());
        p.push(1);
        assert!(apply_delta(&p, &mut pg).is_err());
        let mut q = 1u64.to_le_bytes().to_vec();
        q.extend_from_slice(&1u16.to_le_bytes());
        q.extend_from_slice(&(PAGE_SIZE as u16 - 1).to_le_bytes());
        q.extend_from_slice(&2u16.to_le_bytes());
        q.extend_from_slice(&[1, 2]);
        assert!(apply_delta(&q, &mut pg).is_err());
        assert!(apply_delta(&[1, 2, 3], &mut pg).is_err());
    }

    fn wal_with(records: &[(RecordKind, &[u8])], salt: u32) -> MemFile {
        let mut f = MemFile::default();
        f.0.extend_from_slice(
            &WalHeader {
                salt,
                start_lsn: 10,
                db_id: 1,
            }
            .encode(),
        );
        for (i, (k, p)) in records.iter().enumerate() {
            encode_record(&mut f.0, salt, 10 + i as u64, *k, p);
        }
        f
    }

    #[test]
    fn scanner_reads_valid_and_stops_at_torn_tail() {
        let mut f = wal_with(&[(RecordKind::Commit, &[]), (RecordKind::Commit, &[])], 5);
        let full = f.0.len();
        let mut n = 0;
        {
            let (mut s, _) = WalScanner::open(&mut f).unwrap();
            while s.next_record().unwrap().is_some() {
                n += 1;
            }
            assert!(!s.stopped_early);
        }
        assert_eq!(n, 2);
        // Every possible truncation yields a prefix and never errors.
        for cut in WAL_HEADER_SIZE..full {
            let mut g = MemFile(f.0[..cut].to_vec());
            let (mut s, _) = WalScanner::open(&mut g).unwrap();
            let mut m = 0;
            while s.next_record().unwrap().is_some() {
                m += 1;
            }
            assert!(m < 2);
        }
    }

    #[test]
    fn scanner_rejects_other_salt_and_lsn_gaps() {
        let mut a = wal_with(&[(RecordKind::Commit, &[])], 1);
        // Splice a record encoded with a different salt.
        encode_record(&mut a.0, 2, 11, RecordKind::Commit, &[]);
        // and one with a wrong LSN
        let (mut s, _) = WalScanner::open(&mut a).unwrap();
        assert!(s.next_record().unwrap().is_some());
        assert!(s.next_record().unwrap().is_none());
        assert!(s.stopped_early);

        let mut b = wal_with(&[(RecordKind::Commit, &[])], 1);
        encode_record(&mut b.0, 1, 12, RecordKind::Commit, &[]);
        let (mut s, _) = WalScanner::open(&mut b).unwrap();
        assert!(s.next_record().unwrap().is_some());
        assert!(s.next_record().unwrap().is_none());
    }

    #[test]
    fn scanner_huge_length_does_not_allocate() {
        let mut f = wal_with(&[], 1);
        let mut hdr = [0u8; REC_HEADER_SIZE];
        page::put_u32(&mut hdr, 0, u32::MAX);
        f.0.extend_from_slice(&hdr);
        let (mut s, _) = WalScanner::open(&mut f).unwrap();
        assert!(s.next_record().unwrap().is_none());
    }
}
