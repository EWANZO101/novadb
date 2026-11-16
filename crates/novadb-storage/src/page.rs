//! Fixed-size page layout shared by the data file and WAL page images.
//!
//! ```text
//! offset size field
//!  0     4    crc32c of bytes [4..PAGE_SIZE] (computed on write, verified on read)
//!  4     1    page type
//!  5     3    reserved (0)
//!  8     8    page id (self-identification: catches misdirected writes/reads)
//! 16     8    page LSN (LSN of the WAL record that last logged this page)
//! 24     8    owner tree id (0 = none); catches cross-tree pointer corruption & stale handles
//! 32     ..   body
//! ```

use crate::crc32c::crc32c;
use crate::error::{Error, Result};

/// Page size in bytes (16 KiB, like InnoDB's default).
pub const PAGE_SIZE: usize = 16 * 1024;
/// Size of the common page header.
pub const HEADER_SIZE: usize = 32;
/// Usable body bytes per page.
pub const BODY_SIZE: usize = PAGE_SIZE - HEADER_SIZE;
/// Highest page id we accept (4 TiB data file). Bounds file growth and `verify` memory (32 MiB
/// bitmap) for corrupt/hostile input.
pub const MAX_PAGE_ID: u64 = (1 << 28) - 1;

/// Page number within the data file. Page 0 is the meta page.
pub type PageId = u64;

/// Owned page buffer.
pub type PageBuf = Box<[u8; PAGE_SIZE]>;

/// Allocate a zeroed page buffer on the heap.
pub fn new_page_buf() -> PageBuf {
    Box::new([0u8; PAGE_SIZE])
}

/// Kinds of pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PageType {
    /// Database meta page (page 0).
    Meta = 1,
    /// B+Tree leaf.
    Leaf = 2,
    /// B+Tree internal node.
    Internal = 3,
    /// Page on the free list.
    Free = 4,
}

impl PageType {
    /// Decode a page type byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(PageType::Meta),
            2 => Some(PageType::Leaf),
            3 => Some(PageType::Internal),
            4 => Some(PageType::Free),
            _ => None,
        }
    }
}

/// Read a little-endian u16 at `off` (caller guarantees bounds).
pub(crate) fn get_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
pub(crate) fn get_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
pub(crate) fn get_u64(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(a)
}
#[cfg(test)]
pub(crate) fn put_u16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
pub(crate) fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
pub(crate) fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// Page type byte.
pub fn page_type(p: &[u8; PAGE_SIZE]) -> Option<PageType> {
    PageType::from_u8(p[4])
}
/// Page id from header.
pub fn page_id(p: &[u8; PAGE_SIZE]) -> PageId {
    get_u64(p, 8)
}
/// Page LSN from header.
pub fn page_lsn(p: &[u8; PAGE_SIZE]) -> u64 {
    get_u64(p, 16)
}

/// Initialise a page header (zeroes the whole page first).
pub fn init_page(p: &mut [u8; PAGE_SIZE], id: PageId, ty: PageType) {
    p.fill(0);
    p[4] = ty as u8;
    put_u64(p, 8, id);
}

/// Owner tree id from header.
pub fn page_owner(p: &[u8; PAGE_SIZE]) -> u64 {
    get_u64(p, 24)
}

/// Set the owner tree id.
pub fn set_page_owner(p: &mut [u8; PAGE_SIZE], owner: u64) {
    put_u64(p, 24, owner);
}

/// Offset of the database id inside the meta page (page 0).
pub const META_DB_ID_OFFSET: usize = HEADER_SIZE + 48;

/// Database id stored in a meta page.
pub fn meta_db_id(p: &[u8; PAGE_SIZE]) -> u64 {
    get_u64(p, META_DB_ID_OFFSET)
}

/// Set the page LSN.
pub fn set_page_lsn(p: &mut [u8; PAGE_SIZE], lsn: u64) {
    put_u64(p, 16, lsn);
}

/// Compute and store the checksum.
pub fn seal(p: &mut [u8; PAGE_SIZE]) {
    let c = crc32c(&p[4..]);
    put_u32(p, 0, c);
}

/// Verify checksum, self-id and type byte. Returns the page type.
pub fn verify(p: &[u8; PAGE_SIZE], expected: PageId) -> Result<PageType> {
    let stored = get_u32(p, 0);
    let actual = crc32c(&p[4..]);
    if stored != actual {
        return Err(Error::corrupt(format!(
            "page {expected}: checksum mismatch (stored {stored:#010x}, computed {actual:#010x})"
        )));
    }
    let id = page_id(p);
    if id != expected {
        return Err(Error::corrupt(format!(
            "page {expected}: header claims page id {id}"
        )));
    }
    PageType::from_u8(p[4])
        .ok_or_else(|| Error::corrupt(format!("page {expected}: unknown page type {}", p[4])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_verify_roundtrip_and_detects_flips() {
        let mut p = new_page_buf();
        init_page(&mut p, 7, PageType::Leaf);
        p[100] = 42;
        seal(&mut p);
        assert_eq!(verify(&p, 7).unwrap(), PageType::Leaf);
        assert!(matches!(verify(&p, 8), Err(Error::Corruption(_))));
        for pos in [0usize, 4, 9, 100, PAGE_SIZE - 1] {
            let mut q = p.clone();
            q[pos] ^= 0x10;
            assert!(verify(&q, 7).is_err(), "flip at {pos} undetected");
        }
        let zero = new_page_buf();
        assert!(verify(&zero, 0).is_err(), "all-zero page must not verify");
    }
}
