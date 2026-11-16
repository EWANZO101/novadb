//! Structure-aware WAL fuzzing: the input describes records that are encoded with *valid*
//! salt/LSN/CRC, so the fuzzer reaches the semantic checks in recovery (page ids, image
//! headers, delta ranges). Afterwards the database is opened and fully verified/scanned.
//! Nothing may panic; errors are fine.
#![no_main]
use libfuzzer_sys::fuzz_target;
use novadb_storage::page::{PAGE_SIZE, init_page, new_page_buf, PageType};
use novadb_storage::wal::{RecordKind, WalHeader, encode_record};
use novadb_storage::{DATA_FILE, Db, Options, SimVfs, WAL_FILE};
use std::sync::OnceLock;

fn base_data() -> &'static Vec<u8> {
    static D: OnceLock<Vec<u8>> = OnceLock::new();
    D.get_or_init(|| {
        let v = SimVfs::new();
        let mut db = Db::open_vfs(Box::new(v.clone()), Options::default()).unwrap();
        db.update(|tx| {
            let t = tx.create_tree("t")?;
            for i in 0..300u32 {
                tx.put(&t, &i.to_be_bytes(), &[i as u8; 100])?;
            }
            Ok(())
        })
        .unwrap();
        db.close().unwrap();
        v.get_file(DATA_FILE).unwrap()
    })
}

struct In<'a>(&'a [u8]);
impl In<'_> {
    fn u8(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes([self.u8()?, self.u8()?]))
    }
    fn take(&mut self, n: usize) -> &[u8] {
        let n = n.min(self.0.len());
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        a
    }
}

fuzz_target!(|data: &[u8]| {
    let salt = 0x5EED;
    let db_id = u64::from_le_bytes(base_data()[novadb_storage::page::META_DB_ID_OFFSET..][..8].try_into().unwrap());
    // Occasionally use a foreign db id to exercise the mismatch check.
    let db_id = if data.first() == Some(&0xFF) { db_id ^ 1 } else { db_id };
    let mut wal = WalHeader { salt, start_lsn: 1, db_id }.encode().to_vec();
    let mut lsn = 1;
    let mut inp = In(data);
    let mut n = 0;
    while let Some(op) = inp.u8() {
        n += 1;
        if n > 64 {
            break;
        }
        let page_id = (op >> 2) as u64 % 24; // small ids keep memory bounded
        match op & 3 {
            0 => {
                let mut p = new_page_buf();
                let ty = match inp.u8().unwrap_or(0) % 5 {
                    0 => PageType::Meta,
                    1 => PageType::Leaf,
                    2 => PageType::Internal,
                    _ => PageType::Free,
                };
                init_page(&mut p, page_id, ty);
                if page_id == 0 {
                    p[..PAGE_SIZE].copy_from_slice(&base_data()[..PAGE_SIZE]);
                }
                let off = 32 + inp.u16().unwrap_or(0) as usize % (PAGE_SIZE - 32);
                let len = inp.u8().unwrap_or(0) as usize;
                let src = inp.take(len);
                let end = (off + src.len()).min(PAGE_SIZE);
                p[off..end].copy_from_slice(&src[..end - off]);
                let mut payload = page_id.to_le_bytes().to_vec();
                payload.extend_from_slice(&p[..]);
                encode_record(&mut wal, salt, lsn, RecordKind::PageImage, &payload);
            }
            1 => {
                let mut payload = page_id.to_le_bytes().to_vec();
                let cnt = inp.u8().unwrap_or(0) % 4;
                payload.extend_from_slice(&(cnt as u16).to_le_bytes());
                for _ in 0..cnt {
                    let off = inp.u16().unwrap_or(0) % (PAGE_SIZE as u16 + 8);
                    let len = inp.u8().unwrap_or(0) as u16;
                    payload.extend_from_slice(&off.to_le_bytes());
                    payload.extend_from_slice(&len.to_le_bytes());
                    let d = inp.take(len as usize).to_vec();
                    payload.extend_from_slice(&d);
                }
                encode_record(&mut wal, salt, lsn, RecordKind::PageDelta, &payload);
            }
            _ => encode_record(&mut wal, salt, lsn, RecordKind::Commit, &[]),
        }
        lsn += 1;
    }
    let v = SimVfs::new();
    v.put_file(DATA_FILE, base_data());
    v.put_file(WAL_FILE, &wal);
    let o = Options { cache_pages: 32, ..Options::default() };
    if let Ok(mut db) = Db::open_vfs(Box::new(v), o) {
        let _ = db.verify();
        let _ = db.view(|tx| {
            for name in tx.list_trees()? {
                let t = tx.open_tree(&name)?;
                for r in tx.range(&t, ..)? {
                    r?;
                }
            }
            Ok(())
        });
        let _ = db.update(|tx| {
            let t = tx.open_or_create_tree("t")?;
            tx.put(&t, b"x", b"y")?;
            tx.delete(&t, &5u32.to_be_bytes())?;
            Ok(())
        });
    }
});
