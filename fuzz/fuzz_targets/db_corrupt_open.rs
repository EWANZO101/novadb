//! Mutate a valid database file (then optionally re-seal page checksums so the corruption
//! gets past CRC checks) and use it. Malformed pages must yield errors, never panics/hangs.
#![no_main]
use libfuzzer_sys::fuzz_target;
use novadb_storage::page::{PAGE_SIZE, seal};
use novadb_storage::{DATA_FILE, Db, Options, SimVfs, WAL_FILE};
use std::sync::OnceLock;

fn base() -> &'static (Vec<u8>, Vec<u8>) {
    static D: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    D.get_or_init(|| {
        let v = SimVfs::new();
        let o = Options { cache_pages: 32, ..Options::default() };
        let mut db = Db::open_vfs(Box::new(v.clone()), o).unwrap();
        db.update(|tx| {
            let t = tx.create_tree("a")?;
            for i in 0..1500u32 {
                tx.put(&t, &i.to_be_bytes(), &[i as u8; 40])?;
            }
            let u = tx.create_tree("b")?;
            for i in 0..50u32 {
                tx.put(&u, &i.to_le_bytes(), b"v")?;
            }
            Ok(())
        })
        .unwrap();
        db.update(|tx| {
            let t = tx.open_tree("a")?;
            for i in (0..1500u32).step_by(3) {
                tx.delete(&t, &i.to_be_bytes())?;
            }
            Ok(())
        })
        .unwrap();
        db.close().unwrap();
        (v.get_file(DATA_FILE).unwrap(), v.get_file(WAL_FILE).unwrap())
    })
}

fuzz_target!(|data: &[u8]| {
    let (d, w) = base();
    let mut d = d.clone();
    let Some((&flags, muts)) = data.split_first() else { return };
    for m in muts.chunks_exact(4).take(64) {
        let off = u32::from_le_bytes([m[0], m[1], m[2], 0]) as usize % d.len();
        d[off] ^= m[3];
    }
    if flags & 1 == 1 {
        for page in d.chunks_exact_mut(PAGE_SIZE) {
            let p: &mut [u8; PAGE_SIZE] = page.try_into().unwrap();
            seal(p);
        }
    }
    let v = SimVfs::new();
    v.put_file(DATA_FILE, &d);
    v.put_file(WAL_FILE, w);
    let o = Options { cache_pages: 32 + (flags as usize >> 1) % 64, ..Options::default() };
    let Ok(mut db) = Db::open_vfs(Box::new(v), o) else { return };
    let _ = db.verify();
    let _ = db.view(|tx| {
        for name in tx.list_trees()? {
            let t = tx.open_tree(&name)?;
            let mut n = 0;
            for r in tx.range(&t, ..)? {
                r?;
                n += 1;
            }
            let _ = n;
        }
        Ok(())
    });
    for i in 0..8u32 {
        let _ = db.update(|tx| {
            let t = tx.open_tree("a")?;
            tx.put(&t, &(i * 37).to_be_bytes(), &[1; 300])?;
            tx.delete(&t, &(i * 11).to_be_bytes())?;
            Ok(())
        });
    }
    let _ = db.update(|tx| tx.drop_tree("b"));
    let _ = db.checkpoint();
});
