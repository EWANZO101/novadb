//! Differential fuzzing of the engine against `BTreeMap`, including rollback, checkpoint,
//! reopen and simulated power loss. Any divergence panics.
#![no_main]
use libfuzzer_sys::fuzz_target;
use novadb_storage::{Db, Error, Options, SimRng, SimVfs};
use std::collections::BTreeMap;
use std::ops::Bound;

type Model = BTreeMap<Vec<u8>, Vec<u8>>;

fn opts() -> Options {
    Options { cache_pages: 32, checkpoint_wal_bytes: 64 * 1024, create_if_missing: true }
}

fn dump(db: &mut Db) -> Model {
    db.view(|tx| match tx.open_tree("t") {
        Ok(t) => tx.range(&t, ..)?.collect(),
        Err(Error::TreeNotFound(_)) => Ok(Model::new()),
        Err(e) => Err(e),
    })
    .expect("scan")
}

fuzz_target!(|data: &[u8]| {
    let v = SimVfs::new();
    let mut db = Db::open_vfs(Box::new(v.clone()), opts()).expect("open");
    let mut committed = Model::new();
    let mut ops = data.chunks(4);
    while let Some(c) = ops.next() {
        let op = c[0];
        let k = vec![b'k', *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0) % 8];
        let vlen = (*c.get(3).unwrap_or(&0) as usize) * 17 % 4097;
        match op % 8 {
            // A transaction of up to 16 following ops, committed or rolled back.
            0..=4 => {
                let mut m = committed.clone();
                let mut tx = db.begin().expect("begin");
                let t = tx.open_or_create_tree("t").expect("tree");
                let n = (op as usize >> 3) % 16 + 1;
                let mut res = Ok(());
                for _ in 0..n {
                    let Some(c) = ops.next() else { break };
                    let k = vec![b'k', c[0], *c.get(1).unwrap_or(&0) % 8];
                    let len = (*c.get(2).unwrap_or(&0) as usize) * 17 % 4097;
                    let r = match c.get(3).unwrap_or(&0) % 4 {
                        0 | 1 => tx.put(&t, &k, &vec![c[0]; len]).map(|old| {
                            assert_eq!(old, m.insert(k.clone(), vec![c[0]; len]));
                        }),
                        2 => tx.delete(&t, &k).map(|old| assert_eq!(old, m.remove(&k))),
                        _ => {
                            let lo = Bound::Included(k.as_slice());
                            let got: Result<Vec<_>, _> = tx.range(&t, (lo, Bound::Unbounded)).map(|it| it.take(5).collect());
                            got.and_then(|g: Vec<_>| g.into_iter().collect::<Result<Vec<_>, _>>()).map(|g| {
                                let want: Vec<_> = m.range(k.clone()..).take(5).map(|(a, b)| (a.clone(), b.clone())).collect();
                                assert_eq!(g, want);
                            })
                        }
                    };
                    if let Err(e) = r {
                        assert!(matches!(e, Error::TxnTooLarge { .. }), "unexpected error {e}");
                        res = Err(e);
                        break;
                    }
                }
                if res.is_ok() && op & 0x80 == 0 {
                    tx.commit().expect("commit");
                    committed = m;
                } else {
                    tx.rollback();
                }
            }
            5 => db.checkpoint().expect("checkpoint"),
            6 => {
                drop(db);
                db = Db::open_vfs(Box::new(v.clone()), opts()).expect("reopen");
            }
            _ => {
                // Power loss right now: all commits were fsynced, so nothing may be lost.
                drop(db);
                v.crash(&mut SimRng::new(u64::from(op) << 8 | k[1] as u64 | vlen as u64));
                db = Db::open_vfs(Box::new(v.clone()), opts()).expect("reopen after crash");
            }
        }
    }
    assert_eq!(dump(&mut db), committed);
    db.verify().expect("verify");
});
