#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Database-level behaviour: durability, rollback, limits, corruption handling.

use novadb_storage::page::PAGE_SIZE;
use novadb_storage::{DATA_FILE, Db, Error, Options, SimRng, SimVfs, WAL_FILE};
use std::collections::BTreeMap;
use std::ops::Bound;

fn opts(cache: usize) -> Options {
    Options {
        cache_pages: cache,
        checkpoint_wal_bytes: 64 << 20,
        create_if_missing: true,
    }
}

fn open(v: &SimVfs, cache: usize) -> Db {
    Db::open_vfs(Box::new(v.clone()), opts(cache)).unwrap()
}

fn dump(db: &mut Db, tree: &str) -> BTreeMap<Vec<u8>, Vec<u8>> {
    db.view(|tx| {
        let t = tx.open_tree(tree)?;
        tx.range(&t, ..)?.collect::<Result<BTreeMap<_, _>, _>>()
    })
    .unwrap()
}

fn key(i: u64) -> Vec<u8> {
    format!("key{i:08}").into_bytes()
}

#[test]
fn crud_persists_across_reopen() {
    let v = SimVfs::new();
    {
        let mut db = open(&v, 64);
        db.update(|tx| {
            let t = tx.create_tree("users")?;
            for i in 0..2000 {
                tx.put(&t, &key(i), format!("value-{i}").as_bytes())?;
            }
            Ok(())
        })
        .unwrap();
        db.update(|tx| {
            let t = tx.open_tree("users")?;
            for i in (0..2000).step_by(3) {
                assert!(tx.delete(&t, &key(i))?.is_some());
            }
            assert_eq!(tx.put(&t, &key(1), b"new")?, Some(b"value-1".to_vec()));
            Ok(())
        })
        .unwrap();
        // dropped without close: everything must come back from the WAL
    }
    let mut db = open(&v, 64);
    assert!(db.recovery_report().commits >= 2);
    let m = dump(&mut db, "users");
    assert_eq!(m.len(), 2000 - 667);
    assert_eq!(m[&key(1)], b"new");
    assert!(!m.contains_key(&key(3)));
    db.verify().unwrap();
    db.close().unwrap();
    let mut db = open(&v, 64);
    assert_eq!(
        db.recovery_report().commits,
        0,
        "clean close leaves an empty WAL"
    );
    assert_eq!(dump(&mut db, "users").len(), 1333);
}

#[test]
fn rollback_restores_everything_incl_allocations() {
    let v = SimVfs::new();
    let mut db = open(&v, 256);
    db.update(|tx| {
        let t = tx.create_tree("t")?;
        tx.put(&t, b"a", b"1")
    })
    .unwrap();
    let before = db.stats();
    {
        let mut tx = db.begin().unwrap();
        let t = tx.open_tree("t").unwrap();
        for i in 0..3000 {
            tx.put(&t, &key(i), &[7u8; 200]).unwrap();
        }
        tx.delete(&t, b"a").unwrap();
        tx.create_tree("other").unwrap();
        // dropped -> rollback
    }
    assert_eq!(db.stats().page_count, before.page_count);
    let m = dump(&mut db, "t");
    assert_eq!(m.len(), 1);
    assert!(db.view(|tx| tx.open_tree("other")).is_err());
    db.verify().unwrap();
    // explicit rollback too
    let mut tx = db.begin().unwrap();
    let t = tx.open_tree("t").unwrap();
    tx.put(&t, b"b", b"2").unwrap();
    tx.rollback();
    assert_eq!(dump(&mut db, "t").len(), 1);
    drop(db);
    let mut db = open(&v, 256);
    assert_eq!(dump(&mut db, "t").len(), 1);
    db.verify().unwrap();
}

#[test]
fn txn_too_large_fails_cleanly() {
    let v = SimVfs::new();
    let mut db = open(&v, 32);
    db.update(|tx| tx.create_tree("t").map(|_| ())).unwrap();
    let r = db.update(|tx| {
        let t = tx.open_tree("t")?;
        for i in 0..10_000 {
            tx.put(&t, &key(i), &[1u8; 500])?;
        }
        Ok(())
    });
    assert!(matches!(r, Err(Error::TxnTooLarge { .. })), "{r:?}");
    db.verify().unwrap();
    assert!(dump(&mut db, "t").is_empty());
    // Many small transactions with the same tiny cache work (eviction of committed pages).
    for c in 0..100u64 {
        db.update(|tx| {
            let t = tx.open_tree("t")?;
            for i in 0..100 {
                tx.put(&t, &key(c * 100 + i), &[1u8; 500])?;
            }
            Ok(())
        })
        .unwrap();
    }
    assert_eq!(dump(&mut db, "t").len(), 10_000);
    assert!(db.stats().page_writes > 0, "evictions expected");
    db.verify().unwrap();
}

#[test]
fn failed_tx_cannot_commit() {
    let v = SimVfs::new();
    let mut db = open(&v, 32);
    db.update(|tx| tx.create_tree("t").map(|_| ())).unwrap();
    let mut tx = db.begin().unwrap();
    let t = tx.open_tree("t").unwrap();
    let mut failed = false;
    for i in 0..10_000 {
        if tx.put(&t, &key(i), &[1u8; 500]).is_err() {
            failed = true;
            break;
        }
    }
    assert!(failed);
    assert!(
        tx.get(&t, b"x").is_err(),
        "failed tx must refuse further use"
    );
    assert!(tx.commit().is_err());
    db.verify().unwrap();
}

#[test]
fn size_limits_and_names() {
    let v = SimVfs::new();
    let mut db = open(&v, 64);
    let r = db.update(|tx| {
        let t = tx.create_tree("t")?;
        tx.put(&t, &vec![0; novadb_storage::MAX_KEY_LEN + 1], b"")
    });
    assert!(matches!(r, Err(Error::KeyTooLarge(_))));
    let r = db.update(|tx| {
        let t = tx.create_tree("t")?;
        tx.put(&t, b"k", &vec![0; novadb_storage::MAX_VALUE_LEN + 1])
    });
    assert!(matches!(r, Err(Error::ValueTooLarge(_))));
    // limit errors don't fail the tx
    db.update(|tx| {
        let t = tx.create_tree("t")?;
        assert!(tx.put(&t, &vec![0; 5000], b"").is_err());
        tx.put(&t, b"ok", b"1")?;
        assert!(matches!(tx.create_tree("t"), Err(Error::TreeExists(_))));
        assert!(matches!(tx.create_tree(""), Err(Error::InvalidArgument(_))));
        assert!(tx.create_tree(&"x".repeat(256)).is_err());
        Ok(())
    })
    .unwrap();
    assert_eq!(dump(&mut db, "t").len(), 1);
    assert!(matches!(
        db.view(|tx| tx.open_tree("nope")),
        Err(Error::TreeNotFound(_))
    ));
    assert!(Db::open_vfs(Box::new(SimVfs::new()), opts(1)).is_err());
}

#[test]
fn range_bounds() {
    let v = SimVfs::new();
    let mut db = open(&v, 64);
    let model: BTreeMap<Vec<u8>, Vec<u8>> = (0..3000u64)
        .map(|i| (key(i * 2), vec![i as u8; 30]))
        .collect();
    db.update(|tx| {
        let t = tx.create_tree("t")?;
        for (k, v) in &model {
            tx.put(&t, k, v)?;
        }
        Ok(())
    })
    .unwrap();
    let mut rng = SimRng::new(9);
    for _ in 0..200 {
        let a = key(rng.below(6100));
        let b = key(rng.below(6100));
        let pick = |r: &mut SimRng, k: &Vec<u8>| match r.below(3) {
            0 => Bound::Included(k.clone()),
            1 => Bound::Excluded(k.clone()),
            _ => Bound::Unbounded,
        };
        let (s, e) = (pick(&mut rng, &a), pick(&mut rng, &b));
        if let (Bound::Included(x) | Bound::Excluded(x), Bound::Included(y) | Bound::Excluded(y)) =
            (&s, &e)
            && x > y
        {
            continue; // BTreeMap panics on inverted ranges
        }
        if let (Bound::Excluded(x), Bound::Excluded(y)) = (&s, &e)
            && x == y
        {
            continue;
        }
        let want: Vec<_> = model
            .range::<Vec<u8>, _>((s.clone(), e.clone()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let got = db
            .view(|tx| {
                let t = tx.open_tree("t")?;
                let sb = s.as_ref().map(|x| x.as_slice());
                let eb = e.as_ref().map(|x| x.as_slice());
                tx.range(&t, (sb, eb))?.collect::<Result<Vec<_>, _>>()
            })
            .unwrap();
        assert_eq!(got, want);
    }
}

#[test]
fn drop_tree_frees_pages_and_stale_handles_are_rejected() {
    let v = SimVfs::new();
    let mut db = open(&v, 128);
    let old = db
        .update(|tx| {
            let t = tx.create_tree("a")?;
            for i in 0..2000 {
                tx.put(&t, &key(i), &[3u8; 100])?;
            }
            Ok(t)
        })
        .unwrap();
    db.update(|tx| tx.drop_tree("a")).unwrap();
    let r = db.verify().unwrap();
    assert!(r.free_pages > 10, "{r:?}");
    let pages = db.stats().page_count;
    db.update(|tx| {
        let t = tx.create_tree("b")?;
        for i in 0..2000 {
            tx.put(&t, &key(i), &[4u8; 100])?;
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(db.stats().page_count, pages, "freed pages must be reused");
    // The old handle's root page now belongs to tree "b": must error, not touch b's data.
    let r = db.update(|tx| tx.put(&old, b"evil", b"x"));
    assert!(matches!(r, Err(Error::Corruption(_))), "{r:?}");
    assert_eq!(dump(&mut db, "b").len(), 2000);
    assert_eq!(
        db.view(|tx| tx.list_trees()).unwrap(),
        vec!["b".to_string()]
    );
    db.verify().unwrap();
}

#[test]
fn many_keys_small_cache_with_checkpoints() {
    let v = SimVfs::new();
    let o = Options {
        cache_pages: 48,
        checkpoint_wal_bytes: 256 * 1024,
        create_if_missing: true,
    };
    let mut db = Db::open_vfs(Box::new(v.clone()), o.clone()).unwrap();
    let mut model = BTreeMap::new();
    let mut rng = SimRng::new(3);
    for _ in 0..300 {
        db.update(|tx| {
            let t = tx.open_or_create_tree("t")?;
            for _ in 0..40 {
                let k = key(rng.below(20_000));
                if rng.chance(1, 4) {
                    tx.delete(&t, &k)?;
                    model.remove(&k);
                } else {
                    let val = vec![rng.below(256) as u8; rng.below(700) as usize];
                    tx.put(&t, &k, &val)?;
                    model.insert(k, val);
                }
            }
            Ok(())
        })
        .unwrap();
    }
    assert!(db.stats().checkpoints > 0);
    db.verify().unwrap();
    assert_eq!(dump(&mut db, "t"), model);
    drop(db);
    let mut db = Db::open_vfs(Box::new(v), o).unwrap();
    assert_eq!(dump(&mut db, "t"), model);
    db.verify().unwrap();
}

#[test]
fn lock_prevents_second_open() {
    let v = SimVfs::new();
    let _db = open(&v, 64);
    assert!(matches!(
        Db::open_vfs(Box::new(v.clone()), opts(64)),
        Err(Error::Locked)
    ));

    let dir = std::env::temp_dir().join(format!("novadb-lock-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    {
        let _a = Db::open(&dir, opts(64)).unwrap();
        assert!(matches!(Db::open(&dir, opts(64)), Err(Error::Locked)));
    }
    let b = Db::open(&dir, opts(64)).unwrap();
    b.close().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join(DATA_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "data file must not be group/world accessible"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn corrupted_page_is_reported_not_panicking() {
    let v = SimVfs::new();
    {
        let mut db = open(&v, 64);
        db.update(|tx| {
            let t = tx.create_tree("t")?;
            for i in 0..3000 {
                tx.put(&t, &key(i), &[9u8; 64])?;
            }
            Ok(())
        })
        .unwrap();
        db.close().unwrap(); // checkpoint: WAL empty, data file authoritative
    }
    let mut data = v.get_file(DATA_FILE).unwrap();
    let pages = data.len() / PAGE_SIZE;
    for p in 1..pages {
        let mut d = data.clone();
        d[p * PAGE_SIZE + 100 + p] ^= 0x40;
        let v2 = SimVfs::new();
        v2.put_file(DATA_FILE, &d);
        v2.put_file(WAL_FILE, &v.get_file(WAL_FILE).unwrap());
        let mut db = open(&v2, 64);
        let r = db.verify();
        assert!(matches!(r, Err(Error::Corruption(_))), "page {p}: {r:?}");
    }
    // Corrupt meta page -> open fails cleanly.
    data[50] ^= 1;
    let v3 = SimVfs::new();
    v3.put_file(DATA_FILE, &data);
    v3.put_file(WAL_FILE, &v.get_file(WAL_FILE).unwrap());
    assert!(matches!(
        Db::open_vfs(Box::new(v3), opts(64)),
        Err(Error::Corruption(_))
    ));
}

#[test]
fn torn_data_pages_are_repaired_from_wal() {
    let v = SimVfs::new();
    let mut db = Db::open_vfs(Box::new(v.clone()), opts(32)).unwrap();
    let mut model = BTreeMap::new();
    for c in 0..40u64 {
        db.update(|tx| {
            let t = tx.open_or_create_tree("t")?;
            for i in 0..50 {
                tx.put(&t, &key(c * 50 + i), &[c as u8; 300])?;
                model.insert(key(c * 50 + i), vec![c as u8; 300]);
            }
            Ok(())
        })
        .unwrap();
    }
    assert!(db.stats().page_writes > 0, "need evicted pages on disk");
    drop(db);
    // Garble every data page except meta: all of them are in the WAL (no checkpoint yet).
    let mut data = v.get_file(DATA_FILE).unwrap();
    for (i, chunk) in data.chunks_mut(PAGE_SIZE).enumerate().skip(2) {
        chunk[1000..1512].fill(i as u8); // torn sector
    }
    v.put_file(DATA_FILE, &data);
    let mut db = Db::open_vfs(Box::new(v.clone()), opts(32)).unwrap();
    assert!(db.recovery_report().pages_applied > 0);
    db.verify().unwrap();
    assert_eq!(dump(&mut db, "t"), model);
}

#[test]
fn truncated_wal_yields_a_commit_prefix() {
    let v = SimVfs::new();
    {
        let mut db = open(&v, 64);
        for c in 1..=30u64 {
            db.update(|tx| {
                let t = tx.open_or_create_tree("t")?;
                tx.put(&t, b"counter", &c.to_le_bytes())?;
                tx.put(&t, &key(c), &[c as u8; 900])?;
                Ok(())
            })
            .unwrap();
        }
    }
    let data = v.get_file(DATA_FILE).unwrap();
    let wal = v.get_file(WAL_FILE).unwrap();
    let mut last = 0u64;
    let mut cuts: Vec<usize> = (novadb_storage::wal::WAL_HEADER_SIZE..wal.len())
        .step_by(97)
        .collect();
    cuts.push(wal.len());
    for cut in cuts {
        let v2 = SimVfs::new();
        v2.put_file(DATA_FILE, &data);
        v2.put_file(WAL_FILE, &wal[..cut]);
        let mut db = open(&v2, 64);
        db.verify().unwrap();
        let m = db
            .view(|tx| match tx.open_tree("t") {
                Ok(t) => tx.range(&t, ..)?.collect::<Result<BTreeMap<_, _>, _>>(),
                Err(Error::TreeNotFound(_)) => Ok(BTreeMap::new()),
                Err(e) => Err(e),
            })
            .unwrap();
        let c = m
            .get(b"counter".as_slice())
            .map_or(0, |b| u64::from_le_bytes(b[..8].try_into().unwrap()));
        assert!(c >= last, "a longer WAL prefix must not lose commits");
        last = c;
        assert_eq!(m.len() as u64, if c == 0 { 0 } else { c + 1 }, "cut {cut}");
        for i in 1..=c {
            assert_eq!(m[&key(i)], vec![i as u8; 900]);
        }
    }
    assert_eq!(last, 30);
}

#[test]
fn missing_files_are_detected() {
    let v = SimVfs::new();
    {
        let mut db = open(&v, 64);
        db.update(|tx| tx.create_tree("t").map(|_| ())).unwrap();
    }
    let wal = v.get_file(WAL_FILE).unwrap();
    let data = v.get_file(DATA_FILE).unwrap();
    let only_data = SimVfs::new();
    only_data.put_file(DATA_FILE, &data);
    assert!(matches!(
        Db::open_vfs(Box::new(only_data), opts(64)),
        Err(Error::Corruption(_))
    ));
    let only_wal = SimVfs::new();
    only_wal.put_file(WAL_FILE, &wal);
    assert!(matches!(
        Db::open_vfs(Box::new(only_wal), opts(64)),
        Err(Error::Corruption(_))
    ));
    let mut o = opts(64);
    o.create_if_missing = false;
    assert!(matches!(
        Db::open_vfs(Box::new(SimVfs::new()), o),
        Err(Error::NotFound)
    ));
    // Garbage instead of a WAL
    let bad = SimVfs::new();
    bad.put_file(DATA_FILE, &data);
    bad.put_file(WAL_FILE, b"this is not a wal file at all, definitely not");
    assert!(matches!(
        Db::open_vfs(Box::new(bad), opts(64)),
        Err(Error::Corruption(_))
    ));
}

#[test]
fn wal_from_another_database_is_rejected() {
    let mk = || {
        let v = SimVfs::new();
        let mut db = open(&v, 64);
        db.update(|tx| {
            let t = tx.create_tree("t")?;
            tx.put(&t, b"k", b"v")
        })
        .unwrap();
        v // dropped without checkpoint: WAL has commits
    };
    let (a, b) = (mk(), mk());
    let mixed = SimVfs::new();
    mixed.put_file(DATA_FILE, &a.get_file(DATA_FILE).unwrap());
    mixed.put_file(WAL_FILE, &b.get_file(WAL_FILE).unwrap());
    let r = Db::open_vfs(Box::new(mixed), opts(64));
    assert!(
        matches!(r, Err(Error::Corruption(ref m)) if m.contains("database")),
        "{:?}",
        r.err()
    );
    // Even an empty WAL from another database is refused.
    let mut db = open(&b, 64);
    db.checkpoint().unwrap();
    drop(db);
    let mixed = SimVfs::new();
    mixed.put_file(DATA_FILE, &a.get_file(DATA_FILE).unwrap());
    mixed.put_file(WAL_FILE, &b.get_file(WAL_FILE).unwrap());
    assert!(Db::open_vfs(Box::new(mixed), opts(64)).is_err());
}

#[test]
fn fsync_failure_poisons_the_handle() {
    let v = SimVfs::new();
    let mut db = open(&v, 64);
    db.update(|tx| {
        let t = tx.create_tree("t")?;
        tx.put(&t, b"a", b"1")
    })
    .unwrap();
    v.fail_syncs(true);
    let r = db.update(|tx| {
        let t = tx.open_tree("t")?;
        tx.put(&t, b"b", b"2")
    });
    assert!(r.is_err());
    assert!(
        matches!(db.begin().err(), Some(Error::Poisoned(_))),
        "no retry after failed fsync"
    );
    assert!(db.checkpoint().is_err());
    drop(db);
    v.crash(&mut SimRng::new(1));
    let mut db = open(&v, 64);
    let m = dump(&mut db, "t");
    assert_eq!(m[b"a".as_slice()], b"1");
    assert!(m.len() <= 2);
    db.verify().unwrap();
}

// ----- regression tests for review findings (2026-11-16) -----------------------------------

fn fill(db: &mut Db, name: &str, n: u64, vlen: usize) {
    for c in 0..n.div_ceil(200) {
        db.update(|tx| {
            let t = tx.open_or_create_tree(name)?;
            for i in c * 200..((c + 1) * 200).min(n) {
                tx.put(&t, &key(i), &vec![i as u8; vlen])?;
            }
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn dropping_a_tree_larger_than_the_cache_works() {
    let v = SimVfs::new();
    let mut db = open(&v, 32);
    fill(&mut db, "big", 6000, 300); // ~130 pages, cache is 32
    fill(&mut db, "keep", 100, 10);
    let pages = db.stats().page_count;
    db.update(|tx| tx.drop_tree("big")).unwrap();
    assert_eq!(db.stats().purge_error, None);
    let r = db.verify().unwrap();
    assert_eq!(r.dropped_pending, 0);
    assert_eq!(r.trees, 1);
    assert!(r.free_pages > 100, "{r:?}");
    assert_eq!(
        db.view(|tx| tx.list_trees()).unwrap(),
        vec!["keep".to_string()]
    );
    // the name is immediately reusable, and freed pages are reused
    fill(&mut db, "big", 6000, 300);
    assert!(db.stats().page_count <= pages + 2);
    db.verify().unwrap();
}

#[test]
fn drop_is_atomic_and_reclamation_resumes_after_crash() {
    for seed in 0..20u64 {
        let v = SimVfs::new();
        let mut db = open(&v, 32);
        fill(&mut db, "big", 3000, 300);
        fill(&mut db, "keep", 50, 10);
        // Power fails somewhere during the drop or the page reclamation that follows it.
        let mut rng = SimRng::new(seed);
        v.fail_after(Some(v.op_count() + 1 + rng.below(60)));
        let dropped = db.update(|tx| tx.drop_tree("big")).is_ok();
        drop(db);
        v.crash(&mut rng);
        let mut db = open(&v, 32);
        let r = db.verify().unwrap();
        assert_eq!(
            r.dropped_pending, 0,
            "seed {seed}: reclamation must finish on open"
        );
        let trees = db.view(|tx| tx.list_trees()).unwrap();
        assert!(trees.contains(&"keep".to_string()));
        if dropped {
            // commit was acknowledged before the fault hit the reclamation phase
            assert!(!trees.contains(&"big".to_string()), "seed {seed}");
        }
        if trees.contains(&"big".to_string()) {
            assert_eq!(
                dump(&mut db, "big").len(),
                3000,
                "seed {seed}: drop must be atomic"
            );
        }
    }
}

#[test]
fn lost_data_file_after_checkpoint_is_not_silently_recreated() {
    let v = SimVfs::new();
    {
        let mut db = open(&v, 64);
        fill(&mut db, "t", 10, 10);
        db.close().unwrap(); // WAL now has no commits but start_lsn > 1
    }
    let only_wal = SimVfs::new();
    only_wal.put_file(WAL_FILE, &v.get_file(WAL_FILE).unwrap());
    assert!(matches!(
        Db::open_vfs(Box::new(only_wal), opts(64)),
        Err(Error::Corruption(_))
    ));
}

#[test]
fn handles_are_bound_to_their_db_instance_and_ids_not_reused() {
    let v = SimVfs::new();
    let mut db = open(&v, 64);
    let t = db.update(|tx| tx.create_tree("t")).unwrap();
    drop(db);
    let mut db = open(&v, 64);
    let r = db.update(|tx| tx.put(&t, b"k", b"v"));
    assert!(matches!(r, Err(Error::InvalidArgument(_))), "{r:?}");
    // tree id from a rolled-back create is not handed out again
    let ghost = {
        let mut tx = db.begin().unwrap();
        let g = tx.create_tree("ghost").unwrap();
        tx.rollback();
        g
    };
    let real = db.update(|tx| tx.create_tree("real")).unwrap();
    assert_ne!(ghost.id(), real.id());
    assert!(db.update(|tx| tx.put(&ghost, b"k", b"v")).is_err());
    assert!(
        db.view(|tx| tx.open_tree("a\u{0}b")).is_err(),
        "control chars rejected"
    );
}
