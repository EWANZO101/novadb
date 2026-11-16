#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Deterministic power-loss testing with [`SimVfs`]: run random transactions, inject an I/O
//! fault at a random operation (= the moment power is cut), drop un-synced writes randomly
//! (with torn sectors), reopen, and check that the database equals exactly the last
//! acknowledged commit (or the in-flight one, if its commit record happened to reach disk).

use novadb_storage::{Db, Error, Options, SimRng, SimVfs};
use std::collections::BTreeMap;

type Model = BTreeMap<Vec<u8>, Vec<u8>>;

fn opts() -> Options {
    Options {
        cache_pages: 32,
        checkpoint_wal_bytes: 64 * 1024,
        create_if_missing: true,
    }
}

fn read_all(db: &mut Db) -> Result<Model, Error> {
    db.view(|tx| match tx.open_tree("t") {
        Ok(t) => tx.range(&t, ..)?.collect(),
        Err(Error::TreeNotFound(_)) => Ok(Model::new()),
        Err(e) => Err(e),
    })
}

/// Run one transaction; on success returns the new model.
fn txn(db: &mut Db, rng: &mut SimRng, model: &Model) -> Result<Model, Error> {
    let mut m = model.clone();
    let mut tx = db.begin()?;
    // Side tree churn (not part of the model): exercises drop + lazy page reclamation under
    // power loss; `verify` after every reopen checks it left no leaked/shared pages.
    if rng.chance(1, 8) {
        match tx.open_tree("aux") {
            Ok(_) => tx.drop_tree("aux")?,
            Err(Error::TreeNotFound(_)) => {
                let a = tx.create_tree("aux")?;
                for i in 0..150u32 {
                    tx.put(&a, &i.to_be_bytes(), &[7u8; 90])?;
                }
            }
            Err(e) => return Err(e),
        }
    }
    let t = tx.open_or_create_tree("t")?;
    for _ in 0..rng.below(30) + 1 {
        let k = format!("k{:05}", rng.below(3000)).into_bytes();
        match rng.below(10) {
            0..=5 => {
                let len = if rng.chance(1, 20) {
                    4000
                } else {
                    rng.below(400) as usize
                };
                let v = vec![rng.below(256) as u8; len];
                tx.put(&t, &k, &v)?;
                m.insert(k, v);
            }
            6..=8 => {
                tx.delete(&t, &k)?;
                m.remove(&k);
            }
            _ => {
                assert_eq!(tx.get(&t, &k)?, m.get(&k).cloned());
            }
        }
    }
    tx.commit()?;
    Ok(m)
}

fn run_seed(seed: u64, rounds: usize) {
    let vfs = SimVfs::new();
    let mut rng = SimRng::new(seed);
    let mut acked = Model::new();
    let mut in_flight: Option<Model> = None;
    for round in 0..rounds {
        // Sometimes also cut power during recovery itself; then recover again.
        if rng.chance(1, 4) {
            vfs.fail_after(Some(vfs.op_count() + rng.below(12)));
            if let Ok(db) = Db::open_vfs(Box::new(vfs.clone()), opts()) {
                drop(db);
            }
            vfs.crash(&mut rng);
        }
        let mut db = Db::open_vfs(Box::new(vfs.clone()), opts())
            .unwrap_or_else(|e| panic!("seed {seed} round {round}: reopen failed: {e}"));
        let got = read_all(&mut db).unwrap();
        if got != acked {
            match &in_flight {
                Some(f) if got == *f => acked = f.clone(),
                _ => panic!(
                    "seed {seed} round {round}: state mismatch (got {} keys, acked {}, in-flight {:?})",
                    got.len(),
                    acked.len(),
                    in_flight.as_ref().map(|m| m.len())
                ),
            }
        }
        in_flight = None;
        db.verify()
            .unwrap_or_else(|e| panic!("seed {seed} round {round}: verify: {e}"));

        // Arm the fault: power is cut at a random upcoming I/O operation.
        let budget = rng.below(400) + 1;
        vfs.fail_after(Some(vfs.op_count() + budget));
        if rng.chance(1, 6) {
            vfs.fail_syncs(true);
        }
        loop {
            let mut r2 = rng.clone();
            match txn(&mut db, &mut r2, &acked) {
                Ok(m) => {
                    rng = r2;
                    acked = m;
                    if rng.chance(1, 15) && db.checkpoint().is_err() {
                        break;
                    }
                }
                Err(_) => {
                    // Recompute what this transaction would have produced, in case its commit
                    // record reached the disk before the failure was reported.
                    let mut r3 = rng.clone();
                    let mut m = acked.clone();
                    simulate(&mut r3, &mut m);
                    in_flight = Some(m);
                    rng = r2;
                    break;
                }
            }
        }
        drop(db);
        vfs.crash(&mut rng);
    }
}

/// Replays `txn`'s random choices on a model only.
fn simulate(rng: &mut SimRng, m: &mut Model) {
    let _aux = rng.chance(1, 8);
    for _ in 0..rng.below(30) + 1 {
        let k = format!("k{:05}", rng.below(3000)).into_bytes();
        match rng.below(10) {
            0..=5 => {
                let len = if rng.chance(1, 20) {
                    4000
                } else {
                    rng.below(400) as usize
                };
                let v = vec![rng.below(256) as u8; len];
                m.insert(k, v);
            }
            6..=8 => {
                m.remove(&k);
            }
            _ => {}
        }
    }
}

#[test]
fn power_loss_simulation() {
    let seeds: u64 = std::env::var("NOVADB_SIM_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(40);
    for seed in 0..seeds {
        run_seed(seed, 12);
    }
}
