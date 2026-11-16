//! Crash-test harness used by `scripts/crash-test.sh`.
//!
//! `novadb-crashtest run DIR SEED` commits deterministic transactions forever, printing
//! `ok N` after transaction N's commit returned (i.e. after the WAL fsync). It resumes from
//! the last committed transaction found in the database, so it can be killed and restarted.
//!
//! `novadb-crashtest verify DIR SEED ACKED` opens the database (running recovery), checks all
//! invariants, reads the last committed transaction number N, requires `N >= ACKED`
//! (acknowledged commits are durable) and compares the full contents against a model rebuilt
//! by replaying transactions 1..=N (atomicity: no partial transaction is visible).
#![forbid(unsafe_code)]

use novadb_storage::{Db, Error, Options, SimRng};
use std::collections::BTreeMap;
use std::io::Write;
use std::process::ExitCode;

const LAST: &[u8] = b"~last";
const TREE: &str = "crash";

fn opts() -> Options {
    Options {
        cache_pages: 256,
        checkpoint_wal_bytes: 1 << 20,
        create_if_missing: true,
    }
}

/// The operations of transaction `n` (deterministic in `seed`, `n`).
fn ops(seed: u64, n: u64) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
    let mut r = SimRng::new(seed ^ n.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let count = r.below(60) + 1;
    (0..count)
        .map(|_| {
            let k = format!("k{:05}", r.below(5000)).into_bytes();
            if r.chance(1, 4) {
                (k, None)
            } else {
                let len = if r.chance(1, 30) {
                    novadb_storage::MAX_VALUE_LEN - 8
                } else {
                    r.below(1500) as usize
                };
                let fill = (n as u8).wrapping_mul(31) ^ (r.next_u64() as u8);
                let mut v = vec![fill; len];
                v.extend_from_slice(&n.to_le_bytes());
                (k, Some(v))
            }
        })
        .collect()
}

fn last_committed(db: &mut Db) -> Result<u64, Error> {
    db.view(|tx| match tx.open_tree(TREE) {
        Ok(t) => Ok(tx.get(&t, LAST)?.map_or(0, |b| {
            let mut a = [0u8; 8];
            a.copy_from_slice(&b[..8.min(b.len())]);
            u64::from_le_bytes(a)
        })),
        Err(Error::TreeNotFound(_)) => Ok(0),
        Err(e) => Err(e),
    })
}

fn run(dir: &str, seed: u64) -> Result<(), String> {
    let mut db = Db::open(dir, opts()).map_err(|e| e.to_string())?;
    let mut n = last_committed(&mut db).map_err(|e| e.to_string())?;
    let mut out = std::io::stdout().lock();
    loop {
        n += 1;
        db.update(|tx| {
            let t = tx.open_or_create_tree(TREE)?;
            for (k, v) in ops(seed, n) {
                match v {
                    Some(v) => tx.put(&t, &k, &v)?,
                    None => tx.delete(&t, &k)?,
                };
            }
            tx.put(&t, LAST, &n.to_le_bytes())?;
            Ok(())
        })
        .map_err(|e| e.to_string())?;
        writeln!(out, "ok {n}")
            .and_then(|()| out.flush())
            .map_err(|e| e.to_string())?;
    }
}

fn verify(dir: &str, seed: u64, acked: u64) -> Result<String, String> {
    let mut db = Db::open(dir, opts()).map_err(|e| format!("open: {e}"))?;
    let rep = db.recovery_report().clone();
    db.verify().map_err(|e| format!("verify: {e}"))?;
    let n = last_committed(&mut db).map_err(|e| e.to_string())?;
    if n < acked {
        return Err(format!(
            "DURABILITY: acknowledged txn {acked} but database only has {n}"
        ));
    }
    let mut model: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    for i in 1..=n {
        for (k, v) in ops(seed, i) {
            match v {
                Some(v) => model.insert(k, v),
                None => model.remove(&k),
            };
        }
        model.insert(LAST.to_vec(), i.to_le_bytes().to_vec());
    }
    let got: BTreeMap<Vec<u8>, Vec<u8>> = db
        .view(|tx| match tx.open_tree(TREE) {
            Ok(t) => tx.range(&t, ..)?.collect(),
            Err(Error::TreeNotFound(_)) => Ok(BTreeMap::new()),
            Err(e) => Err(e),
        })
        .map_err(|e| e.to_string())?;
    if got != model {
        let diff = model
            .keys()
            .chain(got.keys())
            .filter(|k| model.get(*k) != got.get(*k))
            .count();
        return Err(format!(
            "ATOMICITY: state differs from txn {n} model in {diff} keys"
        ));
    }
    db.close().map_err(|e| e.to_string())?;
    Ok(format!(
        "ok: txn {n} (acked {acked}), {} keys, recovery replayed {} commits / {} pages, torn tail: {}",
        got.len(),
        rep.commits,
        rep.pages_applied,
        rep.torn_tail
    ))
}

fn main() -> ExitCode {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let num = |s: &String| s.parse::<u64>().map_err(|e| e.to_string());
    let r = match a.as_slice() {
        [c, dir, seed] if c == "run" => num(seed).and_then(|s| run(dir, s)).map(|()| String::new()),
        [c, dir, seed, acked] if c == "verify" => {
            num(seed).and_then(|s| num(acked).and_then(|k| verify(dir, s, k)))
        }
        _ => Err("usage: novadb-crashtest run DIR SEED | verify DIR SEED ACKED".into()),
    };
    match r {
        Ok(m) => {
            println!("{m}");
            ExitCode::SUCCESS
        }
        Err(m) => {
            eprintln!("{m}");
            ExitCode::FAILURE
        }
    }
}
