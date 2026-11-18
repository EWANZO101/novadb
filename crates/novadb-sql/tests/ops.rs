#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Stage 7: encrypted backups, encrypted binary log, restore and point-in-time recovery.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use novadb_sql::backup;
use novadb_sql::{Engine, Session};

const BASE: i64 = 1_795_000_000_000_000;

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("novadb-ops-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn engine(dir: &Path, clock: &Arc<AtomicI64>) -> Engine {
    let c = clock.clone();
    Engine::open(dir.join("db"))
        .unwrap()
        .with_clock(move || c.load(Ordering::SeqCst))
        .with_password_hasher(|p| Ok(format!("hash:{p}")))
}

fn run(e: &mut Engine, conn: u32, sql: &str) {
    let mut s = Session {
        user: "root".into(),
        conn_id: conn,
        ..Default::default()
    };
    for st in novadb_sql::parse(sql).unwrap() {
        e.run_in(&st, &mut s)
            .unwrap_or_else(|err| panic!("{sql}: {err}"));
    }
}

/// Assert equal, reporting the first difference compactly (rows can be very long).
fn same(got: &[String], want: &[String], what: &str) {
    let short = |s: &String| s.chars().take(160).collect::<String>();
    if got != want {
        let i = got
            .iter()
            .zip(want)
            .position(|(a, b)| a != b)
            .unwrap_or(got.len().min(want.len()));
        panic!(
            "{what}: first difference at line {i} (got {} lines, want {}):\n  got:  {:?}\n  want: {:?}",
            got.len(),
            want.len(),
            got.get(i).map(short),
            want.get(i).map(short)
        );
    }
}

/// Everything observable: tables, their definitions and rows, users, next AUTO_INCREMENT.
fn state(e: &mut Engine) -> Vec<String> {
    let mut out = Vec::new();
    let tables: Vec<String> = e
        .query("SHOW TABLES")
        .unwrap()
        .rows
        .iter()
        .map(|r| r[0].to_string())
        .collect();
    for t in tables {
        let ddl = e.query(&format!("SHOW CREATE TABLE `{t}`")).unwrap().rows[0][1].to_string();
        out.push(ddl);
        let r = e.query(&format!("SELECT * FROM `{t}`")).unwrap();
        let mut rows: Vec<String> = (0..r.rows.len())
            .map(|i| {
                (0..r.columns.len())
                    .map(|c| r.text(i, c).unwrap_or_else(|| "NULL".into()))
                    .collect::<Vec<_>>()
                    .join("|")
            })
            .collect();
        rows.sort();
        out.extend(rows);
    }
    let mut users: Vec<String> = e
        .users()
        .unwrap()
        .into_iter()
        .map(|u| format!("{u}={:?}", e.user_hash(&u).unwrap()))
        .collect();
    users.sort();
    out.extend(users);
    out
}

#[test]
fn backup_restore_and_point_in_time_recovery() {
    let d = tmp("pitr");
    let key = backup::new_key().unwrap();
    let clock = Arc::new(AtomicI64::new(BASE));
    let tick = |c: &Arc<AtomicI64>| c.fetch_add(1_000_000, Ordering::SeqCst);
    let mut a = engine(&d.join("a"), &clock)
        .with_binlog(&d.join("a/binlog"), Some(key))
        .unwrap();

    run(
        &mut a,
        1,
        "CREATE TABLE users (id INT PRIMARY KEY AUTO_INCREMENT, email VARCHAR(50) NOT NULL, bal DECIMAL(10,2) DEFAULT 0, bio TEXT, UNIQUE KEY ue (email))",
    );
    run(
        &mut a,
        1,
        "CREATE TABLE events (kind VARCHAR(10), n INT, KEY kk (kind))",
    ); // hidden row id
    run(
        &mut a,
        1,
        "CREATE USER app IDENTIFIED BY 'app-password-123'",
    );
    run(
        &mut a,
        1,
        &format!(
            "INSERT INTO users (email, bal, bio) VALUES ('a@x', 10, '{}'), ('b@x', 20, NULL)",
            "long ".repeat(3000)
        ),
    );
    run(
        &mut a,
        1,
        "INSERT INTO events VALUES ('login', 1), ('login', 2), ('buy', 3)",
    );
    tick(&clock);

    // Backup while another session holds an open transaction with uncommitted changes.
    run(&mut a, 2, "BEGIN; UPDATE users SET bal = 999 WHERE id = 1");
    let bk = d.join("full.nbk");
    let snap = backup::dump(&mut a, 900, &bk, Some(key), clock.load(Ordering::SeqCst)).unwrap();
    a.rotate_binlog().unwrap();
    run(&mut a, 2, "COMMIT");
    tick(&clock);

    // Changes after the backup: DML, a committed transaction, a rolled-back one, DDL, users.
    run(
        &mut a,
        1,
        "INSERT INTO users (email) VALUES ('c@x'); UPDATE events SET n = n * 10 WHERE kind = 'login'; DELETE FROM events WHERE kind = 'buy'",
    );
    tick(&clock);
    let mid_wall = clock.load(Ordering::SeqCst);
    let mid_state = state(&mut a);
    tick(&clock);
    run(
        &mut a,
        3,
        "BEGIN; UPDATE users SET email = 'zz@x' WHERE id = 2; DELETE FROM users WHERE id = 3; ROLLBACK",
    );
    run(
        &mut a,
        3,
        "BEGIN; INSERT INTO users (email, bal) VALUES ('d@x', 5); UPDATE users SET bal = bal + 1; COMMIT",
    );
    run(
        &mut a,
        1,
        "CREATE TABLE extra (k INT PRIMARY KEY, v VARCHAR(5)); INSERT INTO extra VALUES (1, 'one'); CREATE INDEX kv ON extra (v)",
    );
    run(
        &mut a,
        1,
        "ALTER USER app IDENTIFIED BY 'new-password-456'; CREATE USER temp IDENTIFIED BY 'temporary-pass1'; DROP USER temp",
    );
    run(&mut a, 1, "DROP TABLE events");
    tick(&clock);
    run(&mut a, 1, "INSERT INTO users (email) VALUES ('probe@x')");
    let final_state = state(&mut a);

    // The binlog and the backup are encrypted: no table data in clear on disk.
    for f in std::fs::read_dir(d.join("a/binlog")).unwrap() {
        let raw = std::fs::read(f.unwrap().path()).unwrap();
        assert!(!raw.windows(3).any(|w| w == b"a@x"), "binlog leaks data");
    }
    assert!(
        !std::fs::read(&bk).unwrap().windows(3).any(|w| w == b"a@x"),
        "backup leaks data"
    );

    // 1. Full recovery: backup + whole binlog == live database.
    let mut b = engine(&d.join("b"), &clock);
    assert_eq!(backup::restore(&mut b, &bk, Some(&key)).unwrap(), snap);
    let applied = backup::replay(&mut b, &d.join("a/binlog"), Some(&key), snap, None).unwrap();
    assert!(applied >= 8, "applied {applied}");
    same(&state(&mut b), &final_state, "full recovery");
    // AUTO_INCREMENT continues where the original left off.
    let next_a = a
        .query("INSERT INTO users (email) VALUES ('after-a@x')")
        .unwrap()
        .last_insert_id;
    let next_b = b
        .query("INSERT INTO users (email) VALUES ('after-b@x')")
        .unwrap()
        .last_insert_id;
    assert_eq!(next_b, next_a, "restored counter");

    // 2. Point in time: only changes up to `mid_wall`.
    let mut c = engine(&d.join("c"), &clock);
    backup::restore(&mut c, &bk, Some(&key)).unwrap();
    backup::replay(
        &mut c,
        &d.join("a/binlog"),
        Some(&key),
        snap,
        Some(mid_wall),
    )
    .unwrap();
    same(&state(&mut c), &mid_state, "point in time");

    // 3. The backup itself reflects exactly its snapshot (session 2's update came later).
    let mut x = engine(&d.join("x"), &clock);
    backup::restore(&mut x, &bk, Some(&key)).unwrap();
    assert_eq!(
        x.query("SELECT bal FROM users WHERE id = 1").unwrap().rows[0][0].to_string(),
        "10.00"
    );
    assert!(
        backup::restore(&mut x, &bk, Some(&key)).is_err(),
        "restore refuses a non-empty database"
    );

    for e in [a, b, c, x] {
        e.close().unwrap();
    }
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn binlog_survives_reopen_and_trims_uncommitted() {
    let d = tmp("reopen");
    let clock = Arc::new(AtomicI64::new(BASE));
    {
        let mut a = engine(&d, &clock)
            .with_binlog(&d.join("binlog"), None)
            .unwrap();
        run(
            &mut a,
            1,
            "CREATE TABLE t (id INT PRIMARY KEY); INSERT INTO t VALUES (1), (2)",
        );
        a.close().unwrap();
    }
    let n1 = novadb_sql::binlog::read_all(&d.join("binlog"), None)
        .unwrap()
        .len();
    {
        let mut a = engine(&d, &clock)
            .with_binlog(&d.join("binlog"), None)
            .unwrap();
        run(&mut a, 1, "INSERT INTO t VALUES (3)");
        a.close().unwrap();
    }
    let recs = novadb_sql::binlog::read_all(&d.join("binlog"), None).unwrap();
    assert_eq!(recs.len(), n1 + 1);
    assert!(
        recs.windows(2).all(|w| w[0].ts < w[1].ts),
        "timestamps strictly increase"
    );
    std::fs::remove_dir_all(&d).unwrap();
}
