#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! ALTER TABLE: instant changes, online rebuild with concurrent writes, blocking rebuild
//! (primary key changes), transactional ALTER, failure + crash cleanup, binlog replay.

use novadb_sql::{Engine, QueryResult, Session, SqlError};
use std::path::{Path, PathBuf};

static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn tmp(tag: &str) -> PathBuf {
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let d = std::env::temp_dir().join(format!("novadb-alter-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

struct Db {
    dir: PathBuf,
    e: Option<Engine>,
}

fn sess(conn: u32) -> Session {
    Session {
        user: "t".into(),
        conn_id: conn,
        ..Default::default()
    }
}

impl Db {
    fn new() -> Self {
        let dir = tmp("db");
        Db {
            e: Some(Engine::open(&dir).unwrap()),
            dir,
        }
    }
    fn e(&mut self) -> &mut Engine {
        self.e.as_mut().unwrap()
    }
    fn crash(&mut self) {
        drop(self.e.take());
        self.e = Some(Engine::open(&self.dir).unwrap());
    }
    fn reopen(&mut self) {
        self.e.take().unwrap().close().unwrap();
        self.e = Some(Engine::open(&self.dir).unwrap());
    }
    fn on(&mut self, conn: u32, sql: &str) -> Result<QueryResult, SqlError> {
        let mut s = sess(conn);
        let mut out = None;
        for st in novadb_sql::parse(sql)? {
            out = Some(self.e().run_in(&st, &mut s)?);
        }
        Ok(out.unwrap_or_default())
    }
    fn ok(&mut self, conn: u32, sql: &str) -> QueryResult {
        self.on(conn, sql)
            .unwrap_or_else(|e| panic!("conn {conn}: {sql}\n -> {e}"))
    }
    fn code(&mut self, conn: u32, sql: &str) -> u16 {
        match self.on(conn, sql) {
            Ok(r) => panic!("conn {conn}: {sql} should fail, got {r:?}"),
            Err(e) => e.code,
        }
    }
    fn rows(&mut self, sql: &str) -> Vec<String> {
        self.ok(0, sql)
            .rows
            .iter()
            .map(|r| {
                r.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .collect()
    }
    fn create(&mut self) -> String {
        self.ok(0, "SHOW CREATE TABLE t").rows[0][1].to_string()
    }
    /// Start an online ALTER on `conn` without finishing it.
    fn start(&mut self, conn: u32, sql: &str) {
        let st = novadb_sql::parse(sql).unwrap().remove(0);
        let mut s = sess(conn);
        self.e().run_in_start(&st, &mut s).unwrap();
        assert!(self.e().alter_running(), "{sql} should run online");
    }
    fn step_to_end(&mut self) -> QueryResult {
        loop {
            if let Some(r) = self.e().alter_step().unwrap() {
                return r;
            }
        }
    }
    fn shadows(&mut self) -> usize {
        self.e()
            .db()
            .view(|tx| {
                let c = tx.open_tree("sql:catalog")?;
                let n = tx
                    .range(
                        &c,
                        (
                            std::ops::Bound::Included(&b"s\0"[..]),
                            std::ops::Bound::Excluded(&b"s\x01"[..]),
                        ),
                    )?
                    .count();
                Ok(n)
            })
            .unwrap()
    }
}

fn seeded(n: i64) -> Db {
    let mut d = Db::new();
    d.ok(
        0,
        "CREATE TABLE t (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(20) NOT NULL, score INT, note TEXT)",
    );
    let vals: Vec<String> = (1..=n)
        .map(|i| format!("('n{i}', {}, 'note {i}')", i % 7))
        .collect();
    for chunk in vals.chunks(500) {
        d.ok(
            0,
            &format!(
                "INSERT INTO t (name, score, note) VALUES {}",
                chunk.join(",")
            ),
        );
    }
    d
}

#[test]
fn instant_changes() {
    let mut d = seeded(50);
    let r = d.ok(0, "ALTER TABLE t ADD COLUMN extra VARCHAR(10)");
    assert!(r.info.unwrap().contains("instant"));
    assert_eq!(d.rows("SELECT extra FROM t WHERE id = 1"), vec!["NULL"]);
    d.ok(0, "UPDATE t SET extra = 'x' WHERE id = 2");
    assert_eq!(
        d.rows("SELECT COUNT(*) FROM t WHERE extra IS NULL"),
        vec!["49"]
    );
    for sql in [
        "ALTER TABLE t RENAME COLUMN extra TO more",
        "ALTER TABLE t ALTER COLUMN score SET DEFAULT 5",
        "ALTER TABLE t MODIFY note TEXT NULL",
        "ALTER TABLE t MODIFY more VARCHAR(30)",
        "ALTER TABLE t ADD INDEX ix_score (score)", // not instant, but sets up the next ones
    ] {
        d.ok(0, sql);
    }
    let r = d.ok(0, "ALTER TABLE t RENAME INDEX ix_score TO ix_s");
    assert!(r.info.unwrap().contains("instant"));
    assert_eq!(d.rows("SELECT COUNT(*) FROM t WHERE score = 3"), vec!["7"]);
    let r = d.ok(0, "ALTER TABLE t DROP INDEX ix_s, RENAME TO t2");
    assert!(r.info.unwrap().contains("instant"));
    assert_eq!(d.code(0, "SELECT * FROM t"), 1146);
    d.ok(0, "INSERT INTO t2 (name) VALUES ('new')");
    assert_eq!(
        d.rows("SELECT id, score, more FROM t2 WHERE name = 'new'"),
        vec!["51,5,NULL"]
    );
    d.ok(0, "ALTER TABLE t2 RENAME TO t");
    d.reopen();
    let c = d.create();
    assert!(c.contains("`more` varchar(30) DEFAULT NULL"), "{c}");
    assert!(c.contains("`score` int DEFAULT 5"), "{c}");
    assert!(!c.contains("ix_s"), "{c}");
}

#[test]
fn online_rebuild_reshapes_rows() {
    let mut d = seeded(2500);
    let r = d.ok(
        0,
        "ALTER TABLE t DROP COLUMN note, MODIFY score BIGINT NOT NULL DEFAULT 0, \
         ADD COLUMN flag INT NOT NULL DEFAULT 1 FIRST, ADD UNIQUE INDEX u_name (name), \
         CHANGE name label VARCHAR(40) NOT NULL AFTER flag",
    );
    assert!(r.info.as_deref().unwrap().contains("online"), "{r:?}");
    assert_eq!(r.affected, 2500);
    let c = d.create();
    assert!(
        c.contains("`flag` int NOT NULL DEFAULT 1,\n  `label` varchar(40) NOT NULL,\n  `id` int NOT NULL AUTO_INCREMENT"),
        "{c}"
    );
    assert!(c.contains("UNIQUE KEY `u_name` (`label`)"), "{c}");
    assert_eq!(
        d.rows("SELECT flag, label, id, score FROM t WHERE id = 10"),
        vec!["1,n10,10,3"]
    );
    assert_eq!(
        d.rows("SELECT id FROM t WHERE label = 'n2000'"),
        vec!["2000"]
    );
    assert_eq!(d.rows("SELECT COUNT(*) FROM t"), vec!["2500"]);
    // AUTO_INCREMENT continues where it was.
    d.ok(0, "INSERT INTO t (label) VALUES ('after')");
    assert_eq!(
        d.rows("SELECT id FROM t WHERE label = 'after'"),
        vec!["2501"]
    );
    assert_eq!(d.code(0, "INSERT INTO t (label) VALUES ('n5')"), 1062);
    assert_eq!(d.shadows(), 0);
    d.reopen();
    assert_eq!(d.rows("SELECT COUNT(*) FROM t"), vec!["2501"]);
    d.e().db().verify().unwrap();
}

#[test]
fn online_rebuild_with_concurrent_writes() {
    let mut d = seeded(3000);
    d.start(
        1,
        "ALTER TABLE t ADD INDEX ix_score (score), MODIFY note VARCHAR(100)",
    );
    let mut k = 0;
    loop {
        // other sessions keep working between steps
        k += 1;
        d.ok(
            2,
            &format!("INSERT INTO t (name, score, note) VALUES ('live{k}', 99, 'x')"),
        );
        d.ok(
            3,
            &format!("UPDATE t SET score = 100 WHERE id = {}", k * 37 % 3000 + 1),
        );
        d.ok(
            4,
            &format!("DELETE FROM t WHERE id = {}", k * 53 % 3000 + 1),
        );
        if k % 3 == 0 {
            d.ok(5, "BEGIN");
            d.ok(
                5,
                &format!("INSERT INTO t (name, score) VALUES ('tx{k}', 98)"),
            );
            d.ok(5, "UPDATE t SET note = 'in txn' WHERE id = 7");
            d.ok(5, "COMMIT");
        }
        assert_eq!(d.code(6, "CREATE INDEX x ON t (name)"), 1205, "DDL waits");
        if let Some(r) = d.e().alter_step().unwrap() {
            assert!(r.info.unwrap().contains("online"));
            break;
        }
        assert!(k < 1000, "ALTER never finished");
    }
    assert!(k >= 3, "ran in several steps ({k})");
    // The rebuilt table must agree with a full scan via the new index and the PK.
    let all = d.rows("SELECT id, name, score, note FROM t ORDER BY id");
    let by_ix: usize = (0..=100)
        .map(|s| d.rows(&format!("SELECT id FROM t WHERE score = {s}")).len())
        .sum();
    assert_eq!(by_ix, all.len(), "index covers every row");
    assert_eq!(
        d.rows("SELECT COUNT(*) FROM t WHERE score = 99"),
        vec![k.to_string()]
    );
    assert!(d.rows("SELECT note FROM t WHERE id = 7") == vec!["in txn"] || k < 3);
    assert!(d.create().contains("`note` varchar(100)"));
    assert_eq!(d.shadows(), 0);
}

#[test]
fn swap_waits_for_open_transactions() {
    let mut d = seeded(100);
    d.start(1, "ALTER TABLE t DROP COLUMN note");
    d.ok(2, "BEGIN");
    d.ok(2, "UPDATE t SET score = 42 WHERE id = 1");
    for _ in 0..20 {
        assert!(
            d.e().alter_step().unwrap().is_none(),
            "must wait for conn 2"
        );
    }
    d.ok(2, "COMMIT");
    let r = d.step_to_end();
    assert_eq!(r.affected, 100);
    assert_eq!(d.rows("SELECT score FROM t WHERE id = 1"), vec!["42"]);
}

#[test]
fn failures_leave_the_table_unchanged() {
    let mut d = seeded(300);
    let before = d.create();
    // duplicate values for a new unique index
    assert_eq!(d.code(1, "ALTER TABLE t ADD UNIQUE INDEX u (score)"), 1062);
    // narrowing that would truncate data
    assert_ne!(d.code(1, "ALTER TABLE t MODIFY name VARCHAR(1)"), 0);
    // NOT NULL on a column holding NULLs
    d.ok(0, "UPDATE t SET score = NULL WHERE id = 3");
    assert_eq!(d.code(1, "ALTER TABLE t MODIFY score INT NOT NULL"), 1048);
    assert_eq!(d.code(1, "ALTER TABLE t DROP COLUMN nope"), 1054);
    assert_eq!(d.code(1, "ALTER TABLE t ADD COLUMN name INT"), 1060);
    assert_eq!(d.code(1, "ALTER TABLE t DROP INDEX nope"), 1091);
    assert_eq!(d.code(1, "ALTER TABLE nope ADD COLUMN x INT"), 1146);
    assert_eq!(d.create(), before);
    assert_eq!(d.shadows(), 0);
    assert_eq!(d.rows("SELECT COUNT(*) FROM t"), vec!["300"]);
    assert!(!d.e().alter_running());
    // KILL / disconnect mid-way
    d.start(1, "ALTER TABLE t DROP COLUMN note");
    d.e().alter_step().unwrap();
    d.e().end_session(1);
    assert!(!d.e().alter_running());
    assert_eq!(d.shadows(), 0);
    assert_eq!(d.create(), before);
}

#[test]
fn crash_mid_alter_cleans_up() {
    let mut d = seeded(2500);
    let before = d.create();
    d.start(1, "ALTER TABLE t DROP COLUMN note");
    d.e().alter_step().unwrap();
    d.e().alter_step().unwrap();
    d.crash();
    assert_eq!(d.shadows(), 0, "shadow removed at open");
    assert_eq!(d.create(), before);
    assert_eq!(d.rows("SELECT COUNT(*) FROM t"), vec!["2500"]);
    d.e().db().verify().unwrap();
}

#[test]
fn primary_key_changes_and_transactions() {
    let mut d = Db::new();
    d.ok(0, "CREATE TABLE t (a INT, b VARCHAR(5))");
    d.ok(0, "INSERT INTO t VALUES (3, 'c'), (1, 'a'), (2, 'b')");
    d.ok(0, "ALTER TABLE t ADD PRIMARY KEY (a)");
    assert_eq!(
        d.rows("SELECT a FROM t"),
        vec!["1", "2", "3"],
        "now ordered by PK"
    );
    assert_eq!(d.code(0, "INSERT INTO t VALUES (1, 'x')"), 1062);
    d.ok(0, "ALTER TABLE t DROP PRIMARY KEY");
    d.ok(0, "INSERT INTO t VALUES (1, 'x')");
    assert_eq!(d.rows("SELECT COUNT(*) FROM t WHERE a = 1"), vec!["2"]);
    assert_eq!(d.code(0, "ALTER TABLE t ADD PRIMARY KEY (a)"), 1062);
    // Transactional ALTER: rolled back with the rest.
    d.ok(1, "BEGIN");
    d.ok(1, "DELETE FROM t WHERE b = 'x'");
    d.ok(
        1,
        "ALTER TABLE t ADD PRIMARY KEY (a), ADD COLUMN c INT NOT NULL DEFAULT 7",
    );
    assert_eq!(d.rows_on(1, "SELECT c FROM t WHERE a = 2"), vec!["7"]);
    d.ok(1, "ROLLBACK");
    assert_eq!(d.rows("SELECT COUNT(*) FROM t"), vec!["4"]);
    assert!(!d.create().contains("`c`"));
    d.ok(1, "BEGIN");
    d.ok(1, "DELETE FROM t WHERE b = 'x'");
    d.ok(1, "ALTER TABLE t ADD PRIMARY KEY (a)");
    d.ok(1, "COMMIT");
    assert!(d.create().contains("PRIMARY KEY (`a`)"));
}

impl Db {
    fn rows_on(&mut self, conn: u32, sql: &str) -> Vec<String> {
        self.ok(conn, sql)
            .rows
            .iter()
            .map(|r| {
                r.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .collect()
    }
}

#[test]
fn binlog_replays_alter() {
    let dir = tmp("bl");
    let bl = dir.join("binlog");
    let mut e = Engine::open(dir.join("data"))
        .unwrap()
        .with_binlog(&bl, None)
        .unwrap();
    let run = |e: &mut Engine, sql: &str| {
        let mut s = sess(1);
        for st in novadb_sql::parse(sql).unwrap() {
            e.run_in(&st, &mut s).unwrap();
        }
    };
    run(
        &mut e,
        "CREATE TABLE t (id INT PRIMARY KEY, a VARCHAR(10), b INT)",
    );
    run(&mut e, "INSERT INTO t VALUES (1, 'x', 1), (2, 'y', 2)");
    run(
        &mut e,
        "ALTER TABLE t DROP COLUMN b, ADD COLUMN c INT NOT NULL DEFAULT 9 AFTER id, ADD INDEX ia (a)",
    );
    run(&mut e, "INSERT INTO t VALUES (3, 8, 'z')");
    run(&mut e, "ALTER TABLE t RENAME COLUMN a TO aa, RENAME TO t2");
    run(&mut e, "UPDATE t2 SET aa = 'w' WHERE id = 1");
    let dump = |e: &mut Engine| {
        let st = novadb_sql::parse("SELECT * FROM t2 ORDER BY id")
            .unwrap()
            .remove(0);
        let st2 = novadb_sql::parse("SHOW CREATE TABLE t2").unwrap().remove(0);
        (
            format!("{:?}", e.run(&st).unwrap().rows),
            format!("{:?}", e.run(&st2).unwrap().rows),
        )
    };
    let want = dump(&mut e);
    let mut r = Engine::open(tmp("replay")).unwrap();
    novadb_sql::backup::replay(&mut r, Path::new(&bl), None, 0, None).unwrap();
    assert_eq!(dump(&mut r), want);
}

#[test]
fn parser_round_trips() {
    for sql in [
        "ALTER TABLE t ADD c INT",
        "ALTER TABLE t ADD COLUMN c INT NOT NULL DEFAULT 0 AFTER b, ALGORITHM=INPLACE, LOCK=NONE",
        "ALTER TABLE t DROP c, DROP INDEX i, DROP PRIMARY KEY",
        "ALTER TABLE t MODIFY COLUMN c BIGINT FIRST",
        "ALTER TABLE t CHANGE c d VARCHAR(5)",
        "ALTER TABLE t RENAME COLUMN a TO b, RENAME INDEX i TO j, RENAME TO u",
        "ALTER TABLE t ALTER COLUMN c SET DEFAULT 3, ALTER c DROP DEFAULT",
        "ALTER TABLE t ADD UNIQUE KEY u (a, b), ADD INDEX (c), ADD PRIMARY KEY (a)",
    ] {
        assert_eq!(novadb_sql::parse(sql).unwrap().len(), 1, "{sql}");
    }
    assert!(novadb_sql::parse("ALTER TABLE t").is_err());
    assert!(novadb_sql::parse("ALTER TABLE t FROB x").is_err());
}
