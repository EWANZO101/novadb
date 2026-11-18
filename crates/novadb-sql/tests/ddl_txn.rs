#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Transactional DDL: CREATE/DROP TABLE/INDEX inside BEGIN … COMMIT/ROLLBACK, atomic with the
//! data changes around them, crash-safe, binlogged only on COMMIT.

use novadb_sql::{Engine, QueryResult, Session, SqlError};
use std::path::{Path, PathBuf};

static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn tmp(tag: &str) -> PathBuf {
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let d = std::env::temp_dir().join(format!("novadb-ddltxn-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

struct Db {
    dir: PathBuf,
    binlog: Option<PathBuf>,
    e: Option<Engine>,
}

impl Db {
    fn new() -> Self {
        let dir = tmp("db");
        let mut d = Db {
            e: Some(Engine::open(&dir).unwrap()),
            binlog: None,
            dir,
        };
        d.ok(
            0,
            "CREATE TABLE acct (id INT PRIMARY KEY, name VARCHAR(20), bal INT)",
        );
        d.ok(0, "INSERT INTO acct VALUES (1, 'ann', 10), (2, 'bob', 20)");
        d
    }
    fn with_binlog() -> Self {
        let dir = tmp("bl");
        let bl = dir.join("binlog");
        let e = Engine::open(dir.join("data"))
            .unwrap()
            .with_binlog(&bl, None)
            .unwrap();
        let mut d = Db {
            e: Some(e),
            binlog: Some(bl),
            dir,
        };
        d.ok(
            0,
            "CREATE TABLE acct (id INT PRIMARY KEY, name VARCHAR(20), bal INT)",
        );
        d.ok(0, "INSERT INTO acct VALUES (1, 'ann', 10), (2, 'bob', 20)");
        d
    }
    fn e(&mut self) -> &mut Engine {
        self.e.as_mut().unwrap()
    }
    fn reopen(&mut self) {
        self.e.take().unwrap().close().unwrap();
        self.e = Some(Engine::open(&self.dir).unwrap());
    }
    /// Simulated crash: the engine is dropped without close (no checkpoint).
    fn crash(&mut self) {
        drop(self.e.take());
        self.e = Some(Engine::open(&self.dir).unwrap());
    }
    fn on(&mut self, conn: u32, sql: &str) -> Result<QueryResult, SqlError> {
        let mut s = Session {
            user: "t".into(),
            conn_id: conn,
            ..Default::default()
        };
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
    fn col(&mut self, conn: u32, sql: &str) -> Vec<String> {
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
    fn tables(&mut self) -> Vec<String> {
        self.col(0, "SHOW TABLES")
    }
}

#[test]
fn rollback_undoes_create_drop_and_data() {
    let mut d = Db::new();
    d.ok(1, "BEGIN");
    d.ok(1, "INSERT INTO acct VALUES (3, 'cat', 30)");
    d.ok(1, "CREATE TABLE audit (id INT PRIMARY KEY, msg TEXT)");
    d.ok(1, "INSERT INTO audit VALUES (1, 'hello')");
    d.ok(1, "CREATE INDEX ix_name ON acct (name)");
    d.ok(1, "UPDATE acct SET bal = 0");
    assert_eq!(d.col(1, "SELECT COUNT(*) FROM audit"), vec!["1"]);
    assert_eq!(d.e().status(1) & 1, 1, "IN_TRANS");
    d.ok(1, "ROLLBACK");
    assert_eq!(d.tables(), vec!["acct"]);
    assert_eq!(
        d.col(0, "SELECT id, bal FROM acct ORDER BY id"),
        vec!["1,10", "2,20"]
    );
    // the index never existed: creating it again works
    d.ok(0, "CREATE INDEX ix_name ON acct (name)");

    // Dropping a table with data, then rolling back, brings both back.
    d.ok(1, "BEGIN");
    d.ok(1, "DELETE FROM acct WHERE id = 1");
    d.ok(1, "DROP TABLE acct");
    assert_eq!(d.code(1, "SELECT * FROM acct"), 1146);
    d.ok(1, "ROLLBACK");
    assert_eq!(d.col(0, "SELECT id FROM acct ORDER BY id"), vec!["1", "2"]);
    assert_eq!(
        d.col(0, "SELECT id FROM acct WHERE name = 'bob'"),
        vec!["2"]
    );
    d.reopen();
    assert_eq!(d.tables(), vec!["acct"]);
    assert_eq!(d.e().open_transactions(), 0);
}

#[test]
fn commit_is_atomic_and_durable() {
    let mut d = Db::new();
    d.ok(1, "BEGIN");
    d.ok(
        1,
        "CREATE TABLE orders (id INT PRIMARY KEY AUTO_INCREMENT, acct INT, total INT)",
    );
    d.ok(1, "CREATE INDEX ix_acct ON orders (acct)");
    d.ok(1, "INSERT INTO orders (acct, total) VALUES (1, 5), (2, 7)");
    d.ok(1, "UPDATE acct SET bal = bal - 5 WHERE id = 1");
    // A failing statement undoes only itself; the transaction continues.
    assert_eq!(d.code(1, "INSERT INTO orders VALUES (1, 9, 9)"), 1062);
    assert_eq!(d.code(1, "CREATE TABLE orders (x INT)"), 1050);
    d.ok(1, "COMMIT");
    assert_eq!(d.e().status(1) & 1, 0);
    d.crash(); // committed = durable without a clean close
    assert_eq!(d.tables(), vec!["acct", "orders"]);
    assert_eq!(
        d.col(0, "SELECT acct, total FROM orders ORDER BY id"),
        vec!["1,5", "2,7"]
    );
    assert_eq!(d.col(0, "SELECT bal FROM acct WHERE id = 1"), vec!["5"]);
    assert_eq!(d.col(0, "SELECT id FROM orders WHERE acct = 2"), vec!["2"]);
}

#[test]
fn crash_during_migration_leaves_nothing() {
    let mut d = Db::new();
    d.ok(1, "BEGIN");
    d.ok(1, "CREATE TABLE half (id INT PRIMARY KEY)");
    d.ok(1, "INSERT INTO half VALUES (1), (2)");
    d.ok(1, "DROP TABLE acct");
    d.crash();
    assert_eq!(d.tables(), vec!["acct"]);
    assert_eq!(d.col(0, "SELECT COUNT(*) FROM acct"), vec!["2"]);
    d.ok(0, "CREATE TABLE half (id INT PRIMARY KEY)"); // name is free
}

#[test]
fn other_sessions_wait_and_disconnect_rolls_back() {
    let mut d = Db::new();
    // DDL in a transaction still waits for other open transactions...
    d.ok(2, "BEGIN");
    d.ok(2, "SELECT * FROM acct");
    d.ok(1, "BEGIN");
    assert_eq!(d.code(1, "CREATE TABLE x (a INT)"), 1205);
    d.ok(2, "COMMIT");
    // ...and once it runs, everyone else gets 1205 until it ends.
    d.ok(1, "CREATE TABLE x (a INT)");
    assert_eq!(d.code(0, "SELECT * FROM acct"), 1205);
    assert_eq!(d.code(2, "BEGIN"), 1205);
    assert_eq!(d.code(3, "INSERT INTO acct VALUES (9, 'z', 0)"), 1205);
    assert!(d.e().dump_begin(4).is_err());
    d.e().end_session(1); // disconnect
    assert_eq!(d.tables(), vec!["acct"]);
    assert_eq!(d.col(0, "SELECT COUNT(*) FROM acct"), vec!["2"]);
}

#[test]
fn autocommit_off_and_implicit_commits() {
    let mut d = Db::new();
    d.ok(1, "SET autocommit = 0");
    d.ok(1, "CREATE TABLE t1 (a INT)");
    d.ok(1, "INSERT INTO t1 VALUES (1)");
    d.ok(1, "ROLLBACK");
    assert_eq!(d.tables(), vec!["acct"]);
    d.ok(1, "CREATE TABLE t1 (a INT)");
    d.ok(1, "SET autocommit = 1"); // commits
    assert_eq!(d.tables(), vec!["acct", "t1"]);
    // BEGIN commits the previous transaction, DDL included.
    d.ok(1, "BEGIN");
    d.ok(1, "DROP TABLE t1");
    d.ok(1, "BEGIN");
    d.ok(1, "ROLLBACK");
    assert_eq!(d.tables(), vec!["acct"]);
    // Outside a transaction DDL is its own transaction as before.
    d.ok(0, "CREATE TABLE t2 (a INT)");
    assert_eq!(d.tables(), vec!["acct", "t2"]);
}

#[test]
fn binlog_only_gets_committed_schema_changes() {
    let mut d = Db::with_binlog();
    d.ok(1, "BEGIN");
    d.ok(1, "CREATE TABLE gone (id INT PRIMARY KEY)");
    d.ok(1, "INSERT INTO gone VALUES (1)");
    d.ok(1, "ROLLBACK");
    let bl = d.binlog.clone().unwrap();
    let n = novadb_sql::binlog::read_all(&bl, None).unwrap().len();
    d.ok(1, "BEGIN");
    d.ok(1, "INSERT INTO acct VALUES (3, 'cat', 30)");
    d.ok(1, "CREATE TABLE kept (id INT PRIMARY KEY, v INT)");
    d.ok(1, "INSERT INTO kept VALUES (1, 100)");
    d.ok(1, "DROP TABLE acct");
    d.ok(
        1,
        "CREATE TABLE acct (id INT PRIMARY KEY, name VARCHAR(20), bal INT)",
    );
    d.ok(1, "INSERT INTO acct VALUES (7, 'new', 1)");
    assert_eq!(
        novadb_sql::binlog::read_all(&bl, None).unwrap().len(),
        n,
        "nothing logged before COMMIT"
    );
    d.ok(1, "COMMIT");
    // Replaying the whole binlog into an empty database gives the same state.
    let mut r = Engine::open(tmp("replay")).unwrap();
    novadb_sql::backup::replay(&mut r, Path::new(&bl), None, 0, None).unwrap();
    let rows = |e: &mut Engine, q: &str| {
        let st = novadb_sql::parse(q).unwrap().remove(0);
        e.run(&st)
            .unwrap()
            .rows
            .iter()
            .map(|r| {
                r.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(rows(&mut r, "SHOW TABLES"), vec!["acct", "kept"]);
    assert_eq!(rows(&mut r, "SELECT * FROM acct"), vec!["7,new,1"]);
    assert_eq!(rows(&mut r, "SELECT * FROM kept"), vec!["1,100"]);
}
