//! Runs fuzzed SQL against a live in-memory database with tables and indexes.
//! Errors are fine; panics, hangs and storage corruption are not.
#![no_main]
use libfuzzer_sys::fuzz_target;
use novadb_sql::Engine;
use novadb_storage::{Options, SimVfs};

const SCHEMA: &str = "CREATE TABLE t (id INT PRIMARY KEY AUTO_INCREMENT, a INT, b VARCHAR(16), c DECIMAL(8,3), d DATETIME(3), e TEXT, f BLOB, UNIQUE KEY ub (b), KEY kac (a, c));
CREATE TABLE u (x BIGINT, y VARCHAR(8) NOT NULL DEFAULT 'q', KEY ky (y));
INSERT INTO t (a, b, c, d, e) VALUES (1, 'x', 1.5, '2026-01-01 00:00:00', 'hello'), (2, 'y', NULL, NULL, NULL), (NULL, NULL, -3, '1999-12-31 23:59:59.999', '');
INSERT INTO u VALUES (1, 'a'), (NULL, 'b'), (3, 'a');";

fuzz_target!(|data: &[u8]| {
    let Ok(sql) = std::str::from_utf8(data) else { return };
    if sql.len() > 4096 {
        return;
    }
    let opts = Options { cache_pages: 64, checkpoint_wal_bytes: 256 * 1024, create_if_missing: true };
    let mut db = Engine::open_vfs(Box::new(SimVfs::new()), opts).expect("open").with_clock(|| 1_795_005_296_789_012);
    db.execute(SCHEMA).expect("schema");
    // Each statement on its own so one error does not hide the rest.
    for stmt in sql.split(';').take(32) {
        let _ = db.execute(stmt);
    }
    let r = db.db().verify();
    assert!(r.is_ok(), "storage verify failed after fuzzed SQL: {r:?}");
    let _ = db.query("SELECT * FROM t").expect("table t still readable");
    let _ = db.query("SELECT * FROM u WHERE y = 'a'").expect("table u still readable");
});
