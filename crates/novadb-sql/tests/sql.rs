#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! End-to-end SQL behaviour on a real (temp-dir) database.

use novadb_sql::{Engine, QueryResult};

struct TempDb {
    dir: std::path::PathBuf,
    db: Option<Engine>,
}

static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

impl TempDb {
    fn new() -> Self {
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("novadb-sql-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Fixed clock: 2026-11-18 12:34:56.789012
        let db = Engine::open(&dir)
            .unwrap()
            .with_clock(|| 1_795_005_296_789_012);
        TempDb { dir, db: Some(db) }
    }
    fn db(&mut self) -> &mut Engine {
        self.db.as_mut().unwrap()
    }
    fn reopen(&mut self) {
        self.db.take().unwrap().close().unwrap();
        self.db = Some(Engine::open(&self.dir).unwrap());
    }
    fn ok(&mut self, sql: &str) -> QueryResult {
        match self.db().query(sql) {
            Ok(r) => r,
            Err(e) => panic!("{sql}\n  -> {e}"),
        }
    }
    fn err(&mut self, sql: &str) -> u16 {
        match self.db().query(sql) {
            Ok(r) => panic!("{sql} should fail, got {r:?}"),
            Err(e) => e.code,
        }
    }
    /// Rows rendered as text ("NULL" for NULL).
    fn rows(&mut self, sql: &str) -> Vec<Vec<String>> {
        let r = self.ok(sql);
        (0..r.rows.len())
            .map(|i| {
                (0..r.columns.len())
                    .map(|c| r.text(i, c).unwrap_or_else(|| "NULL".into()))
                    .collect()
            })
            .collect()
    }
    fn col(&mut self, sql: &str) -> Vec<String> {
        self.rows(sql)
            .into_iter()
            .map(|mut r| r.remove(0))
            .collect()
    }
    fn one(&mut self, sql: &str) -> String {
        let r = self.rows(sql);
        assert_eq!(r.len(), 1, "{sql}");
        r[0][0].clone()
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        if let Some(db) = self.db.take() {
            let _ = db.close();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn crud_roundtrip_and_persistence() {
    let mut t = TempDb::new();
    t.ok("CREATE TABLE users (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(30) NOT NULL, email VARCHAR(100) UNIQUE, bal DECIMAL(10,2) DEFAULT 0.00, born DATETIME, bio TEXT)");
    let r = t.ok("INSERT INTO users (name, email, bal, born) VALUES ('ann', 'a@x', 10.5, '1990-01-02 03:04:05'), ('bob', NULL, 7, NULL)");
    assert_eq!((r.affected, r.last_insert_id), (2, 1));
    let r = t.ok("INSERT INTO users (name) VALUES ('cat')");
    assert_eq!(r.last_insert_id, 3);
    assert_eq!(
        t.rows("SELECT id, name, email, bal, born FROM users ORDER BY id"),
        vec![
            vec!["1", "ann", "a@x", "10.50", "1990-01-02 03:04:05"],
            vec!["2", "bob", "NULL", "7.00", "NULL"],
            vec!["3", "cat", "NULL", "0.00", "NULL"],
        ]
    );
    let r = t.ok("UPDATE users SET bal = bal + 0.25 WHERE name <> 'cat'");
    assert_eq!(r.affected, 2);
    assert_eq!(t.ok("DELETE FROM users WHERE id = 2").affected, 1);
    t.reopen();
    assert_eq!(
        t.col("SELECT bal FROM users ORDER BY id"),
        vec!["10.75", "0.00"]
    );
    // AUTO_INCREMENT continues after reopen and never reuses ids.
    assert_eq!(
        t.ok("INSERT INTO users (name) VALUES ('dan')")
            .last_insert_id,
        4
    );
    t.ok("INSERT INTO users (id, name) VALUES (100, 'eve')");
    assert_eq!(
        t.ok("INSERT INTO users (name) VALUES ('fay')")
            .last_insert_id,
        101
    );
}

#[test]
fn null_semantics_and_expressions() {
    let mut t = TempDb::new();
    assert_eq!(t.one("SELECT NULL = NULL"), "NULL");
    assert_eq!(t.one("SELECT NULL <=> NULL"), "1");
    assert_eq!(t.one("SELECT 1 IN (2, NULL)"), "NULL");
    assert_eq!(t.one("SELECT 1 IN (1, NULL)"), "1");
    assert_eq!(t.one("SELECT NULL AND 0"), "0");
    assert_eq!(t.one("SELECT NULL OR 1"), "1");
    assert_eq!(t.one("SELECT 0.1 + 0.2 = 0.3"), "1");
    assert_eq!(t.one("SELECT 1 / 3"), "0.3333");
    assert_eq!(t.one("SELECT 7 DIV 2, 7 % 3"), "3");
    assert_eq!(t.one("SELECT 10 / 0"), "NULL");
    assert_eq!(t.one("SELECT -9223372036854775808"), "-9223372036854775808");
    assert_eq!(t.err("SELECT 9223372036854775807 + 1"), 1690);
    assert_eq!(t.one("SELECT CONCAT('a', 1, 2.50)"), "a12.50");
    assert_eq!(t.one("SELECT CONCAT('a', NULL)"), "NULL");
    assert_eq!(t.one("SELECT COALESCE(NULL, NULL, 'x')"), "x");
    assert_eq!(t.one("SELECT UPPER('héllo'), LOWER('ABC')"), "HÉLLO");
    assert_eq!(t.one("SELECT LENGTH('héllo')"), "6");
    assert_eq!(t.one("SELECT CHAR_LENGTH('héllo')"), "5");
    assert_eq!(t.one("SELECT SUBSTRING('hello', 2, 3)"), "ell");
    assert_eq!(t.one("SELECT SUBSTRING('hello', -3)"), "llo");
    assert_eq!(
        t.one("SELECT ROUND(2.5), ROUND(-2.5), ROUND(1.2345, 2), ROUND(1250, -2)"),
        "3"
    );
    assert_eq!(
        t.rows("SELECT ROUND(-2.5), ROUND(1.2345, 2), ROUND(1250, -2)")[0],
        vec!["-3", "1.23", "1300"]
    );
    assert_eq!(t.one("SELECT IF(1 > 2, 'y', 'n')"), "n");
    assert_eq!(t.one("SELECT 'abc' LIKE 'a%c'"), "1");
    assert_eq!(t.one("SELECT 5 BETWEEN 1 AND 10"), "1");
    assert_eq!(t.one("SELECT 5 NOT BETWEEN 1 AND 10"), "0");
    assert_eq!(t.one("SELECT NOW()"), "2026-11-18 12:34:56");
    assert_eq!(t.one("SELECT NOW(3)"), "2026-11-18 12:34:56.789");
    assert_eq!(t.one("SELECT 1 IS TRUE, NULL IS NOT FALSE"), "1");
    assert_eq!(t.err("SELECT nosuchfn(1)"), 1582);
    assert_eq!(t.err("SELECT x"), 1054);
}

#[test]
fn types_and_strict_mode() {
    let mut t = TempDb::new();
    t.ok("CREATE TABLE ty (i INT, b BIGINT, d DECIMAL(5,2), v VARCHAR(3), dt DATETIME(2), x BLOB)");
    t.ok("INSERT INTO ty VALUES (2147483647, -9223372036854775808, 999.99, 'héé', '2024-02-29 23:59:59.995', X'00ff')");
    assert_eq!(
        t.rows("SELECT * FROM ty")[0],
        vec![
            "2147483647",
            "-9223372036854775808",
            "999.99",
            "héé",
            "2024-03-01 00:00:00.00",
            "\0\u{fffd}"
        ]
    );
    assert_eq!(t.err("INSERT INTO ty (i) VALUES (2147483648)"), 1264);
    assert_eq!(t.err("INSERT INTO ty (d) VALUES (1000)"), 1264);
    assert_eq!(t.err("INSERT INTO ty (v) VALUES ('abcd')"), 1406);
    assert_eq!(t.err("INSERT INTO ty (i) VALUES ('12x')"), 1366);
    assert_eq!(t.err("INSERT INTO ty (dt) VALUES ('2023-02-29')"), 1292);
    assert_eq!(
        t.err("INSERT INTO ty (dt) VALUES ('0000-00-00 00:00:00')"),
        1292
    );
    t.ok("INSERT INTO ty (i, d) VALUES ('42', '1.005')");
    assert_eq!(
        t.rows("SELECT i, d FROM ty WHERE i = 42")[0],
        vec!["42", "1.01"]
    );
    assert_eq!(t.err("INSERT INTO ty VALUES (1)"), 1136);
    assert_eq!(t.err("INSERT INTO ty (nope) VALUES (1)"), 1054);
}

#[test]
fn large_values_use_overflow_and_clean_up() {
    let mut t = TempDb::new();
    t.ok("CREATE TABLE docs (id INT PRIMARY KEY, body TEXT, data BLOB)");
    let big = "x".repeat(60_000);
    t.ok(&format!(
        "INSERT INTO docs VALUES (1, '{big}', NULL), (2, 'small', X'01')"
    ));
    assert_eq!(t.one("SELECT LENGTH(body) FROM docs WHERE id = 1"), "60000");
    // shrink, grow, delete — overflow chunks must follow.
    t.ok("UPDATE docs SET body = 'tiny' WHERE id = 1");
    assert_eq!(t.one("SELECT body FROM docs WHERE id = 1"), "tiny");
    t.ok(&format!(
        "UPDATE docs SET body = '{}' WHERE id = 1",
        "y".repeat(50_000)
    ));
    t.reopen();
    assert_eq!(
        t.one("SELECT CHAR_LENGTH(body) FROM docs WHERE id = 1"),
        "50000"
    );
    t.ok("DELETE FROM docs WHERE id = 1");
    assert_eq!(
        t.err(&format!(
            "INSERT INTO docs VALUES (3, '{}', NULL)",
            "z".repeat(70_000)
        )),
        1406
    );
    let report = t.db().db().verify().unwrap();
    // Only row 2 is left: one row entry, zero overflow chunks.
    let n = t.db().db().view(|tx| {
        let o = tx.open_tree("sql:o:1")?;
        Ok(tx.range(&o, ..)?.count())
    });
    assert_eq!(n.unwrap(), 0, "orphaned overflow chunks; verify={report:?}");
}

#[test]
fn keys_constraints_and_atomic_statements() {
    let mut t = TempDb::new();
    t.ok("CREATE TABLE k (a INT, b VARCHAR(10), c INT, PRIMARY KEY (a, b), UNIQUE KEY uc (c))");
    t.ok("INSERT INTO k VALUES (1, 'x', 10), (1, 'y', NULL), (2, 'x', NULL)");
    assert_eq!(t.err("INSERT INTO k VALUES (1, 'x', 99)"), 1062);
    assert_eq!(t.err("INSERT INTO k VALUES (3, 'z', 10)"), 1062);
    // Multi-row insert failing on row 3 keeps nothing.
    assert_eq!(
        t.err("INSERT INTO k VALUES (5, 'a', 50), (6, 'a', 60), (7, 'a', 50)"),
        1062
    );
    assert!(t.rows("SELECT a FROM k WHERE a >= 5").is_empty());
    assert_eq!(t.err("INSERT INTO k (a, c) VALUES (9, 1)"), 1364);
    assert_eq!(t.err("INSERT INTO k VALUES (NULL, 'q', 1)"), 1048);
    // UPDATE moving a primary key, and unique conflicts on update.
    t.ok("UPDATE k SET a = 9 WHERE a = 2");
    assert_eq!(t.col("SELECT a FROM k ORDER BY a, b"), vec!["1", "1", "9"]);
    assert_eq!(t.err("UPDATE k SET c = 10 WHERE a = 9"), 1062);
    assert_eq!(t.err("UPDATE k SET a = 1, b = 'x' WHERE a = 9"), 1062);
    let r = t.ok("UPDATE k SET c = c WHERE a = 1");
    assert_eq!(r.affected, 0, "unchanged rows are not counted");
}

#[test]
fn order_limit_distinct_aliases() {
    let mut t = TempDb::new();
    t.ok("CREATE TABLE s (id INT PRIMARY KEY, g VARCHAR(5), v INT)");
    t.ok("INSERT INTO s VALUES (1,'b',3),(2,'a',NULL),(3,'b',1),(4,'a',2),(5,'c',2)");
    assert_eq!(
        t.col("SELECT id FROM s ORDER BY v"),
        vec!["2", "3", "4", "5", "1"]
    );
    assert_eq!(
        t.col("SELECT id FROM s ORDER BY v DESC, id DESC"),
        vec!["1", "5", "4", "3", "2"]
    );
    assert_eq!(
        t.col("SELECT id FROM s ORDER BY g, id DESC LIMIT 2"),
        vec!["4", "2"]
    );
    assert_eq!(
        t.col("SELECT id FROM s ORDER BY id LIMIT 1, 2"),
        vec!["2", "3"]
    );
    assert_eq!(
        t.col("SELECT id FROM s ORDER BY id LIMIT 2 OFFSET 3"),
        vec!["4", "5"]
    );
    assert_eq!(
        t.col("SELECT DISTINCT g FROM s ORDER BY g"),
        vec!["a", "b", "c"]
    );
    assert_eq!(
        t.col("SELECT v * 10 AS w FROM s WHERE v IS NOT NULL ORDER BY w DESC LIMIT 1"),
        vec!["30"]
    );
    assert_eq!(
        t.col("SELECT id, v + 1 FROM s ORDER BY 2 DESC LIMIT 1"),
        vec!["1"]
    );
    let r = t.ok("SELECT id AS ident, v + 1 FROM s LIMIT 1");
    assert_eq!(r.columns[0].name, "ident");
    assert_eq!(r.columns[1].name, "v + 1");
    assert_eq!(
        t.col("SELECT id FROM s WHERE g = 'b' ORDER BY id LIMIT 0"),
        Vec::<String>::new()
    );
    t.ok("DELETE FROM s ORDER BY id DESC LIMIT 2");
    assert_eq!(t.col("SELECT id FROM s ORDER BY id"), vec!["1", "2", "3"]);
}

#[test]
fn planner_picks_indexes() {
    let mut t = TempDb::new();
    t.ok("CREATE TABLE p (id BIGINT PRIMARY KEY, email VARCHAR(50), city VARCHAR(20), age INT, UNIQUE KEY ue (email), KEY kc (city, age))");
    let plan = |t: &mut TempDb, w: &str| {
        t.rows(&format!("EXPLAIN SELECT * FROM p WHERE {w}"))[0][1..].to_vec()
    };
    assert_eq!(plan(&mut t, "id = 5"), vec!["const", "PRIMARY"]);
    assert_eq!(plan(&mut t, "id BETWEEN 1 AND 9"), vec!["range", "PRIMARY"]);
    assert_eq!(plan(&mut t, "email = 'a@b'"), vec!["const", "ue"]);
    assert_eq!(plan(&mut t, "city = 'x' AND age = 3"), vec!["ref", "kc"]);
    assert_eq!(plan(&mut t, "age > 3"), vec!["ALL", "NULL"]);
    assert_eq!(
        plan(&mut t, "id = 1.5"),
        vec!["ALL", "NULL"],
        "non-integral literal can't use an INT key"
    );
    assert_eq!(
        plan(&mut t, "email = 5"),
        vec!["ALL", "NULL"],
        "number vs string compares numerically"
    );
    assert_eq!(plan(&mut t, "id = 1 OR id = 2"), vec!["ALL", "NULL"]);
}

/// Index correctness: same data in an indexed and an unindexed table; random queries must
/// return identical results.
#[test]
fn indexes_match_full_scans_randomised() {
    let mut t = TempDb::new();
    t.ok("CREATE TABLE ix (id INT PRIMARY KEY, a INT, b VARCHAR(8), c DECIMAL(6,2), KEY ka (a), KEY kba (b, a), UNIQUE KEY uc (c))");
    t.ok("CREATE TABLE nx (id INT PRIMARY KEY, a INT, b VARCHAR(8), c DECIMAL(6,2))");
    let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut rnd = move |n: u64| {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s % n
    };
    let words = ["", "a", "ab", "b", "ba", "zz", "a\\0", "é"];
    let lit = |r: &mut dyn FnMut(u64) -> u64, col: u64| -> String {
        match col {
            0 => format!("{}", r(60)),
            1 => {
                if r(8) == 0 {
                    "NULL".into()
                } else {
                    format!("{}", r(20) as i64 - 10)
                }
            }
            2 => {
                if r(8) == 0 {
                    "NULL".into()
                } else {
                    format!("'{}'", words[r(words.len() as u64) as usize])
                }
            }
            _ => {
                if r(4) == 0 {
                    "NULL".into()
                } else {
                    format!("{}.{:02}", r(50), r(100))
                }
            }
        }
    };
    let cols = ["id", "a", "b", "c"];
    let mut stmts = 0;
    for round in 0..600 {
        let op = rnd(10);
        let sql = if op < 5 {
            let row: Vec<String> = (0..4).map(|c| lit(&mut rnd, c)).collect();
            format!("INSERT INTO {{}} VALUES ({})", row.join(","))
        } else if op < 7 {
            let c = rnd(3) + 1;
            format!(
                "UPDATE {{}} SET {} = {} WHERE {} = {}",
                cols[c as usize],
                lit(&mut rnd, c),
                cols[(rnd(4)) as usize],
                lit(&mut rnd, 1)
            )
        } else if op < 8 {
            format!(
                "DELETE FROM {{}} WHERE a {} {}",
                ["=", "<", ">="][rnd(3) as usize],
                lit(&mut rnd, 1)
            )
        } else {
            String::new()
        };
        if !sql.is_empty() {
            let r1 = t.db().query(&sql.replace("{}", "ix"));
            // The unindexed twin has no unique key on c: only apply when the indexed one accepted it.
            match r1 {
                Ok(r1) => {
                    let r2 = t.db().query(&sql.replace("{}", "nx")).unwrap();
                    assert_eq!(r1.affected, r2.affected, "round {round}: {sql}");
                    stmts += 1;
                }
                Err(e) => assert!(
                    e.code == 1062 || e.code == 1048,
                    "round {round}: {sql}: {e}"
                ),
            }
        }
        // Random query on both.
        let c = rnd(4) as usize;
        let ops = ["=", "<", "<=", ">", ">=", "<>", "<=>"];
        let mut w = format!(
            "{} {} {}",
            cols[c],
            ops[rnd(ops.len() as u64) as usize],
            lit(&mut rnd, c as u64)
        );
        if rnd(2) == 0 {
            let c2 = rnd(4) as usize;
            w = format!(
                "{w} AND {} BETWEEN {} AND {}",
                cols[c2],
                lit(&mut rnd, c2 as u64),
                lit(&mut rnd, c2 as u64)
            );
        }
        let q = format!("SELECT * FROM {{}} WHERE {w} ORDER BY id");
        let a = t.rows(&q.replace("{}", "ix"));
        let b = t.rows(&q.replace("{}", "nx"));
        assert_eq!(a, b, "round {round}: {q}");
    }
    assert!(stmts > 300, "too few statements applied: {stmts}");
    t.reopen();
    assert_eq!(
        t.rows("SELECT * FROM ix ORDER BY id"),
        t.rows("SELECT * FROM nx ORDER BY id")
    );
}

#[test]
fn ddl_and_introspection() {
    let mut t = TempDb::new();
    t.ok("CREATE TABLE `My Table` (id INT NOT NULL AUTO_INCREMENT, n VARCHAR(10) DEFAULT 'it''s', at DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (id), KEY kn (n))");
    assert_eq!(t.err("CREATE TABLE `my table` (x INT)"), 1050);
    t.ok("CREATE TABLE IF NOT EXISTS `My Table` (x INT)");
    t.ok("INSERT INTO `My Table` () VALUES ()");
    assert_eq!(
        t.rows("SELECT id, n, at FROM `my table`")[0],
        vec!["1", "it's", "2026-11-18 12:34:56"]
    );
    let d = t.rows("DESCRIBE `My Table`");
    assert_eq!(
        d[0],
        vec!["id", "int", "NO", "PRI", "NULL", "auto_increment"]
    );
    assert_eq!(d[1], vec!["n", "varchar(10)", "YES", "MUL", "it's", ""]);
    assert_eq!(t.col("SHOW TABLES"), vec!["My Table"]);
    let ddl = t.rows("SHOW CREATE TABLE `My Table`")[0][1].clone();
    assert!(
        ddl.contains("DEFAULT 'it''s'") && ddl.contains("KEY `kn` (`n`)"),
        "{ddl}"
    );
    // The generated DDL parses and builds the same table under a new name.
    t.ok(&ddl.replace("CREATE TABLE `My Table`", "CREATE TABLE copy"));
    assert_eq!(t.rows("DESCRIBE copy"), d);
    t.ok("CREATE UNIQUE INDEX un ON copy (n)");
    t.ok("INSERT INTO copy (n) VALUES ('a'), ('b')");
    assert_eq!(t.err("CREATE UNIQUE INDEX un ON copy (n)"), 1061);
    t.ok("INSERT INTO `My Table` (n) VALUES ('dup'), ('dup')");
    assert_eq!(t.err("CREATE UNIQUE INDEX bad ON `My Table` (n)"), 1062);
    assert_eq!(t.err("DROP INDEX kn2 ON copy"), 1091);
    t.ok("DROP INDEX kn ON copy");
    assert_eq!(t.err("CREATE TABLE bad (a TEXT PRIMARY KEY)"), 1170);
    assert_eq!(
        t.err("CREATE TABLE bad (a INT AUTO_INCREMENT, b INT)"),
        1075
    );
    assert_eq!(t.err("CREATE TABLE bad (a INT, a INT)"), 1060);
    assert_eq!(
        t.err("CREATE TABLE bad (a INT PRIMARY KEY, b INT PRIMARY KEY)"),
        1068
    );
    assert_eq!(
        t.err("CREATE TABLE bad (a INT NOT NULL DEFAULT NULL)"),
        1067
    );
    t.ok("DROP TABLE copy, `My Table`");
    assert_eq!(t.err("DROP TABLE copy"), 1051);
    t.ok("DROP TABLE IF EXISTS copy");
    assert!(t.col("SHOW TABLES").is_empty());
    t.reopen();
    t.ok("CREATE TABLE copy (x INT)");
    assert!(
        t.rows("SELECT * FROM copy").is_empty(),
        "recreated table must start empty"
    );
}

#[test]
fn hostile_input_is_rejected_cleanly() {
    let mut t = TempDb::new();
    t.ok("CREATE TABLE h (id INT PRIMARY KEY, v VARCHAR(10))");
    for bad in [
        "SELECT * FROM h WHERE id = 1; DROP TABLE h' --",
        "SELECT ((((((((((((((((((((",
        "INSERT INTO h VALUES (1, 'x'), (",
        "SELECT * FROM h WHERE v = 'unterminated",
        "\u{0}\u{1}\u{2}",
    ] {
        assert!(t.db().execute(bad).is_err(), "{bad}");
    }
    // Injection attempt stays a string value.
    t.ok("INSERT INTO h VALUES (1, 'a''); DROP')");
    assert_eq!(t.one("SELECT v FROM h"), "a'); DROP");
    assert_eq!(t.col("SHOW TABLES"), vec!["h"]);
    let deep = format!("SELECT {}1{}", "(".repeat(200), ")".repeat(200));
    assert_eq!(t.err(&deep), 1064);
}
