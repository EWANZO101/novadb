#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Stage 5: multi-statement transactions, snapshot isolation, conflicts, version pruning.

use std::collections::BTreeMap;

use novadb_sql::{Engine, QueryResult, Session, SqlError, Value};

struct Db {
    dir: std::path::PathBuf,
    e: Option<Engine>,
}

static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

impl Db {
    fn new() -> Self {
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("novadb-txn-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Db {
            e: Some(Engine::open(&dir).unwrap()),
            dir,
        }
    }
    fn e(&mut self) -> &mut Engine {
        self.e.as_mut().unwrap()
    }
    fn reopen(&mut self) {
        self.e.take().unwrap().close().unwrap();
        self.e = Some(Engine::open(&self.dir).unwrap());
    }
    /// Run `sql` as connection `conn`.
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
            .map(|r| r[0].to_string())
            .collect()
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        if let Some(e) = self.e.take() {
            let _ = e.close();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn setup() -> Db {
    let mut d = Db::new();
    d.ok(0, "CREATE TABLE acct (id INT PRIMARY KEY, owner VARCHAR(20), bal DECIMAL(10,2), UNIQUE KEY uo (owner), KEY kb (bal))");
    d.ok(0, "INSERT INTO acct VALUES (1, 'ann', 100), (2, 'bob', 50)");
    d
}

#[test]
fn commit_and_rollback() {
    let mut d = setup();
    d.ok(1, "BEGIN");
    d.ok(1, "UPDATE acct SET bal = bal - 30 WHERE id = 1");
    d.ok(1, "UPDATE acct SET bal = bal + 30 WHERE id = 2");
    d.ok(1, "INSERT INTO acct VALUES (3, 'cat', 1)");
    d.ok(1, "ROLLBACK");
    assert_eq!(
        d.col(0, "SELECT bal FROM acct ORDER BY id"),
        vec!["100.00", "50.00"]
    );
    d.ok(1, "START TRANSACTION");
    d.ok(1, "UPDATE acct SET bal = bal - 30 WHERE id = 1");
    d.ok(1, "UPDATE acct SET bal = bal + 30 WHERE id = 2");
    d.ok(1, "COMMIT");
    d.reopen();
    assert_eq!(
        d.col(0, "SELECT bal FROM acct ORDER BY id"),
        vec!["70.00", "80.00"]
    );
}

#[test]
fn no_dirty_reads_and_repeatable_reads() {
    let mut d = setup();
    d.ok(1, "BEGIN");
    d.ok(1, "UPDATE acct SET bal = 0 WHERE id = 1");
    d.ok(1, "INSERT INTO acct VALUES (3, 'cat', 5)");
    // Other sessions never see uncommitted changes.
    assert_eq!(
        d.col(2, "SELECT bal FROM acct ORDER BY id"),
        vec!["100.00", "50.00"]
    );
    // Session 3 takes a snapshot, then session 1 commits.
    d.ok(3, "BEGIN");
    assert_eq!(
        d.col(3, "SELECT bal FROM acct WHERE id = 1"),
        vec!["100.00"]
    );
    d.ok(1, "COMMIT");
    assert_eq!(
        d.col(2, "SELECT bal FROM acct ORDER BY id"),
        vec!["0.00", "50.00", "5.00"]
    );
    // Snapshot of session 3 is unchanged: same value, no phantom row, also via an index.
    assert_eq!(
        d.col(3, "SELECT bal FROM acct WHERE id = 1"),
        vec!["100.00"]
    );
    assert_eq!(d.col(3, "SELECT id FROM acct ORDER BY id"), vec!["1", "2"]);
    assert_eq!(
        d.col(3, "SELECT id FROM acct WHERE bal >= 0 ORDER BY id"),
        vec!["1", "2"]
    );
    assert_eq!(
        d.col(3, "SELECT owner FROM acct WHERE owner = 'cat'"),
        Vec::<String>::new()
    );
    d.ok(3, "COMMIT");
    assert_eq!(
        d.col(3, "SELECT id FROM acct ORDER BY id"),
        vec!["1", "2", "3"]
    );
}

#[test]
fn read_your_own_writes_through_indexes() {
    let mut d = setup();
    d.ok(1, "BEGIN");
    d.ok(1, "UPDATE acct SET bal = 999, owner = 'zed' WHERE id = 2");
    d.ok(1, "DELETE FROM acct WHERE id = 1");
    d.ok(1, "INSERT INTO acct VALUES (7, 'ann', 1)"); // 'ann' is free again inside this txn
    assert_eq!(d.col(1, "SELECT id FROM acct WHERE bal = 999"), vec!["2"]);
    assert_eq!(
        d.col(1, "SELECT id FROM acct WHERE owner = 'zed'"),
        vec!["2"]
    );
    assert_eq!(
        d.col(1, "SELECT id FROM acct WHERE owner = 'bob'"),
        Vec::<String>::new()
    );
    assert_eq!(
        d.col(1, "SELECT id FROM acct WHERE owner = 'ann'"),
        vec!["7"]
    );
    assert_eq!(d.col(1, "SELECT id FROM acct ORDER BY id"), vec!["2", "7"]);
    d.ok(1, "COMMIT");
    assert_eq!(
        d.col(0, "SELECT owner FROM acct ORDER BY id"),
        vec!["zed", "ann"]
    );
}

#[test]
fn failed_statement_keeps_earlier_work() {
    let mut d = setup();
    d.ok(1, "BEGIN");
    d.ok(1, "INSERT INTO acct VALUES (3, 'cat', 1)");
    // Row 5 is fine, row 6 duplicates 'ann': the whole statement is undone, not the txn.
    assert_eq!(
        d.code(1, "INSERT INTO acct VALUES (5, 'eve', 1), (6, 'ann', 1)"),
        1062
    );
    d.ok(1, "COMMIT");
    assert_eq!(
        d.col(0, "SELECT id FROM acct ORDER BY id"),
        vec!["1", "2", "3"]
    );
}

#[test]
fn first_committer_wins() {
    let mut d = setup();
    // Lost update prevented: both read 100, both write.
    d.ok(1, "BEGIN");
    d.ok(2, "BEGIN");
    assert_eq!(
        d.col(1, "SELECT bal FROM acct WHERE id = 1"),
        vec!["100.00"]
    );
    assert_eq!(
        d.col(2, "SELECT bal FROM acct WHERE id = 1"),
        vec!["100.00"]
    );
    d.ok(1, "UPDATE acct SET bal = bal + 10 WHERE id = 1");
    d.ok(2, "UPDATE acct SET bal = bal + 20 WHERE id = 1");
    d.ok(1, "COMMIT");
    assert_eq!(d.code(2, "COMMIT"), 1213);
    assert_eq!(
        d.col(0, "SELECT bal FROM acct WHERE id = 1"),
        vec!["110.00"]
    );
    // After a commit by someone else, writing that row in an older snapshot fails at once,
    // and the whole transaction is rolled back.
    d.ok(2, "BEGIN");
    d.ok(2, "UPDATE acct SET bal = 1 WHERE id = 2");
    d.ok(1, "UPDATE acct SET bal = bal + 1 WHERE id = 1");
    assert_eq!(d.code(2, "UPDATE acct SET bal = 0 WHERE id = 1"), 1213);
    assert_eq!(d.e().status(2) & 1, 0, "transaction gone after 1213");
    assert_eq!(
        d.col(0, "SELECT bal FROM acct ORDER BY id"),
        vec!["111.00", "50.00"]
    );
    // Concurrent inserts of the same unique value: second committer fails.
    d.ok(1, "BEGIN");
    d.ok(2, "BEGIN");
    d.ok(1, "INSERT INTO acct VALUES (10, 'dup', 1)");
    d.ok(2, "INSERT INTO acct VALUES (11, 'dup', 1)");
    d.ok(1, "COMMIT");
    assert_eq!(d.code(2, "COMMIT"), 1213);
    assert_eq!(
        d.col(0, "SELECT id FROM acct WHERE owner = 'dup'"),
        vec!["10"]
    );
}

#[test]
fn ddl_autocommit_mode_and_sessions() {
    let mut d = setup();
    // DDL commits the session's own transaction.
    d.ok(1, "BEGIN");
    d.ok(1, "INSERT INTO acct VALUES (3, 'cat', 1)");
    d.ok(1, "CREATE TABLE side (x INT)");
    assert_eq!(d.col(0, "SELECT id FROM acct WHERE id = 3"), vec!["3"]);
    // ...and waits for other sessions' open transactions.
    d.ok(2, "BEGIN");
    d.ok(2, "SELECT * FROM acct");
    assert_eq!(d.code(1, "DROP TABLE side"), 1205);
    d.ok(2, "COMMIT");
    d.ok(1, "DROP TABLE side");
    // autocommit = 0: statements open a transaction implicitly.
    d.ok(4, "SET autocommit = 0");
    assert_eq!(d.e().status(4), 0);
    d.ok(4, "UPDATE acct SET bal = 0 WHERE id = 2");
    assert_eq!(d.e().status(4), 1, "IN_TRANS");
    assert_eq!(d.col(0, "SELECT bal FROM acct WHERE id = 2"), vec!["50.00"]);
    d.ok(4, "ROLLBACK");
    d.ok(4, "UPDATE acct SET bal = 1 WHERE id = 2");
    d.ok(4, "SET autocommit = 1"); // commits
    assert_eq!(d.e().status(4), 2);
    assert_eq!(d.col(0, "SELECT bal FROM acct WHERE id = 2"), vec!["1.00"]);
    // Disconnect rolls back.
    d.ok(5, "BEGIN");
    d.ok(5, "DELETE FROM acct");
    d.e().end_session(5);
    assert_eq!(d.col(0, "SELECT COALESCE(1, 0) FROM acct").len(), 3);
    assert_eq!(d.e().open_transactions(), 0);
}

fn versions(d: &mut Db, tree: &str, id: i64) -> usize {
    let mut k = Vec::new();
    novadb_sql::codec::key_encode(&mut k, &Value::Int(id), novadb_sql::ColType::Int).unwrap();
    d.e()
        .db()
        .view(|tx| {
            let t = tx.open_tree(tree)?;
            Ok(novadb_sql::mvcc::version_count(tx, &t, &k)
                .map_err(|e| novadb_storage::Error::Corruption(e.to_string())))
        })
        .unwrap()
        .unwrap()
}

#[test]
fn old_versions_are_pruned() {
    let mut d = setup();
    for i in 0..50 {
        d.ok(0, &format!("UPDATE acct SET bal = {i} WHERE id = 1"));
    }
    assert_eq!(
        versions(&mut d, "sql:t:1", 1),
        1,
        "no snapshot needs old versions"
    );
    // An open snapshot keeps the version it can see.
    d.ok(1, "BEGIN");
    d.ok(1, "SELECT * FROM acct");
    for i in 0..10 {
        d.ok(
            0,
            &format!("UPDATE acct SET bal = {} WHERE id = 1", 100 + i),
        );
    }
    assert_eq!(
        versions(&mut d, "sql:t:1", 1),
        2,
        "newest + the one snapshot 1 sees"
    );
    assert_eq!(d.col(1, "SELECT bal FROM acct WHERE id = 1"), vec!["49.00"]);
    d.ok(1, "COMMIT");
    d.ok(0, "UPDATE acct SET bal = 0 WHERE id = 2"); // any commit prunes pending keys
    assert_eq!(versions(&mut d, "sql:t:1", 1), 1);
    d.ok(0, "DELETE FROM acct WHERE id = 1");
    assert_eq!(
        versions(&mut d, "sql:t:1", 1),
        0,
        "deleted row leaves nothing behind"
    );
}

/// Randomised snapshot-isolation checker: 4 sessions, random interleavings, compared against
/// a model of "snapshot + own writes" with first-committer-wins conflicts.
#[test]
fn snapshot_isolation_randomised() {
    let mut d = Db::new();
    d.ok(0, "CREATE TABLE kv (k INT PRIMARY KEY, v INT, KEY kvv (v))");
    type State = BTreeMap<i64, i64>;
    #[derive(Default)]
    struct T {
        snap: State,
        snap_seq: u64,
        writes: BTreeMap<i64, Option<i64>>,
    }
    let mut committed: State = State::new();
    let mut last_commit: BTreeMap<i64, u64> = BTreeMap::new();
    let mut seq: u64 = 0;
    let mut txns: BTreeMap<u32, T> = BTreeMap::new();
    // NOVADB_SEED overrides the seed (used to run extra seeds in CI/locally).
    let mut rng: u64 = std::env::var("NOVADB_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0x1234_5678_9abc_def1)
        | 1;
    let mut r = move |n: u64| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng % n
    };
    let view = |t: &T| -> State {
        let mut s = t.snap.clone();
        for (k, v) in &t.writes {
            match v {
                Some(v) => {
                    s.insert(*k, *v);
                }
                None => {
                    s.remove(k);
                }
            }
        }
        s
    };
    let (mut commits, mut conflicts) = (0, 0);
    for step in 0..12_000 {
        let c = r(4) as u32 + 1;
        if let std::collections::btree_map::Entry::Vacant(slot) = txns.entry(c) {
            d.ok(c, "BEGIN");
            slot.insert(T {
                snap: committed.clone(),
                snap_seq: seq,
                writes: BTreeMap::new(),
            });
            continue;
        }
        let k = r(12) as i64;
        let v = r(5) as i64;
        let op = r(10);
        let t = txns.get(&c).unwrap();
        let cur = view(t);
        let changed_since = |k: i64| last_commit.get(&k).is_some_and(|&s| s > t.snap_seq);
        // What the engine must do for a write to key k. A transaction that already wrote a key
        // and lost the race on it is doomed; the engine may report that early (e.g. via an
        // index entry the winner committed) or at COMMIT — both are correct.
        let doomed = t.writes.keys().any(|&w| changed_since(w));
        let expect_write = |k: i64| {
            if !t.writes.contains_key(&k) && changed_since(k) {
                "conflict"
            } else if doomed {
                "either"
            } else {
                "ok"
            }
        };
        match op {
            0..=2 => {
                // reads: full scan, point, index
                let (sql, want): (String, Vec<String>) = match r(3) {
                    0 => (
                        "SELECT k, v FROM kv ORDER BY k".into(),
                        cur.iter().map(|(k, v)| format!("{k}:{v}")).collect(),
                    ),
                    1 => (
                        format!("SELECT k, v FROM kv WHERE k = {k}"),
                        cur.get(&k)
                            .map(|v| format!("{k}:{v}"))
                            .into_iter()
                            .collect(),
                    ),
                    _ => (
                        format!("SELECT k, v FROM kv WHERE v = {v} ORDER BY k"),
                        cur.iter()
                            .filter(|(_, x)| **x == v)
                            .map(|(k, x)| format!("{k}:{x}"))
                            .collect(),
                    ),
                };
                let got: Vec<String> = d
                    .ok(c, &sql)
                    .rows
                    .iter()
                    .map(|row| format!("{}:{}", row[0], row[1]))
                    .collect();
                assert_eq!(got, want, "step {step} conn {c}: {sql}");
            }
            3..=7 => {
                let (sql, write): (String, Option<Option<i64>>) = match op {
                    3 | 4 => (
                        format!("INSERT INTO kv VALUES ({k}, {v})"),
                        if cur.contains_key(&k) {
                            None
                        } else {
                            Some(Some(v))
                        },
                    ),
                    5 | 6 => (
                        format!("UPDATE kv SET v = {v} WHERE k = {k}"),
                        match cur.get(&k) {
                            Some(&old) if old != v => Some(Some(v)),
                            _ => None, // no row or unchanged: nothing written
                        },
                    ),
                    _ => (
                        format!("DELETE FROM kv WHERE k = {k}"),
                        if cur.contains_key(&k) {
                            Some(None)
                        } else {
                            None
                        },
                    ),
                };
                let dup = (op == 3 || op == 4) && cur.contains_key(&k);
                let res = d.on(c, &sql);
                match (write, res) {
                    (None, Err(e)) if dup && e.code == 1062 => {}
                    (None, Ok(q)) if !dup => assert_eq!(q.affected, 0, "step {step}: {sql}"),
                    (Some(w), Ok(_)) => {
                        assert_ne!(
                            expect_write(k),
                            "conflict",
                            "step {step} conn {c}: {sql} should have conflicted"
                        );
                        txns.get_mut(&c).unwrap().writes.insert(k, w);
                    }
                    (Some(_), Err(e)) if e.code == 1213 => {
                        assert_ne!(
                            expect_write(k),
                            "ok",
                            "step {step} conn {c}: {sql}: unexpected conflict"
                        );
                        txns.remove(&c);
                        conflicts += 1;
                    }
                    (w, res) => {
                        panic!("step {step} conn {c}: {sql}: model write {w:?}, engine {res:?}")
                    }
                }
            }
            8 => {
                let t = txns.remove(&c).unwrap();
                let should_conflict = t
                    .writes
                    .keys()
                    .any(|k| last_commit.get(k).is_some_and(|&s| s > t.snap_seq));
                match d.on(c, "COMMIT") {
                    Ok(_) => {
                        assert!(
                            !should_conflict,
                            "step {step} conn {c}: commit should have failed"
                        );
                        if !t.writes.is_empty() {
                            seq += 1;
                            for (k, v) in &t.writes {
                                last_commit.insert(*k, seq);
                                match v {
                                    Some(v) => {
                                        committed.insert(*k, *v);
                                    }
                                    None => {
                                        committed.remove(k);
                                    }
                                }
                            }
                        }
                        commits += 1;
                    }
                    Err(e) => {
                        assert!(
                            e.code == 1213 && should_conflict,
                            "step {step} conn {c}: commit -> {e}"
                        );
                        conflicts += 1;
                    }
                }
            }
            _ => {
                d.ok(c, "ROLLBACK");
                txns.remove(&c);
            }
        }
    }
    assert!(
        commits > 200 && conflicts > 10,
        "commits {commits}, conflicts {conflicts}"
    );
    for c in 1..=4 {
        d.ok(c, "ROLLBACK");
    }
    let all: Vec<String> = d
        .ok(0, "SELECT k, v FROM kv ORDER BY k")
        .rows
        .iter()
        .map(|row| format!("{}:{}", row[0], row[1]))
        .collect();
    let want: Vec<String> = committed.iter().map(|(k, v)| format!("{k}:{v}")).collect();
    assert_eq!(all, want);
    d.reopen();
    let all: Vec<String> = d
        .ok(0, "SELECT k, v FROM kv ORDER BY k")
        .rows
        .iter()
        .map(|row| format!("{}:{}", row[0], row[1]))
        .collect();
    assert_eq!(all, want, "after reopen");
}
