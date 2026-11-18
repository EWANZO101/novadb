#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Cluster replication at the engine level: capture on a leader, apply the same entries on
//! every replica in order, compare.

use novadb_sql::binlog::Record;
use novadb_sql::{Engine, Session, SqlError};

static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn eng(tag: &str) -> Engine {
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let d = std::env::temp_dir().join(format!("novadb-cluster-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    Engine::open(&d)
        .unwrap()
        .with_password_hasher(|pw| Ok(format!("h:{pw}")))
}

struct C {
    leader: Engine,
    followers: Vec<Engine>,
    index: u64,
    log: Vec<Vec<Record>>,
}

impl C {
    fn new() -> C {
        C {
            leader: eng("l"),
            followers: vec![eng("f1"), eng("f2")],
            index: 0,
            log: Vec::new(),
        }
    }
    /// Capture on the leader; if it has changes, "commit" them to the log and apply everywhere.
    fn run(&mut self, conn: u32, sql: &str) -> Result<novadb_sql::QueryResult, SqlError> {
        let mut s = Session {
            user: "root".into(),
            conn_id: conn,
            ..Default::default()
        };
        let mut last = None;
        for st in novadb_sql::parse(sql)? {
            let cap = self.leader.capture(&st, &mut s)?;
            if !cap.records.is_empty() {
                self.commit(cap.records)?;
            }
            last = Some(cap.result);
        }
        Ok(last.unwrap_or_default())
    }
    fn commit(&mut self, recs: Vec<Record>) -> Result<(), SqlError> {
        self.index += 1;
        let i = self.index;
        let r = self.leader.apply_cluster(&recs, i).unwrap();
        for f in &mut self.followers {
            let fr = f.apply_cluster(&recs, i).unwrap();
            assert_eq!(
                fr.is_ok(),
                r.is_ok(),
                "apply outcome must be the same on every node"
            );
        }
        self.log.push(recs);
        r
    }
    fn ok(&mut self, conn: u32, sql: &str) -> novadb_sql::QueryResult {
        self.run(conn, sql).unwrap_or_else(|e| panic!("{sql}: {e}"))
    }
    fn state(e: &mut Engine) -> String {
        let mut out = String::new();
        let tables = e.query("SHOW TABLES").unwrap();
        for t in tables.rows {
            let name = t[0].to_string();
            let c = e.query(&format!("SHOW CREATE TABLE `{name}`")).unwrap();
            out.push_str(&c.rows[0][1].to_string());
            let r = e.query(&format!("SELECT * FROM `{name}`")).unwrap();
            out.push_str(&format!("{:?}\n", r.rows));
        }
        out.push_str(&format!("{:?}", e.users().unwrap()));
        out
    }
    fn check_same(&mut self) {
        let want = Self::state(&mut self.leader);
        for f in &mut self.followers {
            assert_eq!(Self::state(f), want, "replica differs");
        }
    }
}

#[test]
fn replicas_converge() {
    let mut c = C::new();
    c.ok(1, "CREATE TABLE a (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(20), UNIQUE KEY un (name))");
    let r = c.ok(1, "INSERT INTO a (name) VALUES ('x'), ('y')");
    assert_eq!((r.affected, r.last_insert_id), (2, 1));
    // a SELECT replicates nothing
    let before = c.index;
    assert_eq!(
        c.ok(1, "SELECT COUNT(*) FROM a").rows[0][0].to_string(),
        "2"
    );
    assert_eq!(c.index, before);
    // transaction: statements stay local until COMMIT, which is one entry
    c.ok(2, "BEGIN");
    c.ok(2, "INSERT INTO a (name) VALUES ('t1')");
    c.ok(2, "INSERT INTO a (name) VALUES ('t2')");
    c.ok(2, "UPDATE a SET name = 'X' WHERE id = 1");
    assert_eq!(c.index, before, "nothing replicated before COMMIT");
    c.ok(2, "COMMIT");
    assert_eq!(c.index, before + 1);
    c.ok(
        1,
        "ALTER TABLE a ADD COLUMN n INT NOT NULL DEFAULT 5, ADD INDEX ix (n)",
    );
    c.ok(1, "CREATE USER app IDENTIFIED BY 'app-password-123'");
    c.ok(1, "GRANT SELECT ON a TO app");
    c.ok(1, "DELETE FROM a WHERE name = 'y'");
    c.ok(1, "CREATE TABLE b (k VARCHAR(5))"); // hidden row id
    c.ok(1, "INSERT INTO b VALUES ('p'), ('q')");
    c.check_same();
    // auto-increment keeps counting on all replicas after failover
    let new_leader = c.followers.remove(0);
    let old = std::mem::replace(&mut c.leader, new_leader);
    c.followers.push(old);
    let r = c.ok(3, "INSERT INTO a (name) VALUES ('after')");
    assert_eq!(r.last_insert_id, 5);
    c.check_same();
}

#[test]
fn conflicts_and_failed_entries_are_deterministic() {
    let mut c = C::new();
    c.ok(
        1,
        "CREATE TABLE acct (id INT PRIMARY KEY, bal INT, email VARCHAR(20), UNIQUE KEY ue (email))",
    );
    c.ok(1, "INSERT INTO acct VALUES (1, 100, 'a'), (2, 100, 'b')");
    // lost update prevented: first committer wins, second gets 1213 at capture
    c.ok(2, "BEGIN");
    c.ok(2, "SELECT bal FROM acct WHERE id = 1");
    c.ok(3, "BEGIN");
    c.ok(3, "SELECT bal FROM acct WHERE id = 1");
    c.ok(2, "UPDATE acct SET bal = 90 WHERE id = 1");
    c.ok(3, "UPDATE acct SET bal = 80 WHERE id = 1");
    c.ok(2, "COMMIT");
    assert_eq!(c.run(3, "COMMIT").unwrap_err().code, 1213);
    // two entries captured against the same state, conflicting on a unique key: the second
    // fails identically everywhere (nothing applied, index still advances)
    let mut s = Session {
        user: "root".into(),
        conn_id: 9,
        ..Default::default()
    };
    let st1 = novadb_sql::parse("INSERT INTO acct VALUES (3, 0, 'dup')")
        .unwrap()
        .remove(0);
    let st2 = novadb_sql::parse("INSERT INTO acct VALUES (4, 0, 'dup')")
        .unwrap()
        .remove(0);
    let e1 = c.leader.capture(&st1, &mut s).unwrap().records;
    let e2 = c.leader.capture(&st2, &mut s).unwrap().records;
    c.commit(e1).unwrap();
    assert_eq!(c.commit(e2).unwrap_err().code, 1062);
    assert_eq!(
        c.leader.query("SELECT COUNT(*) FROM acct").unwrap().rows[0][0].to_string(),
        "3"
    );
    c.check_same();
    // replaying an already applied index is a no-op (crash between apply and ack)
    let recs = c.log[1].clone();
    for e in std::iter::once(&mut c.leader).chain(c.followers.iter_mut()) {
        assert!(e.apply_cluster(&recs, 2).unwrap().is_ok());
        assert_eq!(e.cluster_applied().unwrap(), c.index);
    }
    c.check_same();
}

#[test]
fn capture_leaves_no_trace() {
    let mut c = C::new();
    c.ok(
        1,
        "CREATE TABLE t (id INT PRIMARY KEY AUTO_INCREMENT, v INT)",
    );
    // a follower captures a write: it has records (= reject), and its data is unchanged
    let f = &mut c.followers[0];
    let mut s = Session {
        user: "root".into(),
        conn_id: 5,
        ..Default::default()
    };
    let st = novadb_sql::parse("INSERT INTO t (v) VALUES (1)")
        .unwrap()
        .remove(0);
    let cap = f.capture(&st, &mut s).unwrap();
    assert!(!cap.records.is_empty());
    assert_eq!(
        f.query("SELECT COUNT(*) FROM t").unwrap().rows[0][0].to_string(),
        "0"
    );
    c.check_same();
    // errors in capture change nothing either
    assert_eq!(
        c.run(1, "INSERT INTO t VALUES (1, 1), (1, 2)")
            .unwrap_err()
            .code,
        1062
    );
    assert_eq!(c.run(1, "DROP TABLE nope").unwrap_err().code, 1051);
    c.check_same();
}
