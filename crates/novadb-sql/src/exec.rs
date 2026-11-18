//! Single-node executor (Stage 3). Every statement runs in one storage transaction, so a
//! statement is atomic: on any error nothing it did is kept.

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::ops::Bound;
use std::path::Path;

use novadb_storage::{Db, MAX_KEY_LEN, MAX_VALUE_LEN, Options, Tree, Tx, Vfs};

use crate::ast::*;
use crate::binlog::{Binlog, LogOp, Record};
use crate::catalog::{
    CATALOG_TREE, Column, Index, MAX_COLUMNS, MAX_INDEXES, Table, counter_key, table_key,
};
use crate::codec::{key_encode, prefix_end, row_decode, row_encode};
use crate::error::{Result, SqlError};
use crate::mvcc::{self, Mv, TS_LEN, WriteSet};
use crate::parser::parse;
use crate::privs;

mod alter;
mod cluster;

use crate::value::{ArithOp, ColType, Value, arith, coerce, compare, like, sort_cmp};
pub use cluster::Captured;

/// Max rows a statement may hold in memory (sorting, UPDATE/DELETE candidate sets, results).
/// Disk spill for sorts arrives with the planner (Stage 6); until then this is a hard cap.
pub const MAX_ROWS_IN_MEMORY: usize = 1_000_000;
/// Max encoded row size (rows above `INLINE_MAX` are chunked into the overflow tree).
pub const MAX_ROW_BYTES: usize = 4 << 20;
/// Row payload that fits one storage value (minus the MVCC flag and the inline/overflow byte).
const INLINE_MAX: usize = MAX_VALUE_LEN - 2;
const CHUNK: usize = 4000;
const SCAN_BATCH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColumnMeta {
    pub name: String,
    /// Source column type when the item is a plain column reference.
    pub ty: Option<ColType>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct QueryResult {
    pub columns: Vec<ColumnMeta>,
    pub rows: Vec<Vec<Value>>,
    pub affected: u64,
    pub last_insert_id: u64,
    pub info: Option<String>,
}

impl QueryResult {
    fn ok(affected: u64) -> Self {
        QueryResult {
            affected,
            ..Default::default()
        }
    }
    /// Cell `col` of `row` as text (None = NULL), using the column type for formatting.
    pub fn text(&self, row: usize, col: usize) -> Option<String> {
        let v = self.rows.get(row)?.get(col)?;
        v.text_as(self.columns.get(col).and_then(|c| c.ty))
    }

    /// True for statements that return a result set.
    pub fn is_rows(&self) -> bool {
        !self.columns.is_empty()
    }
}

type Clock = Box<dyn Fn() -> i64 + Send>;
/// Turns a plaintext password into a stored hash (the server plugs in Argon2id).
pub type PasswordHasher = Box<dyn Fn(&str) -> std::result::Result<String, String> + Send>;

/// Per-connection state visible to SQL (CURRENT_USER(), CONNECTION_ID(), LAST_INSERT_ID()).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Session {
    pub user: String,
    pub conn_id: u32,
    pub last_insert_id: u64,
    /// SET max_execution_time (ms, SELECT only; 0 = unlimited).
    pub max_execution_ms: u64,
}

pub const USERS_TREE: &str = "sql:users";
pub const PW_MIN: usize = 12;
pub const PW_MAX: usize = 128;

thread_local! {
    // The session of the statement currently executing on this thread (set by `run_in`).
    static CURRENT: std::cell::RefCell<Session> = std::cell::RefCell::new(Session::default());
}

/// An open multi-statement transaction.
struct Txn {
    snap: u64,
    ws: WriteSet,
}

/// Max versioned keys re-checked for pruning per commit.
const GC_BATCH: usize = 1000;

pub struct Engine {
    db: Db,
    clock: Clock,
    hasher: Option<PasswordHasher>,
    default_session: Session,
    /// Open transactions by connection id.
    txns: HashMap<u32, Txn>,
    /// Connections with autocommit = 0.
    manual: HashSet<u32>,
    /// Keys whose old versions were kept for a then-active snapshot.
    pending: HashSet<(Tree, Vec<u8>)>,
    /// Binary log (point-in-time recovery), if enabled.
    binlog: Option<Binlog>,
    /// Enforce GRANTs (server); embedded use is trusted.
    enforce: bool,
    /// Connection running a transaction that contains DDL (storage outer transaction).
    ddl_owner: Option<u32>,
    /// Binlog records held back until that transaction commits.
    deferred: Option<Vec<Record>>,
    /// Online ALTER TABLE in progress.
    alter: Option<alter::Job>,
    /// Called with the logical changes of every durable commit (change feeds).
    hook: Option<ChangeHook>,
    /// Cluster: running a statement in capture mode / applying a committed entry.
    capturing: bool,
    applying: bool,
}

/// Receives the logical changes (rows put/deleted, DDL text, …) of each durable commit.
pub type ChangeHook = Box<dyn Fn(&[LogOp]) + Send>;

/// Append to the binlog, or hold the record back while a transactional-DDL transaction is open.
fn log_rec(
    binlog: &mut Option<Binlog>,
    deferred: &mut Option<Vec<Record>>,
    r: Record,
) -> Result<()> {
    match (binlog.as_mut(), deferred.as_mut()) {
        (_, Some(d)) => {
            d.push(r);
            Ok(())
        }
        (Some(b), None) => b.append(&r),
        (None, None) => Ok(()),
    }
}

fn ddl_busy() -> SqlError {
    let mut e = SqlError::internal(
        "Lock wait timeout exceeded; another session has an open transaction that changes the schema (retry after it commits or rolls back)",
    );
    e.code = 1205;
    e
}

fn system_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_micros()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

impl Engine {
    fn after_open(mut self) -> Result<Engine> {
        self.cleanup_shadows()?;
        Ok(self)
    }
    pub fn open(dir: impl AsRef<Path>) -> Result<Engine> {
        (Engine {
            db: Db::open(dir, Options::default())?,
            clock: Box::new(system_now),
            hasher: None,
            default_session: Session::default(),
            txns: HashMap::new(),
            manual: HashSet::new(),
            pending: HashSet::new(),
            binlog: None,
            enforce: false,
            ddl_owner: None,
            deferred: None,
            alter: None,
            hook: None,
            capturing: false,
            applying: false,
        })
        .after_open()
    }
    pub fn open_vfs(vfs: Box<dyn Vfs>, opts: Options) -> Result<Engine> {
        (Engine {
            db: Db::open_vfs(vfs, opts)?,
            clock: Box::new(system_now),
            hasher: None,
            default_session: Session::default(),
            txns: HashMap::new(),
            manual: HashSet::new(),
            pending: HashSet::new(),
            binlog: None,
            enforce: false,
            ddl_owner: None,
            deferred: None,
            alter: None,
            hook: None,
            capturing: false,
            applying: false,
        })
        .after_open()
    }
    /// Replace the clock used by NOW()/CURRENT_TIMESTAMP (tests).
    pub fn with_clock(mut self, f: impl Fn() -> i64 + Send + 'static) -> Self {
        self.clock = Box::new(f);
        self
    }
    pub fn db(&mut self) -> &mut Db {
        &mut self.db
    }
    pub fn close(self) -> Result<()> {
        Ok(self.db.close()?)
    }

    /// Parse and run every statement in `sql`; stops at the first error.
    pub fn execute(&mut self, sql: &str) -> Result<Vec<QueryResult>> {
        let stmts = parse(sql)?;
        let mut out = Vec::with_capacity(stmts.len());
        for s in &stmts {
            out.push(self.run(s)?);
        }
        Ok(out)
    }

    /// Convenience: run exactly one statement.
    pub fn query(&mut self, sql: &str) -> Result<QueryResult> {
        let mut v = self.execute(sql)?;
        if v.len() != 1 {
            return Err(SqlError::internal("expected exactly one statement"));
        }
        Ok(v.remove(0))
    }

    /// Install the password hasher used by CREATE/ALTER USER.
    pub fn with_password_hasher(
        mut self,
        f: impl Fn(&str) -> std::result::Result<String, String> + Send + 'static,
    ) -> Self {
        self.hasher = Some(Box::new(f));
        self
    }

    /// Stored password hash for `user` (None if no such user).
    pub fn user_hash(&mut self, user: &str) -> Result<Option<String>> {
        let k = user.to_lowercase();
        let v = self.db.view(|tx| match tx.open_tree(USERS_TREE) {
            Ok(t) => tx.get(&t, k.as_bytes()),
            Err(novadb_storage::Error::TreeNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        })?;
        v.map(|b| String::from_utf8(b).map_err(|_| SqlError::corrupt("users: invalid hash")))
            .transpose()
    }

    /// Names of all SQL users (lowercase).
    pub fn users(&mut self) -> Result<Vec<String>> {
        let v = self.db.view(|tx| match tx.open_tree(USERS_TREE) {
            Ok(t) => tx
                .range(&t, ..)?
                .map(|r| r.map(|(k, _)| k))
                .collect::<novadb_storage::Result<Vec<_>>>(),
            Err(novadb_storage::Error::TreeNotFound(_)) => Ok(Vec::new()),
            Err(e) => Err(e),
        })?;
        Ok(v.into_iter()
            .map(|k| String::from_utf8_lossy(&k).into_owned())
            .collect())
    }

    /// Store an already-hashed password (bootstrap / ALTER USER).
    pub fn set_user_hash(&mut self, user: &str, hash: &str) -> Result<()> {
        if self.ddl_owner.is_some() {
            return Err(ddl_busy());
        }
        let k = user.to_lowercase();
        self.db.update(|tx| {
            let t = tx.open_or_create_tree(USERS_TREE)?;
            tx.put(&t, k.as_bytes(), hash.as_bytes()).map(|_| ())
        })?;
        Ok(())
    }

    fn hash(&self, pw: &str) -> Result<String> {
        let n = pw.chars().count();
        if !(PW_MIN..=PW_MAX).contains(&n) {
            return Err(SqlError::weak_password());
        }
        match &self.hasher {
            Some(h) => h(pw).map_err(SqlError::internal),
            None => Err(SqlError::unsupported("user management outside the server")),
        }
    }

    fn user_stmt(&mut self, s: &Stmt) -> Result<QueryResult> {
        match s {
            Stmt::CreateUser {
                name,
                password,
                if_not_exists,
            } => {
                if self.user_hash(name)?.is_some() {
                    if *if_not_exists {
                        return Ok(QueryResult::ok(0));
                    }
                    return Err(SqlError::user_op("CREATE USER", name));
                }
                let h = self.hash(password)?;
                self.set_user_hash(name, &h)?;
            }
            Stmt::AlterUser {
                name,
                password,
                if_exists,
            } => {
                if self.user_hash(name)?.is_none() {
                    if *if_exists {
                        return Ok(QueryResult::ok(0));
                    }
                    return Err(SqlError::user_op("ALTER USER", name));
                }
                let h = self.hash(password)?;
                self.set_user_hash(name, &h)?;
            }
            Stmt::DropUser { names, if_exists } => {
                let all = self.users()?;
                let lower: Vec<String> = names.iter().map(|n| n.to_lowercase()).collect();
                if let Some(m) = lower.iter().find(|n| !all.contains(n))
                    && !*if_exists
                {
                    return Err(SqlError::user_op("DROP USER", m));
                }
                if all.iter().all(|u| lower.contains(u)) {
                    return Err(SqlError::user_op(
                        "DROP USER (would remove the last user)",
                        &names.join(","),
                    ));
                }
                self.db.update(|tx| {
                    let t = tx.open_or_create_tree(USERS_TREE)?;
                    for n in &lower {
                        tx.delete(&t, n.as_bytes())?;
                    }
                    Ok(())
                })?;
            }
            _ => return Err(SqlError::internal("not a user statement")),
        }
        Ok(QueryResult::ok(0))
    }

    /// Run one statement for a connection's session (an online ALTER TABLE runs to the end).
    pub fn run_in(&mut self, s: &Stmt, sess: &mut Session) -> Result<QueryResult> {
        let r = self.run_in_start(s, sess)?;
        if matches!(s, Stmt::AlterTable { .. })
            && self.alter.as_ref().is_some_and(|j| j.conn == sess.conn_id)
        {
            loop {
                if let Some(r) = self.alter_step()? {
                    return Ok(r);
                }
            }
        }
        Ok(r)
    }

    /// Like `run_in`, but an online ALTER TABLE only starts: while `alter_running()`, call
    /// `alter_step` until it returns the result, releasing the engine lock between calls.
    pub fn run_in_start(&mut self, s: &Stmt, sess: &mut Session) -> Result<QueryResult> {
        CURRENT.with(|c| *c.borrow_mut() = sess.clone());
        let conn = sess.conn_id;
        if let Stmt::Set(assignments) = s {
            for (n, e) in assignments {
                if n == "max_execution_time" {
                    let env = Env {
                        t: None,
                        row: &[],
                        now: (self.clock)(),
                    };
                    let v = eval(e, &env)?
                        .to_num()
                        .map_or(0, |(x, sc)| crate::value::rescale(x, sc, 0).unwrap_or(0));
                    sess.max_execution_ms = u64::try_from(v).unwrap_or(0);
                }
            }
        }
        if self.ddl_owner.is_some_and(|o| o != conn) {
            return Err(ddl_busy());
        }
        if self.enforce && !self.applying {
            let user = sess.user.clone();
            self.authorize(s, &user)?;
        }
        set_deadline(match s {
            Stmt::Select(_) if sess.max_execution_ms > 0 => Some(
                std::time::Instant::now() + std::time::Duration::from_millis(sess.max_execution_ms),
            ),
            _ => None,
        });
        let r = match s {
            Stmt::Txn(TxnKind::Begin) => {
                self.commit_txn(conn)?;
                self.begin_txn(conn).map(|_| QueryResult::ok(0))
            }
            Stmt::Txn(TxnKind::Commit) => self.commit_txn(conn).map(|_| QueryResult::ok(0)),
            Stmt::Txn(TxnKind::Rollback) => {
                self.txns.remove(&conn);
                self.rollback_ddl(conn);
                Ok(QueryResult::ok(0))
            }
            Stmt::Set(assignments) if assignments.iter().any(|(n, _)| n == "autocommit") => {
                for (n, e) in assignments {
                    if n == "autocommit" {
                        let env = Env {
                            t: None,
                            row: &[],
                            now: (self.clock)(),
                        };
                        match eval(e, &env)?.truth() {
                            Some(true) => {
                                self.commit_txn(conn)?;
                                self.manual.remove(&conn);
                            }
                            Some(false) => {
                                self.manual.insert(conn);
                            }
                            None => {
                                return Err(SqlError::bad_value(
                                    "autocommit",
                                    "NULL",
                                    "autocommit",
                                ));
                            }
                        }
                    }
                }
                self.exec_stmt(s, conn)
            }
            Stmt::CreateUser { .. } | Stmt::AlterUser { .. } | Stmt::DropUser { .. } => {
                self.commit_txn(conn)?;
                let r = self.user_stmt(s)?;
                if let Stmt::DropUser { names, .. } = s {
                    for n in names {
                        privs::drop_user(&mut self.db, n)?;
                    }
                }
                self.log_after(s)?;
                Ok(r)
            }
            Stmt::Grant { .. } | Stmt::Revoke { .. } => {
                self.commit_txn(conn)?;
                let r = self.grant_stmt(s, &sess.user)?;
                if let Some(sql) = Self::grant_log_text(s) {
                    self.log_now(vec![LogOp::Ddl(sql)])?;
                }
                Ok(r)
            }
            Stmt::ShowGrants(_) => self.grant_stmt(s, &sess.user),
            Stmt::ShowTables if self.enforce && !privs::is_root(&sess.user) => {
                let mut r = self.exec_stmt(s, conn)?;
                let user = sess.user.clone();
                let mut kept = Vec::new();
                for row in r.rows {
                    let name = row.first().and_then(Value::text).unwrap_or_default();
                    if privs::effective(&mut self.db, &user, Some(&name))? & privs::TABLE_ALL != 0 {
                        kept.push(row);
                    }
                }
                r.rows = kept;
                Ok(r)
            }
            Stmt::CreateTable(_)
            | Stmt::DropTable { .. }
            | Stmt::CreateIndex { .. }
            | Stmt::DropIndex { .. }
            | Stmt::AlterTable { .. } => {
                // Inside a transaction (BEGIN or autocommit=0) DDL is transactional: it joins
                // the transaction and ROLLBACK undoes it. Outside one it is its own transaction.
                // Either way it needs the tables to itself.
                let transactional = self.ddl_owner == Some(conn)
                    || self.txns.contains_key(&conn)
                    || self.manual.contains(&conn);
                if self.applying {
                    // Replicated DDL must apply on every node regardless of local readers.
                    self.pending.clear();
                    if matches!(s, Stmt::AlterTable { .. }) {
                        return self.alter_exec(s, conn, false);
                    }
                    let r = self.exec_stmt(s, conn)?;
                    self.log_after(s)?;
                    return Ok(r);
                }
                if let Some(j) = &self.alter {
                    let mut e = SqlError::internal(format!(
                        "Lock wait timeout exceeded; ALTER TABLE on `{}` is in progress (retry when it finishes)",
                        j.table
                    ));
                    e.code = 1205;
                    Err(e)
                } else if self.txns.keys().any(|c| *c != conn) {
                    let mut e = SqlError::internal(
                        "Lock wait timeout exceeded; another session has an open transaction (DDL waits for it to COMMIT or ROLLBACK)",
                    );
                    e.code = 1205;
                    Err(e)
                } else if transactional {
                    if self.ddl_owner.is_none() {
                        self.db.begin_outer()?;
                        self.deferred = Some(Vec::new());
                        // The transaction's earlier changes become part of the outer one.
                        if let Err(e) = self.commit_txn(conn) {
                            self.db.rollback_outer();
                            self.deferred = None;
                            return Err(e);
                        }
                        self.ddl_owner = Some(conn);
                    }
                    self.pending.clear();
                    if matches!(s, Stmt::AlterTable { .. }) {
                        return self.alter_exec(s, conn, false);
                    }
                    let r = self.exec_stmt(s, conn)?;
                    self.log_after(s)?;
                    Ok(r)
                } else if matches!(s, Stmt::AlterTable { .. }) {
                    self.commit_txn(conn)?;
                    let online = !self.capturing;
                    self.alter_exec(s, conn, online)
                } else {
                    // Old versions in dropped trees are gone; forget them.
                    self.pending.clear();
                    let r = self.exec_stmt(s, conn)?;
                    self.log_after(s)?;
                    Ok(r)
                }
            }
            _ => self.exec_stmt(s, conn),
        };
        match &r {
            // A serialization failure rolls back the whole transaction (like InnoDB deadlocks).
            Err(e) if e.code == 1213 => {
                self.txns.remove(&conn);
            }
            Ok(q) if q.last_insert_id > 0 => sess.last_insert_id = q.last_insert_id,
            _ => {}
        }
        r
    }

    /// Forget a connection (rolls back its open transaction).
    pub fn end_session(&mut self, conn_id: u32) {
        if self.alter.as_ref().is_some_and(|j| j.conn == conn_id) {
            self.alter_abort();
        }
        self.txns.remove(&conn_id);
        self.rollback_ddl(conn_id);
        self.manual.remove(&conn_id);
    }

    /// MySQL server status bits for a connection: IN_TRANS (1) and AUTOCOMMIT (2).
    pub fn status(&self, conn_id: u32) -> u16 {
        u16::from(self.txns.contains_key(&conn_id) || self.ddl_owner == Some(conn_id))
            | if self.manual.contains(&conn_id) { 0 } else { 2 }
    }

    /// Number of open multi-statement transactions.
    pub fn open_transactions(&self) -> usize {
        self.txns.len()
    }

    fn begin_txn(&mut self, conn: u32) -> Result<()> {
        let mut tx = self.db.begin()?;
        let cat = catalog(&mut tx)?;
        let snap = mvcc::last_ts(&mut tx, &cat);
        tx.rollback();
        self.txns.insert(
            conn,
            Txn {
                snap: snap?,
                ws: WriteSet::default(),
            },
        );
        Ok(())
    }

    /// Discard a transactional-DDL transaction owned by `conn`.
    fn rollback_ddl(&mut self, conn: u32) {
        if self.ddl_owner == Some(conn) {
            self.db.rollback_outer();
            self.ddl_owner = None;
            self.deferred = None;
            self.pending.clear();
        }
    }

    /// Commit the open transactional-DDL transaction (binlog first, then one storage commit).
    fn commit_ddl(&mut self) -> Result<()> {
        self.ddl_owner = None;
        let recs = self.deferred.take().unwrap_or_default();
        let r = (|| {
            if let Some(b) = self.binlog.as_mut() {
                for rec in &recs {
                    b.append(rec)?;
                }
            }
            Ok(self.db.commit_outer()?)
        })();
        if r.is_err() {
            self.db.rollback_outer();
        } else {
            for rec in &recs {
                self.emit(&rec.ops);
            }
        }
        r
    }

    fn commit_txn(&mut self, conn: u32) -> Result<()> {
        if self.ddl_owner == Some(conn) {
            self.txns.remove(&conn);
            return self.commit_ddl();
        }
        let Some(txn) = self.txns.remove(&conn) else {
            return Ok(());
        };
        if txn.ws.is_empty() {
            return Ok(());
        }
        let snaps: Vec<u64> = self.txns.values().map(|t| t.snap).collect();
        let now = (self.clock)();
        let mut tx = self.db.begin()?;
        let r = (|| {
            let cat = catalog(&mut tx)?;
            let ts = mvcc::commit(&mut tx, &cat, &txn.ws, txn.snap, &snaps, &mut self.pending)?;
            if let Some(j) = self.alter.as_mut() {
                alter::note(j, &txn.ws.log);
            }
            gc_pending(&mut tx, &snaps, &mut self.pending)?;
            log_rec(
                &mut self.binlog,
                &mut self.deferred,
                Record {
                    ts,
                    wall_us: now,
                    ops: txn.ws.log.clone(),
                },
            )?;
            Ok(())
        })();
        match r {
            Ok(()) => {
                tx.commit()?;
                self.emit(&txn.ws.log);
                Ok(())
            }
            Err(e) => {
                tx.rollback();
                Err(e)
            }
        }
    }

    /// Run a non-transaction-control statement in the connection's transaction (or as its own
    /// transaction in autocommit mode).
    fn exec_stmt(&mut self, s: &Stmt, conn: u32) -> Result<QueryResult> {
        let now = (self.clock)();
        let starts_txn = matches!(
            s,
            Stmt::Select(_) | Stmt::Insert { .. } | Stmt::Update { .. } | Stmt::Delete { .. }
        );
        // In a transactional-DDL transaction each statement commits into the storage outer
        // transaction (no other session can run meanwhile), so no MVCC write set is kept.
        let in_txn = self.ddl_owner != Some(conn)
            && (self.txns.contains_key(&conn) || (self.manual.contains(&conn) && starts_txn));
        let mut tx = self.db.begin()?;
        let cat = match catalog(&mut tx) {
            Ok(c) => c,
            Err(e) => {
                tx.rollback();
                return Err(e);
            }
        };
        if in_txn {
            if let std::collections::hash_map::Entry::Vacant(slot) = self.txns.entry(conn) {
                let snap = match mvcc::last_ts(&mut tx, &cat) {
                    Ok(s) => s,
                    Err(e) => {
                        tx.rollback();
                        return Err(e);
                    }
                };
                slot.insert(Txn {
                    snap,
                    ws: WriteSet::default(),
                });
            }
            let Some(txn) = self.txns.get_mut(&conn) else {
                tx.rollback();
                return Err(SqlError::internal("transaction vanished"));
            };
            // Statement-level atomicity inside a transaction: undo just this statement.
            let saved = txn.ws.clone();
            let res = {
                let mut mv = Mv {
                    tx: &mut tx,
                    snap: txn.snap,
                    ws: &mut txn.ws,
                };
                run_stmt(&mut mv, s, now)
            };
            match res {
                // Only counters (AUTO_INCREMENT) reach storage before COMMIT.
                Ok(r) => {
                    tx.commit()?;
                    Ok(r)
                }
                Err(e) => {
                    txn.ws = saved;
                    tx.rollback();
                    Err(e)
                }
            }
        } else {
            let mut ws = WriteSet::default();
            let mut emitted = Vec::new();
            let res = (|| {
                let snap = mvcc::last_ts(&mut tx, &cat)?;
                let r = {
                    let mut mv = Mv {
                        tx: &mut tx,
                        snap,
                        ws: &mut ws,
                    };
                    run_stmt(&mut mv, s, now)?
                };
                let snaps: Vec<u64> = self.txns.values().map(|t| t.snap).collect();
                if !ws.is_empty() {
                    let ts = mvcc::commit(&mut tx, &cat, &ws, snap, &snaps, &mut self.pending)?;
                    gc_pending(&mut tx, &snaps, &mut self.pending)?;
                    if let Some(j) = self.alter.as_mut() {
                        alter::note(j, &ws.log);
                    }
                    if self.hook.is_some() && self.deferred.is_none() {
                        emitted = ws.log.clone();
                    }
                    log_rec(
                        &mut self.binlog,
                        &mut self.deferred,
                        Record {
                            ts,
                            wall_us: now,
                            ops: std::mem::take(&mut ws.log),
                        },
                    )?;
                }
                Ok(r)
            })();
            match res {
                Ok(r) => {
                    tx.commit()?;
                    self.emit(&emitted);
                    Ok(r)
                }
                Err(e) => {
                    tx.rollback();
                    Err(e)
                }
            }
        }
    }

    pub fn run(&mut self, s: &Stmt) -> Result<QueryResult> {
        let mut sess = std::mem::take(&mut self.default_session);
        let r = self.run_in(s, &mut sess);
        self.default_session = sess;
        r
    }
}

/// Re-check keys whose old versions were kept for an older snapshot.
fn gc_pending(
    tx: &mut Tx<'_>,
    snaps: &[u64],
    pending: &mut HashSet<(Tree, Vec<u8>)>,
) -> Result<()> {
    let batch: Vec<(Tree, Vec<u8>)> = pending.iter().take(GC_BATCH).cloned().collect();
    for (t, k) in batch {
        if mvcc::prune(tx, &t, &k, snaps)? {
            pending.remove(&(t, k));
        }
    }
    Ok(())
}

fn run_stmt(mv: &mut Mv<'_, '_>, s: &Stmt, now: i64) -> Result<QueryResult> {
    match s {
        Stmt::CreateTable(c) => create_table(mv, c),
        Stmt::DropTable { names, if_exists } => drop_table(mv, names, *if_exists),
        Stmt::CreateIndex {
            name,
            table,
            cols,
            unique,
        } => create_index(mv, name, table, cols, *unique),
        Stmt::DropIndex { name, table } => drop_index(mv, name, table),
        Stmt::AlterTable { .. } => Err(SqlError::internal(
            "ALTER TABLE runs through Engine::alter_exec",
        )),
        Stmt::Insert {
            table,
            cols,
            rows,
            select: source,
        } => {
            let mut rows = rows.clone();
            for r in &mut rows {
                for e in r {
                    crate::query::materialize_expr(mv, e, now)?;
                }
            }
            if let Some(sel) = source {
                let q = select(mv, sel, now)?;
                rows = q
                    .rows
                    .into_iter()
                    .map(|r| r.into_iter().map(Expr::Lit).collect())
                    .collect();
            }
            insert(mv, table, cols.as_deref(), &rows, now)
        }
        Stmt::Grant { .. } | Stmt::Revoke { .. } | Stmt::ShowGrants(_) => Err(SqlError::internal(
            "grant statements run through Engine::run_in",
        )),
        Stmt::Kill { .. } | Stmt::ShowProcesslist | Stmt::Backup(_) => Err(SqlError::unsupported(
            "KILL / SHOW PROCESSLIST outside the server",
        )),
        Stmt::Select(sel) => select(mv, sel, now),
        Stmt::Update {
            table,
            sets,
            filter,
            order,
            limit,
        } => {
            let mut sets = sets.clone();
            let mut filter = filter.clone();
            let mut order = order.clone();
            for (_, e) in &mut sets {
                crate::query::materialize_expr(mv, e, now)?;
                crate::query::strip_qualifiers(e, table, None)?;
            }
            if let Some(f) = &mut filter {
                crate::query::materialize_expr(mv, f, now)?;
                crate::query::strip_qualifiers(f, table, None)?;
            }
            for o in &mut order {
                crate::query::strip_qualifiers(&mut o.expr, table, None)?;
            }
            update(mv, table, &sets, filter.as_ref(), &order, *limit, now)
        }
        Stmt::Delete {
            table,
            filter,
            order,
            limit,
        } => {
            let mut filter = filter.clone();
            let mut order = order.clone();
            if let Some(f) = &mut filter {
                crate::query::materialize_expr(mv, f, now)?;
                crate::query::strip_qualifiers(f, table, None)?;
            }
            for o in &mut order {
                crate::query::strip_qualifiers(&mut o.expr, table, None)?;
            }
            delete(mv, table, filter.as_ref(), &order, *limit, now)
        }
        Stmt::ShowTables => show_tables(mv.tx),
        Stmt::Describe(t) => describe(mv.tx, t),
        Stmt::ShowCreateTable(t) => show_create(mv.tx, t),
        Stmt::Explain(inner) => explain(mv, inner, now),
        Stmt::ShowDatabases => Ok(QueryResult {
            columns: meta(&["Database"]),
            rows: vec![vec![Value::Str("novadb".into())]],
            ..Default::default()
        }),
        Stmt::ShowWarnings => Ok(QueryResult {
            columns: meta(&["Level", "Code", "Message"]),
            ..Default::default()
        }),
        Stmt::ShowVariables { like, status } => show_variables(like.as_deref(), *status),
        Stmt::Use(db) => {
            if db.eq_ignore_ascii_case("novadb") {
                Ok(QueryResult::ok(0))
            } else {
                Err(SqlError::unknown_db(db))
            }
        }
        Stmt::Set(assignments) => {
            let env = Env {
                t: None,
                row: &[],
                now,
            };
            for (name, e) in assignments {
                if !SETTABLE.contains(&name.as_str()) {
                    return Err(SqlError::unknown_sysvar(name));
                }
                eval(e, &env)?;
            }
            Ok(QueryResult::ok(0))
        }
        // Transaction control is handled by Engine::run_in.
        Stmt::Txn(_) => Ok(QueryResult::ok(0)),
        Stmt::CreateUser { .. } | Stmt::AlterUser { .. } | Stmt::DropUser { .. } => Err(
            SqlError::internal("user statements run through Engine::run_in"),
        ),
    }
}

// ----- catalog access ------------------------------------------------------------------------

fn catalog(tx: &mut Tx<'_>) -> Result<Tree> {
    Ok(tx.open_or_create_tree(CATALOG_TREE)?)
}

fn find_table(tx: &mut Tx<'_>, name: &str) -> Result<Option<Table>> {
    let c = catalog(tx)?;
    match tx.get(&c, &table_key(name))? {
        Some(b) => Table::decode(&b).map(Some),
        None => Ok(None),
    }
}

pub(crate) fn load_table(tx: &mut Tx<'_>, name: &str) -> Result<Table> {
    find_table(tx, name)?.ok_or_else(|| SqlError::no_table(name))
}

fn save_table(tx: &mut Tx<'_>, t: &Table) -> Result<()> {
    let c = catalog(tx)?;
    let b = t.encode();
    if b.len() > MAX_VALUE_LEN {
        return Err(SqlError::unsupported(
            "table definition this large (too many columns/indexes)",
        ));
    }
    tx.put(&c, &table_key(&t.name), &b)?;
    Ok(())
}

fn read_counter(tx: &mut Tx<'_>, key: &[u8], default: u64) -> Result<u64> {
    let c = catalog(tx)?;
    Ok(match tx.get(&c, key)? {
        Some(b) => u64::from_le_bytes(
            b.as_slice()
                .try_into()
                .map_err(|_| SqlError::corrupt("bad counter"))?,
        ),
        None => default,
    })
}

fn write_counter(tx: &mut Tx<'_>, key: &[u8], v: u64) -> Result<()> {
    let c = catalog(tx)?;
    tx.put(&c, key, &v.to_le_bytes())?;
    Ok(())
}

fn rowid_key(id: u64) -> Vec<u8> {
    let mut k = b"r\0".to_vec();
    k.extend_from_slice(&id.to_be_bytes());
    k
}

pub(crate) struct Trees {
    rows: Tree,
    ovf: Tree,
    idx: Vec<Tree>,
}

pub(crate) fn open_trees(tx: &mut Tx<'_>, t: &Table) -> Result<Trees> {
    let rows = tx.open_tree(&t.rows_tree())?;
    let ovf = tx.open_tree(&t.overflow_tree())?;
    let mut idx = Vec::with_capacity(t.indexes.len());
    for ix in &t.indexes {
        idx.push(tx.open_tree(&t.index_tree(ix))?);
    }
    Ok(Trees { rows, ovf, idx })
}

// ----- row storage ---------------------------------------------------------------------------

fn chunk_key(pk: &[u8], i: u32) -> Vec<u8> {
    let mut k = pk.to_vec();
    k.extend_from_slice(&i.to_be_bytes());
    k
}

fn stored_chunks(stored: &[u8]) -> Result<Option<(usize, u32)>> {
    match stored.first() {
        Some(0) => Ok(None),
        Some(1) if stored.len() == 9 => {
            let len = u32::from_le_bytes(
                stored[1..5]
                    .try_into()
                    .map_err(|_| SqlError::corrupt("overflow header"))?,
            ) as usize;
            let n = u32::from_le_bytes(
                stored[5..9]
                    .try_into()
                    .map_err(|_| SqlError::corrupt("overflow header"))?,
            );
            Ok(Some((len, n)))
        }
        _ => Err(SqlError::corrupt("row: bad storage header")),
    }
}

fn decode_stored(
    mv: &mut Mv<'_, '_>,
    tr: &Trees,
    pk: &[u8],
    stored: &[u8],
    ncols: usize,
) -> Result<Vec<Value>> {
    match stored_chunks(stored)? {
        None => row_decode(&stored[1..], ncols),
        Some((len, n)) => {
            if len > MAX_ROW_BYTES || n as usize > MAX_ROW_BYTES / CHUNK + 1 {
                return Err(SqlError::corrupt("row: overflow too large"));
            }
            let mut buf = Vec::with_capacity(len);
            for i in 0..n {
                let c = mv
                    .get(&tr.ovf, &chunk_key(pk, i))?
                    .ok_or_else(|| SqlError::corrupt("row: overflow chunk missing"))?;
                buf.extend_from_slice(&c);
            }
            if buf.len() != len {
                return Err(SqlError::corrupt("row: overflow length mismatch"));
            }
            row_decode(&buf, ncols)
        }
    }
}

fn get_row(mv: &mut Mv<'_, '_>, tr: &Trees, pk: &[u8], ncols: usize) -> Result<Option<Vec<Value>>> {
    match mv.get(&tr.rows, pk)? {
        Some(s) => decode_stored(mv, tr, pk, &s, ncols).map(Some),
        None => Ok(None),
    }
}

fn delete_chunks(mv: &mut Mv<'_, '_>, tr: &Trees, pk: &[u8]) -> Result<()> {
    if let Some(old) = mv.get(&tr.rows, pk)?
        && let Some((_, n)) = stored_chunks(&old)?
    {
        for i in 0..n {
            mv.delete(&tr.ovf, &chunk_key(pk, i))?;
        }
    }
    Ok(())
}

fn put_row(mv: &mut Mv<'_, '_>, tr: &Trees, pk: &[u8], row: &[Value]) -> Result<()> {
    let enc = row_encode(row)?;
    if enc.len() > MAX_ROW_BYTES {
        return Err(SqlError::row_too_big());
    }
    delete_chunks(mv, tr, pk)?;
    if enc.len() <= INLINE_MAX {
        let mut v = Vec::with_capacity(enc.len() + 1);
        v.push(0);
        v.extend_from_slice(&enc);
        mv.put(&tr.rows, pk, &v)?;
    } else {
        let mut n = 0u32;
        for (i, c) in enc.chunks(CHUNK).enumerate() {
            mv.put(&tr.ovf, &chunk_key(pk, i as u32), c)?;
            n += 1;
        }
        let mut h = vec![1u8];
        h.extend_from_slice(&(enc.len() as u32).to_le_bytes());
        h.extend_from_slice(&n.to_le_bytes());
        mv.put(&tr.rows, pk, &h)?;
    }
    Ok(())
}

fn del_row(mv: &mut Mv<'_, '_>, tr: &Trees, pk: &[u8]) -> Result<()> {
    delete_chunks(mv, tr, pk)?;
    mv.delete(&tr.rows, pk)?;
    Ok(())
}

fn pk_key(t: &Table, row: &[Value]) -> Result<Vec<u8>> {
    let mut k = Vec::new();
    for &c in &t.pk {
        key_encode(&mut k, &row[c], t.cols[c].ty)?;
    }
    // room for the overflow chunk number and the MVCC version suffix
    if k.len() > MAX_KEY_LEN - 4 - TS_LEN {
        return Err(SqlError::key_too_long());
    }
    Ok(k)
}

fn hidden_key(rowid: u64) -> Result<Vec<u8>> {
    let mut k = Vec::new();
    key_encode(&mut k, &Value::Int(rowid as i64), ColType::BigInt)?;
    Ok(k)
}

/// Index entry key. Unique indexes key on the column values alone when none is NULL, so two
/// transactions inserting the same value write the same key and the MVCC conflict check
/// catches it; otherwise (non-unique, or NULLs) the primary key is appended.
fn index_key(t: &Table, ix: &Index, row: &[Value], pk: &[u8]) -> Result<Vec<u8>> {
    let mut k = Vec::new();
    for &c in &ix.cols {
        key_encode(&mut k, &row[c], t.cols[c].ty)?;
    }
    if !(ix.unique && ix.cols.iter().all(|&c| !row[c].is_null())) {
        k.extend_from_slice(pk);
    }
    if k.len() > MAX_KEY_LEN - TS_LEN {
        return Err(SqlError::key_too_long());
    }
    Ok(k)
}

fn render_key(cols: &[usize], row: &[Value]) -> String {
    cols.iter()
        .map(|&c| row[c].text().unwrap_or_else(|| "NULL".into()))
        .collect::<Vec<_>>()
        .join("-")
}

fn index_insert(
    mv: &mut Mv<'_, '_>,
    t: &Table,
    tr: &Trees,
    row: &[Value],
    pk: &[u8],
) -> Result<()> {
    for (i, ix) in t.indexes.iter().enumerate() {
        let k = index_key(t, ix, row, pk)?;
        if ix.unique
            && ix.cols.iter().all(|&c| !row[c].is_null())
            && let Some(other) = mv.get(&tr.idx[i], &k)?
            && other != pk
        {
            return Err(SqlError::dup_entry(&render_key(&ix.cols, row), &ix.name));
        }
        mv.put(&tr.idx[i], &k, pk)?;
    }
    Ok(())
}

fn index_delete(
    mv: &mut Mv<'_, '_>,
    t: &Table,
    tr: &Trees,
    row: &[Value],
    pk: &[u8],
) -> Result<()> {
    for (i, ix) in t.indexes.iter().enumerate() {
        let k = index_key(t, ix, row, pk)?;
        mv.delete(&tr.idx[i], &k)?;
    }
    Ok(())
}

// ----- expressions ---------------------------------------------------------------------------

pub(crate) struct Env<'a> {
    pub(crate) t: Option<&'a Table>,
    pub(crate) row: &'a [Value],
    pub(crate) now: i64,
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

thread_local! {
    /// Cancellation flag (set by the server for KILL QUERY) and statement deadline
    /// (max_execution_time) for the statement running on this thread.
    static INTERRUPT: std::cell::RefCell<(Option<std::sync::Arc<std::sync::atomic::AtomicBool>>, Option<std::time::Instant>)> =
        const { std::cell::RefCell::new((None, None)) };
}

/// Install the cancellation flag checked by long-running statements on this thread.
pub fn set_cancel_flag(flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>) {
    INTERRUPT.with(|i| i.borrow_mut().0 = flag);
}

fn set_deadline(d: Option<std::time::Instant>) {
    INTERRUPT.with(|i| i.borrow_mut().1 = d);
}

/// Error out if the running statement was killed or ran past its deadline.
pub(crate) fn check_interrupt() -> Result<()> {
    INTERRUPT.with(|i| {
        let i = i.borrow();
        if let Some(f) = &i.0
            && f.load(std::sync::atomic::Ordering::Relaxed)
        {
            let mut e = SqlError::internal("Query execution was interrupted");
            e.code = 1317;
            e.state = "70100";
            return Err(e);
        }
        if let Some(d) = i.1
            && std::time::Instant::now() >= d
        {
            let mut e = SqlError::internal(
                "Query execution was interrupted, maximum statement execution time exceeded",
            );
            e.code = 3024;
            return Err(e);
        }
        Ok(())
    })
}

fn check_cols(e: &Expr, t: Option<&Table>) -> Result<()> {
    let mut cols = Vec::new();
    e.columns(&mut cols);
    for c in cols {
        if t.and_then(|t| t.col(c)).is_none() {
            return Err(SqlError::bad_column(c));
        }
    }
    Ok(())
}

fn tv(b: Option<bool>) -> Value {
    b.map_or(Value::Null, Value::bool)
}

pub(crate) fn eval(e: &Expr, env: &Env<'_>) -> Result<Value> {
    Ok(match e {
        Expr::Lit(v) => v.clone(),
        Expr::Param(_) => return Err(SqlError::param_count()),
        // Subqueries are replaced by their results before evaluation (query::materialize_*).
        Expr::Subquery(_) | Expr::InSubquery { .. } | Expr::Exists { .. } => {
            return Err(SqlError::internal("subquery was not materialized"));
        }
        Expr::Col(c) => {
            let i = env
                .t
                .and_then(|t| t.col(c))
                .ok_or_else(|| SqlError::bad_column(c))?;
            env.row.get(i).cloned().unwrap_or(Value::Null)
        }
        Expr::Unary { op: UnOp::Not, e } => tv(eval(e, env)?.truth().map(|b| !b)),
        Expr::Unary { op: UnOp::Neg, e } => arith(ArithOp::Sub, &Value::Int(0), &eval(e, env)?)?,
        Expr::Binary { op, l, r } => {
            match op {
                BinOp::And => {
                    let a = eval(l, env)?.truth();
                    if a == Some(false) {
                        return Ok(Value::Int(0));
                    }
                    let b = eval(r, env)?.truth();
                    return Ok(match (a, b) {
                        (_, Some(false)) => Value::Int(0),
                        (Some(true), Some(true)) => Value::Int(1),
                        _ => Value::Null,
                    });
                }
                BinOp::Or => {
                    let a = eval(l, env)?.truth();
                    if a == Some(true) {
                        return Ok(Value::Int(1));
                    }
                    let b = eval(r, env)?.truth();
                    return Ok(match (a, b) {
                        (_, Some(true)) => Value::Int(1),
                        (Some(false), Some(false)) => Value::Int(0),
                        _ => Value::Null,
                    });
                }
                _ => {}
            }
            let a = eval(l, env)?;
            let b = eval(r, env)?;
            match op {
                BinOp::Xor => tv(match (a.truth(), b.truth()) {
                    (Some(x), Some(y)) => Some(x ^ y),
                    _ => None,
                }),
                BinOp::Eq => tv(compare(&a, &b).map(|o| o == Ordering::Equal)),
                BinOp::Ne => tv(compare(&a, &b).map(|o| o != Ordering::Equal)),
                BinOp::Lt => tv(compare(&a, &b).map(|o| o == Ordering::Less)),
                BinOp::Le => tv(compare(&a, &b).map(|o| o != Ordering::Greater)),
                BinOp::Gt => tv(compare(&a, &b).map(|o| o == Ordering::Greater)),
                BinOp::Ge => tv(compare(&a, &b).map(|o| o != Ordering::Less)),
                BinOp::NullSafeEq => Value::bool(match (a.is_null(), b.is_null()) {
                    (true, true) => true,
                    (false, false) => compare(&a, &b) == Some(Ordering::Equal),
                    _ => false,
                }),
                BinOp::Add => arith(ArithOp::Add, &a, &b)?,
                BinOp::Sub => arith(ArithOp::Sub, &a, &b)?,
                BinOp::Mul => arith(ArithOp::Mul, &a, &b)?,
                BinOp::Div => arith(ArithOp::Div, &a, &b)?,
                BinOp::IntDiv => arith(ArithOp::IntDiv, &a, &b)?,
                BinOp::Mod => arith(ArithOp::Mod, &a, &b)?,
                BinOp::And | BinOp::Or => Value::Null,
            }
        }
        Expr::IsNull { e, neg } => Value::bool(eval(e, env)?.is_null() != *neg),
        Expr::InList { e, list, neg } => {
            let v = eval(e, env)?;
            if v.is_null() {
                return Ok(Value::Null);
            }
            let mut saw_null = false;
            let mut hit = false;
            for x in list {
                match compare(&v, &eval(x, env)?) {
                    Some(Ordering::Equal) => {
                        hit = true;
                        break;
                    }
                    None => saw_null = true,
                    _ => {}
                }
            }
            if hit {
                Value::bool(!neg)
            } else if saw_null {
                Value::Null
            } else {
                Value::bool(*neg)
            }
        }
        Expr::Between { e, lo, hi, neg } => {
            let v = eval(e, env)?;
            let a = compare(&v, &eval(lo, env)?).map(|o| o != Ordering::Less);
            let b = compare(&v, &eval(hi, env)?).map(|o| o != Ordering::Greater);
            let r = match (a, b) {
                (Some(false), _) | (_, Some(false)) => Some(false),
                (Some(true), Some(true)) => Some(true),
                _ => None,
            };
            tv(if *neg { r.map(|x| !x) } else { r })
        }
        Expr::Like { e, pat, neg } => {
            let (v, p) = (eval(e, env)?, eval(pat, env)?);
            match (v.text(), p.text()) {
                (Some(v), Some(p)) => Value::bool(like(&v, &p) != *neg),
                _ => Value::Null,
            }
        }
        Expr::Func { name, args } => func(name, args, env)?,
    })
}

fn func(name: &str, args: &[Expr], env: &Env<'_>) -> Result<Value> {
    let n = args.len();
    let arg = |i: usize| -> Result<Value> { args.get(i).map_or(Ok(Value::Null), |a| eval(a, env)) };
    let need = |ok: bool| {
        if ok {
            Ok(())
        } else {
            Err(SqlError::wrong_func(name))
        }
    };
    Ok(match name {
        "now" | "current_timestamp" | "localtimestamp" | "sysdate" => {
            need(n <= 1)?;
            let fsp = match arg(0)? {
                Value::Null => 0,
                v => v
                    .to_num()
                    .map_or(0, |(x, s)| crate::value::rescale(x, s, 0).unwrap_or(0))
                    .clamp(0, 6) as u8,
            };
            Value::DateTime(trunc_fsp(env.now, fsp))
        }
        "lower" | "lcase" | "upper" | "ucase" => {
            need(n == 1)?;
            let up = name.starts_with('u');
            match arg(0)? {
                Value::Null => Value::Null,
                Value::Bytes(b) => Value::Bytes(if up {
                    b.to_ascii_uppercase()
                } else {
                    b.to_ascii_lowercase()
                }),
                v => {
                    let s = v.text().unwrap_or_default();
                    Value::Str(if up {
                        s.to_uppercase()
                    } else {
                        s.to_lowercase()
                    })
                }
            }
        }
        "length" | "octet_length" => {
            need(n == 1)?;
            match arg(0)? {
                Value::Null => Value::Null,
                Value::Bytes(b) => Value::Int(b.len() as i64),
                v => Value::Int(v.text().unwrap_or_default().len() as i64),
            }
        }
        "char_length" | "character_length" => {
            need(n == 1)?;
            match arg(0)? {
                Value::Null => Value::Null,
                Value::Bytes(b) => Value::Int(b.len() as i64),
                v => Value::Int(v.text().unwrap_or_default().chars().count() as i64),
            }
        }
        "concat" => {
            need(n >= 1)?;
            let mut bin = false;
            let mut out: Vec<u8> = Vec::new();
            for i in 0..n {
                let v = arg(i)?;
                match v {
                    Value::Null => return Ok(Value::Null),
                    Value::Bytes(b) => {
                        bin = true;
                        out.extend_from_slice(&b);
                    }
                    v => out.extend_from_slice(v.text().unwrap_or_default().as_bytes()),
                }
                if out.len() > crate::MAX_STATEMENT_BYTES {
                    return Err(SqlError::resource("CONCAT result too large"));
                }
            }
            if bin {
                Value::Bytes(out)
            } else {
                Value::Str(String::from_utf8_lossy(&out).into_owned())
            }
        }
        "coalesce" => {
            need(n >= 1)?;
            for i in 0..n {
                let v = arg(i)?;
                if !v.is_null() {
                    return Ok(v);
                }
            }
            Value::Null
        }
        "ifnull" => {
            need(n == 2)?;
            let a = arg(0)?;
            if a.is_null() { arg(1)? } else { a }
        }
        "nullif" => {
            need(n == 2)?;
            let (a, b) = (arg(0)?, arg(1)?);
            if compare(&a, &b) == Some(Ordering::Equal) {
                Value::Null
            } else {
                a
            }
        }
        "if" => {
            need(n == 3)?;
            if arg(0)?.truth() == Some(true) {
                arg(1)?
            } else {
                arg(2)?
            }
        }
        "abs" => {
            need(n == 1)?;
            let v = arg(0)?;
            match v.to_num() {
                None => Value::Null,
                Some((x, _)) if x < 0 => arith(ArithOp::Sub, &Value::Int(0), &v)?,
                Some(_) => match v {
                    Value::Int(_) | Value::Dec { .. } => v,
                    other => {
                        let (x, s) = other.to_num().unwrap_or((0, 0));
                        if s == 0 {
                            i64::try_from(x)
                                .map(Value::Int)
                                .unwrap_or(Value::Dec { v: x, s })
                        } else {
                            Value::Dec { v: x, s }
                        }
                    }
                },
            }
        }
        "round" => {
            need(n == 1 || n == 2)?;
            let v = arg(0)?;
            let d = if n == 2 {
                match arg(1)?.to_num() {
                    None => return Ok(Value::Null),
                    Some((x, s)) => {
                        crate::value::rescale(x, s, 0).unwrap_or(0).clamp(-38, 30) as i32
                    }
                }
            } else {
                0
            };
            let Some((x, s)) = v.to_num() else {
                return Ok(Value::Null);
            };
            let oor = || SqlError::value_out_of_range("round");
            if d >= 0 {
                let d = d as u8;
                if d >= s {
                    return Ok(match v {
                        Value::Int(_) | Value::Dec { .. } => v,
                        _ => Value::Dec { v: x, s },
                    });
                }
                let r = crate::value::rescale(x, s, d).ok_or_else(oor)?;
                if d == 0 {
                    i64::try_from(r)
                        .map(Value::Int)
                        .unwrap_or(Value::Dec { v: r, s: 0 })
                } else {
                    Value::Dec { v: r, s: d }
                }
            } else {
                let whole = crate::value::rescale(x, s, 0).ok_or_else(oor)?;
                let p = crate::value::pow10((-d) as u8).ok_or_else(oor)?;
                let q = crate::value::rescale(whole, (-d) as u8, 0).ok_or_else(oor)?;
                let r = q.checked_mul(p).ok_or_else(oor)?;
                i64::try_from(r)
                    .map(Value::Int)
                    .unwrap_or(Value::Dec { v: r, s: 0 })
            }
        }
        "substring" | "substr" => {
            need(n == 2 || n == 3)?;
            let s = arg(0)?;
            let Some(text) = s.text() else {
                return Ok(Value::Null);
            };
            let Some((p, ps)) = arg(1)?.to_num() else {
                return Ok(Value::Null);
            };
            let p = crate::value::rescale(p, ps, 0).unwrap_or(0);
            let chars: Vec<char> = text.chars().collect();
            let len = chars.len() as i128;
            let start = if p > 0 {
                p - 1
            } else if p < 0 {
                len + p
            } else {
                return Ok(Value::Str(String::new()));
            };
            if start < 0 || start >= len {
                return Ok(Value::Str(String::new()));
            }
            let take = if n == 3 {
                match arg(2)?.to_num() {
                    None => return Ok(Value::Null),
                    Some((l, ls)) => crate::value::rescale(l, ls, 0).unwrap_or(0).max(0),
                }
            } else {
                len
            };
            let end = (start + take).min(len);
            Value::Str(chars[start as usize..end as usize].iter().collect())
        }
        "__sysvar" => {
            let n = arg(0)?.text().unwrap_or_default();
            sysvar(&n).ok_or_else(|| SqlError::unknown_sysvar(&n))?
        }
        "current_user" | "user" | "session_user" | "system_user" => {
            need(n == 0)?;
            Value::Str(format!(
                "{}@localhost",
                CURRENT.with(|c| c.borrow().user.clone())
            ))
        }
        "connection_id" => {
            need(n == 0)?;
            Value::Int(i64::from(CURRENT.with(|c| c.borrow().conn_id)))
        }
        "last_insert_id" => {
            need(n == 0)?;
            Value::Int(CURRENT.with(|c| c.borrow().last_insert_id) as i64)
        }
        "__is_true" => Value::bool(arg(0)?.truth() == Some(true)),
        "__is_false" => Value::bool(arg(0)?.truth() == Some(false)),
        "version" => {
            need(n == 0)?;
            Value::Str(concat!("8.0.0-NovaDB-", env!("CARGO_PKG_VERSION")).into())
        }
        "database" | "schema" => {
            need(n == 0)?;
            Value::Str("novadb".into())
        }
        // Aggregates are evaluated by the grouping code; anywhere else they are misplaced.
        _ if crate::query::is_aggregate(name) => {
            let mut e = SqlError::internal("Invalid use of group function");
            e.code = 1111;
            return Err(e);
        }
        _ => return Err(SqlError::wrong_func(name)),
    })
}

/// Current time cut to `fsp` fractional digits (NOW(), DEFAULT CURRENT_TIMESTAMP).
fn trunc_fsp(now: i64, fsp: u8) -> i64 {
    now - now.rem_euclid(10i64.pow(u32::from(6 - fsp.min(6))))
}

pub(crate) fn matches(filter: Option<&Expr>, env: &Env<'_>) -> Result<bool> {
    match filter {
        None => Ok(true),
        Some(f) => Ok(eval(f, env)?.truth() == Some(true)),
    }
}

// ----- planner -------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Access {
    Full,
    /// Primary-key range (point when lo == hi on the full key).
    Pk {
        lo: Bound<Vec<u8>>,
        hi: Bound<Vec<u8>>,
        point: bool,
    },
    /// Secondary index range; entries map to primary keys.
    Idx {
        ix: usize,
        lo: Bound<Vec<u8>>,
        hi: Bound<Vec<u8>>,
        point: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Op {
    Eq,
    Lt,
    Le,
    Gt,
    Ge,
}

fn conjuncts<'a>(e: &'a Expr, out: &mut Vec<&'a Expr>) {
    match e {
        Expr::Binary {
            op: BinOp::And,
            l,
            r,
        } => {
            conjuncts(l, out);
            conjuncts(r, out);
        }
        other => out.push(other),
    }
}

fn is_const(e: &Expr) -> bool {
    let mut c = Vec::new();
    e.columns(&mut c);
    c.is_empty()
}

/// A literal is usable as an index bound only if it converts to the column type without
/// changing value and compares the same way the WHERE clause will (so no rows are missed).
fn key_value(t: &Table, col: usize, lit: &Value) -> Option<Value> {
    let ty = t.cols[col].ty;
    let family_ok = match lit {
        Value::Int(_) | Value::Dec { .. } => ty.is_numeric(),
        Value::Str(_) => matches!(ty, ColType::Varchar(_) | ColType::DateTime(_)),
        Value::DateTime(_) => matches!(ty, ColType::DateTime(_)),
        _ => false,
    };
    if !family_ok || ty.is_lob() {
        return None;
    }
    let c = coerce(lit.clone(), ty, "").ok()?;
    (compare(&c, lit) == Some(Ordering::Equal)).then_some(c)
}

fn simple_preds(t: &Table, filter: &Expr, now: i64) -> Vec<(usize, Op, Value)> {
    let mut cs = Vec::new();
    conjuncts(filter, &mut cs);
    let mut out = Vec::new();
    let env = Env {
        t: None,
        row: &[],
        now,
    };
    let lit = |e: &Expr| -> Option<Value> {
        if is_const(e) {
            eval(e, &env).ok()
        } else {
            None
        }
    };
    for c in cs {
        match c {
            Expr::Binary { op, l, r } => {
                let op = match op {
                    BinOp::Eq => Op::Eq,
                    BinOp::Lt => Op::Lt,
                    BinOp::Le => Op::Le,
                    BinOp::Gt => Op::Gt,
                    BinOp::Ge => Op::Ge,
                    _ => continue,
                };
                let (col, v, op) = match (&**l, &**r) {
                    (Expr::Col(n), e) => match (t.col(n), lit(e)) {
                        (Some(c), Some(v)) => (c, v, op),
                        _ => continue,
                    },
                    (e, Expr::Col(n)) => match (t.col(n), lit(e)) {
                        (Some(c), Some(v)) => (
                            c,
                            v,
                            match op {
                                Op::Lt => Op::Gt,
                                Op::Le => Op::Ge,
                                Op::Gt => Op::Lt,
                                Op::Ge => Op::Le,
                                Op::Eq => Op::Eq,
                            },
                        ),
                        _ => continue,
                    },
                    _ => continue,
                };
                if let Some(kv) = key_value(t, col, &v) {
                    out.push((col, op, kv));
                }
            }
            Expr::Between {
                e,
                lo,
                hi,
                neg: false,
            } => {
                if let Expr::Col(n) = &**e
                    && let Some(col) = t.col(n)
                {
                    if let Some(v) = lit(lo).and_then(|v| key_value(t, col, &v)) {
                        out.push((col, Op::Ge, v));
                    }
                    if let Some(v) = lit(hi).and_then(|v| key_value(t, col, &v)) {
                        out.push((col, Op::Le, v));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn enc1(t: &Table, col: usize, v: &Value) -> Option<Vec<u8>> {
    let mut k = Vec::new();
    key_encode(&mut k, v, t.cols[col].ty).ok()?;
    Some(k)
}

/// (lower bound, upper bound, is an equality prefix)
type KeyRange = (Bound<Vec<u8>>, Bound<Vec<u8>>, bool);

/// Bounds on keys whose first component is column `col`, given `preds`.
fn first_col_bounds(t: &Table, col: usize, preds: &[(usize, Op, Value)]) -> Option<KeyRange> {
    let mine: Vec<&(usize, Op, Value)> = preds.iter().filter(|p| p.0 == col).collect();
    if let Some((_, _, v)) = mine.iter().find(|p| p.1 == Op::Eq) {
        let p = enc1(t, col, v)?;
        let hi = prefix_end(&p).map_or(Bound::Unbounded, Bound::Excluded);
        return Some((Bound::Included(p), hi, true));
    }
    let mut lo = Bound::Unbounded;
    let mut hi = Bound::Unbounded;
    for (_, op, v) in &mine {
        let k = enc1(t, col, v)?;
        match op {
            Op::Ge if lo == Bound::Unbounded => lo = Bound::Included(k),
            Op::Gt if lo == Bound::Unbounded => {
                lo =
                    prefix_end(&k).map_or(Bound::Excluded(vec![0xFF; MAX_KEY_LEN]), Bound::Included)
            }
            Op::Le if hi == Bound::Unbounded => {
                hi = prefix_end(&k).map_or(Bound::Unbounded, Bound::Excluded)
            }
            Op::Lt if hi == Bound::Unbounded => hi = Bound::Excluded(k),
            _ => {}
        }
    }
    if lo == Bound::Unbounded && hi == Bound::Unbounded {
        return None;
    }
    // Exclude NULLs (encoded as 0x00) from upper-only ranges: comparisons never match NULL.
    if lo == Bound::Unbounded {
        lo = Bound::Included(vec![0x01]);
    }
    Some((lo, hi, false))
}

pub(crate) fn plan(t: &Table, filter: Option<&Expr>, now: i64) -> Access {
    let Some(f) = filter else { return Access::Full };
    let preds = simple_preds(t, f, now);
    if preds.is_empty() {
        return Access::Full;
    }
    let eq = |c: usize| {
        preds
            .iter()
            .find(|p| p.0 == c && p.1 == Op::Eq)
            .map(|p| &p.2)
    };
    // 1. full primary key equality
    if !t.pk.is_empty() && t.pk.iter().all(|&c| eq(c).is_some()) {
        let mut k = Vec::new();
        let ok =
            t.pk.iter()
                .all(|&c| eq(c).is_some_and(|v| key_encode(&mut k, v, t.cols[c].ty).is_ok()));
        if ok {
            return Access::Pk {
                lo: Bound::Included(k.clone()),
                hi: Bound::Included(k),
                point: true,
            };
        }
    }
    // 2. unique index with full equality
    for (i, ix) in t.indexes.iter().enumerate() {
        if ix.unique && ix.cols.iter().all(|&c| eq(c).is_some()) {
            let mut k = Vec::new();
            if ix
                .cols
                .iter()
                .all(|&c| eq(c).is_some_and(|v| key_encode(&mut k, v, t.cols[c].ty).is_ok()))
            {
                let hi = prefix_end(&k).map_or(Bound::Unbounded, Bound::Excluded);
                return Access::Idx {
                    ix: i,
                    lo: Bound::Included(k),
                    hi,
                    point: true,
                };
            }
        }
    }
    // 3. primary key prefix / range on its first column
    if let Some(&c0) = t.pk.first()
        && let Some((lo, hi, _)) = first_col_bounds(t, c0, &preds)
    {
        return Access::Pk {
            lo,
            hi,
            point: false,
        };
    }
    // 4. any index: full equality prefix, else range on its first column
    for (i, ix) in t.indexes.iter().enumerate() {
        let mut k = Vec::new();
        let mut n = 0;
        for &c in &ix.cols {
            match eq(c) {
                Some(v) if key_encode(&mut k, v, t.cols[c].ty).is_ok() => n += 1,
                _ => break,
            }
        }
        if n > 0 {
            let hi = prefix_end(&k).map_or(Bound::Unbounded, Bound::Excluded);
            return Access::Idx {
                ix: i,
                lo: Bound::Included(k),
                hi,
                point: true,
            };
        }
    }
    for (i, ix) in t.indexes.iter().enumerate() {
        if let Some(&c0) = ix.cols.first()
            && let Some((lo, hi, _)) = first_col_bounds(t, c0, &preds)
        {
            return Access::Idx {
                ix: i,
                lo,
                hi,
                point: false,
            };
        }
    }
    Access::Full
}

/// Visit matching rows in access order; `visit` returns false to stop early.
pub(crate) fn scan(
    mv: &mut Mv<'_, '_>,
    t: &Table,
    tr: &Trees,
    access: &Access,
    filter: Option<&Expr>,
    now: i64,
    mut visit: impl FnMut(Vec<u8>, Vec<Value>) -> Result<bool>,
) -> Result<()> {
    let ncols = t.cols.len();
    let test = |row: &[Value]| {
        matches(
            filter,
            &Env {
                t: Some(t),
                row,
                now,
            },
        )
    };
    match access {
        Access::Full | Access::Pk { .. } => {
            let (mut lo, hi) = match access {
                Access::Pk { lo, hi, .. } => (lo.clone(), hi.clone()),
                _ => (Bound::Unbounded, Bound::Unbounded),
            };
            loop {
                check_interrupt()?;
                let b = mv.scan(&tr.rows, &lo, &hi, SCAN_BATCH)?;
                let Some((last, _)) = b.last() else { break };
                lo = Bound::Excluded(last.clone());
                for (k, stored) in b {
                    let row = decode_stored(mv, tr, &k, &stored, ncols)?;
                    if test(&row)? && !visit(k, row)? {
                        return Ok(());
                    }
                }
            }
        }
        Access::Idx { ix, lo, hi, .. } => {
            let tree = tr
                .idx
                .get(*ix)
                .ok_or_else(|| SqlError::internal("index handle"))?;
            let mut lo = lo.clone();
            loop {
                check_interrupt()?;
                let b = mv.scan(tree, &lo, hi, SCAN_BATCH)?;
                let Some((last, _)) = b.last() else { break };
                lo = Bound::Excluded(last.clone());
                for (_, pk) in b {
                    let row = get_row(mv, tr, &pk, ncols)?
                        .ok_or_else(|| SqlError::corrupt("index entry points to a missing row"))?;
                    if test(&row)? && !visit(pk, row)? {
                        return Ok(());
                    }
                }
            }
        }
    }
    Ok(())
}

fn access_desc(t: &Table, a: &Access) -> (&'static str, Option<String>) {
    match a {
        Access::Full => ("ALL", None),
        Access::Pk { point: true, .. } => ("const", Some("PRIMARY".into())),
        Access::Pk { .. } => ("range", Some("PRIMARY".into())),
        Access::Idx { ix, point, .. } => {
            let index = t.indexes.get(*ix);
            let kind = match (point, index.is_some_and(|i| i.unique)) {
                (true, true) => "const",
                (true, false) => "ref",
                _ => "range",
            };
            (kind, index.map(|i| i.name.clone()))
        }
    }
}

// ----- DDL -----------------------------------------------------------------------------------

fn valid_name(n: &str) -> Result<()> {
    if n.is_empty() || n.chars().count() > crate::parser::MAX_IDENT {
        return Err(SqlError::bad_ident(n));
    }
    Ok(())
}

fn col_pos(cols: &[Column], n: &str) -> Result<usize> {
    cols.iter()
        .position(|x| x.name.eq_ignore_ascii_case(n))
        .ok_or_else(|| SqlError::bad_column(n))
}

fn create_table(mv: &mut Mv<'_, '_>, c: &CreateTable) -> Result<QueryResult> {
    valid_name(&c.name)?;
    if find_table(mv.tx, &c.name)?.is_some() {
        if c.if_not_exists {
            return Ok(QueryResult {
                info: Some(format!("Table '{}' already exists", c.name)),
                ..Default::default()
            });
        }
        return Err(SqlError::table_exists(&c.name));
    }
    let mut t = build_table(c)?;
    t.id = read_counter(mv.tx, b"n", 1)?;
    write_counter(mv.tx, b"n", t.id + 1)?;
    mv.tx.create_tree(&t.rows_tree())?;
    mv.tx.create_tree(&t.overflow_tree())?;
    for ix in &t.indexes {
        mv.tx.create_tree(&t.index_tree(ix))?;
    }
    save_table(mv.tx, &t)?;
    Ok(QueryResult::ok(0))
}

/// Validate a table definition and build its schema (id 0; no storage touched).
fn build_table(c: &CreateTable) -> Result<Table> {
    if c.cols.is_empty() || c.cols.len() > MAX_COLUMNS {
        return Err(SqlError::unsupported(
            "tables without columns or with more than 1024 columns",
        ));
    }
    let mut cols: Vec<Column> = Vec::with_capacity(c.cols.len());
    let mut seen = HashSet::new();
    for d in &c.cols {
        valid_name(&d.name)?;
        if !seen.insert(d.name.to_lowercase()) {
            return Err(SqlError::dup_column(&d.name));
        }
        let default = match &d.default {
            None => None,
            Some(DefaultExpr::Now) if matches!(d.ty, ColType::DateTime(_)) => {
                Some(DefaultExpr::Now)
            }
            Some(DefaultExpr::Now) => return Err(SqlError::invalid_default(&d.name)),
            Some(DefaultExpr::Value(Value::Null)) if !d.nullable || d.primary => {
                return Err(SqlError::invalid_default(&d.name));
            }
            Some(DefaultExpr::Value(v)) if d.ty.is_lob() && !v.is_null() => {
                return Err(SqlError::invalid_default(&d.name));
            }
            Some(DefaultExpr::Value(v)) => Some(DefaultExpr::Value(
                coerce(v.clone(), d.ty, &d.name).map_err(|_| SqlError::invalid_default(&d.name))?,
            )),
        };
        if d.auto_inc && !matches!(d.ty, ColType::Int | ColType::BigInt) {
            return Err(SqlError::auto_inc());
        }
        cols.push(Column {
            name: d.name.clone(),
            ty: d.ty,
            nullable: d.nullable,
            default,
            auto_inc: d.auto_inc,
        });
    }
    // primary key
    let col_pk: Vec<usize> = c
        .cols
        .iter()
        .enumerate()
        .filter(|(_, d)| d.primary)
        .map(|(i, _)| i)
        .collect();
    let pk: Vec<usize> = match (&c.pk, col_pk.len()) {
        (Some(_), n) if n > 0 => return Err(SqlError::multiple_pk()),
        (_, n) if n > 1 => return Err(SqlError::multiple_pk()),
        (Some(names), _) => names
            .iter()
            .map(|n| col_pos(&cols, n))
            .collect::<Result<_>>()?,
        (None, _) => col_pk,
    };
    if pk.iter().collect::<HashSet<_>>().len() != pk.len() {
        return Err(SqlError::dup_column("primary key"));
    }
    for &p in &pk {
        if cols[p].ty.is_lob() {
            return Err(SqlError::blob_key(&cols[p].name));
        }
        cols[p].nullable = false;
    }
    // indexes
    let mut indexes: Vec<Index> = Vec::new();
    let mut next_index_id = 1u32;
    let mut defs: Vec<IndexDef> = c
        .cols
        .iter()
        .filter(|d| d.unique)
        .map(|d| IndexDef {
            name: Some(d.name.clone()),
            cols: vec![d.name.clone()],
            unique: true,
        })
        .collect();
    defs.extend(c.indexes.iter().cloned());
    for d in defs {
        let ic: Vec<usize> = d
            .cols
            .iter()
            .map(|n| col_pos(&cols, n))
            .collect::<Result<_>>()?;
        if ic.iter().collect::<HashSet<_>>().len() != ic.len() {
            return Err(SqlError::dup_column(&d.cols.join(",")));
        }
        for &x in &ic {
            if cols[x].ty.is_lob() {
                return Err(SqlError::blob_key(&cols[x].name));
            }
        }
        let name = match d.name {
            Some(n) => n,
            None => {
                let base = cols[ic[0]].name.clone();
                let mut n = base.clone();
                let mut k = 2;
                while indexes.iter().any(|i| i.name.eq_ignore_ascii_case(&n)) {
                    n = format!("{base}_{k}");
                    k += 1;
                }
                n
            }
        };
        valid_name(&name)?;
        if name.eq_ignore_ascii_case("primary")
            || indexes.iter().any(|i| i.name.eq_ignore_ascii_case(&name))
        {
            return Err(SqlError::dup_key_name(&name));
        }
        indexes.push(Index {
            id: next_index_id,
            name,
            cols: ic,
            unique: d.unique,
        });
        next_index_id += 1;
    }
    if indexes.len() > MAX_INDEXES {
        return Err(SqlError::unsupported("more than 64 indexes"));
    }
    // AUTO_INCREMENT: at most one, and it must lead a key.
    let ai: Vec<usize> = cols
        .iter()
        .enumerate()
        .filter(|(_, x)| x.auto_inc)
        .map(|(i, _)| i)
        .collect();
    if ai.len() > 1 {
        return Err(SqlError::auto_inc());
    }
    if let Some(&a) = ai.first()
        && pk.first() != Some(&a)
        && !indexes.iter().any(|i| i.cols.first() == Some(&a))
    {
        return Err(SqlError::auto_inc());
    }
    Ok(Table {
        id: 0,
        name: c.name.clone(),
        cols,
        pk,
        indexes,
        next_index_id,
    })
}

fn drop_table(mv: &mut Mv<'_, '_>, names: &[String], if_exists: bool) -> Result<QueryResult> {
    let mut missing = Vec::new();
    for n in names {
        match find_table(mv.tx, n)? {
            None => missing.push(n.clone()),
            Some(t) => {
                mv.tx.drop_tree(&t.rows_tree())?;
                mv.tx.drop_tree(&t.overflow_tree())?;
                for ix in &t.indexes {
                    mv.tx.drop_tree(&t.index_tree(ix))?;
                }
                let c = catalog(mv.tx)?;
                mv.tx.delete(&c, &table_key(&t.name))?;
                mv.tx.delete(&c, &counter_key(t.id))?;
                mv.tx.delete(&c, &rowid_key(t.id))?;
            }
        }
    }
    if !missing.is_empty() && !if_exists {
        return Err(SqlError::new_unknown_tables(&missing));
    }
    Ok(QueryResult::ok(0))
}

fn create_index(
    mv: &mut Mv<'_, '_>,
    name: &str,
    table: &str,
    cols: &[String],
    unique: bool,
) -> Result<QueryResult> {
    valid_name(name)?;
    let mut t = load_table(mv.tx, table)?;
    if name.eq_ignore_ascii_case("primary")
        || t.indexes.iter().any(|i| i.name.eq_ignore_ascii_case(name))
    {
        return Err(SqlError::dup_key_name(name));
    }
    if t.indexes.len() >= MAX_INDEXES {
        return Err(SqlError::unsupported("more than 64 indexes"));
    }
    let ic: Vec<usize> = cols
        .iter()
        .map(|n| t.col(n).ok_or_else(|| SqlError::bad_column(n)))
        .collect::<Result<_>>()?;
    if ic.iter().collect::<HashSet<_>>().len() != ic.len() {
        return Err(SqlError::dup_column(&cols.join(",")));
    }
    for &x in &ic {
        if t.cols[x].ty.is_lob() {
            return Err(SqlError::blob_key(&t.cols[x].name));
        }
    }
    let ix = Index {
        id: t.next_index_id,
        name: name.to_string(),
        cols: ic,
        unique,
    };
    t.next_index_id += 1;
    let tree_name = t.index_tree(&ix);
    let itree = mv.tx.create_tree(&tree_name)?;
    // Build from existing rows (unique violations abort the whole statement).
    let base = open_trees(mv.tx, &t)?;
    let one = Table {
        indexes: vec![ix.clone()],
        ..t.clone()
    };
    let tr = Trees {
        rows: base.rows,
        ovf: base.ovf,
        idx: vec![itree],
    };
    let mut rows = Vec::new();
    scan(mv, &t, &tr, &Access::Full, None, 0, |pk, row| {
        rows.push((pk, row));
        if rows.len() > MAX_ROWS_IN_MEMORY {
            return Err(SqlError::resource(
                "table too large to index in one statement",
            ));
        }
        Ok(true)
    })?;
    for (pk, row) in &rows {
        index_insert(mv, &one, &tr, row, pk)?;
    }
    t.indexes.push(ix);
    save_table(mv.tx, &t)?;
    Ok(QueryResult::ok(0))
}

fn drop_index(mv: &mut Mv<'_, '_>, name: &str, table: &str) -> Result<QueryResult> {
    let mut t = load_table(mv.tx, table)?;
    let Some(pos) = t
        .indexes
        .iter()
        .position(|i| i.name.eq_ignore_ascii_case(name))
    else {
        return Err(SqlError::no_key(name));
    };
    let ix = t.indexes.remove(pos);
    if let Some(a) = t.auto_inc_col()
        && t.pk.first() != Some(&a)
        && !t.indexes.iter().any(|i| i.cols.first() == Some(&a))
    {
        return Err(SqlError::auto_inc());
    }
    mv.tx.drop_tree(&t.index_tree(&ix))?;
    save_table(mv.tx, &t)?;
    Ok(QueryResult::ok(0))
}

// ----- DML -----------------------------------------------------------------------------------

/// Store `row` as a new row (PK / unique checks, indexes). Returns the primary key.
fn insert_row(mv: &mut Mv<'_, '_>, t: &Table, tr: &Trees, row: &[Value]) -> Result<Vec<u8>> {
    let pk = if t.pk.is_empty() {
        let id = read_counter(mv.tx, &rowid_key(t.id), 1)?;
        write_counter(mv.tx, &rowid_key(t.id), id + 1)?;
        mv.ws.log.push(LogOp::Counter {
            table: t.name.clone(),
            rowid: true,
            value: id + 1,
        });
        hidden_key(id)?
    } else {
        let k = pk_key(t, row)?;
        if mv.get(&tr.rows, &k)?.is_some() {
            return Err(SqlError::dup_entry(&render_key(&t.pk, row), "PRIMARY"));
        }
        k
    };
    index_insert(mv, t, tr, row, &pk)?;
    put_row(mv, tr, &pk, row)?;
    mv.ws.log.push(LogOp::Put {
        table: t.name.clone(),
        key: pk.clone(),
        row: row.to_vec(),
    });
    Ok(pk)
}

fn finish_row(t: &Table, row: &mut [Value]) -> Result<()> {
    for (i, c) in t.cols.iter().enumerate() {
        if row[i].is_null() && !c.nullable {
            return Err(SqlError::not_null(&c.name));
        }
    }
    Ok(())
}

fn insert(
    mv: &mut Mv<'_, '_>,
    table: &str,
    cols: Option<&[String]>,
    rows: &[Vec<Expr>],
    now: i64,
) -> Result<QueryResult> {
    let t = load_table(mv.tx, table)?;
    let tr = open_trees(mv.tx, &t)?;
    let targets: Vec<usize> = match cols {
        None => (0..t.cols.len()).collect(),
        Some(names) => {
            let mut v = Vec::with_capacity(names.len());
            for n in names {
                let c = t.col(n).ok_or_else(|| SqlError::bad_column(n))?;
                if v.contains(&c) {
                    return Err(SqlError::dup_column(n));
                }
                v.push(c);
            }
            v
        }
    };
    let ai = t.auto_inc_col();
    let mut counter = match ai {
        Some(_) => Some(read_counter(mv.tx, &counter_key(t.id), 1)?),
        None => None,
    };
    let mut first_id = 0u64;
    let mut n = 0u64;
    let env = Env {
        t: None,
        row: &[],
        now,
    };
    for exprs in rows {
        if exprs.len() != targets.len() {
            return Err(SqlError::column_count());
        }
        let mut row = vec![Value::Null; t.cols.len()];
        let mut given = vec![false; t.cols.len()];
        for (e, &c) in exprs.iter().zip(&targets) {
            let v = eval(e, &env)?;
            row[c] = coerce(v, t.cols[c].ty, &t.cols[c].name)?;
            given[c] = true;
        }
        for (i, c) in t.cols.iter().enumerate() {
            if given[i] || c.auto_inc {
                continue;
            }
            row[i] = match &c.default {
                Some(DefaultExpr::Value(v)) => v.clone(),
                Some(DefaultExpr::Now) => Value::DateTime(trunc_fsp(
                    now,
                    match c.ty {
                        ColType::DateTime(f) => f,
                        _ => 0,
                    },
                )),
                None if c.nullable => Value::Null,
                None => return Err(SqlError::no_default(&c.name)),
            };
        }
        if let (Some(a), Some(ctr)) = (ai, counter.as_mut()) {
            let explicit = match &row[a] {
                Value::Int(v) if *v != 0 => Some(*v),
                _ => None,
            };
            match explicit {
                Some(v) => {
                    if v > 0 && (v as u64) >= *ctr {
                        *ctr = (v as u64).saturating_add(1);
                    }
                }
                None => {
                    let id = *ctr;
                    let limit = if t.cols[a].ty == ColType::Int {
                        i32::MAX as u64
                    } else {
                        i64::MAX as u64
                    };
                    if id > limit {
                        return Err(SqlError::out_of_range(&t.cols[a].name));
                    }
                    row[a] = Value::Int(id as i64);
                    *ctr = id + 1;
                    if first_id == 0 {
                        first_id = id;
                    }
                }
            }
        }
        finish_row(&t, &mut row)?;
        insert_row(mv, &t, &tr, &row)?;
        n += 1;
    }
    if let (Some(_), Some(ctr)) = (ai, counter) {
        write_counter(mv.tx, &counter_key(t.id), ctr)?;
        mv.ws.log.push(LogOp::Counter {
            table: t.name.clone(),
            rowid: false,
            value: ctr,
        });
    }
    Ok(QueryResult {
        affected: n,
        last_insert_id: first_id,
        ..Default::default()
    })
}

fn order_rows(
    t: &Table,
    rows: &mut [(Vec<u8>, Vec<Value>)],
    order: &[OrderBy],
    now: i64,
) -> Result<()> {
    if order.is_empty() {
        return Ok(());
    }
    let mut keyed: Vec<(Vec<Value>, usize)> = Vec::with_capacity(rows.len());
    for (i, (_, row)) in rows.iter().enumerate() {
        let env = Env {
            t: Some(t),
            row,
            now,
        };
        keyed.push((
            order
                .iter()
                .map(|o| eval(&o.expr, &env))
                .collect::<Result<_>>()?,
            i,
        ));
    }
    keyed.sort_by(|a, b| cmp_keys(&a.0, &b.0, order));
    let perm: Vec<usize> = keyed.into_iter().map(|(_, i)| i).collect();
    let mut sorted: Vec<(Vec<u8>, Vec<Value>)> =
        perm.iter().map(|&i| std::mem::take(&mut rows[i])).collect();
    rows.swap_with_slice(&mut sorted);
    Ok(())
}

fn cmp_keys(a: &[Value], b: &[Value], order: &[OrderBy]) -> Ordering {
    for (i, o) in order.iter().enumerate() {
        let c = sort_cmp(&a[i], &b[i]);
        let c = if o.desc { c.reverse() } else { c };
        if c != Ordering::Equal {
            return c;
        }
    }
    Ordering::Equal
}

fn collect(
    mv: &mut Mv<'_, '_>,
    t: &Table,
    tr: &Trees,
    filter: Option<&Expr>,
    order: &[OrderBy],
    limit: Option<u64>,
    now: i64,
) -> Result<Vec<(Vec<u8>, Vec<Value>)>> {
    if let Some(f) = filter {
        check_cols(f, Some(t))?;
    }
    for o in order {
        check_cols(&o.expr, Some(t))?;
    }
    let access = plan(t, filter, now);
    let cap = if order.is_empty() {
        limit.map(|l| l as usize)
    } else {
        None
    };
    let mut rows = Vec::new();
    if cap == Some(0) {
        return Ok(rows);
    }
    scan(mv, t, tr, &access, filter, now, |pk, row| {
        rows.push((pk, row));
        if rows.len() > MAX_ROWS_IN_MEMORY {
            return Err(SqlError::resource(
                "statement matches too many rows to process at once; add a LIMIT or a narrower WHERE",
            ));
        }
        Ok(cap.is_none_or(|c| rows.len() < c))
    })?;
    order_rows(t, &mut rows, order, now)?;
    if let Some(l) = limit {
        rows.truncate(l as usize);
    }
    Ok(rows)
}

fn update(
    mv: &mut Mv<'_, '_>,
    table: &str,
    sets: &[(String, Expr)],
    filter: Option<&Expr>,
    order: &[OrderBy],
    limit: Option<u64>,
    now: i64,
) -> Result<QueryResult> {
    let t = load_table(mv.tx, table)?;
    let tr = open_trees(mv.tx, &t)?;
    let mut targets = Vec::with_capacity(sets.len());
    for (c, e) in sets {
        let i = t.col(c).ok_or_else(|| SqlError::bad_column(c))?;
        check_cols(e, Some(&t))?;
        targets.push((i, e));
    }
    let rows = collect(mv, &t, &tr, filter, order, limit, now)?;
    let mut changed = 0u64;
    let matched = rows.len();
    for (pk, old) in rows {
        let mut new = old.clone();
        for &(i, e) in &targets {
            let v = eval(
                e,
                &Env {
                    t: Some(&t),
                    row: &new,
                    now,
                },
            )?;
            new[i] = coerce(v, t.cols[i].ty, &t.cols[i].name)?;
        }
        finish_row(&t, &mut new)?;
        if new == old {
            continue;
        }
        let new_pk = if t.pk.is_empty() {
            pk.clone()
        } else {
            pk_key(&t, &new)?
        };
        index_delete(mv, &t, &tr, &old, &pk)?;
        if new_pk != pk {
            if mv.get(&tr.rows, &new_pk)?.is_some() {
                return Err(SqlError::dup_entry(&render_key(&t.pk, &new), "PRIMARY"));
            }
            del_row(mv, &tr, &pk)?;
            mv.ws.log.push(LogOp::Del {
                table: t.name.clone(),
                key: pk.clone(),
            });
        }
        index_insert(mv, &t, &tr, &new, &new_pk)?;
        put_row(mv, &tr, &new_pk, &new)?;
        mv.ws.log.push(LogOp::Put {
            table: t.name.clone(),
            key: new_pk.clone(),
            row: new.clone(),
        });
        changed += 1;
    }
    Ok(QueryResult {
        affected: changed,
        info: Some(format!(
            "Rows matched: {matched}  Changed: {changed}  Warnings: 0"
        )),
        ..Default::default()
    })
}

fn delete(
    mv: &mut Mv<'_, '_>,
    table: &str,
    filter: Option<&Expr>,
    order: &[OrderBy],
    limit: Option<u64>,
    now: i64,
) -> Result<QueryResult> {
    let t = load_table(mv.tx, table)?;
    let tr = open_trees(mv.tx, &t)?;
    let rows = collect(mv, &t, &tr, filter, order, limit, now)?;
    let n = rows.len() as u64;
    for (pk, row) in rows {
        index_delete(mv, &t, &tr, &row, &pk)?;
        del_row(mv, &tr, &pk)?;
        mv.ws.log.push(LogOp::Del {
            table: t.name.clone(),
            key: pk.clone(),
        });
    }
    Ok(QueryResult::ok(n))
}

// ----- SELECT --------------------------------------------------------------------------------

enum Item<'a> {
    Col(usize),
    Expr(&'a Expr),
}

pub(crate) fn select(mv: &mut Mv<'_, '_>, s: &Select, now: i64) -> Result<QueryResult> {
    let mut owned = s.clone();
    crate::query::materialize_select(mv, &mut owned, now)?;
    if crate::query::needs_general(&owned) {
        return crate::query::select_general(mv, &owned, now);
    }
    if let Some(name) = &owned.from {
        let alias = owned.alias.clone();
        for it in &mut owned.items {
            if let SelectItem::Expr { expr, .. } = it {
                crate::query::strip_qualifiers(expr, name, alias.as_deref())?;
            }
        }
        if let Some(f) = &mut owned.filter {
            crate::query::strip_qualifiers(f, name, alias.as_deref())?;
        }
        for o in &mut owned.order {
            crate::query::strip_qualifiers(&mut o.expr, name, alias.as_deref())?;
        }
    }
    let s = &owned;
    let t = match &s.from {
        Some(name) => Some(load_table(mv.tx, name)?),
        None => None,
    };
    // Resolve select list.
    let mut items: Vec<Item<'_>> = Vec::new();
    let mut columns = Vec::new();
    for it in &s.items {
        match it {
            SelectItem::TableStar(_) => {
                return Err(SqlError::internal("t.* is handled by the join path"));
            }
            SelectItem::Star => {
                let Some(t) = &t else {
                    return Err(SqlError::syntax(0, "*", "SELECT * needs a FROM clause"));
                };
                for (i, c) in t.cols.iter().enumerate() {
                    items.push(Item::Col(i));
                    columns.push(ColumnMeta {
                        name: c.name.clone(),
                        ty: Some(c.ty),
                    });
                }
            }
            SelectItem::Expr { expr, alias, text } => {
                check_cols(expr, t.as_ref())?;
                match (expr, &t) {
                    (Expr::Col(c), Some(t)) => {
                        let i = t.col(c).ok_or_else(|| SqlError::bad_column(c))?;
                        items.push(Item::Col(i));
                        columns.push(ColumnMeta {
                            name: alias.clone().unwrap_or_else(|| t.cols[i].name.clone()),
                            ty: Some(t.cols[i].ty),
                        });
                    }
                    _ => {
                        items.push(Item::Expr(expr));
                        columns.push(ColumnMeta {
                            name: alias.clone().unwrap_or_else(|| text.clone()),
                            ty: None,
                        });
                    }
                }
            }
        }
    }
    // ORDER BY may name a select alias or a 1-based position.
    let order: Vec<OrderBy> = s
        .order
        .iter()
        .map(|o| match &o.expr {
            Expr::Lit(Value::Int(n)) if *n >= 1 && (*n as usize) <= s.items.len() => {
                let idx = *n as usize - 1;
                match s.items.get(idx) {
                    Some(SelectItem::Expr { expr, .. }) => Ok(OrderBy {
                        expr: expr.clone(),
                        desc: o.desc,
                    }),
                    _ => Err(SqlError::unsupported("ORDER BY position of *")),
                }
            }
            Expr::Col(name) if t.as_ref().is_none_or(|t| t.col(name).is_none()) => {
                let hit = s.items.iter().find_map(|it| match it {
                    SelectItem::Expr {
                        expr,
                        alias: Some(a),
                        ..
                    } if a.eq_ignore_ascii_case(name) => Some(expr.clone()),
                    _ => None,
                });
                hit.map(|expr| OrderBy { expr, desc: o.desc })
                    .ok_or_else(|| SqlError::bad_column(name))
            }
            _ => Ok(o.clone()),
        })
        .collect::<Result<_>>()?;

    let project = |row: &[Value], t: Option<&Table>| -> Result<Vec<Value>> {
        let env = Env { t, row, now };
        items
            .iter()
            .map(|it| match it {
                Item::Col(i) => Ok(row.get(*i).cloned().unwrap_or(Value::Null)),
                Item::Expr(e) => eval(e, &env),
            })
            .collect()
    };

    let mut out: Vec<Vec<Value>> = match &t {
        None => {
            if let Some(f) = &s.filter {
                check_cols(f, None)?;
                if !matches(
                    Some(f),
                    &Env {
                        t: None,
                        row: &[],
                        now,
                    },
                )? {
                    return Ok(QueryResult {
                        columns,
                        ..Default::default()
                    });
                }
            }
            vec![project(&[], None)?]
        }
        Some(t) => {
            let tr = open_trees(mv.tx, t)?;
            let need = if s.distinct {
                None
            } else {
                s.limit.map(|l| l.saturating_add(s.offset))
            };
            let rows = collect(mv, t, &tr, s.filter.as_ref(), &order, need, now)?;
            rows.iter()
                .map(|(_, r)| project(r, Some(t)))
                .collect::<Result<_>>()?
        }
    };
    if s.distinct {
        let mut seen: Vec<Vec<Value>> = Vec::new();
        out.retain(|r| {
            let dup = seen.iter().any(|x| {
                x.len() == r.len()
                    && x.iter()
                        .zip(r)
                        .all(|(a, b)| sort_cmp(a, b) == Ordering::Equal)
            });
            if !dup {
                seen.push(r.clone());
            }
            !dup
        });
    }
    let off = usize::try_from(s.offset).unwrap_or(usize::MAX);
    out = out.into_iter().skip(off).collect();
    if let Some(l) = s.limit {
        out.truncate(usize::try_from(l).unwrap_or(usize::MAX));
    }
    Ok(QueryResult {
        columns,
        rows: out,
        ..Default::default()
    })
}

// ----- introspection -------------------------------------------------------------------------

fn meta(names: &[&str]) -> Vec<ColumnMeta> {
    names
        .iter()
        .map(|n| ColumnMeta {
            name: (*n).into(),
            ty: None,
        })
        .collect()
}

fn show_tables(tx: &mut Tx<'_>) -> Result<QueryResult> {
    let c = catalog(tx)?;
    let entries = tx
        .range(
            &c,
            (Bound::Included(&b"t\0"[..]), Bound::Excluded(&b"t\x01"[..])),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let mut rows = Vec::new();
    for (_, v) in entries {
        rows.push(vec![Value::Str(Table::decode(&v)?.name)]);
    }
    Ok(QueryResult {
        columns: meta(&["Tables_in_novadb"]),
        rows,
        ..Default::default()
    })
}

fn describe(tx: &mut Tx<'_>, name: &str) -> Result<QueryResult> {
    let t = load_table(tx, name)?;
    let mut rows = Vec::new();
    for (i, c) in t.cols.iter().enumerate() {
        let key = if t.pk.contains(&i) {
            "PRI"
        } else if t
            .indexes
            .iter()
            .any(|x| x.unique && x.cols.len() == 1 && x.cols[0] == i)
        {
            "UNI"
        } else if t.indexes.iter().any(|x| x.cols.first() == Some(&i)) {
            "MUL"
        } else {
            ""
        };
        let default = match &c.default {
            None => Value::Null,
            Some(DefaultExpr::Now) => Value::Str("CURRENT_TIMESTAMP".into()),
            Some(DefaultExpr::Value(v)) => v.text().map_or(Value::Null, Value::Str),
        };
        rows.push(vec![
            Value::Str(c.name.clone()),
            Value::Str(c.ty.sql()),
            Value::Str(if c.nullable { "YES" } else { "NO" }.into()),
            Value::Str(key.into()),
            default,
            Value::Str(if c.auto_inc { "auto_increment" } else { "" }.into()),
        ]);
    }
    Ok(QueryResult {
        columns: meta(&["Field", "Type", "Null", "Key", "Default", "Extra"]),
        rows,
        ..Default::default()
    })
}

fn quote(n: &str) -> String {
    format!("`{}`", n.replace('`', "``"))
}

fn sql_literal(v: &Value) -> String {
    match v {
        Value::Null => "NULL".into(),
        Value::Int(_) | Value::Dec { .. } => v.text().unwrap_or_default(),
        Value::Bytes(b) => format!(
            "X'{}'",
            b.iter().map(|x| format!("{x:02X}")).collect::<String>()
        ),
        other => format!(
            "'{}'",
            other
                .text()
                .unwrap_or_default()
                .replace('\\', "\\\\")
                .replace('\'', "''")
        ),
    }
}

fn show_create(tx: &mut Tx<'_>, name: &str) -> Result<QueryResult> {
    let t = load_table(tx, name)?;
    let mut lines = Vec::new();
    for c in &t.cols {
        let mut l = format!("  {} {}", quote(&c.name), c.ty.sql());
        if !c.nullable {
            l.push_str(" NOT NULL");
        }
        match &c.default {
            Some(DefaultExpr::Now) => l.push_str(" DEFAULT CURRENT_TIMESTAMP"),
            Some(DefaultExpr::Value(v)) => l.push_str(&format!(" DEFAULT {}", sql_literal(v))),
            None if c.nullable && !c.ty.is_lob() => l.push_str(" DEFAULT NULL"),
            None => {}
        }
        if c.auto_inc {
            l.push_str(" AUTO_INCREMENT");
        }
        lines.push(l);
    }
    let names = |cols: &[usize]| {
        cols.iter()
            .map(|&i| quote(&t.cols[i].name))
            .collect::<Vec<_>>()
            .join(",")
    };
    if !t.pk.is_empty() {
        lines.push(format!("  PRIMARY KEY ({})", names(&t.pk)));
    }
    for ix in &t.indexes {
        lines.push(format!(
            "  {}KEY {} ({})",
            if ix.unique { "UNIQUE " } else { "" },
            quote(&ix.name),
            names(&ix.cols)
        ));
    }
    let ddl = format!(
        "CREATE TABLE {} (\n{}\n) ENGINE=NovaDB",
        quote(&t.name),
        lines.join(",\n")
    );
    Ok(QueryResult {
        columns: meta(&["Table", "Create Table"]),
        rows: vec![vec![Value::Str(t.name.clone()), Value::Str(ddl)]],
        ..Default::default()
    })
}

fn explain(mv: &mut Mv<'_, '_>, s: &Stmt, now: i64) -> Result<QueryResult> {
    let (table, filter) = match s {
        Stmt::Select(sel) => (sel.from.as_deref(), sel.filter.as_ref()),
        Stmt::Update { table, filter, .. } | Stmt::Delete { table, filter, .. } => {
            (Some(table.as_str()), filter.as_ref())
        }
        _ => return Err(SqlError::unsupported("EXPLAIN for this statement")),
    };
    let row = match table {
        None => vec![
            Value::Null,
            Value::Str("No tables used".into()),
            Value::Null,
        ],
        Some(name) => {
            let t = load_table(mv.tx, name)?;
            if let Some(f) = filter {
                check_cols(f, Some(&t))?;
            }
            let (ty, key) = access_desc(&t, &plan(&t, filter, now));
            vec![
                Value::Str(t.name.clone()),
                Value::Str(ty.into()),
                key.map_or(Value::Null, Value::Str),
            ]
        }
    };
    Ok(QueryResult {
        columns: meta(&["table", "type", "key"]),
        rows: vec![row],
        ..Default::default()
    })
}

impl SqlError {
    fn new_unknown_tables(names: &[String]) -> SqlError {
        let mut e = SqlError::no_table(&names.join(","));
        e.code = 1051;
        e.msg = format!("Unknown table '{}'", names.join(","));
        e
    }
}

/// Variables clients may SET. Values are accepted but behaviour stays fixed (strict mode,
/// utf8mb4, autocommit) — see docs/protocol.md.
const SETTABLE: &[&str] = &[
    "autocommit",
    "character_set_client",
    "character_set_connection",
    "character_set_results",
    "collation_connection",
    "names",
    "sql_mode",
    "time_zone",
    "transaction_isolation",
    "tx_isolation",
    "wait_timeout",
    "interactive_timeout",
    "net_read_timeout",
    "net_write_timeout",
    "sql_safe_updates",
    "foreign_key_checks",
    "unique_checks",
    "max_execution_time",
    "sql_auto_is_null",
    "group_concat_max_len",
    "session_track_schema",
    "session_track_state_change",
    "session_track_system_variables",
    "sql_select_limit",
    "sql_notes",
    "sql_quote_show_create",
    "transaction_read_only",
    "tx_read_only",
    "default_storage_engine",
    "lc_messages",
    "innodb_lock_wait_timeout",
];

fn sysvars() -> Vec<(&'static str, Value)> {
    let s = |v: &str| Value::Str(v.to_string());
    let i = Value::Int;
    vec![
        ("auto_increment_increment", i(1)),
        ("auto_increment_offset", i(1)),
        ("autocommit", i(1)),
        ("character_set_client", s("utf8mb4")),
        ("character_set_connection", s("utf8mb4")),
        ("character_set_database", s("utf8mb4")),
        ("character_set_results", s("utf8mb4")),
        ("character_set_server", s("utf8mb4")),
        ("collation_connection", s("utf8mb4_bin")),
        ("collation_database", s("utf8mb4_bin")),
        ("collation_server", s("utf8mb4_bin")),
        ("default_storage_engine", s("NovaDB")),
        ("init_connect", s("")),
        ("interactive_timeout", i(28800)),
        ("license", s("Proprietary")),
        ("lower_case_table_names", i(1)),
        ("max_allowed_packet", i(67_108_864)),
        ("net_buffer_length", i(16384)),
        ("net_write_timeout", i(60)),
        ("performance_schema", i(0)),
        ("port", i(3307)),
        ("protocol_version", i(10)),
        ("query_cache_size", i(0)),
        ("query_cache_type", s("OFF")),
        ("require_secure_transport", s("ON")),
        (
            "sql_mode",
            s("STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO"),
        ),
        (
            "sql_select_limit",
            Value::Dec {
                v: 18_446_744_073_709_551_615,
                s: 0,
            },
        ),
        ("system_time_zone", s("UTC")),
        ("time_zone", s("SYSTEM")),
        ("transaction_isolation", s("REPEATABLE-READ")),
        ("transaction_read_only", i(0)),
        ("tx_isolation", s("REPEATABLE-READ")),
        ("tx_read_only", i(0)),
        (
            "version",
            s(concat!("8.0.0-NovaDB-", env!("CARGO_PKG_VERSION"))),
        ),
        ("version_comment", s("NovaDB")),
        ("version_compile_os", s("Linux")),
        ("wait_timeout", i(28800)),
    ]
}

fn sysvar(name: &str) -> Option<Value> {
    sysvars()
        .into_iter()
        .find(|(n, _)| *n == name)
        .map(|(_, v)| v)
}

fn show_variables(like_pat: Option<&str>, status: bool) -> Result<QueryResult> {
    let mut rows = Vec::new();
    if !status {
        for (n, v) in sysvars() {
            if like_pat.is_none_or(|p| like(n, &p.to_lowercase())) {
                rows.push(vec![
                    Value::Str(n.into()),
                    Value::Str(v.text().unwrap_or_default()),
                ]);
            }
        }
    }
    Ok(QueryResult {
        columns: meta(&["Variable_name", "Value"]),
        rows,
        ..Default::default()
    })
}

// ----- Stage 7: binary log, dumps, replay ----------------------------------------------------

/// Rows of one dump batch and the primary key to continue after.
pub type DumpBatch = (Vec<Vec<Value>>, Option<Vec<u8>>);

impl Engine {
    /// Enable the binary log in `dir` (records newer than the storage's last commit are
    /// trimmed). `key`: optional 32-byte key — records are then encrypted (XChaCha20-Poly1305).
    pub fn with_binlog(mut self, dir: &Path, key: Option<[u8; 32]>) -> Result<Self> {
        let ts = self.last_ts()?;
        self.binlog = Some(Binlog::open(dir, ts, key)?);
        Ok(self)
    }

    /// Last committed timestamp.
    pub fn last_ts(&mut self) -> Result<u64> {
        let mut tx = self.db.begin()?;
        let r = catalog(&mut tx).and_then(|c| mvcc::last_ts(&mut tx, &c));
        tx.rollback();
        r
    }

    /// Call `f` with the logical changes of every durable commit (after it is on disk; for a
    /// transaction with DDL, at its COMMIT). Must be quick and must not call back into the engine.
    pub fn set_change_hook(&mut self, f: ChangeHook) {
        self.hook = Some(f);
    }

    /// Binlog or change hook wants logical records.
    fn logging(&self) -> bool {
        self.binlog.is_some() || self.hook.is_some() || self.capturing
    }

    fn emit(&self, ops: &[LogOp]) {
        if self.deferred.is_none()
            && !ops.is_empty()
            && let Some(h) = &self.hook
        {
            h(ops);
        }
    }

    /// Start a new binlog file (done at every backup).
    pub fn rotate_binlog(&mut self) -> Result<()> {
        match self.binlog.as_mut() {
            Some(b) => b.rotate(),
            None => Ok(()),
        }
    }

    /// Log non-row changes (DDL, users) under a fresh timestamp.
    fn log_now(&mut self, ops: Vec<LogOp>) -> Result<()> {
        if !self.logging() || ops.is_empty() {
            return Ok(());
        }
        let emitted = if self.hook.is_some() {
            ops.clone()
        } else {
            Vec::new()
        };
        let wall = (self.clock)();
        let mut tx = self.db.begin()?;
        let r = (|| {
            let cat = catalog(&mut tx)?;
            let ts = mvcc::last_ts(&mut tx, &cat)? + 1;
            tx.put(&cat, mvcc::TS_KEY, &ts.to_le_bytes())?;
            log_rec(
                &mut self.binlog,
                &mut self.deferred,
                Record {
                    ts,
                    wall_us: wall,
                    ops,
                },
            )?;
            Ok(())
        })();
        match r {
            Ok(()) => {
                tx.commit()?;
                self.emit(&emitted);
                Ok(())
            }
            Err(e) => {
                tx.rollback();
                Err(e)
            }
        }
    }

    /// Re-executable SQL for a DDL statement that just succeeded.
    fn ddl_text(&mut self, s: &Stmt) -> Result<Option<String>> {
        Ok(match s {
            Stmt::CreateTable(c) => {
                let mut tx = self.db.begin()?;
                let r = show_create(&mut tx, &c.name);
                tx.rollback();
                let ddl = r?
                    .rows
                    .first()
                    .and_then(|row| row.get(1))
                    .and_then(Value::text)
                    .unwrap_or_default();
                Some(ddl.replacen("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))
            }
            Stmt::DropTable { names, .. } => Some(format!(
                "DROP TABLE IF EXISTS {}",
                names
                    .iter()
                    .map(|n| quote(n))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            Stmt::CreateIndex {
                name,
                table,
                cols,
                unique,
            } => Some(format!(
                "CREATE {}INDEX {} ON {} ({})",
                if *unique { "UNIQUE " } else { "" },
                quote(name),
                quote(table),
                cols.iter().map(|c| quote(c)).collect::<Vec<_>>().join(", ")
            )),
            Stmt::DropIndex { name, table } => {
                Some(format!("DROP INDEX {} ON {}", quote(name), quote(table)))
            }
            _ => None,
        })
    }

    fn log_after(&mut self, s: &Stmt) -> Result<()> {
        if !self.logging() {
            return Ok(());
        }
        let ops = match s {
            Stmt::CreateUser { name, .. } | Stmt::AlterUser { name, .. } => {
                vec![LogOp::User {
                    name: name.to_lowercase(),
                    hash: self.user_hash(name)?,
                }]
            }
            Stmt::DropUser { names, .. } => names
                .iter()
                .map(|n| LogOp::User {
                    name: n.to_lowercase(),
                    hash: None,
                })
                .collect(),
            _ => match self.ddl_text(s)? {
                Some(sql) => vec![LogOp::Ddl(sql)],
                None => vec![],
            },
        };
        self.log_now(ops)
    }

    /// Begin a consistent dump: registers a snapshot for `conn` (old versions it needs are kept
    /// until `end_session`). Returns the snapshot timestamp.
    pub fn dump_begin(&mut self, conn: u32) -> Result<u64> {
        if self.ddl_owner.is_some() {
            return Err(ddl_busy());
        }
        self.commit_txn(conn)?;
        self.begin_txn(conn)?;
        Ok(self.txns.get(&conn).map_or(0, |t| t.snap))
    }

    /// Tables with their CREATE TABLE text and counters (AUTO_INCREMENT next, row-id next).
    pub fn dump_tables(&mut self) -> Result<Vec<(String, String, u64)>> {
        let mut tx = self.db.begin()?;
        let r = (|| {
            let names: Vec<String> = show_tables(&mut tx)?
                .rows
                .into_iter()
                .filter_map(|r| r.into_iter().next())
                .filter_map(|v| v.text())
                .collect();
            let mut out = Vec::new();
            for n in names {
                let t = load_table(&mut tx, &n)?;
                let ddl = show_create(&mut tx, &n)?
                    .rows
                    .first()
                    .and_then(|row| row.get(1))
                    .and_then(Value::text)
                    .unwrap_or_default();
                let ai = if t.auto_inc_col().is_some() {
                    read_counter(&mut tx, &counter_key(t.id), 1)?
                } else {
                    0
                };
                out.push((t.name.clone(), ddl, ai));
            }
            Ok(out)
        })();
        tx.rollback();
        r
    }

    /// Next batch of rows of `table` at the dump snapshot of `conn`, after primary key `after`.
    pub fn dump_rows(
        &mut self,
        conn: u32,
        table: &str,
        after: Option<&[u8]>,
        n: usize,
    ) -> Result<DumpBatch> {
        let Some(txn) = self.txns.get_mut(&conn) else {
            return Err(SqlError::internal("dump_rows without dump_begin"));
        };
        let mut tx = self.db.begin()?;
        let r = (|| {
            let t = load_table(&mut tx, table)?;
            let tr = open_trees(&mut tx, &t)?;
            let mut ws = WriteSet::default();
            let mut mv = Mv {
                tx: &mut tx,
                snap: txn.snap,
                ws: &mut ws,
            };
            let lo = match after {
                Some(k) => std::ops::Bound::Excluded(k.to_vec()),
                None => std::ops::Bound::Unbounded,
            };
            let b = mv.scan(&tr.rows, &lo, &std::ops::Bound::Unbounded, n)?;
            let last = b.last().map(|(k, _)| k.clone());
            let mut rows = Vec::with_capacity(b.len());
            for (k, stored) in b {
                rows.push(decode_stored(&mut mv, &tr, &k, &stored, t.cols.len())?);
            }
            Ok((rows, last))
        })();
        tx.rollback();
        r
    }

    /// Set a table's AUTO_INCREMENT (or hidden row-id) counter to at least `value`.
    pub fn set_counter(&mut self, table: &str, rowid: bool, value: u64) -> Result<()> {
        if self.ddl_owner.is_some() {
            return Err(ddl_busy());
        }
        let mut tx = self.db.begin()?;
        let r = (|| {
            let t = load_table(&mut tx, table)?;
            let key = if rowid {
                rowid_key(t.id)
            } else {
                counter_key(t.id)
            };
            let cur = read_counter(&mut tx, &key, 1)?;
            if value > cur {
                write_counter(&mut tx, &key, value)?;
            }
            Ok(())
        })();
        match r {
            Ok(()) => Ok(tx.commit()?),
            Err(e) => {
                tx.rollback();
                Err(e)
            }
        }
    }

    /// Apply one binary-log record (point-in-time recovery). Row changes of a record are
    /// applied atomically; constraints were checked when the change was first made.
    pub fn apply_record(&mut self, rec: &Record) -> Result<()> {
        if self.ddl_owner.is_some() {
            return Err(ddl_busy());
        }
        let mut rows: Vec<&LogOp> = Vec::new();
        for op in &rec.ops {
            match op {
                LogOp::Ddl(sql) => {
                    self.execute(sql)?;
                }
                LogOp::User { name, hash } => match hash {
                    Some(h) => self.set_user_hash(name, h)?,
                    None => {
                        let k = name.to_lowercase();
                        self.db.update(|tx| {
                            let t = tx.open_or_create_tree(USERS_TREE)?;
                            tx.delete(&t, k.as_bytes()).map(|_| ())
                        })?;
                    }
                },
                LogOp::Counter {
                    table,
                    rowid,
                    value,
                } => self.set_counter(table, *rowid, *value)?,
                LogOp::Put { .. } | LogOp::Del { .. } => rows.push(op),
            }
        }
        if rows.is_empty() {
            return Ok(());
        }
        let mut tx = self.db.begin()?;
        let r = (|| {
            let cat = catalog(&mut tx)?;
            let snap = mvcc::last_ts(&mut tx, &cat)?;
            let mut ws = WriteSet::default();
            {
                let mut mv = Mv {
                    tx: &mut tx,
                    snap,
                    ws: &mut ws,
                };
                let mut cache: HashMap<String, (Table, Trees)> = HashMap::new();
                for op in rows {
                    let (table, key) = match op {
                        LogOp::Put { table, key, .. } | LogOp::Del { table, key } => (table, key),
                        _ => continue,
                    };
                    if !cache.contains_key(table) {
                        let t = load_table(mv.tx, table)?;
                        let tr = open_trees(mv.tx, &t)?;
                        cache.insert(table.to_string(), (t, tr));
                    }
                    let Some((t, tr)) = cache.get(table) else {
                        continue;
                    };
                    if let Some(old) = get_row(&mut mv, tr, key, t.cols.len())? {
                        index_delete(&mut mv, t, tr, &old, key)?;
                        del_row(&mut mv, tr, key)?;
                    }
                    if let LogOp::Put { row, .. } = op {
                        if row.len() != t.cols.len() {
                            return Err(SqlError::corrupt(
                                "binlog row does not match the table definition",
                            ));
                        }
                        index_insert(&mut mv, t, tr, row, key)?;
                        put_row(&mut mv, tr, key, row)?;
                    }
                }
            }
            mvcc::commit(&mut tx, &cat, &ws, snap, &[], &mut self.pending)?;
            Ok(())
        })();
        match r {
            Ok(()) => Ok(tx.commit()?),
            Err(e) => {
                tx.rollback();
                Err(e)
            }
        }
    }
}

/// SQL literal for a value (dumps).
pub fn sql_value(v: &Value) -> String {
    sql_literal(v)
}

/// Backtick-quoted identifier (dumps).
pub fn sql_ident(n: &str) -> String {
    quote(n)
}

// ----- privileges ------------------------------------------------------------------------

/// Tables read by a SELECT, including its subqueries.
fn select_tables(sel: &Select, out: &mut Vec<String>) {
    if let Some(f) = &sel.from {
        out.push(f.clone());
    }
    for j in &sel.joins {
        out.push(j.table.clone());
    }
    let mut copy = sel.clone();
    let mut subs: Vec<Select> = Vec::new();
    walk_select_mut(&mut copy, &mut |e| match e {
        Expr::Subquery(s) | Expr::Exists { sub: s, .. } | Expr::InSubquery { sub: s, .. } => {
            subs.push((**s).clone())
        }
        _ => {}
    });
    for s in &subs {
        select_tables(s, out);
    }
}

fn expr_subquery_tables(e: &Expr, out: &mut Vec<String>) {
    let mut copy = e.clone();
    let mut subs: Vec<Select> = Vec::new();
    walk_expr_mut(&mut copy, &mut |x| match x {
        Expr::Subquery(s) | Expr::Exists { sub: s, .. } | Expr::InSubquery { sub: s, .. } => {
            subs.push((**s).clone())
        }
        _ => {}
    });
    for s in &subs {
        select_tables(s, out);
    }
}

fn resolve_mask(privs: u64, table: Option<&str>) -> Result<u64> {
    let full = if table.is_some() {
        privs::TABLE_ALL
    } else {
        privs::GLOBAL_ALL
    };
    let m = if privs == u64::MAX { full } else { privs };
    if table.is_some() && m & !privs::TABLE_ALL != 0 {
        let mut e = SqlError::internal(
            "Illegal GRANT/REVOKE command; CREATE USER, PROCESS and SUPER are global (use ON *.*)",
        );
        e.code = 1144;
        e.state = "42000";
        return Err(e);
    }
    Ok(m)
}

fn scope_sql(table: Option<&str>) -> String {
    table.map_or_else(|| "*.*".to_string(), |t| format!("`novadb`.{}", quote(t)))
}

impl Engine {
    /// Enforce GRANTs (the server does; embedded users of the engine are trusted).
    pub fn with_privileges(mut self) -> Self {
        self.enforce = true;
        self
    }

    /// Does `user` hold global privilege `p`? (root: always)
    pub fn has_global(&mut self, user: &str, p: u64) -> Result<bool> {
        Ok(privs::effective(&mut self.db, user, None)? & p != 0)
    }

    /// All grants (user, scope, mask) — backups.
    pub fn grants(&mut self) -> Result<Vec<(String, String, u64)>> {
        privs::all(&mut self.db)
    }

    /// Set a grant directly (restore).
    pub fn set_grant(&mut self, user: &str, scope: &str, mask: u64) -> Result<()> {
        if self.ddl_owner.is_some() {
            return Err(ddl_busy());
        }
        privs::set(
            &mut self.db,
            user,
            if scope == "*" { None } else { Some(scope) },
            mask,
        )
    }

    fn need(&mut self, user: &str, p: u64, table: &str) -> Result<()> {
        if privs::effective(&mut self.db, user, Some(table))? & p == 0 {
            return Err(privs::denied_table(p, user, table));
        }
        Ok(())
    }

    fn need_global(&mut self, user: &str, p: u64) -> Result<()> {
        if privs::effective(&mut self.db, user, None)? & p == 0 {
            return Err(privs::denied_global(p));
        }
        Ok(())
    }

    /// Check that `user` may run `s`.
    fn authorize(&mut self, s: &Stmt, user: &str) -> Result<()> {
        if privs::is_root(user) {
            return Ok(());
        }
        match s {
            Stmt::Select(sel) => {
                let mut ts = Vec::new();
                select_tables(sel, &mut ts);
                for t in ts {
                    self.need(user, privs::SELECT, &t)?;
                }
            }
            Stmt::Explain(inner) => self.authorize(inner, user)?,
            Stmt::Insert {
                table,
                rows,
                select,
                ..
            } => {
                self.need(user, privs::INSERT, table)?;
                let mut ts = Vec::new();
                if let Some(sel) = select {
                    select_tables(sel, &mut ts);
                }
                for r in rows {
                    for e in r {
                        expr_subquery_tables(e, &mut ts);
                    }
                }
                for t in ts {
                    self.need(user, privs::SELECT, &t)?;
                }
            }
            Stmt::Update {
                table,
                sets,
                filter,
                ..
            } => {
                self.need(user, privs::UPDATE, table)?;
                self.need(user, privs::SELECT, table)?;
                let mut ts = Vec::new();
                for (_, e) in sets {
                    expr_subquery_tables(e, &mut ts);
                }
                if let Some(f) = filter {
                    expr_subquery_tables(f, &mut ts);
                }
                for t in ts {
                    self.need(user, privs::SELECT, &t)?;
                }
            }
            Stmt::Delete { table, filter, .. } => {
                self.need(user, privs::DELETE, table)?;
                self.need(user, privs::SELECT, table)?;
                let mut ts = Vec::new();
                if let Some(f) = filter {
                    expr_subquery_tables(f, &mut ts);
                }
                for t in ts {
                    self.need(user, privs::SELECT, &t)?;
                }
            }
            Stmt::CreateTable(c) => self.need(user, privs::CREATE, &c.name)?,
            Stmt::DropTable { names, .. } => {
                for n in names {
                    self.need(user, privs::DROP, n)?;
                }
            }
            Stmt::CreateIndex { table, .. } | Stmt::DropIndex { table, .. } => {
                self.need(user, privs::INDEX, table)?
            }
            Stmt::AlterTable { name, actions } => {
                self.need(user, privs::ALTER, name)?;
                for a in actions {
                    if let AlterAction::RenameTable(n) = a {
                        // like MySQL: the old name goes away, the new one is created
                        self.need(user, privs::DROP, name)?;
                        self.need(user, privs::CREATE, n)?;
                    }
                }
            }
            Stmt::Describe(t) | Stmt::ShowCreateTable(t) => self.need(user, privs::TABLE_ALL, t)?,
            Stmt::CreateUser { .. } | Stmt::DropUser { .. } => {
                self.need_global(user, privs::CREATE_USER)?
            }
            Stmt::AlterUser { name, .. } => {
                if !name.eq_ignore_ascii_case(user) {
                    self.need_global(user, privs::CREATE_USER)?;
                }
            }
            Stmt::Grant {
                privs: p, table, ..
            }
            | Stmt::Revoke {
                privs: p, table, ..
            } => {
                let eff = privs::effective(&mut self.db, user, table.as_deref())?;
                if eff & privs::GRANT_OPTION == 0 {
                    return Err(privs::denied_global(privs::GRANT_OPTION));
                }
                let want = resolve_mask(*p, table.as_deref())?;
                let missing = want & !eff;
                if missing != 0 {
                    // Report the first missing privilege.
                    return Err(privs::denied_global(missing & missing.wrapping_neg()));
                }
            }
            Stmt::ShowGrants(Some(other)) if !other.eq_ignore_ascii_case(user) => {
                self.need_global(user, privs::CREATE_USER)?
            }
            _ => {}
        }
        Ok(())
    }

    fn grant_stmt(&mut self, s: &Stmt, sess_user: &str) -> Result<QueryResult> {
        match s {
            Stmt::Grant {
                privs: p,
                table,
                users,
                grant_option,
            }
            | Stmt::Revoke {
                privs: p,
                table,
                users,
                grant_option,
            } => {
                let granting = matches!(s, Stmt::Grant { .. });
                let t = table.as_deref();
                if let Some(t) = t {
                    let mut tx = self.db.begin()?;
                    let found = find_table(&mut tx, t);
                    tx.rollback();
                    if found?.is_none() {
                        return Err(SqlError::no_table(t));
                    }
                }
                let mut mask = resolve_mask(*p, t)?;
                if *grant_option {
                    mask |= privs::GRANT_OPTION;
                }
                for u in users {
                    if privs::is_root(u) {
                        continue; // root always has everything
                    }
                    if self.user_hash(u)?.is_none() {
                        let mut e = SqlError::internal(format!(
                            "User '{u}' does not exist (CREATE USER first)"
                        ));
                        e.code = 1410;
                        e.state = "42000";
                        return Err(e);
                    }
                    let old = privs::get(&mut self.db, u, t)?;
                    let new = if granting { old | mask } else { old & !mask };
                    privs::set(&mut self.db, u, t, new)?;
                }
                Ok(QueryResult::ok(0))
            }
            Stmt::ShowGrants(who) => {
                let u = who.clone().unwrap_or_else(|| sess_user.to_string());
                let mut rows = Vec::new();
                let all: Vec<(String, String, u64)> = if privs::is_root(&u) {
                    vec![(
                        u.clone(),
                        "*".into(),
                        privs::GLOBAL_ALL | privs::GRANT_OPTION,
                    )]
                } else {
                    privs::all(&mut self.db)?
                        .into_iter()
                        .filter(|(x, _, _)| x.eq_ignore_ascii_case(&u))
                        .collect()
                };
                if !all.iter().any(|(_, s, _)| s == "*") {
                    rows.push(vec![Value::Str(format!("GRANT USAGE ON *.* TO `{u}`@`%`"))]);
                }
                for (_, scope, mask) in all {
                    let global = scope == "*";
                    let line = format!(
                        "GRANT {} ON {} TO `{u}`@`%`{}",
                        privs::names(mask, global),
                        scope_sql(if global { None } else { Some(scope.as_str()) }),
                        if mask & privs::GRANT_OPTION != 0 {
                            " WITH GRANT OPTION"
                        } else {
                            ""
                        }
                    );
                    rows.push(vec![Value::Str(line)]);
                }
                Ok(QueryResult {
                    columns: meta(&[&format!("Grants for {u}@%")]),
                    rows,
                    ..Default::default()
                })
            }
            _ => Err(SqlError::internal("not a grant statement")),
        }
    }

    fn grant_log_text(s: &Stmt) -> Option<String> {
        match s {
            Stmt::Grant {
                privs: p,
                table,
                users,
                grant_option,
            }
            | Stmt::Revoke {
                privs: p,
                table,
                users,
                grant_option,
            } => {
                let granting = matches!(s, Stmt::Grant { .. });
                let global = table.is_none();
                let mut list = if *p == u64::MAX {
                    "ALL PRIVILEGES".to_string()
                } else {
                    privs::names(*p, global)
                };
                if !granting && *grant_option {
                    list = if *p == 0 {
                        "GRANT OPTION".into()
                    } else {
                        format!("{list}, GRANT OPTION")
                    };
                }
                let who = users
                    .iter()
                    .map(|u| quote(u))
                    .collect::<Vec<_>>()
                    .join(", ");
                Some(if granting {
                    format!(
                        "GRANT {list} ON {} TO {who}{}",
                        scope_sql(table.as_deref()),
                        if *grant_option {
                            " WITH GRANT OPTION"
                        } else {
                            ""
                        }
                    )
                } else {
                    format!(
                        "REVOKE {list} ON {} FROM {who}",
                        scope_sql(table.as_deref())
                    )
                })
            }
            _ => None,
        }
    }
}
