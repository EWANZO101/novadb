//! Cluster replication hooks (Stage 8).
//!
//! Every durable change on every node comes from applying a committed Raft entry:
//! * the leader runs a statement with [`Engine::capture`]: it executes normally inside a storage
//!   outer transaction, collects the logical changes it would commit (the same records the binlog
//!   gets), and rolls everything back; the result (rows, affected, last insert id, errors) is
//!   what the client will get if the entry commits;
//! * the records are replicated; every node (the leader too) applies them with
//!   [`Engine::apply_cluster`], atomically together with the Raft index (`raft\0applied`), so
//!   a crash never applies an entry twice or half.
//!
//! The leader serialises writes and applies each entry before capturing the next, so the MVCC
//! first-committer-wins check done during capture sees every earlier commit. Apply is
//! deterministic: an entry that fails (e.g. a unique violation) fails on every node and changes
//! nothing.

use super::*;

const APPLIED_KEY: &[u8] = b"raft\0applied";

/// Result of [`Engine::capture`].
#[derive(Debug, Default)]
pub struct Captured {
    pub result: QueryResult,
    /// Logical changes to replicate (empty: nothing to commit, e.g. a SELECT).
    pub records: Vec<Record>,
}

/// Statements that run inside an open transaction without committing it.
fn non_committing(s: &Stmt) -> bool {
    matches!(
        s,
        Stmt::Select(_) | Stmt::Insert { .. } | Stmt::Update { .. } | Stmt::Delete { .. }
    )
}

impl Engine {
    /// Run `s` for `sess` without making anything durable; return its result and the changes
    /// it would commit. Statements inside an open transaction (that don't end it) run normally:
    /// their effects stay in the transaction until COMMIT, which is then captured.
    pub fn capture(&mut self, s: &Stmt, sess: &mut Session) -> Result<Captured> {
        let st = self.status(sess.conn_id);
        let in_txn = st & 1 == 1 || st & 2 == 0;
        if in_txn && non_committing(s) {
            let result = self.run_in(s, sess)?;
            return Ok(Captured {
                result,
                records: Vec::new(),
            });
        }
        if self.ddl_owner.is_some() || self.db.in_outer() {
            return Err(SqlError::internal(
                "capture: an outer transaction is already open",
            ));
        }
        if matches!(
            s,
            Stmt::CreateTable(_)
                | Stmt::DropTable { .. }
                | Stmt::CreateIndex { .. }
                | Stmt::DropIndex { .. }
                | Stmt::AlterTable { .. }
        ) && in_txn
        {
            // DDL implicitly commits in cluster mode (transactional DDL is single-node only).
            let commit = Stmt::Txn(TxnKind::Commit);
            let first = self.capture(&commit, sess)?;
            if !first.records.is_empty() {
                return Err(SqlError::unsupported(
                    "DDL inside a transaction with uncommitted changes in cluster mode (COMMIT first)",
                ));
            }
        }
        self.db.begin_outer()?;
        self.deferred = Some(Vec::new());
        self.capturing = true;
        let r = self.run_in(s, sess);
        self.capturing = false;
        let records = self.deferred.take().unwrap_or_default();
        self.db.rollback_outer();
        self.pending.clear();
        let result = r?;
        Ok(Captured {
            result,
            records: records.into_iter().filter(|r| !r.ops.is_empty()).collect(),
        })
    }

    /// Raft index of the last applied cluster entry (durable).
    pub fn cluster_applied(&mut self) -> Result<u64> {
        let mut tx = self.db.begin()?;
        let r = (|| {
            match tx.open_tree(CATALOG_TREE) {
                Ok(_) => {}
                Err(novadb_storage::Error::TreeNotFound(_)) => return Ok(0),
                Err(e) => return Err(e.into()),
            }
            read_counter(&mut tx, APPLIED_KEY, 0)
        })();
        tx.rollback();
        r
    }

    /// Apply a committed cluster entry at Raft index `index`. All of it or nothing; the index
    /// advances either way (a failed entry fails on every node). Returns the entry's error.
    pub fn apply_cluster(
        &mut self,
        recs: &[Record],
        index: u64,
    ) -> Result<std::result::Result<(), SqlError>> {
        if index <= self.cluster_applied()? {
            return Ok(Ok(())); // already applied (replay after a crash)
        }
        if self.ddl_owner.is_some() || self.db.in_outer() || self.alter.is_some() {
            return Err(SqlError::internal(
                "apply: engine busy with a local schema change",
            ));
        }
        self.db.begin_outer()?;
        self.applying = true;
        // swallow the records DDL statements log while being re-executed
        self.deferred = Some(Vec::new());
        let r = (|| {
            for rec in recs {
                self.apply_one(rec)?;
            }
            Ok(())
        })();
        self.applying = false;
        self.deferred = None;
        let outcome = match r {
            Ok(()) => {
                self.set_applied(index)?;
                self.db.commit_outer()?;
                for rec in recs {
                    self.emit(&rec.ops);
                }
                Ok(())
            }
            Err(e) => {
                self.db.rollback_outer();
                self.set_applied(index)?;
                Err(e)
            }
        };
        self.pending.clear();
        Ok(outcome)
    }

    fn set_applied(&mut self, index: u64) -> Result<()> {
        let mut tx = self.db.begin()?;
        let r = (|| {
            let c = tx.open_or_create_tree(CATALOG_TREE)?;
            tx.put(&c, APPLIED_KEY, &index.to_le_bytes())?;
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

    fn apply_one(&mut self, rec: &Record) -> Result<()> {
        let mut rows: Vec<&LogOp> = Vec::new();
        for op in &rec.ops {
            match op {
                LogOp::Ddl(sql) => {
                    for st in parse(sql)? {
                        let mut s = Session {
                            user: "root".into(),
                            ..Session::default()
                        };
                        self.run_in(&st, &mut s)?;
                    }
                }
                LogOp::User { name, hash } => match hash {
                    Some(h) => self.set_user_hash(name, h)?,
                    None => {
                        let k = name.to_lowercase();
                        self.db.update(|tx| {
                            let t = tx.open_or_create_tree(USERS_TREE)?;
                            tx.delete(&t, k.as_bytes()).map(|_| ())
                        })?;
                        privs::drop_user(&mut self.db, name)?;
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
        let snaps: Vec<u64> = self.txns.values().map(|t| t.snap).collect();
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
                    let lk = table.to_lowercase();
                    if !cache.contains_key(&lk) {
                        let t = load_table(mv.tx, table)?;
                        let tr = open_trees(mv.tx, &t)?;
                        cache.insert(lk.clone(), (t, tr));
                    }
                    let Some((t, tr)) = cache.get(&lk) else {
                        continue;
                    };
                    if let Some(old) = get_row(&mut mv, tr, key, t.cols.len())? {
                        index_delete(&mut mv, t, tr, &old, key)?;
                        del_row(&mut mv, tr, key)?;
                    }
                    if let LogOp::Put { row, .. } = op {
                        if row.len() != t.cols.len() {
                            return Err(SqlError::corrupt(
                                "replicated row does not match the table definition",
                            ));
                        }
                        index_insert(&mut mv, t, tr, row, key)?;
                        put_row(&mut mv, tr, key, row)?;
                    }
                }
            }
            mvcc::commit(&mut tx, &cat, &ws, snap, &snaps, &mut self.pending)?;
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
