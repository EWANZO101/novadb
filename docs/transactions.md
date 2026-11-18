# Transactions (Stage 5) — MVCC with snapshot isolation

Module: `crates/novadb-sql/src/mvcc.rs`, transaction manager in `exec.rs` (`Engine::run_in`).

## What you get
* `BEGIN` / `START TRANSACTION`, `COMMIT`, `ROLLBACK`, and `SET autocommit = 0|1` (with
  autocommit off, the first statement opens a transaction implicitly; `SET autocommit = 1`
  commits). Disconnecting rolls back.
* **Snapshot isolation** (MySQL calls the level REPEATABLE READ): a transaction sees the database
  as of its start plus its own changes — no dirty reads, no non-repeatable reads, no phantoms,
  also through secondary indexes.
* **Readers never block and are never blocked.** There are no row locks, so there are no
  deadlocks and no lock waits.
* **First committer wins:** if another transaction committed a change to a row you also change,
  you get `ERROR 1213 (40001) Deadlock found … try restarting transaction` — the code drivers and
  ORMs already retry on. It is raised as early as possible (on the write, if the other commit
  already happened; otherwise at `COMMIT`) and rolls back the whole transaction, like InnoDB.
* Unique keys are safe under concurrency: two transactions inserting the same unique value write
  the same index key, so the second committer gets 1213 (on retry: 1062 duplicate).
* Statements stay atomic inside a transaction: a failing statement is undone, earlier statements
  of the transaction are kept.
* Commits are atomic and durable (one storage transaction, WAL fsync). Uncommitted changes never
  reach disk, so a crash can only lose transactions that had not committed.
* The server reports `SERVER_STATUS_IN_TRANS` / `SERVER_STATUS_AUTOCOMMIT` in OK packets.

## How it works
* Every row, index entry and overflow chunk is stored with an 8-byte commit-timestamp suffix,
  newest first: `logical key ‖ !commit_ts`. The value says live or deleted.
* A transaction has a snapshot timestamp and a private write set. Reads take the newest version
  ≤ snapshot, overlaid with the write set (point lookups and ordered range scans merge both).
* `COMMIT` checks every written key for a committed version newer than the snapshot, then writes
  all versions at a new timestamp and bumps the counter — in one storage transaction.
* **Pruning**: after a commit, each written key keeps only the newest version plus, for every
  open snapshot, the version that snapshot sees. A deletion marker is removed once no snapshot
  needs it (including for conflict detection). Keys kept for a long-running snapshot are queued and
  re-pruned after later commits.
* AUTO_INCREMENT values are handed out immediately and never reused, even if the transaction
  rolls back (same as InnoDB).
* DDL (`CREATE/DROP TABLE/INDEX`) inside a transaction is **transactional** (next section).
  Outside a transaction it is its own transaction. User statements (`CREATE/ALTER/DROP USER`,
  `GRANT`, `REVOKE`) implicitly commit the session's transaction, like MySQL.
  While **another** session has an open transaction, DDL fails with `ERROR 1205 Lock wait timeout
  exceeded` instead of pulling tables out from under it — retry after it commits.

## Transactional DDL
```sql
BEGIN;
CREATE TABLE orders (id INT PRIMARY KEY AUTO_INCREMENT, acct INT, total INT);
CREATE INDEX ix_acct ON orders (acct);
INSERT INTO orders (acct, total) SELECT id, 0 FROM acct;
DROP TABLE old_orders;
COMMIT;          -- or ROLLBACK: everything above, schema and data, is undone
```
* Works after `BEGIN`/`START TRANSACTION` and with `autocommit = 0`. Changes made earlier in the
  same transaction become part of it.
* `ROLLBACK`, disconnecting, `KILL` and a crash discard all of it; `COMMIT` makes all of it durable
  with one WAL commit. A failing statement undoes only itself and the transaction continues.
* `BEGIN` and `SET autocommit = 1` commit it (like any transaction); user/GRANT statements too.
* The binlog receives the transaction's records only at `COMMIT`, so point-in-time recovery never
  replays a rolled-back migration.
* **Exclusive while open**: the first DDL statement waits for no one — it needs every other
  session to be outside a transaction (else 1205) — and from then until COMMIT/ROLLBACK every
  other session's statements get `ERROR 1205` (retry). Keep migration transactions short.
* Size: all pages it changes stay in the buffer pool until COMMIT, so a very large migration (e.g.
  an index over a big table) fails with `ERROR 1038 out of memory` (the transaction stays open; roll
  back). Run such statements outside a transaction, or raise the cache size.
* How: the storage engine has an *outer transaction* (`Db::begin_outer`): statement-level storage
  transactions nest inside it — a nested commit only hands its page before-images to the outer
  one (no WAL write, pages stay pinned = no-steal), a nested rollback restores just its own pages.
  `commit_outer` writes all changed pages to the WAL in one commit; checkpoints are refused while
  it is open, so nothing uncommitted can reach the data file.

## Not (yet) provided
* SERIALIZABLE: snapshot isolation allows *write skew* (two transactions each read what the other
  writes and both commit). Use a write to a shared row to serialise such cases.
* `SELECT … FOR UPDATE` / `LOCK IN SHARE MODE`, savepoints, `READ COMMITTED`.
* Group commit: commits are serialised and each one fsyncs (fine for a single node; batching is
  planned with the ops/replication work).
* Transactions larger than 256 MiB of changes are refused (`ERROR 1038`).
* A transaction left open for hours keeps old versions alive and blocks DDL; there is no idle-in-
  transaction timeout yet (connections themselves close after 8 h idle).

## Tests
* `tests/ddl_txn.rs`: rollback of CREATE/DROP TABLE/INDEX together with data; atomic + durable
  commit (survives a crash right after); failing statements inside; crash mid-migration leaves
  nothing; other sessions get 1205 and disconnect rolls back; autocommit=0 and implicit commits;
  binlog has only committed changes and replaying it reproduces the database.
* `novadb-storage/tests/db.rs` `outer_txn_*`: nested commit/rollback, dropped/new trees, crash with
  an open outer transaction, no checkpoint while open, overflowing the cache fails cleanly.
* `tests/txn.rs`: commit/rollback + durability across reopen; dirty/non-repeatable/phantom reads
  prevented (also via indexes); read-your-own-writes through unique and secondary indexes;
  statement-level undo; lost update and concurrent unique inserts → 1213; DDL inside transactions and
  1205; autocommit=0; disconnect rollback; version pruning with and without open snapshots.
* **Randomised snapshot-isolation checker**: 4 sessions, 12,000 interleaved steps of random
  reads (full scan, point, index), inserts, updates, deletes, commits and rollbacks, checked
  against a model (snapshot + own writes, first-committer-wins). Every read must match, every
  1213 must be justified, every commit that should conflict must. Run with extra seeds via
  `NOVADB_SEED=<n>` (seeds 1, 7, 42, 1337, 987654321 pass).
* All earlier SQL tests (incl. the index-vs-full-scan differential test) run on the versioned
  storage unchanged.
* Over the wire with Node `mysql2`: 11 checks (two connections, rollback, 1213/40001, repeatable
  read, disconnect rollback, autocommit=0).
