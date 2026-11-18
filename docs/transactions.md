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
* DDL (`CREATE/DROP TABLE/INDEX`, user statements) implicitly commits the session's transaction.
  While **another** session has an open transaction, DDL fails with `ERROR 1205 Lock wait timeout
  exceeded` instead of pulling tables out from under it — retry after it commits.

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
* `tests/txn.rs`: commit/rollback + durability across reopen; dirty/non-repeatable/phantom reads
  prevented (also via indexes); read-your-own-writes through unique and secondary indexes;
  statement-level undo; lost update and concurrent unique inserts → 1213; DDL implicit commit and
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
