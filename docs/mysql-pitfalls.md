# MySQL's known problems — and what NovaDB does about each

Status: **✅ done** (tested) · **🟡 partly / planned with a stage** · **⏳ backlog**.
Requested by the owner on 2026-11-18; keep this list current as stages land.

## Security risks
| MySQL problem | NovaDB | Status |
|---|---|---|
| SQL injection | Server-side prepared statements (binary protocol, values never spliced into SQL); multi-statements only when the client explicitly enables them; tests store `x'); DROP TABLE …` as plain data. Still the application's job to use parameters. | ✅ |
| Overly permissive users (`ALL PRIVILEGES`, `'user'@'%'`) | **Least privilege by default**: a new user can log in and nothing else. `GRANT/REVOKE` per table (SELECT/INSERT/UPDATE/DELETE/CREATE/DROP/INDEX/ALTER) and globally (+ CREATE USER, PROCESS, SUPER), `WITH GRANT OPTION` delegation limited to what the grantor holds, `SHOW GRANTS`; every table a statement touches is checked (joins, subqueries, INSERT … SELECT); `SHOW TABLES` hides tables you can't access; BACKUP needs SUPER; users can change only their own password. `@'%'` is accepted but the server listens on loopback by default. | ✅ |
| Unencrypted connections | TLS 1.2/1.3 is **mandatory**; plaintext clients get `ERROR 3159` before any credential is sent. | ✅ |
| Weak auth plugins (`mysql_native_password`) | Only `caching_sha2_password` full auth over TLS, verified against **Argon2id**; SHA1 plugin never offered (CI check). Rate limits before hashing, no user enumeration. | ✅ |
| Port 3306 exposed to the internet | Default `127.0.0.1:3307`; CI fails on any 3306 default or wildcard bind; per-IP and global connection caps; brute-force limiter. | ✅ |
| `secure_file_priv` file read/write (`LOAD DATA`, `INTO OUTFILE`, `LOAD_FILE`) | Not implemented **by design**; parser refuses them with ERROR 1235; CI check. The only file SQL can create is `BACKUP` into `<data>/backups/` with a validated name. | ✅ |
| `LOCAL INFILE` (rogue server reads client files) | The server never offers `CLIENT_LOCAL_FILES` and never sends a file request (CI check). | ✅ |
| UDFs / plugins → OS code execution | No `CREATE FUNCTION … SONAME`, no `INSTALL PLUGIN`, no dynamic library loading anywhere in the code (CI check); `#![forbid(unsafe_code)]` in every crate. | ✅ |
| Unencrypted backups and binary logs | Backups **and** binary logs are always encrypted (XChaCha20-Poly1305, separate key, tamper/truncation detection). | ✅ |
| Default credentials | None: random one-time root password in a 0600 file; CI check. | ✅ |

## Behaviour / reliability
| MySQL problem | NovaDB | Status |
|---|---|---|
| Lenient defaults (silent truncation, zero dates, fallback values) | Strict mode only, cannot be turned off: too long → 1406, out of range → 1264, bad value → 1366, zero dates rejected, NOT NULL without default → 1364. | ✅ |
| `utf8` = 3 bytes, broken emoji | Only utf8mb4; invalid UTF-8 rejected at the lexer and protocol layer. | ✅ |
| Implicit commit on DDL / no transactional DDL | **Transactional DDL**: `CREATE/DROP TABLE/INDEX` inside `BEGIN` (or with `autocommit = 0`) join the transaction — `ROLLBACK`, a disconnect or a crash undo the schema change *and* the data changes around it; a failing statement undoes only itself. A half-run migration can't leave a half-changed schema. Binlog gets it only on COMMIT. While such a transaction is open, other sessions get 1205 (retry). User/GRANT statements still commit implicitly. See [transactions.md](transactions.md#transactional-ddl). | ✅ |
| Storage-engine fragmentation (MyISAM vs InnoDB) | One engine; every table is transactional and crash-safe. | ✅ |
| Painful schema changes on big tables (`gh-ost`, `pt-osc`) | **Built-in online `ALTER TABLE`**: renames, defaults, DROP INDEX, adding a nullable column, widening are *instant* (catalog only); everything else (drop/reorder columns, type changes, ADD INDEX, NOT NULL) is an *online rebuild* — batches copied into a hidden shadow table, concurrent changes re-applied, then an atomic swap; other sessions keep reading and writing. Interrupted/crashed ALTERs leave the table untouched. See [alter.md](alter.md). | ✅ |
| Concurrency / locking bottlenecks | MVCC snapshot isolation: readers never block, no row locks, no deadlocks, conflicts → 1213 retry. | ✅ |
| Replication lag / stale replicas | **Raft cluster**: a commit is acknowledged only after a majority stored it; failover elects a node that has every acknowledged write; `--linearizable-reads` (ReadIndex) for reads that never miss an acknowledged write. No async replicas, no split brain. See [cluster.md](cluster.md). | ✅ |
| Single-node writes, no sharding | Stage 8 gives a replicated cluster (still one leader). Sharding is a later project. | ⏳ |
| Single-threaded queries | Planned: parallel scans / aggregation. | ⏳ |
| Weak optimizer, manual index hints | Planner never changes results (differential tests); index nested-loop joins. Cost-based join ordering / statistics planned. | 🟡 |
| Weak JSON, no partial indexes, no materialized views, GIS | Backlog: JSON type with path indexes (JSONB-like), partial (filtered) indexes, materialized views. | ⏳ |
| Point-in-time recovery needs care | Built in: encrypted binlog + `--restore … --until`, tested end to end. | ✅ |
