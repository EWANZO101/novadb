# NovaDB — test log

All builds and tests run **inside Docker** (`novadb-builder`, `--cpus 2 --memory 3g`,
`nice -n 19`) from a **fresh `git clone`** using `docker/run-tests.sh`. Nothing is built on the host.
Toolchain: rustc 1.100.0 stable, nightly 2026-11-11 for cargo-fuzz; cargo-deny 0.20.2,
cargo-audit 0.23.0, cargo-nextest 0.9.152.

## 2026-11-18 — Privileges (GRANT / REVOKE, least privilege)
From the owner's MySQL-pitfalls list ([docs/mysql-pitfalls.md](docs/mysql-pitfalls.md)).

| check | result |
|---|---|
| `tests/privs.rs`: new user denied everything (1142/1227), no table names leak, table-level grants, joins/subqueries/INSERT…SELECT all checked, revoke, global ALL, global-only privs refused on tables (1144), DROP USER clears grants, grant to unknown user (1410), own-password change only, GRANT OPTION delegation limited to the grantor's privileges | ✅ 2/2 |
| real server + mariadb client: SELECT denied (1142), BACKUP denied (1227 SUPER), GRANT → allowed, SHOW GRANTS | ✅ |
| Node `mysql2` regression 20/20, transactions 11/11, Stage 6 7/7 | ✅ |
| grants included in backups and the binary log (replayed on restore) | ✅ |

## 2026-11-18 — Stage 7 (operations: backups, binlog, PITR, metrics, packaging)
Details: [docs/operations.md](docs/operations.md), [docs/mysql-pitfalls.md](docs/mysql-pitfalls.md).
New deps: chacha20poly1305, getrandom (RustCrypto / permissive).

| check | result |
|---|---|
| binlog unit tests: round trip, trim records newer than storage, torn tail, rotation, encrypted log (no clear text on disk, wrong/missing key refused) | ✅ |
| backup format test: framing incl. 150 KB item, wrong/missing key, truncation and tampering detected | ✅ |
| `tests/ops.rs`: backup while another session has an open txn → restore + full binlog replay == live DB (tables, rows, indexes, users, counters, DDL, rolled-back txn absent); `--until` == state at that moment; no data in clear in backup/binlog files | ✅ |
| real server: `BACKUP DATABASE TO` online, refuses `../../etc/x` and non-root, files 0600; stop → `--restore … --binlog-dir` → new server answers identically incl. post-backup changes and users | ✅ |
| metrics endpoint: counters for connections/logins/queries/errors, 404 elsewhere | ✅ |
| parser refuses LOAD DATA / LOAD XML / INTO OUTFILE / DUMPFILE / CREATE FUNCTION…SONAME / INSTALL PLUGIN / triggers / procedures (1235); security-check: no LOCAL INFILE capability, no dynamic loading, no LOAD_FILE | ✅ |
| `systemd-analyze verify packaging/novadb.service` | ✅ |
| all earlier suites, clippy | ✅ |

Found while building: metrics counters were defined but never incremented (caught on the live
check); my own test bugs (probe row inserted after capturing the expected state; Docker volume
owned by root) — the engine/server were right.

## 2026-11-18 — Stage 6 (joins, aggregates, subqueries, KILL)
Details: [docs/sql.md](docs/sql.md) (Queries / Aggregates / Subqueries / Planner).

| check | result |
|---|---|
| `tests/query.rs` (5 tests) incl. randomised join-vs-brute-force differential test (120 rounds of INNER/LEFT joins with ON/WHERE variations + grouped HAVING variant) | ✅ |
| all earlier tests (SQL 20+10+8, protocol, server, storage) | ✅ |
| Node `mysql2`: Stage 6 7/7 (prepared LEFT JOIN + GROUP BY, IN-subquery with a parameter, SHOW PROCESSLIST, live KILL QUERY of a running join → 1317, KILL closes the connection, max_execution_time → 3024), transactions 11/11, regression 20/20 | ✅ |
| clippy `-D warnings` workspace | ✅ |

Found while building: an aggregate in WHERE reported "unknown function" (1582) instead of
"Invalid use of group function" (1111); my AVG(DECIMAL) test expectation had the wrong scale
(NovaDB matches MySQL's scale + 4).

Not done: correlated subqueries, UNION, derived tables, window functions, join reordering
(nested loops in FROM order), disk spill for big sorts/joins (1M-row in-memory cap).

## 2026-11-18 — Stage 5 (transactions: MVCC, snapshot isolation)
Details: [docs/transactions.md](docs/transactions.md). No new dependencies.

| check | result |
|---|---|
| all earlier tests on versioned storage (SQL 20 + 10, protocol 9, server 3, storage …) | ✅ |
| `tests/txn.rs` (8 tests) | ✅ |
| randomised SI checker, 12,000 steps × 6 seeds (default, 1, 7, 42, 1337, 987654321) | ✅ |
| Node `mysql2` over TLS: transactions 11/11, regression 20/20 | ✅ |
| clippy `-D warnings` workspace | ✅ |
| fresh-clone suite on Stage 4 commit 8e45a7a | ✅ 20/20 steps |

Bugs found while building (all caught by the tests before commit):
1. Pruning kept every version newer than the oldest snapshot instead of only what each open
   snapshot can see (11 versions instead of 2) — now per-snapshot.
2. The SI checker found that dropping a deletion marker too early hid a write-write conflict
   from an older transaction (an INSERT that should have got 1213 succeeded). The newest version
   now stays until no open snapshot predates it.
3. The checker flagged an "unexpected" 1213 that turned out to be correct: a transaction that
   had already lost the race on a row was told early (via an index entry the winner committed)
   instead of at COMMIT. The model now accepts early detection for doomed transactions.

Not done in this stage: SERIALIZABLE (write skew possible), SELECT … FOR UPDATE, savepoints,
group commit, idle-in-transaction timeout.

## 2026-11-18 — Stage 4 (MySQL wire protocol over TLS)
Details: [docs/protocol.md](docs/protocol.md). New deps: tokio, tokio-rustls/rustls (ring), rcgen, argon2.

| check | result |
|---|---|
| unit tests (protocol 9, server 3, SQL 20 + 10 integration) | ✅ |
| clippy `-D warnings`, cargo-deny, cargo-audit (175 crates) | ✅ |
| security-check (new: no `mysql_native_password`, no wildcard bind) | ✅ |
| `mariadb` CLI over TLS: sysvars, DDL/DML, LAST_INSERT_ID, DATETIME(3), errors 1146/1062 | ✅ |
| Node `mysql2` 3.11: 20 checks (prepared + binary rows, DECIMAL/DATETIME/BLOB/UTF-8/NULL, multi-statements, CREATE USER + login, weak/wrong password, plaintext refused) | ✅ 20/20 |
| `scripts/protocol-abuse.py`: >64 KiB pre-auth packet, garbage, 10 s handshake timeout, 33-connection flood → 1040, brute force → 1129 | ✅ 7/7 |
| `scripts/wire-test.sh` in the builder image | ✅ 15 checks |
| fuzz `protocol_decode` 60 s | ✅ 896,860 runs, no crash |

Bugs found while building: OK-packet info string must be length-prefixed (MariaDB client said
"malformed packet" on UPDATE); two security-check hits (a doc comment naming the wildcard
address, a test using the SHA1 plugin name) — fixed by rewording, rules left strict.

Known limits: no privileges yet (every user is all-powerful), no `information_schema` (GUI tools),
ROLLBACK errors until Stage 5, one database (`novadb`).

## 2026-11-18 — Stage 3 (single-node SQL)
Details: [docs/sql.md](docs/sql.md). Hand-written lexer/parser/executor, no new dependencies.

| check | result |
|---|---|
| `novadb-sql` unit tests | ✅ 19/19 (lexer, parser incl. depth bombs, decimal/datetime maths, LIKE, key-order properties, row + catalog codecs incl. every truncation) |
| `tests/sql.rs` | ✅ 10/10 incl. randomised index-vs-full-scan differential test (600 rounds, identical results) |
| doc-test | ✅ |
| clippy `-D warnings` workspace | ✅ |
| fuzz `sql_parse` 60 s | ✅ 1,032,469 runs, no crash |
| fuzz `sql_exec` 90 s | ✅ 5,652 runs, no crash, storage verify ok after every run |
| CLI `novadb DIR sql` / `shell` smoke run | ✅ |

Bugs found while building: `INSERT … () VALUES ()` not parsed; DATETIME results ignored the
column's fractional precision (now rendered from column metadata); EXPLAIN labels aligned with
MySQL (`const`/`ref`/`range`/`ALL`). All fixed before commit.

Known limits (later stages): no joins/aggregates/subqueries (6), no BEGIN/COMMIT/MVCC (5), sort
and UPDATE/DELETE sets capped at 1M rows in memory, binary collation, no network server (4).

## 2026-11-18 — Stage 9 (control dashboard + identity), started early
Built at the owner's request ahead of Stages 3–8. Details: [docs/dashboard.md](docs/dashboard.md).

| check | result |
|---|---|
| `cargo test -p novadb-dashboard` | ✅ 14/14 (TOTP RFC 6238 vectors + replay, PKCE RFC 7636, Argon2id params, policy, limiter, escaping, audit tamper/delete detection, persistence, OAuth state single-use) |
| clippy `-D warnings` (all targets) | ✅ (`result_large_err` allowed in `web.rs` only: axum `Result<Response, Response>` handlers) |
| cargo-deny / cargo-audit | ✅ advisories, bans, licences, sources ok (warnings: duplicate `base64`, `windows-sys`) |
| `scripts/dashboard-e2e.py` on a throwaway container | ✅ 37/37 |
| one-time admin password file | ✅ 0600, deleted after first password change |
| Pre-existing Stage 1+2 suite (fresh clone, commit df1b48b, FUZZ_SECS=60) | ✅ 15/15 |

Bugs found while building: wrong expected value in my own PKCE test (code was right; vector re-checked with openssl).
Bug found live: `Referrer-Policy: no-referrer` makes browsers send `Origin: null` on form POSTs, so the Origin check blocked every real login ("Cross-site request blocked"). Fixed: policy `same-origin`; `Origin: null` accepted only with `Sec-Fetch-Site: same-origin`. e2e now sends browser-style headers (4 new checks).

Open: passkeys/WebAuthn, recovery codes, OAuth live test needs Discord/GitHub app credentials,
per-database permissions (Stage 3+), REST tokens (Stage 10).

## 2026-11-16 — Stage 1 + Stage 2 (storage engine)

### What was built
* **Stage 1:** cargo workspace (`novadb-storage`, `-sql`, `-protocol`, `-server`, `-cli`),
  `unsafe_code = "forbid"` in **every** crate (the plan allowed an exception for storage; it
  wasn't needed), clippy `-D warnings` (incl. `unwrap_used`/`expect_used`/`panic` outside tests),
  `deny.toml` (permissive licences, crates.io only, yanked = deny), pinned `Cargo.lock`, CI
  workflow (in `ci/` — see Open items), `scripts/security-check.sh`.
* **Stage 2:** storage engine without third-party dependencies. It has CRC-32C pages with a
  self-id and owner id, a pager, and a CLOCK buffer pool with a hard cap and no-steal pinning.
  The B+Tree supports split, merge and rebalance with stable root ids. Writes go through a
  redo WAL (full-page images plus deltas, salted, database-id bound). On top of that are crash
  recovery, checkpoints, fsync-failure poisoning, a catalog of named trees with lazy drop, and
  `Db::verify()`. Design: [docs/storage.md](docs/storage.md).

### Final run (fresh clone in container)
Commit `c3f7204`, run 2026-11-16T08:24:41Z, `FUZZ_SECS=180`:

- ✅ fmt
- ✅ build
- ✅ clippy
- ✅ tests
- ✅ tests (release)
- ✅ doctest
- ✅ audit
- ✅ deny
- ✅ security-check
- ✅ fuzz:btree_model (180s)
- ✅ fuzz:db_corrupt_open (180s)
- ✅ fuzz:node_decode (180s)
- ✅ fuzz:wal_replay (180s)
- ✅ fuzz:wal_scan_raw (180s)
- ✅ crash-recovery

Result: **all 15 steps passed.**

Earlier full runs on 5a3365d (fuzz 120 s/target) and 8eaf1fa (fuzz 180 s/target) were also
all green.

### What the tests cover
| suite | what |
|---|---|
| unit (23) | CRC-32C vectors, page checksum/flip detection, WAL header/record/delta encode+bounds, torn-tail scan, salt/LSN rejection, huge-length no-alloc, B+Tree vs `BTreeMap` (random, sequential, reverse, max-size entries, mixed key lengths), delete-induced parent split, cycle + shared-child detection, SimVfs semantics, path traversal, locking |
| `tests/db.rs` (20) | durability across reopen, rollback incl. allocations, `TxnTooLarge`, size limits, range bounds vs `BTreeMap`, drop + stale handles, small cache with checkpoints, flock + 0600/0700 perms, every-page corruption reported (no panic), torn data pages repaired from WAL, truncated WAL = exact commit prefix, missing data/WAL detection, foreign-WAL rejection, fsync failure poisons the handle, large drop with 32-page cache, drop atomic under power loss, checkpointed-WAL-without-data refused, handle/instance binding, corrupt dropped tree errors instead of hanging |
| `tests/crash_sim.rs` | **power-loss simulation**: 40 seeds × 12 rounds (CI). Each round cuts power at a random I/O op, keeps a random subset of un-synced writes, tears writes at 512 B granularity, drops un-synced directory entries, sometimes crashes recovery itself. Checks state == last acked commit (or the in-flight one) and `verify()`. Also ran **300 seeds** in release: pass |
| `scripts/crash-test.sh` | real filesystem, `kill -9` at random times, 40 cycles: every acknowledged commit present (durability) + state equals exact model of txn N (atomicity) + `verify()` |
| fuzz (5 targets) | `node_decode` (round-trip), `wal_scan_raw`, `wal_replay` (structure-aware, CRC-valid records → semantic checks + open + verify + writes), `db_corrupt_open` (mutated + re-sealed data files), `btree_model` (differential vs `BTreeMap` with rollback/checkpoint/reopen/power-loss). No crashes found |

**Mutation check of the test harness:** I deliberately broke durability four ways: removed
the WAL fsync, removed the data fsync at checkpoint, replayed an uncommitted tail, and wrote a
delta without its base image. The suites caught all four.

### Bugs found and fixed during this run
Found by an independent review pass (a second agent reading the code without my notes), then
by a re-review of the fixes. Every fix has a regression test.

| # | severity | issue | fix |
|---|---|---|---|
| 1 | high (§4.7) | `drop_tree` walk had no visited set → exponential time/memory on a corrupt "DAG" tree | visited set → `Corruption` |
| 2 | high (§4.7/4.16) | reclaiming a corrupt dropped tree looped forever (on every open) | unreachable key → `Corruption`, bounded steps |
| 3 | medium | delete-rebalance can lengthen a separator so the parent overflows → spurious error | parent split propagates upward like insert |
| 4 | medium | data file lost after a checkpoint → database silently recreated empty | re-create only for a never-used WAL |
| 5 | medium | trees larger than the cache couldn't be dropped (`TxnTooLarge`) | atomic rename + lazy bounded reclamation |
| 6 | medium (robustness) | a WAL from another database could be replayed into this data file | random db id in meta page + WAL header |
| 7 | low | hostile `page_count`/page ids → 512 MiB verify bitmap / 64 TiB sparse file | `MAX_PAGE_ID` = 2^28−1 (4 TiB) |
| 8 | low | db-id check could use an uncommitted meta image | committed images only |
| 9 | low | tree ids reusable after rollback; handles usable across `Db` instances | id floor + per-instance handle id |
| 10 | low (§4.12) | `verify` I/O errors didn't poison | runs under the poisoning wrapper |
| 11 | low | hostile WAL `start_lsn`/`next_tree_id` near `u64::MAX` → overflow panic | headroom checks (2^62) |
| 12 | low | checkpoint failure after a durable commit was reported as a failed commit | commit Ok + handle poisoned |

### Security review vs PLAN.md §4 (storage-relevant items)
| § | status |
|---|---|
| 4.1 admin/admin | n/a yet (no auth). `security-check.sh` fails the build on default credentials |
| 4.2/4.3 encryption, page swap/rollback | **not implemented** (Stage 7+). Headers already carry page id + LSN + owner for future AAD; WAL is bound to the db id. CRC is not a MAC: someone with write access to the files can forge pages/WAL |
| 4.4 auth | n/a yet. Check script forbids `mysql_native_password`/SHA1 |
| 4.6 pre-auth limits | n/a yet. Constants fixed in `novadb-protocol` (64 KiB pre-auth packet, 10 s handshake, default listen 127.0.0.1:3307, never 3306) |
| 4.7 memory | ✅ buffer pool hard cap, per-txn pin cap, length checked before allocation in WAL scan, streaming recovery, depth and leaf-chain limits, bounded reclamation, 4 TiB max |
| 4.12 fsync | ✅ any fsync/write error poisons the handle (tested with injected EIO); no retry; reopen = recovery. Directory fsync after create/rename. (Windows `FILE_FLAG_WRITE_THROUGH` not done; Linux only tested) |
| 4.15 supply chain | ✅ cargo-deny + cargo-audit pass; lockfile pinned; zero third-party runtime deps (fuzz crate: libfuzzer-sys only) |
| 4.16 fuzzing | ✅ page decoder + WAL replay + corrupt DB + model fuzzing; malformed input → `Error::Corruption`, no panics found |
| 4.18 secrets/logs | ✅ engine does no logging. Data dir 0700, files 0600 |
| other | ✅ exclusive `flock` per database dir; file names validated (no path traversal) |

### Open items / risks
* **CI not active on GitHub:** the bot's token has no `workflow` scope, so the workflow is at
  `ci/github-actions-ci.yml`. Move it to `.github/workflows/` (see `ci/README.md`).
* No encryption at rest / MAC yet (see 4.2/4.3 above).
* `kill -9` keeps the OS page cache. True power loss is only simulated (SimVfs); it has not been
  tested on real hardware or with dm-flakey.
* Single writer (`&mut Db`); concurrency/MVCC is Stage 5. No performance numbers yet.
* Values ≤ 4 KiB and keys ≤ 1 KiB (overflow pages are needed for BLOB/TEXT in Stage 3).
  Max 4 TiB per database.
* Dropped-tree reclamation deletes key by key (correct but slow for huge trees).
* Fuzzing so far is smoke-level (≈ 2–3 min per target per run); a longer campaign is still to do.
