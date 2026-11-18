# NovaDB — Build Plan (based on Master Spec v0.2)
Status (2026-11-18): Stages 1–7 done, Stage 9 dashboard in progress (live), privileges + transactional DDL done; next
online `ALTER TABLE`, then Stage 8. Current state: [README.md](README.md), results: [TESTING.md](TESTING.md).
Location: this GitHub repo only (nothing kept on the server, see §6).

## 0. Reality check
The spec is many person-years (an engine + Raft cluster + identity provider + cloud + website).
We build it in thin vertical stages; each stage ends with something runnable and tested.
No "MySQL compatible" / "high availability" / "fast" claims until the matching test suites pass (spec §5, §19).

## 1. Host constraints (this VPS)
- 6 vCPU / 16 GB RAM (upgraded from 4 / 7 GB, 2026-11-16), shared with FiveM + MariaDB + panel. Rust builds and benchmarks will steal CPU from the game server.
  -> all builds/tests run in the `novadb-builder` Docker image capped at 2 CPU / 3 GB with `nice -n 19` (docker/README.md).
- Port 3306 is MariaDB's. NovaDB dev listens on 127.0.0.1:3307 only; REST on 127.0.0.1 behind nginx later.
- Rust toolchain (stable + nightly for fuzzing), cargo-deny, cargo-audit, cargo-fuzz, cargo-nextest live only inside that image.
- Cluster testing = 3 Docker containers on one host (fine for correctness, not for perf numbers).

## 2. Key design decisions (recommended)
| Area | Choice | Why |
|---|---|---|
| SQL parser | **custom** (hand-written recursive descent, user decision) | must be fuzzed from day 1 |
| Wire protocol | own implementation (reference `opensrv-mysql`) | core product; must be fuzzed |
| Storage | B+Tree, 16 KiB pages, checksums (CRC32C/xxh3), WAL + full-page-image on first write after checkpoint | torn-page protection |
| Txn | MVCC (undo log), snapshot isolation first, then RR/RC like InnoDB | |
| Consensus | **custom Raft** (user decision) | highest-risk component: needs deterministic simulation tests + partition testing |
| Encryption at rest | per-file DEK, AES-256-GCM with **deterministic nonce = (page_id, write counter)** or XChaCha20-Poly1305; AAD = file id + page id + LSN | see §4 |
| Auth (SQL) | `caching_sha2_password` + TLS required; Argon2id for dashboard/REST | see §4 |
| Licence | clean-room; do NOT copy MySQL/MariaDB (GPL) source | legal |

## 3. Stages
✅ done · 🟡 in progress · ⏳ planned. Extra work from the owner's MySQL-pitfalls list ([docs/mysql-pitfalls.md](docs/mysql-pitfalls.md)): ✅ GRANT/REVOKE privileges → ✅ transactional DDL → ✅ online `ALTER TABLE` → then Stage 8.

- ✅ **Stage 1 (Mon 16 Nov) — skeleton**: cargo workspace (engine, protocol, sql, server, cli), CI (fmt, clippy -D warnings, test, cargo-deny/audit), `#![forbid(unsafe_code)]` everywhere except storage crate.
- ✅ **Stage 2 — storage**: pager, buffer pool w/ memory cap, B+Tree, WAL, fsync, crash recovery. Crash tests (kill -9 loop + verify).
- ✅ **Stage 3 — SQL single-node**: CREATE/DROP TABLE, INSERT/SELECT/UPDATE/DELETE, WHERE, ORDER BY, LIMIT, PK + secondary index, core types (INT, BIGINT, DECIMAL, VARCHAR, TEXT, BLOB, DATETIME).
- ✅ **Stage 4 — MySQL protocol**: handshake, TLS, auth, COM_QUERY, COM_STMT_*, result sets, errors. Gate: `mysql` CLI, HeidiSQL, DBeaver, PHP PDO, Node mysql2, Python connector connect + CRUD in automated tests. *(Done: `mariadb` CLI + Node mysql2; PHP PDO, Python, JDBC, GUI tools still untested — docs/protocol.md.)*
- ✅ **Stage 5 — transactions**: MVCC, BEGIN/COMMIT/ROLLBACK, deadlock detection, group commit, isolation tests. *(Snapshot isolation, first-committer-wins → 1213; no row locks so no deadlocks — docs/transactions.md.)*
- ✅ **Stage 6 — joins/aggregates/planner**: JOIN, GROUP BY, HAVING, subqueries, cost-based index selection, query timeout/cancel (KILL). *(Done except cost-based selection: rule-based index choice + index nested-loop joins, no join reordering yet — docs/sql.md.)*
- ✅ **Stage 7 — ops**: Docker image, systemd unit, backup/restore + PITR, Prometheus metrics.
- ⏳ **Stage 8 — replication/cluster (custom Raft)**: 3-node, leader election, log replication, join tokens, mTLS, partition tests (Jepsen-style).
- 🟡 **Stage 9 — Control dashboard + Identity** (Argon2id, TOTP, passkeys, Discord/GitHub OAuth, audit log). *(Live at the dashboard; passkeys not done yet — docs/dashboard.md.)*
- ✅ **Stage 10 — REST/WebSocket + SDKs**: token-scoped REST CRUD, saved queries, opt-in SQL, WebSocket queries/transactions/live change feed, JS + Python SDKs ([docs/rest.md](docs/rest.md)). Website: later.
**Later / separate project**: Windows installer, Kubernetes/Helm, NovaDB Cloud + billing, stored procedures, triggers, LSM engine.

## 4. Security review of the spec — issues & fixes
1. **admin/admin** — never compiled in. First run generates random admin pw, printed once to console/file 0600, forced change + MFA. (Spec already says this; enforce in tests.)
2. **AES-GCM nonce reuse** — pages are rewritten millions of times with the same key; random 96-bit nonces hit collision risk ~2^32 writes, and one reuse leaks plaintext XOR + allows forgery. Use counter/derived nonces or XChaCha20-Poly1305, and rotate DEKs.
3. **Page swap / rollback attacks** — GCM alone doesn't stop copying an old valid page over a new one. Bind AAD to page id + LSN; keep per-file MAC root in the WAL/control file.
4. **Argon2id vs MySQL wire auth conflict** — MySQL challenge-response can't verify against an Argon2id hash. Options: caching_sha2_password (SHA-256 based), or clear-text-over-TLS + Argon2id. Never offer `mysql_native_password` (SHA1) by default.
5. **Argon2id = DoS lever** — each login costs ~50–100 ms CPU. Rate-limit per IP *before* hashing, cap concurrent auth, cache verified sessions.
6. **Pre-auth DoS** — limits on handshake time, max packet size (max_allowed_packet), connections per IP, total connections, before any allocation based on client-supplied lengths.
7. **Memory blowups** — streamed result sets, per-query memory budget, sort/hash spill to disk (encrypted temp files), recursion depth limit in parser/planner.
8. **REST "permitted query execution"** — this is SQL-injection-as-a-service. Only parameterised, allow-listed operations per token scope; row/time limits; no raw SQL on tokens without explicit admin scope.
9. **OAuth account takeover** — never auto-link accounts by matching e-mail (Discord/GitHub e-mails can be unverified). Link only while already logged in; validate `state`, use PKCE, exact redirect URI match; store provider user *ID* not username.
10. **Cluster join tokens** — one-time, short TTL, bound to cluster CA fingerprint (kubeadm-style); mTLS for all node traffic; separate CA from client TLS.
11. **Split-brain** — no time-based leader leases without bounded clock drift; fencing tokens on writes; never fail over without quorum.
12. **fsync correctness** — on fsync error, crash and recover from WAL (don't retry: Linux may drop dirty pages = silent loss). Windows needs FlushFileBuffers + FILE_FLAG_WRITE_THROUGH.
13. **Geo restrictions / device IDs** — spoofable (VPN, header forgery). Treat as extra signals only; never as an auth factor. Never trust X-Forwarded-For unless from configured proxy.
14. **Query cache** — MySQL removed it in 8.0 (lock contention + stale-data bugs). Deprioritise.
15. **Supply chain** — cargo-deny + cargo-audit in CI, pinned Cargo.lock, signed release binaries (minisign/sigstore), SBOM, signed APT repo key kept offline.
16. **Fuzzing (mandatory)** — protocol packet decoder, SQL parser, page decoder, WAL replay. Malformed pages/WAL must never panic or UB.
17. **Backups** — encrypted with separate key; if the KEK is lost, backups are gone -> documented key-escrow procedure; automated restore test.
18. **Secrets/logs** — never log passwords, tokens, query parameters by default; audit log append-only + hash-chained.
19. **Cloud multi-tenancy** — one tenant per VM/container minimum, never shared engine process; that's a separate project.
20. **Name** — check "NovaDB" trademark/existing products before public website/branding.

## 5. Open questions for the user
- ~~Build host~~ -> Docker container `novadb-builder` on this VPS, capped 2 CPU / 3 GB (see docker/README.md).
- ~~Crates~~ -> everything custom (parser, protocol, storage, Raft). Third-party crates only for primitives: tokio, crypto (RustCrypto/ring), rustls, argon2, zstd.
- Repo stays private until decided otherwise.

## 6. Working rules (from the user, 2026-11-13)
- **Nothing is kept on the server.** All source and build files are written straight to this GitHub repo (work in a temp dir, commit + push, then delete it).
- **Testing is always done from a fresh `git clone`** of this repo into a temp dir: build -> `cargo test` -> clippy -> cargo-audit/cargo-deny -> fuzz smoke runs -> crash/recovery tests -> security checks from §4. Delete the clone afterwards.
- Results go in `TESTING.md` in the repo (date, commit, what passed/failed).
- **Alert the user when all bug + security testing is complete** (push notification + chat message), with a summary of findings.
- Build started Monday 2026-11-16.
