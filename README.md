# NovaDB
Rust database engine aiming for MySQL/MariaDB wire compatibility. Everything is custom
(SQL parser, wire protocol, storage engine, Raft) — see [PLAN.md](PLAN.md).

**Status:** Stage 1 (workspace, CI, policies), Stage 2 (storage engine), Stage 3 (single-node
SQL, [docs/sql.md](docs/sql.md)) and Stage 4 (MySQL wire protocol over TLS,
[docs/protocol.md](docs/protocol.md)) Stage 5 (MVCC transactions, snapshot isolation,
[docs/transactions.md](docs/transactions.md)) Stage 6 (joins, aggregates, subqueries) and Stage 7 (encrypted backups + binary log,
point-in-time recovery, metrics, hardened systemd/Docker — [docs/operations.md](docs/operations.md)) done.
How NovaDB avoids MySQL's known problems: [docs/mysql-pitfalls.md](docs/mysql-pitfalls.md) — see
[TESTING.md](TESTING.md) and [docs/storage.md](docs/storage.md). Stage 9 control dashboard +
identity started early (2026-11-18) — see [docs/dashboard.md](docs/dashboard.md). Not production-ready. No
compatibility or performance claims until the matching test suites pass.

## Layout
| path | what |
|---|---|
| `crates/novadb-storage` | pager, buffer pool, B+Tree, WAL, crash recovery, `SimVfs` |
| `crates/novadb-sql` | SQL: lexer, parser, types, catalog, planner, executor (Stage 3) |
| `crates/novadb-protocol` | MySQL wire protocol codec: handshake, auth, result sets, prepared statements (Stage 4) |
| `crates/novadb-server` | server: TLS-only MySQL protocol on 127.0.0.1:3307, Argon2id users |
| `crates/novadb-dashboard` | Stage 9 control dashboard + identity (Argon2id, TOTP, OAuth linking, hash-chained audit log) |
| `crates/novadb-cli` | `novadb` CLI: `sql`, interactive `shell`, plus raw `put/get/del/scan/trees/drop/verify/stats` |
| `fuzz/` | cargo-fuzz targets (page decoder, WAL replay, corrupt DB, B+Tree model, SQL parser, SQL executor, protocol decoder) |
| `scripts/crash-test.sh` | SIGKILL crash/recovery loop |
| `scripts/wire-test.sh` | real `mariadb` client against a throwaway server + `protocol-abuse.py` |
| `scripts/dashboard-e2e.py` | black-box dashboard test (throwaway instance only) |
| `scripts/security-check.sh` | automated part of the PLAN §4 security review |
| `docker/` | `novadb-builder` image (all builds/tests run inside it) + `dashboard.Dockerfile` runtime image |
| `ci/` | GitHub Actions workflow (move to `.github/workflows/`, see ci/README.md) |

## Build & test (Docker only)
    docker build -t novadb-builder docker/
    docker run --rm --cpus 2 --memory 3g --pids-limit 512 --security-opt no-new-privileges \
      -e GH_TOKEN="$(gh auth token)" -e FUZZ_SECS=60 novadb-builder

Policies: `unsafe_code = "forbid"` in every crate, clippy `-D warnings`, cargo-deny
(permissive licences only, crates.io only), cargo-audit, pinned `Cargo.lock`.
