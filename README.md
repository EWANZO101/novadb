# NovaDB
Rust database engine aiming for MySQL/MariaDB wire compatibility. Everything is custom
(SQL parser, wire protocol, storage engine, Raft) — see [PLAN.md](PLAN.md).

**Status:** not production-ready. No compatibility or performance claims until the matching test
suites pass. Test results for every stage: [TESTING.md](TESTING.md).

| stage | what | state | docs |
|---|---|---|---|
| 1 | workspace, CI, policies | ✅ done | [ci/README.md](ci/README.md) |
| 2 | storage engine: pages, buffer pool, B+Tree, WAL, crash recovery | ✅ done | [docs/storage.md](docs/storage.md) |
| 3 | single-node SQL + CLI shell | ✅ done | [docs/sql.md](docs/sql.md) |
| 4 | MySQL wire protocol over TLS (127.0.0.1:3307) | ✅ done | [docs/protocol.md](docs/protocol.md) |
| 5 | transactions: MVCC, snapshot isolation | ✅ done | [docs/transactions.md](docs/transactions.md) |
| 6 | joins, aggregates, subqueries, KILL / `max_execution_time` | ✅ done | [docs/sql.md](docs/sql.md) |
| 7 | encrypted backups + binlog, point-in-time recovery, metrics, systemd/Docker | ✅ done | [docs/operations.md](docs/operations.md) |
| — | privileges: `GRANT` / `REVOKE` / `SHOW GRANTS`, least privilege by default | ✅ done | [docs/sql.md](docs/sql.md#privileges) |
| 8 | replication / custom Raft cluster | ⏳ planned | [PLAN.md](PLAN.md) |
| 9 | control dashboard + identity (started early, live) | 🟡 in progress | [docs/dashboard.md](docs/dashboard.md) |
| 10 | REST / WebSocket + SDKs | ⏳ planned | [PLAN.md](PLAN.md) |

How NovaDB avoids MySQL's known problems, and what is next (transactional DDL, online
`ALTER TABLE`, then Stage 8): [docs/mysql-pitfalls.md](docs/mysql-pitfalls.md).

## Layout
| path | what |
|---|---|
| `crates/novadb-storage` | pager, buffer pool, B+Tree, WAL, crash recovery, `SimVfs` |
| `crates/novadb-sql` | SQL: lexer, parser, types, catalog, planner, executor, MVCC transactions, privileges, backups + binlog |
| `crates/novadb-protocol` | MySQL wire protocol codec: handshake, auth, result sets, prepared statements (Stage 4) |
| `crates/novadb-server` | server: TLS-only MySQL protocol on 127.0.0.1:3307, Argon2id users, `--restore`, Prometheus metrics |
| `crates/novadb-dashboard` | Stage 9 control dashboard + identity (Argon2id, TOTP, recovery codes, OAuth linking, hash-chained audit log, SQL workspace, backups) |
| `crates/novadb-cli` | `novadb` CLI: `sql`, interactive `shell`, plus raw `put/get/del/scan/trees/drop/verify/stats` |
| `fuzz/` | cargo-fuzz targets (page decoder, WAL replay, corrupt DB, B+Tree model, SQL parser, SQL executor, protocol decoder) |
| `scripts/crash-test.sh` | SIGKILL crash/recovery loop |
| `scripts/wire-test.sh` | real `mariadb` client against a throwaway server + `protocol-abuse.py` |
| `scripts/dashboard-e2e.py` | black-box dashboard test (throwaway instance only) |
| `scripts/security-check.sh` | automated part of the PLAN §4 security review |
| `packaging/novadb.service` | hardened systemd unit ([docs/operations.md](docs/operations.md)) |
| `docker/` | `novadb-builder` image (all builds/tests run inside it) + `dashboard.Dockerfile` runtime image |
| `ci/` | GitHub Actions workflow (move to `.github/workflows/`, see [ci/README.md](ci/README.md)) |
| `docs/` | per-component docs (linked in the status table above) |

## Build & test (Docker only)
    docker build -t novadb-builder docker/
    docker run --rm --cpus 2 --memory 3g --pids-limit 512 --security-opt no-new-privileges \
      -e GH_TOKEN="$(gh auth token)" -e FUZZ_SECS=60 novadb-builder

Policies: `unsafe_code = "forbid"` in every crate, clippy `-D warnings`, cargo-deny
(permissive licences only, crates.io only), cargo-audit, pinned `Cargo.lock`.
