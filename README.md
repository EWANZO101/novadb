# NovaDB
Rust database engine aiming for MySQL/MariaDB wire compatibility. Everything is custom
(SQL parser, wire protocol, storage engine, Raft) — see [PLAN.md](PLAN.md).

**Status:** Stage 1 (workspace, CI, policies) and Stage 2 (storage engine) done — see
[TESTING.md](TESTING.md) and [docs/storage.md](docs/storage.md). Stage 9 control dashboard +
identity started early (2026-11-18) — see [docs/dashboard.md](docs/dashboard.md). Not production-ready. No
compatibility or performance claims until the matching test suites pass.

## Layout
| path | what |
|---|---|
| `crates/novadb-storage` | pager, buffer pool, B+Tree, WAL, crash recovery, `SimVfs` |
| `crates/novadb-sql` | SQL parser (Stage 3, placeholder + limits) |
| `crates/novadb-protocol` | MySQL wire protocol (Stage 4, placeholder + limits) |
| `crates/novadb-server` | server binary (placeholder; will listen on 127.0.0.1:3307) |
| `crates/novadb-dashboard` | Stage 9 control dashboard + identity (Argon2id, TOTP, OAuth linking, hash-chained audit log) |
| `crates/novadb-cli` | `novadb` developer CLI (`put/get/del/scan/trees/drop/verify/stats`) |
| `fuzz/` | cargo-fuzz targets (page decoder, WAL replay, corrupt DB, B+Tree model) |
| `scripts/crash-test.sh` | SIGKILL crash/recovery loop |
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
