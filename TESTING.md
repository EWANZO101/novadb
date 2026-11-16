# NovaDB — test log

All builds and tests run **inside Docker** (`novadb-builder`, `--cpus 2 --memory 3g`,
`nice -n 19`) from a **fresh `git clone`** using `docker/run-tests.sh`. Nothing is built on the host.
Toolchain: rustc 1.100.0 stable, nightly 2026-11-11 for cargo-fuzz; cargo-deny 0.20.2,
cargo-audit 0.23.0, cargo-nextest 0.9.152.

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
