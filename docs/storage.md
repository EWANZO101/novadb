# NovaDB storage engine (Stage 2)

Crate: `crates/novadb-storage`. 100 % safe Rust (`#![forbid(unsafe_code)]`), no third-party
dependencies.

## Files
A database is a directory (created 0700, files 0600):

| file | purpose |
|---|---|
| `data.ndb` | 16 KiB pages. Page 0 = meta, page 1 = catalog root |
| `wal.ndb` | write-ahead log (current generation) |
| `LOCK` | exclusive `flock` so two processes can't open the same database |

## Page format
Every page starts with a 32-byte header: CRC-32C of the rest of the page, page type,
**self page id** (detects misdirected reads/writes), page LSN, and **owner tree id** (detects
cross-tree pointer corruption and stale `Tree` handles). Checksums are verified on every read.

## B+Tree
* Leaves hold sorted `(key, value)` pairs and a right-sibling link; internal nodes hold
  separators + child ids. Keys ≤ 1024 B, values ≤ 4096 B (overflow pages come with BLOB support
  in Stage 3). Static assertions prove every overfull node can be split into two pages.
* Nodes are decoded into owned structs, modified and re-encoded; a single validating decoder
  (fuzzed) is the only way page bytes become a node.
* Delete merges or rebalances nodes that fall below 1/4 full; the root collapses when it has a
  single child. Root page ids never change, so the catalog never needs updating.
* Deletes can *grow* a parent (a rebalance may replace a short separator with a long one);
  such a parent splits and the split propagates upward exactly like on insert.
* Depth limit (48), leaf-chain step limit and a visited-set in page walks turn pointer cycles
  and shared children in corrupt files into errors (no hangs, no exponential walks).
* `drop_tree` atomically renames the tree to a hidden `\0dropped\0<id>` catalog entry; its
  pages are reclaimed after commit (and on every open) in bounded transactions, so trees larger
  than the buffer pool can be dropped and a crash mid-reclamation simply resumes.
* `Tree` handles carry a random per-`Db`-instance id and tree ids are never reused within an
  instance (even after rollback), so stale handles fail instead of touching another tree.

## Buffer pool
Fixed number of frames (`Options::cache_pages`, default 2048 = 32 MiB, minimum 32) with CLOCK
eviction.
Pages modified by the running transaction are pinned (**no-steal**): uncommitted data never
reaches the data file. A transaction that would pin more than `cache_pages - 8` pages fails
with `TxnTooLarge` and rolls back (memory cap, PLAN §4.7).

## WAL and commit
Redo-only physical logging. At commit, for every modified page the engine appends either a
**full page image** (first change since the last checkpoint — this is what repairs torn data-page
writes) or a **byte-range delta** against the previously logged state, then a `Commit` record,
then `fsync`. Records carry a CRC-32C over a per-generation random salt, consecutive LSNs, and
the WAL header carries the database id, so stale or foreign records are never replayed.

**Checkpoint** (when the WAL exceeds `checkpoint_wal_bytes`, default 64 MiB, on `close()`, and
after recovery): flush dirty pages → fsync data file → write new WAL header to a temp file →
fsync → atomic rename → fsync directory.

**fsync failure** (PLAN §4.12): the handle is poisoned; every later call returns
`Error::Poisoned`. The data is never "retried" because Linux may have dropped the dirty pages.
Reopen = crash recovery from the WAL.

## Recovery
1. Scan the WAL; stop at the first torn/stale record (bad length, CRC, salt or LSN).
2. Check the WAL's database id against the data file (or, if page 0 is torn, against a
   *committed* meta-page image in the WAL). A WAL from another database is refused.
3. Re-apply all page records up to the last `Commit`; records of an unfinished transaction are
   ignored. Deltas must apply on top of an image from the same WAL.
4. fsync the data file and start a new WAL generation. Recovery is idempotent.

Structurally invalid records *with a valid CRC* are reported as corruption instead of being
silently treated as end-of-log.

## Testing hooks
* `SimVfs`: in-memory file system that models power loss (un-synced writes and directory
  entries are lost or torn at 512-byte granularity) and injects I/O errors after N operations.
* `Db::verify()`: full invariant check (ordering, bounds, uniform depth, leaf chain, page
  ownership, every page referenced exactly once, free-list consistency).
* `novadb-crashtest` + `scripts/crash-test.sh`: SIGKILL loop on a real file system.

## Known limitations (to address in later stages)
* Single writer (`&mut Db`); MVCC/concurrency is Stage 5.
* Maximum database size 4 TiB (2^28 pages) — bounds hostile inputs; raise when needed.
* Dropped-tree reclamation deletes keys one by one (simple, always a valid tree; slow for very
  large trees).
* No overflow pages (values > 4 KiB), no prefix/suffix compression, node ops decode the full
  page (CPU cost; optimise with in-place binary search later).
* No encryption at rest yet (PLAN §4.2/§4.3: the header already has page id + LSN for AAD).
* The data file never shrinks (freed pages are reused, not returned to the OS).
