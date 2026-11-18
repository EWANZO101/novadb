# Cluster mode (Stage 8) — Raft replication

A NovaDB cluster is 1, 3 or 5 (any number of) nodes that agree on every change through **Raft**
(own implementation, `crates/novadb-raft`). A write is acknowledged only after a **majority**
has it durably; any node can fail and the rest carry on as long as a majority is up.

## Setting up
```sh
# node 1 (creates the cluster, its CA, and holds the key that issues join tokens)
novadb-server cluster init  --data-dir /var/lib/novadb --node-id 1 --raft 0.0.0.0:7400 --advertise 10.0.0.1:7400 --sql 10.0.0.1:3307
novadb-server --data-dir /var/lib/novadb --listen 10.0.0.1:3307        # root password → initial-root-password.txt

# for each new node: a one-time token from node 1 …
novadb-server cluster token --data-dir /var/lib/novadb --minutes 60
# … used on the new node, then start it
novadb-server cluster join  --data-dir /var/lib/novadb --node-id 2 --raft 0.0.0.0:7400 --advertise 10.0.0.2:7400 --sql 10.0.0.2:3307 --token nvdbjoin_…
novadb-server --data-dir /var/lib/novadb --listen 10.0.0.2:3307
```
The new node asks the leader to add it; it is a voting member once that change commits
(`cluster status`, `GET /v1/cluster`). Remove a node: `POST /v1/cluster/nodes/{id}/remove` with
a REST token for `root` (one change at a time; a removed leader steps down).

## Security (PLAN.md §4.10/4.11)
* **Mutual TLS** on every node-to-node connection, with a dedicated cluster CA (separate from the
  SQL TLS certificate). A node's identity comes from its certificate (`node-<id>.novadb`), never
  from the message.
* **Join tokens** are one-time, short-lived (default 60 min, max 7 days), stored hashed, and carry
  the SHA-256 of the cluster CA: the joining node only accepts the issuer if its chain contains
  exactly that CA and verifies against it (no trust on first use). Join attempts are rate-limited.
* **No split brain**: PreVote + CheckQuorum — a leader that cannot reach a majority steps down
  within an election timeout; a node cut off and coming back cannot disrupt the cluster; nothing
  commits without a majority. No time-based leases are used for safety.

## How writes work
1. Clients send writes to the **leader**. A follower answers with `ERROR 1290 … read-only …
   (leader is node N at host:port)`.
2. The leader runs the statement in *capture* mode: it executes normally inside a storage outer
   transaction, records the logical changes (rows, DDL, users, counters — the binlog format) and
   rolls everything back. Writes are serialised on the leader (capture → replicate → apply), so
   the MVCC first-committer-wins check during capture sees every earlier commit (`ERROR 1213` on
   conflicts, as on a single node).
3. The changes are proposed to Raft; when a majority has stored them, every node (leader too)
   applies them atomically together with the Raft index — a crash never applies an entry twice
   or half. Apply is deterministic: an entry that fails (e.g. a unique-key race) fails on every
   node and changes nothing; the client gets that error.
4. The client gets its result after the leader applied the entry. If leadership changes before
   that, the client gets `ERROR 1180 commit outcome unknown` (the write may or may not have
   committed — check, then retry).

Multi-statement transactions work as on a single node; their changes are replicated as one entry
at `COMMIT`. DDL inside a transaction commits implicitly in cluster mode (transactional DDL is
single-node only). `ALTER TABLE` runs as a blocking rebuild on each node.

## Reads
* Default: every node answers reads from its own data — followers may be slightly behind the
  leader (usually milliseconds).
* `--linearizable-reads`: SELECTs are served only by the leader, after a **ReadIndex** round
  (the leader confirms with a majority that it still leads, then waits until it applied that
  index) — reads never miss an acknowledged write. Followers answer 1290.

## Durability & catch-up
* Raft log: CRC-checked records, fsync before any message is sent; torn tails are cut at start.
* Snapshots every 10,000 entries (a dump of the database); the log before it is dropped. A node
  that is too far behind (or new) receives the snapshot and replaces its database with it, then
  continues from the log.
* The local binlog is off in cluster mode (the Raft log replaces it); use backups.

## Tests
* `crates/novadb-raft/tests/sim.rs` — deterministic simulation with partitions, loss,
  duplication, reordering, crashes, membership changes and snapshots; checks election safety,
  state machine safety, durability of acknowledged writes, linearizable ReadIndex and liveness;
  `chaos_soak` ran 6,000 random seeds.
* `crates/novadb-sql/tests/cluster.rs` — capture/apply at the engine level: replicas identical,
  first-committer-wins, deterministic failed entries, idempotent replay, failover counters.
* `scripts/cluster-test.sh` — 3 real nodes (containers): init + join tokens (single use, tamper
  refused), replication, follower refusal, leader kill + failover, frozen leader returning (no
  split brain), snapshot catch-up, node removal, identical data at the end (21 checks).
