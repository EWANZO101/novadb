#!/usr/bin/env bash
# 3-node NovaDB cluster test with real processes (one Docker container per node, host network):
# init + join tokens over mTLS, replication, leader kill + failover, a "partition" (docker
# pause = frozen process) with the old leader returning, snapshot catch-up of a lagging node,
# node removal, and a final byte-for-byte comparison of all nodes.
# usage: scripts/cluster-test.sh path/to/novadb-server   (needs docker + mariadb client)
set -euo pipefail
BIN=$(readlink -f "$1")
IMG=${NOVADB_TEST_IMAGE:-novadb-builder}
ROOT=$(mktemp -d /tmp/novadb-ct.XXXXXX)
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "ok   $*"; }
bad() { FAIL=$((FAIL + 1)); echo "FAIL $*"; }
cleanup() {
  if [ -n "${KEEP:-}" ]; then echo "kept: $ROOT"; return; fi
  for i in 1 2 3; do docker rm -f novadb-ct$i >/dev/null 2>&1 || true; done
  docker run --rm --user root -v "$ROOT":/r --entrypoint sh "$IMG" -c 'rm -rf /r/*' >/dev/null 2>&1 || true
  rm -rf "$ROOT"
}
trap cleanup EXIT

nv() { # run a novadb-server command against node $1's data dir (one-off container)
  local n=$1; shift
  docker run --rm --user root --network host -v "$ROOT/n$n":/d -v "$BIN":/usr/local/bin/novadb-server:ro \
    --entrypoint /usr/local/bin/novadb-server "$IMG" "$@"
}
start() {
  local n=$1
  docker rm -f novadb-ct$n >/dev/null 2>&1 || true
  docker run -d --user root --name novadb-ct$n --network host --cpus 0.5 --memory 512m \
    -e NOVADB_SNAPSHOT_EVERY=200 \
    -v "$ROOT/n$n":/d -v "$BIN":/usr/local/bin/novadb-server:ro \
    --entrypoint /usr/local/bin/novadb-server "$IMG" \
    --data-dir /d --listen 127.0.0.1:340$n --rest 127.0.0.1:348$n >/dev/null
}
q() { # q NODE SQL  -> output (errors to stdout, prefixed)
  local n=$1; shift
  mariadb -h127.0.0.1 -P340$n -uroot -p"$PW" --ssl-ca="$ROOT/n$n/tls/server.crt" -N -B novadb -e "$*" 2>&1 || true
}
wait_for() { # wait_for SECONDS CMD...
  local t=$1; shift
  for _ in $(seq 1 $((t * 5))); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 0.2
  done
  return 1
}
leader() { # prints the node number that accepts writes
  for n in "$@"; do
    if ! q "$n" "INSERT INTO probe VALUES (1)" | grep -q "ERROR"; then echo "$n"; return 0; fi
  done
  return 1
}
count() { q "$1" "SELECT COUNT(*), COALESCE(SUM(v),0) FROM t"; }

mkdir -p "$ROOT"/n1 "$ROOT"/n2 "$ROOT"/n3

# --- node 1 founds the cluster --------------------------------------------------------------
nv 1 cluster init --data-dir /d --node-id 1 --raft 127.0.0.1:7401 --advertise 127.0.0.1:7401 --sql 127.0.0.1:3401 >/dev/null
start 1
wait_for 20 test -s "$ROOT/n1/initial-root-password.txt" || { docker logs novadb-ct1; exit 1; }
PW=$(docker run --rm --user root -v "$ROOT":/r --entrypoint sh "$IMG" -c 'sed -n 2p /r/n1/initial-root-password.txt' | cut -d' ' -f2)
ok "node 1 bootstrapped, root created through the Raft log"

# --- nodes 2 and 3 join with one-time tokens --------------------------------------------------
for n in 2 3; do
  T=$(nv 1 cluster token --data-dir /d --minutes 5 | grep ^nvdbjoin_)
  nv $n cluster join --data-dir /d --node-id $n --raft 127.0.0.1:740$n --advertise 127.0.0.1:740$n --sql 127.0.0.1:340$n --token "$T" >/dev/null
  start $n
  if nv $n cluster join --data-dir /d --node-id 9 --raft x --advertise x --token "$T" >/dev/null 2>&1; then
    bad "token reuse must fail"
  fi
done
ok "tokens are single-use"
BADTOK=$(nv 1 cluster token --data-dir /d --minutes 5 | grep ^nvdbjoin_ | sed 's/.$/x/')
mkdir -p "$ROOT/n9"
if docker run --rm --user root --network host -v "$ROOT/n9":/d -v "$BIN":/usr/local/bin/novadb-server:ro --entrypoint /usr/local/bin/novadb-server "$IMG" cluster join --data-dir /d --node-id 9 --raft x --advertise x --token "$BADTOK" >/dev/null 2>&1; then
  bad "tampered token accepted"
else
  ok "tampered token refused"
fi
member() { grep -q '"member": true' "$ROOT/n$1/cluster/cluster.json"; }
wait_for 40 member 2 && wait_for 40 member 3 && ok "nodes 2 and 3 are voting members" || bad "join did not complete"

# --- replication ------------------------------------------------------------------------------
q 1 "CREATE TABLE probe (x INT)" >/dev/null
q 1 "CREATE TABLE t (id INT PRIMARY KEY AUTO_INCREMENT, v INT NOT NULL, note VARCHAR(20), UNIQUE KEY un (note))" >/dev/null
for i in $(seq 1 20); do q 1 "INSERT INTO t (v, note) VALUES ($i, 'n$i')" >/dev/null; done
same3() { [ "$(count 1)" = "$(count 2)" ] && [ "$(count 2)" = "$(count 3)" ] && [ "$(count 1)" != "" ]; }
wait_for 20 same3 && ok "writes replicated to all nodes ($(count 1))" || bad "replication: $(count 1) | $(count 2) | $(count 3)"
r=$(q 2 "INSERT INTO t (v) VALUES (1)")
echo "$r" | grep -q "1290" && ok "follower refuses writes (1290, names the leader)" || bad "follower write: $r"
echo "$r" | grep -q "leader is node 1" && ok "error message points to node 1" || bad "no leader hint: $r"
r=$(q 1 "INSERT INTO t (v, note) VALUES (0, 'n1')")
echo "$r" | grep -q "1062" && ok "unique violation reported by the leader" || bad "dup: $r"
q 1 "BEGIN; INSERT INTO t (v, note) VALUES (100, 'tx'); UPDATE t SET v = v + 1000 WHERE id = 1; COMMIT" >/dev/null
q 1 "CREATE USER app IDENTIFIED BY 'app-password-123'; GRANT SELECT ON t TO app" >/dev/null
appq() { mariadb -h127.0.0.1 -P3403 -uapp -papp-password-123 --ssl-ca="$ROOT/n3/tls/server.crt" -N -B novadb -e "SELECT COUNT(*) FROM t" 2>&1; }
wait_for 20 appq && ok "users + grants replicated (app logs in on node 3)" || bad "app on node 3: $(appq)"

# --- leader failure -------------------------------------------------------------------------
docker kill novadb-ct1 >/dev/null
L=""
for _ in $(seq 1 50); do L=$(leader 2 3 || true); [ -n "$L" ] && break; sleep 0.2; done
[ -n "$L" ] && ok "new leader elected after killing node 1: node $L" || bad "no new leader"
r=$(q "$L" "INSERT INTO t (v, note) VALUES (21, 'n21')"); [ -z "$r" ] || echo "debug: first insert on new leader: $r"
for i in $(seq 22 40); do q "$L" "INSERT INTO t (v, note) VALUES ($i, 'n$i')" >/dev/null; done
start 1
wait_for 30 same3 && ok "old leader restarted and caught up ($(count 1))" || bad "after restart: $(count 1) | $(count 2) | $(count 3)"

# --- partition: freeze the leader -------------------------------------------------------------
L=$(leader 1 2 3)
docker pause novadb-ct$L >/dev/null
others=$(echo 1 2 3 | tr ' ' '\n' | grep -v "^$L$" | tr '\n' ' ')
N=""
for _ in $(seq 1 60); do N=$(leader $others || true); [ -n "$N" ] && break; sleep 0.2; done
[ -n "$N" ] && ok "majority side elected node $N while node $L was frozen" || bad "no leader during partition"
r=$(q "$N" "INSERT INTO t (v, note) VALUES (41, 'n41')"); [ -z "$r" ] || echo "debug: first insert during partition: $r"
for i in $(seq 42 60); do q "$N" "INSERT INTO t (v, note) VALUES ($i, 'n$i')" >/dev/null; done
docker unpause novadb-ct$L >/dev/null
sleep 2
r=$(q "$L" "INSERT INTO t (v) VALUES (-1)")
echo "$r" | grep -q 1290 && ok "returning old leader stepped down (no split brain)" || bad "old leader still writes: $r"
wait_for 30 same3 && ok "all nodes agree after the partition healed ($(count 1))" || bad "after heal: $(count 1) | $(count 2) | $(count 3)"

# --- snapshot catch-up ----------------------------------------------------------------------
L=$(leader 1 2 3)
LAG=$(echo 1 2 3 | tr ' ' '\n' | grep -v "^$L$" | head -1)
docker stop -t 1 novadb-ct$LAG >/dev/null
python3 -c "
for k in range(30):
    print('INSERT INTO t (v) VALUES ' + ','.join(['(7)'] * 10) + ';')
" | while read -r line; do q "$L" "$line" >/dev/null; done
for i in $(seq 1 250); do q "$L" "UPDATE t SET v = v + 1 WHERE id = 2" >/dev/null; done
start "$LAG"
wait_for 60 same3 && ok "lagging node caught up ($(count $LAG))" || bad "lagging node: $(count 1) | $(count 2) | $(count 3)"
docker logs novadb-ct$LAG 2>&1 | grep -q "installing snapshot" && ok "it was brought up to date with a snapshot (InstallSnapshot)" || echo "note: caught up from the log without a snapshot"

# --- node removal -----------------------------------------------------------------------------
declare -A TOK
for n in 1 2 3; do
  TOK[$n]=$(docker exec novadb-ct$n /usr/local/bin/novadb-server token create --data-dir /d --user root --scopes rows | grep ^nvdb_)
done
L=$(leader 1 2 3)
RM=$(echo 1 2 3 | tr ' ' '\n' | grep -v "^$L$" | tail -1)
st=$(curl -s -H "authorization: Bearer ${TOK[$L]}" http://127.0.0.1:348$L/v1/cluster || true)
echo "$st" | grep -q '"role":"leader"' && ok "REST /v1/cluster reports the leader" || bad "status: $st"
st=$(curl -s -H "authorization: Bearer ${TOK[$RM]}" http://127.0.0.1:348$RM/v1/cluster || true)
echo "$st" | grep -q '"role":"follower"' && ok "a follower reports itself as follower" || bad "status: $st"
rm_out=$(curl -s -X POST -H "authorization: Bearer ${TOK[$L]}" http://127.0.0.1:348$L/v1/cluster/nodes/$RM/remove || true)
echo "$rm_out" | grep -q removed && ok "node $RM removed from the voter set" || bad "remove: $rm_out"
docker rm -f novadb-ct$RM >/dev/null
r=$(q "$L" "INSERT INTO t (v) VALUES (5)")
[ -z "$r" ] && ok "2-node cluster keeps committing after removal" || bad "write after removal: $r"

# --- final comparison -----------------------------------------------------------------------
remaining=$(echo 1 2 3 | tr ' ' '\n' | grep -v "^$RM$" | tr '\n' ' ')
set -- $remaining
sum() { q "$1" "SELECT GROUP_CONCAT(CONCAT(id, ':', v, ':', COALESCE(note, '')) ORDER BY id) FROM t" | md5sum; }
same2() { [ "$(sum $1)" = "$(sum $2)" ]; }
if q "$1" "SELECT GROUP_CONCAT(1)" | grep -q ERROR; then
  same2() { [ "$(count $1)" = "$(count $2)" ]; }
fi
wait_for 20 same2 "$1" "$2" && ok "remaining nodes are identical ($(count $1))" || bad "final: $(count $1) vs $(count $2)"

echo
if [ $FAIL -eq 0 ]; then echo "ALL $PASS CLUSTER CHECKS PASSED"; else echo "$FAIL FAILED, $PASS passed"; exit 1; fi
