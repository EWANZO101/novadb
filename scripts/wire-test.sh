#!/usr/bin/env bash
# Starts a throwaway novadb-server and drives it with the real `mariadb` client over TLS,
# then runs the pre-auth abuse checks. Needs: target/debug/novadb-server, mariadb, python3.
set -uo pipefail
cd "$(dirname "$0")/.."
BIN=${NOVADB_SERVER:-target/debug/novadb-server}
PORT=${WIRE_PORT:-3398}
D=$(mktemp -d)
trap 'kill $PID 2>/dev/null; wait $PID 2>/dev/null; rm -rf "$D"' EXIT
"$BIN" --data-dir "$D/srv" --listen 127.0.0.1:$PORT >"$D/log" 2>&1 &
PID=$!
for _ in $(seq 50); do grep -q listening "$D/log" && break; sleep 0.2; done
grep -q listening "$D/log" || { echo "server did not start"; cat "$D/log"; exit 1; }
PW=$(sed -n 2p "$D/srv/initial-root-password.txt" | cut -d' ' -f2)
[ "$(stat -c %a "$D/srv/initial-root-password.txt")" = 600 ] || { echo "password file not 0600"; exit 1; }
printf '[client]\nuser=root\npassword=%s\nhost=127.0.0.1\nport=%s\nssl-ca=%s\n' "$PW" "$PORT" "$D/srv/tls/server.crt" > "$D/my.cnf"
M="mariadb --defaults-extra-file=$D/my.cnf -N -B novadb"
FAIL=0
expect() { local want="$1"; shift; local got; got=$("$@" 2>&1); if [ "$got" = "$want" ]; then echo "ok:   $*"; else echo "FAIL: $* -> got [$got] want [$want]"; FAIL=1; fi; }
expect "NovaDB" $M -e "SELECT @@version_comment"
expect "root@localhost" $M -e "SELECT CURRENT_USER()"
$M -e "CREATE TABLE w (id INT PRIMARY KEY AUTO_INCREMENT, v VARCHAR(10), d DECIMAL(6,2)); INSERT INTO w (v, d) VALUES ('a', 1.5), ('b', NULL)" || FAIL=1
expect $'1\ta\t1.50\n2\tb\tNULL' $M -e "SELECT * FROM w ORDER BY id"
expect "" $M -e "UPDATE w SET d = 2 WHERE id = 2"
expect "2.00" $M -e "SELECT d FROM w WHERE id = 2"
got=$($M -e 'SELECT * FROM nope' 2>&1)
echo "$got" | grep -q "ERROR 1146 (42S02)" && echo "ok:   unknown table -> 1146 42S02" || { echo "FAIL: $got"; FAIL=1; }
got=$(mariadb -h127.0.0.1 -P$PORT -uroot -p"$PW" --skip-ssl -e 'select 1' 2>&1)
echo "$got" | grep -q 3159 && echo "ok:   plaintext refused" || { echo "FAIL: plaintext not refused: $got"; FAIL=1; }
got=$(mariadb -h127.0.0.1 -P$PORT -uroot -pwrong-password --ssl-ca="$D/srv/tls/server.crt" -e 'select 1' 2>&1)
echo "$got" | grep -q 1045 && echo "ok:   wrong password refused" || { echo "FAIL: $got"; FAIL=1; }
python3 -I scripts/protocol-abuse.py 127.0.0.1 $PORT "$D/srv/tls/server.crt" "$D/srv/initial-root-password.txt" || FAIL=1
exit $FAIL
