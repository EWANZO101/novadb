#!/usr/bin/env bash
# kill -9 crash/recovery loop on a real file system (PLAN.md Stage 2).
# Repeatedly starts a writer, SIGKILLs it at a random moment, then verifies durability
# (every acknowledged commit survived) and atomicity (no partial transaction visible).
# Note: SIGKILL keeps the OS page cache, so this tests process crashes; power loss with
# torn/lost writes is covered by the SimVfs tests (crates/novadb-storage/tests/crash_sim.rs).
set -euo pipefail
cd "$(dirname "$0")/.."
ITERS="${CRASH_ITERS:-40}"
SEED="${CRASH_SEED:-$(( (RANDOM << 15) | RANDOM ))}"
cargo build --release --locked -q -p novadb-storage --bin novadb-crashtest
BIN="${CARGO_TARGET_DIR:-target}/release/novadb-crashtest"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
DB="$WORK/db"
ACKED=0
echo "crash-test: $ITERS iterations, seed $SEED"
for i in $(seq 1 "$ITERS"); do
  "$BIN" run "$DB" "$SEED" >"$WORK/out.log" 2>"$WORK/err.log" &
  PID=$!
  # random 20..1200 ms
  sleep "$(awk -v r="$RANDOM" 'BEGIN { printf "%.3f", 0.02 + (r % 1180) / 1000 }')"
  kill -9 "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
  if [ -s "$WORK/err.log" ]; then echo "writer error:"; cat "$WORK/err.log"; exit 1; fi
  LAST=$(grep -E '^ok [0-9]+$' "$WORK/out.log" | tail -1 | cut -d' ' -f2 || true)
  if [ -n "${LAST:-}" ] && [ "$LAST" -gt "$ACKED" ]; then ACKED=$LAST; fi
  if ! OUT=$("$BIN" verify "$DB" "$SEED" "$ACKED" 2>&1); then
    echo "iteration $i FAILED (seed $SEED): $OUT"
    exit 1
  fi
  echo "[$i/$ITERS] $OUT"
done
echo "crash-test: PASS ($ITERS kill -9 cycles, final acked txn $ACKED)"
