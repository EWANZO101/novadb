#!/usr/bin/env bash
# Fresh clone -> build -> test -> lint -> audit -> fuzz smoke. Writes report to /out/report.md if /out is mounted.
set -uo pipefail
REF="${NOVADB_REF:-main}"
URL="https://x-access-token:${GH_TOKEN:?GH_TOKEN required (private repo)}@github.com/EWANZO101/novadb.git"
SRC="$(mktemp -d)"
git clone -q --depth 1 --branch "$REF" "$URL" "$SRC" || { echo "clone failed"; exit 2; }
unset GH_TOKEN; cd "$SRC"
COMMIT=$(git rev-parse --short HEAD)
R=/tmp/report.md; FAIL=0
step(){ local n="$1"; shift; echo "== $n"; if "$@" >/tmp/step.log 2>&1; then echo "- ✅ $n" >>$R; else echo "- ❌ $n" >>$R; FAIL=1; tail -40 /tmp/step.log | sed 's/^/    /' >>$R; fi; }
echo "# NovaDB test run $(date -u +%FT%TZ) commit $COMMIT" >$R
if [ ! -f Cargo.toml ]; then echo "- ⏭ no Cargo.toml yet (planning stage)" >>$R; cat $R; exit 0; fi
step "fmt"     cargo fmt --all -- --check
step "build"   cargo build --workspace --all-targets --locked
step "clippy"  cargo clippy --workspace --all-targets --locked -- -D warnings
step "tests"   cargo nextest run --workspace --locked
step "tests (release)" cargo test --workspace --release --locked
step "doctest" cargo test --workspace --doc --locked
step "audit"   cargo audit
[ -f deny.toml ] && step "deny" cargo deny check
[ -x scripts/security-check.sh ] && step "security-check" scripts/security-check.sh
# cargo-fuzz from binstall is a musl build and would default to the musl target: pass the host.
HOST=$(rustc -vV | sed -n 's/^host: //p')
if [ -d fuzz ]; then for t in $(cd fuzz && cargo +nightly fuzz list 2>/dev/null); do
  step "fuzz:$t (${FUZZ_SECS:-60}s)" bash -c "cd fuzz && cargo +nightly fuzz run --target $HOST $t -- -max_total_time=${FUZZ_SECS:-60} -rss_limit_mb=2048"; done; fi
[ -x scripts/crash-test.sh ] && step "crash-recovery" scripts/crash-test.sh
cat $R; [ -d /out ] && cp $R /out/report.md
exit $FAIL
