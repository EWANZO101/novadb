#!/usr/bin/env bash
# Automated part of the PLAN.md §4 security review. Fails on any violation.
set -uo pipefail
cd "$(dirname "$0")/.."
FAIL=0
bad(){ echo "FAIL: $*"; FAIL=1; }
ok(){ echo "ok:   $*"; }

# forbid(unsafe_code): workspace lint + attribute in every crate root
grep -q 'unsafe_code = "forbid"' Cargo.toml && ok "workspace lint unsafe_code=forbid" || bad "workspace unsafe_code lint missing"
for f in $(find crates -path '*/src/lib.rs' -o -path '*/src/main.rs' -o -path '*/src/bin/*.rs'); do
  grep -q '#!\[forbid(unsafe_code)\]' "$f" || bad "$f lacks #![forbid(unsafe_code)]"
done
if grep -rnE '\bunsafe\s*(\{|fn|impl|trait)' crates fuzz/fuzz_targets --include=*.rs; then bad "unsafe code found"; else ok "no unsafe blocks"; fi

# never default to MariaDB's port, never bind 0.0.0.0 by default
if grep -rnE '(:|= *)3306\b' crates --include=*.rs | grep -v 'ends_with(":3306")'; then bad "port 3306 referenced"; else ok "no 3306 defaults"; fi
if grep -rn '0\.0\.0\.0' crates --include=*.rs; then bad "0.0.0.0 bind found"; else ok "no wildcard binds"; fi

# no default credentials (PLAN §4.1)
if grep -rniE '"admin"|admin/admin|password *= *"' crates --include=*.rs; then bad "default credentials"; else ok "no default credentials"; fi

# no mysql_native_password / SHA1 auth (PLAN §4.4)
if grep -rni 'mysql_native_password\|sha1' crates --include=*.rs; then bad "SHA1/native auth referenced"; else ok "no SHA1 auth"; fi

# no secrets committed
FILES=$(git ls-files) || { bad "git ls-files failed"; FILES=""; }
if echo "$FILES" | grep -E '(^|/)\.env$|\.pem$|\.key$|id_rsa'; then bad "secret-looking files tracked"; else ok "no secret files tracked"; fi
git grep -nE '(ghp_|gho_|github_pat_|sk-ant-|AKIA[0-9A-Z]{16}|xox[baprs]-)' -- . ':!scripts/security-check.sh'
case $? in 1) ok "no token-like strings";; 0) bad "token-like string in repo";; *) bad "git grep failed";; esac

# only crates.io dependencies, lockfile present
[ -f Cargo.lock ] && ok "Cargo.lock committed" || bad "Cargo.lock missing"
if grep -nE 'git *=|registry *=' crates/*/Cargo.toml Cargo.toml; then bad "non-crates.io dependency"; else ok "deps from crates.io only"; fi

# storage: decoders must not use unwrap/expect/panic outside tests (clippy enforces; double-check)
for f in crates/novadb-storage/src/{btree,wal,recovery,pager,page}.rs; do
  body=$(sed '/#\[cfg(test)\]/,$d' "$f")
  if echo "$body" | grep -nE '\.unwrap\(\)|\.expect\(|panic!\(|unreachable!\(' ; then bad "$f: panic path in decoder"; fi
done
ok "decoder panic-path scan done"

# file permissions: data files 0600, dirs 0700
grep -q 'o.mode(0o600)' crates/novadb-storage/src/vfs.rs && grep -q 'b.mode(0o700)' crates/novadb-storage/src/vfs.rs \
  && ok "data files 0600 / dirs 0700" || bad "file permission hardening missing"

exit $FAIL
