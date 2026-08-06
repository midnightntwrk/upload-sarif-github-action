#!/usr/bin/env bash
#
# End-to-end test of the differential gate against a real scanner.
#
#   ./tests/integration-differential.sh
#
# Unit tests feed hand-written SARIF to the counter. This covers the seam they
# cannot reach - a real scanner's real SARIF, through the counter, through the
# gate - which is how the "gitleaks findings were never gated" bug surfaced.
#
# gitleaks: no rule registry to fetch, no vulnerability database changing under
# the test. Threshold is `warning`, since gitleaks emits no severity and SARIF
# 3.27.10 makes such a result a warning.
#
# Skips (exit 0) without earth or docker, so it can sit in a lint-only job.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
THRESHOLD=warning

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; return 0; }

command -v earth > /dev/null 2>&1 || { echo "SKIP: earth not on PATH"; exit 0; }
docker info > /dev/null 2>&1 || { echo "SKIP: docker unavailable"; exit 0; }

work="$(mktemp -d)"
trap 'rm -rf "$work" "$ROOT/scan_reports"' EXIT

# Two trees differing by exactly one secret. Key material is assembled at
# runtime, not committed: a real secret in tests/ would be flagged by this
# repo's own gitleaks scan, and committing one to make a security tool's test
# pass is a bad habit to build in.
mkdir -p "$work/base" "$work/head"
{
    printf -- '-----BEGIN RSA PRIVATE KEY-----\n'
    printf 'MIIEowIBAAKCAQEAy8Dbv8prpJ%s\n' 'RXghtUOZ0kSTLPHmzoVCiVJ0dPjw1'
    printf -- '-----END RSA PRIVATE KEY-----\n'
} > "$work/base/id_rsa"
printf 'nothing to see here\n' > "$work/base/README.md"
cp "$work/base/README.md" "$work/head/README.md"   # the "PR": key removed

# scan <tree> <label> -- echoes the finding count, or ERR
scan() {
    local reports="$work/reports-$2"
    rm -rf "$ROOT/scan_reports"
    mkdir -p "$reports"
    (cd "$ROOT" && earth ./+gitleaks --USER_SOURCE_DIR="$1") > "$work/earth-$2.log" 2>&1 \
        || { printf ERR; return; }
    [ -d "$ROOT/scan_reports" ] && cp -r "$ROOT/scan_reports/." "$reports/"
    local rc=0
    FINDINGS_COUNT_FILE="$work/count-$2" bash "$ROOT/scripts/fail-on-severity.sh" \
        "$THRESHOLD" "$reports" > "$work/count-$2.log" 2>&1 || rc=$?
    [ "$rc" -gt 1 ] && { printf ERR; return; }
    cat "$work/count-$2"
}

echo "== scanning two trees with a real scanner =="
base_count="$(scan "$work/base" base)"
head_count="$(scan "$work/head" head)"

if [ "$base_count" = ERR ] || [ "$head_count" = ERR ]; then
    no "scan failed" "$(tail -5 "$work"/earth-*.log 2>/dev/null | tr '\n' '|')"
    printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
    exit 1
fi

# Asserted explicitly: if the scanner silently stopped detecting anything, every
# comparison below is still satisfiable and the test would prove nothing.
if [ "$base_count" -gt 0 ]; then
    ok "scanner fires on the target tree ($base_count finding(s))"
else
    no "scanner found nothing in a tree containing a private key" "test would be vacuous"
fi
if [ "$head_count" -lt "$base_count" ]; then
    ok "the fix reduces the count ($base_count -> $head_count)"
else
    no "removing the secret did not reduce the count ($base_count -> $head_count)"
fi

echo "== the gate agrees =="
gate() {  # gate <head> <base> <want_pass 0|1> <label>
    local rc=0
    bash "$ROOT/scripts/differential-gate.sh" "$1" "$2" > /dev/null 2>&1 || rc=$?
    if [ "$rc" = "$3" ]; then ok "$4"; else no "$4"; fi
}
gate "$head_count" "$base_count"       0 "passes the PR that removes the secret"
gate "$base_count" "$base_count"       1 "blocks an unrelated PR (count unchanged)"
gate "$((base_count + 1))" "$base_count" 1 "blocks a PR that adds a finding"

echo
printf '%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
