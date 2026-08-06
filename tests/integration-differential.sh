#!/usr/bin/env bash
#
# End-to-end test of the differential gate against a real scanner.
#
#   ./tests/integration-differential.sh
#
# Unit tests feed hand-written SARIF to the counter. This exercises the seam
# they cannot reach: a real scanner's real SARIF, through the counter, through
# the gate. It is the difference between "the arithmetic is right" and "the
# thing gates what we think it gates".
#
# gitleaks is the scanner used: no rule registry to fetch, no vulnerability
# database that changes underneath the test, and a private key is detected the
# same way on every run. Threshold is `warning`, because gitleaks emits no
# severity and SARIF 3.27.10 makes such a result a warning.
#
# Requires earth and a working docker. Skips (exit 0) if either is missing, so
# it can sit in a lint-only job without failing it.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
COUNT_SH="$ROOT/scripts/fail-on-severity.sh"
GATE_SH="$ROOT/scripts/differential-gate.sh"
THRESHOLD=warning

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() {
    FAIL=$((FAIL + 1))
    printf '  FAIL %s\n' "$1"
    [ -n "${2:-}" ] && printf '       %s\n' "$2"
    return 0
}

if ! command -v earth > /dev/null 2>&1; then
    echo "SKIP: earth not on PATH"
    exit 0
fi
if ! docker info > /dev/null 2>&1; then
    echo "SKIP: docker is not available"
    exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Two trees differing by exactly one secret. The key material is assembled at
# runtime rather than committed: a real secret in tests/ would be flagged by
# this repo's own gitleaks scan, and committing one to make a test pass is a
# bad habit to build into a security tool.
mkdir -p "$work/base" "$work/head"
{
    printf -- '-----BEGIN RSA PRIVATE KEY-----\n'
    printf 'MIIEowIBAAKCAQEAy8Dbv8prpJ%s\n' 'RXghtUOZ0kSTLPHmzoVCiVJ0dPjw1'
    printf -- '-----END RSA PRIVATE KEY-----\n'
} > "$work/base/id_rsa"
printf 'nothing to see here\n' > "$work/base/README.md"
# The "PR": the key is gone, everything else identical.
cp "$work/base/README.md" "$work/head/README.md"

# scan <tree> <label> -- echoes the finding count, or "ERR"
scan() {
    local tree="$1" label="$2"
    local out_dir="$work/reports-$label"
    local count_file="$work/count-$label"
    rm -rf "$ROOT/scan_reports" "$out_dir"
    mkdir -p "$out_dir"

    if ! (cd "$ROOT" && earth ./+gitleaks --USER_SOURCE_DIR="$tree") > "$work/earth-$label.log" 2>&1; then
        printf 'ERR'
        return
    fi
    if [ -d "$ROOT/scan_reports" ]; then
        cp -r "$ROOT/scan_reports/." "$out_dir/"
    fi

    FINDINGS_COUNT_FILE="$count_file" bash "$COUNT_SH" "$THRESHOLD" "$out_dir" > "$work/count-$label.log" 2>&1
    local rc=$?
    if [ "$rc" -gt 1 ]; then
        printf 'ERR'
        return
    fi
    cat "$count_file"
}

echo "== scanning the two trees with a real scanner =="
base_count="$(scan "$work/base" base)"
head_count="$(scan "$work/head" head)"

if [ "$base_count" = ERR ] || [ "$head_count" = ERR ]; then
    no "scan failed" "$(tail -5 "$work"/earth-*.log 2>/dev/null | tr '\n' '|')"
    printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
    exit 1
fi

# Asserted explicitly: if the scanner silently stopped detecting anything, every
# comparison below would still be arithmetically satisfiable and the test would
# pass while proving nothing.
if [ "$base_count" -gt 0 ]; then
    ok "scanner fires on the target tree ($base_count finding(s))"
else
    no "scanner found nothing in a tree containing a private key" \
       "the test would be vacuous; check $THRESHOLD threshold and gitleaks output"
fi
if [ "$head_count" -lt "$base_count" ]; then
    ok "the fix reduces the count ($base_count -> $head_count)"
else
    no "removing the secret did not reduce the count ($base_count -> $head_count)"
fi

echo "== the gate agrees =="
if bash "$GATE_SH" "$head_count" "$base_count" > /dev/null 2>&1; then
    ok "gate passes the PR that removes the secret"
else
    no "gate blocked a PR that removes the secret"
fi
if bash "$GATE_SH" "$base_count" "$base_count" > /dev/null 2>&1; then
    no "gate passed an unrelated PR while a finding is outstanding"
else
    ok "gate blocks an unrelated PR (count unchanged)"
fi
if bash "$GATE_SH" "$((base_count + 1))" "$base_count" > /dev/null 2>&1; then
    no "gate passed a PR that adds a finding"
else
    ok "gate blocks a PR that adds a finding"
fi

rm -rf "$ROOT/scan_reports"

echo
printf '%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
