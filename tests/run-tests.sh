#!/usr/bin/env bash
#
# Unit tests for the severity gate scripts. No containers, no network:
# fixtures in tests/fixtures/ are plain SARIF, the scripts are plain bash.
#
#   ./tests/run-tests.sh
#
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
FIX="$HERE/fixtures"
COUNT_SH="$ROOT/scripts/fail-on-severity.sh"
GATE_SH="$ROOT/scripts/differential-gate.sh"

PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() {
    FAIL=$((FAIL + 1))
    printf '  FAIL %s\n' "$1"
    [ -n "${2:-}" ] && printf '       %s\n' "$2"
    return 0
}

# count_case <fixture> <threshold> <want_count> <want_rc>
#
# Asserts both the count written to the count file and the exit status, so a
# script that gets the number right but the exit code wrong still fails.
count_case() {
    local fixture="$1" threshold="$2" want_count="$3" want_rc="$4"
    local cf d out rc got
    # A path that does not exist yet: `mktemp` would create the file, so an
    # empty read would be indistinguishable from "the script wrote nothing".
    d="$(mktemp -d)"
    cf="$d/count"
    out="$(FINDINGS_COUNT_FILE="$cf" bash "$COUNT_SH" "$threshold" "$FIX/$fixture" 2>&1)"
    rc=$?
    got="$(cat "$cf" 2>/dev/null || echo '<no count file>')"
    rm -rf "$d"

    if [ "$got" = "$want_count" ] && [ "$rc" = "$want_rc" ]; then
        ok "count $fixture @$threshold -> $want_count (rc $want_rc)"
    else
        no "count $fixture @$threshold -> want $want_count/rc $want_rc, got $got/rc $rc" \
           "$(printf '%s' "$out" | head -3 | tr '\n' '|')"
    fi
}

# gate_case <head> <base> <want_rc>
gate_case() {
    local head="$1" base="$2" want_rc="$3" out rc
    out="$(bash "$GATE_SH" "$head" "$base" 2>&1)"
    rc=$?
    if [ "$rc" = "$want_rc" ]; then
        ok "gate head=$head base=$base -> rc $want_rc"
    else
        no "gate head=$head base=$base -> want rc $want_rc, got $rc" \
           "$(printf '%s' "$out" | head -2 | tr '\n' '|')"
    fi
}

echo "== severity counting =="
count_case one-high    high 1 1
count_case two-high    high 2 1   # HIGH + CRITICAL both >= high
count_case note-only   high 0 0   # NOTE and MEDIUM are below high
count_case note-only   medium 1 1 # ... but MEDIUM counts at medium
count_case empty       high 0 0   # a SARIF run with no results
# Regression pin: a finding carrying neither `locations` nor `message`. Empty
# trailing fields must survive the read (tab is IFS whitespace, so `IFS=$'\t'
# read` collapses them and shifts every later column), and an empty message
# must not leave the loop with a non-zero status that reads as a parse failure.
count_case no-detail   high 1 1
count_case nonexistent high 0 0   # missing dir: 0 findings, not a crash

echo "== unmapped severities must not abort the count =="
# Regression: `${SEVERITY_MAP[$sev]}` under `set -u` aborts on an unknown key,
# so a single Trivy UNKNOWN killed the whole gate with "unbound variable".
# Worse for the differential gate, where a partial count is a wrong verdict.
count_case unknown-sev high 0 0
count_case level-none  high 0 0
count_case mixed       high 2 1   # across two files: HIGH + CRITICAL counted, UNKNOWN skipped

echo "== a result with no severity defaults to warning, per SARIF 3.27.10 =="
# gitleaks emits neither `level` nor `properties.severity`, and sets no
# rule-level defaultConfiguration either (checked against 8.30.1: 222 rules,
# none carrying a level). Dropping such results meant a committed private key
# could not fail the build at ANY threshold - verified before this fix.
count_case no-severity note    1 1
count_case no-severity warning 1 1
count_case no-severity medium  0 0   # warning is below medium, so still not gated there
# A rule-level default is the documented fallback and outranks the bare default.
count_case rule-default-error high 1 1

echo "== invocation errors are rc 2, never a silent pass =="
# rc 0 = clean, rc 1 = findings at or above threshold, rc 2 = bad invocation.
# The differential gate must be able to tell "no findings" from "gate broken";
# conflating them turns a typo in fail_severity into a green build.
# No count file at all on rc 2 - deliberately stronger than "writes 0". A caller
# that read 0 out of a broken invocation would pass the build, which is the
# failure mode this exit status exists to prevent.
count_case one-high hgh '<no count file>' 2   # typo in fail_severity
count_case one-high ''  '<no count file>' 2   # empty threshold

echo "== differential gate: pass only when the count goes down =="
gate_case 1 2 0   # a genuine fix: 2 -> 1
gate_case 0 2 0   # fixes both
gate_case 1 1 1   # unchanged count (incl. a straight swap) does not pass
gate_case 2 1 1   # regression
gate_case 1 0 1   # clean target, PR introduces one
gate_case 0 0 0   # nothing anywhere
gate_case 1 '' 2  # missing base count is a broken invocation, not a pass
gate_case x 2 2   # non-numeric

echo
printf '%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
