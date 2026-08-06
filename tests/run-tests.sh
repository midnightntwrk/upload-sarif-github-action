#!/usr/bin/env bash
#
# Unit tests for the gate scripts. No containers, no network.
#
#   ./tests/run-tests.sh
#
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
FIX="$HERE/fixtures"
COUNT_SH="$ROOT/scripts/fail-on-severity.sh"
GATE_SH="$ROOT/scripts/differential-gate.sh"
BASE_SH="$ROOT/scripts/materialise-base.sh"

# Isolate scratch-repo git calls from user config: commit signing would prompt,
# and a global core.hooksPath would run this repo's hooks in the fixture.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() {
    FAIL=$((FAIL + 1))
    printf '  FAIL %s\n' "$1"
    [ -n "${2:-}" ] && printf '       %s\n' "$2"
    return 0
}
# is <label> <test args...> - passes the condition as real arguments to test(1),
# never as a string: `[ "$condition" ]` would only check it is non-empty and
# every assertion would pass vacuously.
is() { local l="$1"; shift; if test "$@"; then ok "$l"; else no "$l"; fi; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# count <fixture> <threshold> <want_count> <want_rc>
# Asserts the count AND the exit status: right number, wrong exit code still fails.
count() {
    local d out rc got
    # A path that does not exist yet - mktemp would create the file, making an
    # empty read indistinguishable from "the script wrote nothing".
    d="$(mktemp -d)"
    out="$(FINDINGS_COUNT_FILE="$d/c" bash "$COUNT_SH" "$2" "$FIX/$1" 2>&1)"
    rc=$?
    got="$(cat "$d/c" 2>/dev/null || echo '<none>')"
    rm -rf "$d"
    if [ "$got" = "$3" ] && [ "$rc" = "$4" ]; then
        ok "count $1 @$2 -> $3 (rc $4)"
    else
        no "count $1 @$2 -> want $3/rc $4, got $got/rc $rc" \
           "$(printf '%s' "$out" | head -2 | tr '\n' '|')"
    fi
}

# gate <head> <base> <want_rc>
gate() {
    local out rc
    out="$(bash "$GATE_SH" "$1" "$2" 2>&1)"
    rc=$?
    if [ "$rc" = "$3" ]; then
        ok "gate head=$1 base=$2 -> rc $3"
    else
        no "gate head=$1 base=$2 -> want rc $3, got $rc" "$(printf '%s' "$out" | head -1)"
    fi
}

echo "== severity counting =="
count one-high    high   1 1
count two-high    high   2 1   # HIGH + CRITICAL both >= high
count note-only   high   0 0
count note-only   medium 1 1
count empty       high   0 0   # a run with no results
count no-detail   high   1 1   # no locations, no message: empty trailing fields must survive
count nonexistent high   0 0   # missing dir: 0 findings, not a crash
count mixed       high   2 1   # across two files, UNKNOWN skipped

# Regression: `${SEVERITY_MAP[$sev]}` under `set -u` aborts on an unknown key,
# so one Trivy UNKNOWN killed the gate. A partial count is a wrong verdict.
echo "== unmapped severities must not abort the count =="
count unknown-sev high 0 0
count level-none  high 0 0

# gitleaks emits no severity and no rule-level default (8.30.1: 222 rules, none
# with a level), so dropping these meant a committed private key could not fail
# the build at ANY threshold.
echo "== no severity defaults to warning, per SARIF 3.27.10 =="
count no-severity        note    1 1
count no-severity        warning 1 1
count no-severity        medium  0 0   # warning is below medium
count rule-default-error high    1 1   # rule default outranks the bare default

# rc 0 clean, 1 findings, 2 bad invocation. Conflating 0 and 2 turns a typo in
# fail_severity into a green build, so rc 2 writes no count at all.
echo "== invocation errors are rc 2, never a silent pass =="
count one-high hgh '<none>' 2
count one-high ''  '<none>' 2

echo "== differential gate: pass only when the count goes down =="
gate 1 2 0   # a genuine fix
gate 0 2 0   # fixes both
gate 1 1 1   # unchanged, incl. a straight swap
gate 2 1 1   # regression
gate 1 0 1   # clean target, PR adds one
gate 0 0 0   # nothing anywhere
gate 1 '' 2
gate x 2  2

# A two-commit repo with no remote: a fetch attempt must fail locally rather
# than reach the network, so these behave the same on an air-gapped runner.
repo="$work/repo"
git init -q "$repo"
printf 'one\n' > "$repo/first.txt"
git -C "$repo" add . && git -C "$repo" commit -qm first
first="$(git -C "$repo" rev-parse HEAD)"
printf 'two\n' > "$repo/second.txt"
printf 'one changed\n' > "$repo/first.txt"
git -C "$repo" add . && git -C "$repo" commit -qm second
second="$(git -C "$repo" rev-parse HEAD)"

# base <label> <rev> <want_rc> [repo] -- sets $DEST and $OUT
DEST=""
OUT=""
base() {
    local rc
    DEST="$work/$1"
    OUT="$(bash "$BASE_SH" "$2" "$DEST" "${4:-$ROOT}" 2>&1)"
    rc=$?
    if [ "$rc" = "$3" ]; then
        ok "base $1 -> rc $3"
    else
        no "base $1 -> want rc $3, got $rc" "$(printf '%s' "$OUT" | head -2 | tr '\n' '|')"
    fi
}

echo "== base materialisation: the rev argument selects the tree =="
base first "$first" 0 "$repo"
is "first: first.txt present" -f "$DEST/first.txt"
# The sharp end: if the rev were ignored, second.txt would be here.
is "first: second.txt absent (rev honoured)" ! -e "$DEST/second.txt"
is "first: content is that commit's" "$(cat "$DEST/first.txt" 2>/dev/null)" = one

base second "$second" 0 "$repo"
is "second: second.txt present" -f "$DEST/second.txt"
# +user-source strips .git, so a base tree carrying history would make gitleaks
# and Scorecard behave differently across the two passes.
is "second: no .git in output" ! -e "$DEST/.git"

# Skipped in the hermetic +test container, which has no .git.
if git -C "$ROOT" rev-parse --git-dir > /dev/null 2>&1; then
    base head HEAD 0
    is "head: works against a real checkout" -f "$DEST/action.yml"
fi

echo "== base materialisation fails loudly, leaving no half-tree =="
# 40 zeros: valid object name, guaranteed absent. Must not read as "empty base
# branch", which would be 0 findings and pass any PR.
base bogus 0000000000000000000000000000000000000000 1 "$repo"
# A partial tree scans as fewer findings than reality.
is "bogus: no partial tree left behind" -z "$(ls -A "$DEST" 2>/dev/null)"

# CI clones shallow, so HEAD~1 is absent and `git fetch origin HEAD~1` is
# `fatal: invalid refspec` - a remote takes object names and refs, not rev
# expressions.
base rev-expr 'HEAD~99' 1 "$repo"
hits="$(printf '%s' "$OUT" | grep -c 'not a fetchable')"
is "rev-expr: diagnostic explains why it cannot be fetched" "$hits" -ge 1

base empty-rev ''   2
base not-a-repo HEAD 2 "$work"
bash "$BASE_SH" HEAD > /dev/null 2>&1
rc=$?
is "base: no dest arg -> rc 2" "$rc" = 2

echo
printf '%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
