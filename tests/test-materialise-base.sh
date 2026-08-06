#!/usr/bin/env bash
#
# Tests for scripts/materialise-base.sh against this repository's own git
# objects. No containers, no network (every rev used is already local).
#
#   ./tests/test-materialise-base.sh
#
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
SCRIPT="$ROOT/scripts/materialise-base.sh"

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() {
    FAIL=$((FAIL + 1))
    printf '  FAIL %s\n' "$1"
    [ -n "${2:-}" ] && printf '       %s\n' "$2"
    return 0
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# run <label> <rev> <want_rc> -- asserts exit status and sets $DEST.
#
# Sets a global rather than echoing the path: ok/no also write to stdout, so a
# `dest="$(run ...)"` capture swallows the assertion lines into the path.
DEST=""
run() {
    local label="$1" rev="$2" want_rc="$3" out rc
    DEST="$work/$label"
    out="$(bash "$SCRIPT" "$rev" "$DEST" "$ROOT" 2>&1)"
    rc=$?
    if [ "$rc" = "$want_rc" ]; then
        ok "$label -> rc $want_rc"
    else
        no "$label -> want rc $want_rc, got $rc" "$(printf '%s' "$out" | head -2 | tr '\n' '|')"
    fi
}

echo "== materialising a real commit =="
run head HEAD 0
dest="$DEST"
if [ -f "$dest/action.yml" ]; then ok "head: action.yml present"; else no "head: action.yml missing"; fi
if [ -f "$dest/Earthfile" ]; then ok "head: Earthfile present"; else no "head: Earthfile missing"; fi

# The scanners run against a tree staged by +user-source, which strips .git.
# Handing them a tree that still had history would make gitleaks and Scorecard
# behave differently between the base and head passes, so the two counts would
# not be comparable. `git archive` gives a history-free tree by construction;
# this pins that.
if [ -e "$dest/.git" ]; then no "head: .git leaked into the base tree"; else ok "head: no .git in output"; fi

echo "== an older commit gives a different tree =="
run prev HEAD~1 0
dest_prev="$DEST"
if [ -f "$dest_prev/action.yml" ]; then ok "prev: action.yml present"; else no "prev: action.yml missing"; fi
if [ -n "$(diff -rq "$dest" "$dest_prev" 2>&1)" ]; then
    ok "prev: tree differs from HEAD"
else
    no "prev: tree identical to HEAD" "materialise-base is probably ignoring its rev argument"
fi

echo "== failures are loud, and never leave a usable half-tree =="
# 40 zeros: well-formed as a sha, guaranteed absent. Must not be mistaken for
# "an empty base branch", which would read as 0 findings and pass any PR.
run bogus 0000000000000000000000000000000000000000 1
dest_bogus="$DEST"
if [ -d "$dest_bogus" ] && [ -n "$(ls -A "$dest_bogus" 2>/dev/null)" ]; then
    no "bogus: left files behind" "a partial tree scans as fewer findings than reality"
else
    ok "bogus: no partial tree left behind"
fi

run empty-rev '' 2

# Missing destination argument entirely - `run` always supplies one, so this
# calls the script directly. rc is captured before any other command runs:
# `[ "$?" = 2 ]` in an else branch reads the status of the preceding test.
bash "$SCRIPT" HEAD > /dev/null 2>&1
rc=$?
if [ "$rc" = 2 ]; then ok "no dest arg -> rc 2"; else no "no dest arg -> want rc 2, got $rc"; fi

echo
printf '%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
