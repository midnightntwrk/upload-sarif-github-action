#!/usr/bin/env bash
#
# Tests for scripts/materialise-base.sh.
#
#   ./tests/test-materialise-base.sh
#
# Most assertions run against a scratch repository built here, not against this
# checkout: CI clones shallow (actions/checkout defaults to fetch-depth 1), so
# `HEAD~1` does not exist on the runner and any test depending on local history
# passes on a laptop and fails in CI.
#
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
SCRIPT="$ROOT/scripts/materialise-base.sh"

# Isolate every scratch-repo git call from the user's configuration: commit
# signing would prompt or fail, and a global core.hooksPath would run this
# repo's hooks inside the fixture.
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null
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

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# run <label> <rev> <want_rc> [repo] -- asserts exit status, sets $DEST and $OUT.
#
# Sets globals rather than echoing: ok/no also write to stdout, so a
# `dest="$(run ...)"` capture swallows the assertion lines into the path.
DEST=""
OUT=""
run() {
    local label="$1" rev="$2" want_rc="$3" repo="${4:-$ROOT}" rc
    DEST="$work/$label"
    OUT="$(bash "$SCRIPT" "$rev" "$DEST" "$repo" 2>&1)"
    rc=$?
    if [ "$rc" = "$want_rc" ]; then
        ok "$label -> rc $want_rc"
    else
        no "$label -> want rc $want_rc, got $rc" "$(printf '%s' "$OUT" | head -3 | tr '\n' '|')"
    fi
}

# A two-commit repository with no remote. No remote is deliberate: a fetch
# attempt must fail fast and locally rather than reaching the network, so these
# tests behave identically on an air-gapped runner.
repo="$work/fixture-repo"
git init -q "$repo"
printf 'one\n' > "$repo/first.txt"
git -C "$repo" add first.txt
git -C "$repo" commit -qm first
first_sha="$(git -C "$repo" rev-parse HEAD)"
printf 'two\n' > "$repo/second.txt"
printf 'one changed\n' > "$repo/first.txt"
git -C "$repo" add .
git -C "$repo" commit -qm second
second_sha="$(git -C "$repo" rev-parse HEAD)"

echo "== the rev argument selects the tree =="
run first "$first_sha" 0 "$repo"
dest_first="$DEST"
if [ -f "$dest_first/first.txt" ]; then ok "first: first.txt present"; else no "first: first.txt missing"; fi
# The sharp end: if the script ignored its rev and used the working tree or
# HEAD, second.txt would be here.
if [ -e "$dest_first/second.txt" ]; then
    no "first: second.txt present" "the rev argument is being ignored - this is HEAD's tree, not the requested commit"
else
    ok "first: second.txt absent"
fi
if [ "$(cat "$dest_first/first.txt" 2>/dev/null)" = one ]; then
    ok "first: file content is from that commit"
else
    no "first: file content is not the version at that commit"
fi

run second "$second_sha" 0 "$repo"
dest_second="$DEST"
if [ -f "$dest_second/second.txt" ]; then ok "second: second.txt present"; else no "second: second.txt missing"; fi
if [ "$(cat "$dest_second/first.txt" 2>/dev/null)" = "one changed" ]; then
    ok "second: file content is from that commit"
else
    no "second: file content is not the version at that commit"
fi

echo "== the output tree carries no history =="
# +user-source strips .git before staging, so a base tree that still had
# history would make gitleaks and Scorecard behave differently between the two
# passes and the counts would not be comparable. `git archive` gives a
# history-free tree by construction; this pins it.
if [ -e "$dest_second/.git" ]; then no "second: .git leaked into the base tree"; else ok "second: no .git in output"; fi

echo "== against this checkout, however shallow =="
run head HEAD 0
dest="$DEST"
if [ -f "$dest/action.yml" ]; then ok "head: action.yml present"; else no "head: action.yml missing"; fi
if [ -f "$dest/Earthfile" ]; then ok "head: Earthfile present"; else no "head: Earthfile missing"; fi

echo "== failures are loud, and never leave a usable half-tree =="
# 40 zeros: well-formed as an object name, guaranteed absent. Must not be
# mistaken for "an empty base branch", which reads as 0 findings and passes
# any PR.
run bogus 0000000000000000000000000000000000000000 1 "$repo"
if [ -d "$DEST" ] && [ -n "$(ls -A "$DEST" 2>/dev/null)" ]; then
    no "bogus: left files behind" "a partial tree scans as fewer findings than reality"
else
    ok "bogus: no partial tree left behind"
fi

# Regression: a rev expression that is not present locally. `git fetch origin
# HEAD~1` is `fatal: invalid refspec`, which says nothing about what to do.
# Only an object name or a ref can be fetched from a remote.
run rev-expr 'HEAD~99' 1 "$repo"
if printf '%s' "$OUT" | grep -q 'not a fetchable'; then
    ok "rev-expr: diagnostic explains why it cannot be fetched"
else
    no "rev-expr: unhelpful diagnostic" "$(printf '%s' "$OUT" | head -2 | tr '\n' '|')"
fi

run empty-rev '' 2
run not-a-repo HEAD 2 "$work"

# Missing destination argument entirely - `run` always supplies one, so this
# calls the script directly. rc is captured before any other command runs:
# `[ "$?" = 2 ]` in an else branch reads the status of the preceding test.
bash "$SCRIPT" HEAD > /dev/null 2>&1
rc=$?
if [ "$rc" = 2 ]; then ok "no dest arg -> rc 2"; else no "no dest arg -> want rc 2, got $rc"; fi

echo
printf '%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
