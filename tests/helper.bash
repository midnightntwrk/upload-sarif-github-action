#!/usr/bin/env bash
# Shared setup for the bats suites.
#
# Every variable here is consumed by the .bats files that `load` this one, so
# the linter cannot see the uses. (A comment beginning with the linter's own
# name is parsed as a directive, hence the wording.)
# shellcheck disable=SC2034

ROOT="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
FIX="$BATS_TEST_DIRNAME/fixtures"
COUNT_SH="$ROOT/scripts/fail-on-severity.sh"
GATE_SH="$ROOT/scripts/differential-gate.sh"
BASE_SH="$ROOT/scripts/materialise-base.sh"
SEVERITY_JQ="$ROOT/scripts/severity.jq"
SEVERITIES='{"INFO":0,"NONE":0,"NOTE":0,"LOW":1,"WARNING":1,"MEDIUM":2,"HIGH":3,"ERROR":3,"CRITICAL":4}'

# Keep scratch-repo git calls away from the user's config: commit signing would
# prompt, and a global core.hooksPath would run this repo's hooks in a fixture.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid

# count_findings <reports_dir> <threshold>
#
# Runs the counter and exposes both halves of its contract: $status, $output and
# $count. $count is the string "<none>" when no count file was written, which is
# the required behaviour on a bad invocation - a caller that read 0 there would
# pass the build.
count_findings() {
    local dir="$1" threshold="$2" tmp
    tmp="$(mktemp -d)"
    run env FINDINGS_COUNT_FILE="$tmp/c" bash "$COUNT_SH" "$threshold" "$dir"
    count="$(cat "$tmp/c" 2>/dev/null || echo '<none>')"
    rm -rf "$tmp"
}

# sarif <path> <json>  -- write a one-off SARIF document
sarif() {
    mkdir -p "$(dirname "$1")"
    printf '%s\n' "$2" > "$1"
}

# two_commit_repo <path>  -- a repo with no remote, so a fetch attempt fails
# locally instead of reaching the network. FIRST_SHA and SECOND_SHA are set.
two_commit_repo() {
    local repo="$1"
    git init -q "$repo"
    printf 'one\n' > "$repo/first.txt"
    git -C "$repo" add .
    git -C "$repo" commit -qm first
    FIRST_SHA="$(git -C "$repo" rev-parse HEAD)"
    printf 'two\n' > "$repo/second.txt"
    printf 'one changed\n' > "$repo/first.txt"
    git -C "$repo" add .
    git -C "$repo" commit -qm second
    SECOND_SHA="$(git -C "$repo" rev-parse HEAD)"
}
