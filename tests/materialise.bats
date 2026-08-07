#!/usr/bin/env bats
#
# Checking out the PR target's tree for the differential gate's second pass.

load helper

setup() {
    TMP="$(mktemp -d)"
    REPO="$TMP/repo"
    two_commit_repo "$REPO"
}

teardown() {
    rm -rf "$TMP"
}

# base <rev> [repo] -- destination is $TMP/out
base() {
    run bash "$BASE_SH" "$1" "$TMP/out" "${2:-$REPO}"
}

@test "materialises the tree of the requested commit" {
    base "$FIRST_SHA"
    [ "$status" -eq 0 ]
    [ -f "$TMP/out/first.txt" ]
    [ "$(cat "$TMP/out/first.txt")" = one ]
}

# The sharp end: if the rev argument were ignored and HEAD used instead,
# second.txt would be present.
@test "an earlier commit does not contain later files" {
    base "$FIRST_SHA"
    [ ! -e "$TMP/out/second.txt" ]
}

@test "the later commit contains both files, at their later contents" {
    base "$SECOND_SHA"
    [ -f "$TMP/out/second.txt" ]
    [ "$(cat "$TMP/out/first.txt")" = "one changed" ]
}

# +user-source strips .git before staging, so a base tree carrying history would
# make gitleaks and Scorecard behave differently between the two passes and the
# counts would not be comparable.
@test "the output tree carries no git history" {
    base "$SECOND_SHA"
    [ ! -e "$TMP/out/.git" ]
}

@test "a ref name works, not just a raw sha" {
    base "$(git -C "$REPO" symbolic-ref --short HEAD)"
    [ "$status" -eq 0 ]
    [ -f "$TMP/out/second.txt" ]
}

@test "a nested destination path is created" {
    run bash "$BASE_SH" "$SECOND_SHA" "$TMP/a/b/c" "$REPO"
    [ "$status" -eq 0 ]
    [ -f "$TMP/a/b/c/first.txt" ]
}

# A destination left over from an earlier run must be replaced, not merged: a
# stale file would be scanned as part of the target branch.
@test "an existing destination is replaced, not merged" {
    mkdir -p "$TMP/out"
    printf 'stale\n' > "$TMP/out/leftover.txt"
    base "$SECOND_SHA"
    [ "$status" -eq 0 ]
    [ ! -e "$TMP/out/leftover.txt" ]
}

@test "works against a real checkout" {
    if ! git -C "$ROOT" rev-parse --git-dir > /dev/null 2>&1; then
        skip "no .git here (the hermetic +test container)"
    fi
    run bash "$BASE_SH" HEAD "$TMP/out" "$ROOT"
    [ "$status" -eq 0 ]
    [ -f "$TMP/out/action.yml" ]
}

# 40 zeros: a well-formed object name, guaranteed absent. It must not be mistaken
# for "the target branch is empty", which would read as 0 findings and pass any PR.
@test "an absent commit fails rather than yielding an empty tree" {
    base 0000000000000000000000000000000000000000
    [ "$status" -eq 1 ]
}

@test "a failed materialisation leaves no partial tree" {
    base 0000000000000000000000000000000000000000
    [ -z "$(ls -A "$TMP/out" 2>/dev/null)" ]
}

# CI clones shallow, so HEAD~1 is absent, and `git fetch origin HEAD~1` reports
# `fatal: invalid refspec` - a remote takes object names and refs, not rev
# expressions. The diagnostic has to say so.
@test "a rev expression that is not local explains why it cannot be fetched" {
    base 'HEAD~99'
    [ "$status" -eq 1 ]
    [[ "$output" == *"not a fetchable"* ]]
    [[ "$output" == *"git rev-parse"* ]]
}

@test "an empty rev is rc 2" {
    base ''
    [ "$status" -eq 2 ]
}

@test "a missing destination argument is rc 2" {
    run bash "$BASE_SH" "$SECOND_SHA"
    [ "$status" -eq 2 ]
}

@test "a directory that is not a git repository is rc 2" {
    mkdir -p "$TMP/plain"
    base "$SECOND_SHA" "$TMP/plain"
    [ "$status" -eq 2 ]
}

@test "a repo directory that does not exist is rc 2" {
    base "$SECOND_SHA" "$TMP/nope"
    [ "$status" -eq 2 ]
}

# The token is passed via GIT_CONFIG_* so it never reaches argv (visible to any
# process via `ps`) or .git/config (persists on disk for later steps to leak).
@test "GH_TOKEN is not written into the repository config" {
    GH_TOKEN=s3cret run bash "$BASE_SH" "$SECOND_SHA" "$TMP/out" "$REPO"
    [ "$status" -eq 0 ]
    run grep -r extraheader "$REPO/.git/config"
    [ "$status" -ne 0 ]
}
