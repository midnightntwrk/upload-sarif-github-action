#!/usr/bin/env bash
#
# Check out a commit's tree into a directory, for the differential gate's
# second scan pass.
#
#   materialise-base.sh <rev> <dest_dir> [repo_dir]
#
#   0  dest_dir now holds that commit's tree
#   1  the commit could not be obtained (unknown rev, fetch failed)
#   2  bad invocation
#
# Set GH_TOKEN to authenticate the fetch on a private repo.
#
# `git archive`, not a worktree or second clone: it yields a history-free tree,
# which is what +user-source stages anyway. A base tree carrying .git would make
# gitleaks and Scorecard behave differently across the two passes.

set -uo pipefail

usage() {
    echo "::error::$1" >&2
    echo "usage: $(basename "$0") <rev> <dest_dir> [repo_dir]" >&2
    exit 2
}

REV="${1:-}"
DEST="${2:-}"
REPO="${3:-${GITHUB_WORKSPACE:-.}}"

[ -n "$REV" ] || usage "no revision given"
[ -n "$DEST" ] || usage "no destination directory given"
[ -d "$REPO" ] || usage "repo directory '$REPO' does not exist"
git -C "$REPO" rev-parse --git-dir > /dev/null 2>&1 || usage "'$REPO' is not a git repository"

# Token via GIT_CONFIG_*, not argv (visible via `ps`) or .git/config (persists).
if [ -n "${GH_TOKEN:-}" ]; then
    b64="$(printf 'x-access-token:%s' "$GH_TOKEN" | base64 | tr -d '\n')"
    export GIT_CONFIG_COUNT=1
    export GIT_CONFIG_KEY_0=http.extraheader
    export GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $b64"
fi

# actions/checkout is shallow by default, so the target-branch commit is
# usually absent even though the ref exists upstream.
if ! git -C "$REPO" cat-file -e "${REV}^{commit}" 2>/dev/null; then
    # A remote takes object names and refs, nothing else. Sent a rev expression
    # git says `fatal: invalid refspec`, which hints at nothing - and only on a
    # shallow clone, where it could not be resolved locally first.
    case "$REV" in
        *'~'* | *'^'* | *'@{'* | *:*)
            echo "::error::'$REV' is not present locally and is not a fetchable object name" >&2
            echo "  Rev expressions (~ ^ @{} :) are not fetchable; pass a full commit SHA" >&2
            echo "  or a ref name. Resolve it first:  git rev-parse '$REV'" >&2
            exit 1
            ;;
    esac
    echo "Commit $REV not present locally; fetching."
    if ! git -C "$REPO" fetch --no-tags --depth=1 origin "$REV" 2>&1; then
        echo "::error::cannot obtain commit '$REV' from origin" >&2
        echo "  The differential gate needs the PR's target commit to scan." >&2
        echo "  On a private repo, pass the github_token input." >&2
        echo "  If the target branch was force-pushed, re-run the job." >&2
        exit 1
    fi
fi

# Staged, then moved into place once complete: a half-extracted tree scans as
# fewer findings than the target really has, reading as "this PR fixed something".
staging="${DEST}.partial.$$"
rm -rf "$staging" "$DEST"
mkdir -p "$staging"

if ! git -C "$REPO" archive "$REV" | tar -C "$staging" -xf -; then
    echo "::error::could not extract the tree of '$REV'" >&2
    rm -rf "$staging"
    exit 1
fi

mkdir -p "$(dirname "$DEST")"
mv "$staging" "$DEST"
echo "Materialised $REV into $DEST"
