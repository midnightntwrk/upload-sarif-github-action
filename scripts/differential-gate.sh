#!/usr/bin/env bash
#
# Decide a PR's fate from two finding counts.
#
#   differential-gate.sh <head_count> <base_count>
#
#   0  head < base   - the PR strictly reduces the finding count
#   1  otherwise     - blocked
#   2  bad invocation
#
# Strictly-fewer, not fewer-or-equal: while findings at or above the threshold
# are outstanding on the target branch, the only changes allowed to land are
# ones that remove at least one. An unrelated PR leaves the count unchanged and
# is blocked - that is the point, not a side-effect.
#
# A PR that removes two findings and introduces a third still passes (2 -> 1).
# Accepted deliberately: the count is the whole contract, so this needs no
# fingerprinting and cannot be fooled by a line shift.

set -uo pipefail

usage() {
    echo "::error::$1" >&2
    echo "usage: $(basename "$0") <head_count> <base_count>" >&2
    exit 2
}

HEAD_COUNT="${1:-}"
BASE_COUNT="${2:-}"

case "$HEAD_COUNT" in '' | *[!0-9]*) usage "head count '$HEAD_COUNT' is not a non-negative integer" ;; esac
case "$BASE_COUNT" in '' | *[!0-9]*) usage "base count '$BASE_COUNT' is not a non-negative integer" ;; esac

if [ "$HEAD_COUNT" -eq 0 ]; then
    # Unreachable in the action (a clean head scan never triggers the base
    # pass), but a gate that blocks a PR with no findings at all would be
    # indefensible, so it is explicit rather than emergent from `0 < 0`.
    echo "No findings at or above the threshold with this PR applied. Passing."
    exit 0
fi

if [ "$HEAD_COUNT" -lt "$BASE_COUNT" ]; then
    echo "Findings: $BASE_COUNT on the target branch, $HEAD_COUNT with this PR applied."
    echo "The count goes down. Passing."
    exit 0
fi

echo "::error::this PR does not reduce the number of findings at or above the severity threshold"
echo "  target branch: $BASE_COUNT finding(s)"
echo "  with this PR:  $HEAD_COUNT finding(s)"
echo

if [ "$HEAD_COUNT" -gt "$BASE_COUNT" ]; then
    echo "The PR introduces $((HEAD_COUNT - BASE_COUNT)) new finding(s). Fix them."
else
    echo "The target branch has outstanding findings, and this PR neither adds nor"
    echo "removes any. While findings are outstanding, only changes that reduce the"
    echo "count can land. Either fix at least one, or wait for a fix to merge."
    echo
    echo "A PR that swaps one finding for another also lands here: the count is"
    echo "unchanged, so it does not pass."
fi
exit 1
