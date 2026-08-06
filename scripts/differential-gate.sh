#!/usr/bin/env bash
#
# Decide a PR's fate from two finding counts.
#
#   differential-gate.sh <head_count> <base_count>
#
#   0  head < base - the PR strictly reduces the finding count
#   1  blocked
#   2  bad invocation
#
# Strictly fewer, not fewer-or-equal: while findings are outstanding on the
# target, only changes that remove one may land. An unrelated PR leaves the
# count level and is blocked - the point, not a side-effect.
#
# A PR removing two findings and adding a third still passes (2 -> 1). Accepted
# deliberately: the count is the whole contract, so there is nothing to
# fingerprint and a line shift cannot fool it.

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
    # Unreachable in the action (a clean head scan never triggers the base pass),
    # but explicit rather than emergent from `0 < 0`: blocking a PR with no
    # findings would be indefensible.
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
    echo "This PR neither adds nor removes a finding. While any are outstanding,"
    echo "only changes that reduce the count can land: fix at least one, or wait"
    echo "for a fix to merge. A PR swapping one finding for another lands here too."
fi
exit 1
