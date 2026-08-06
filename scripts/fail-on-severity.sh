#!/usr/bin/env bash
#
# Count SARIF findings at or above a severity threshold.
#
#   fail-on-severity.sh <threshold> [reports_dir]
#
#   0  no findings at or above the threshold
#   1  one or more at or above it
#   2  bad invocation - distinct from 0 so the differential gate cannot read a
#      broken run as a clean scan
#
# FINDINGS_COUNT_FILE, if set, receives the count; stdout stays human-readable
# so a finding message can never be parsed as the count.

set -uo pipefail

JQ="$(cd "$(dirname "$0")" && pwd)/severity.jq"
SEVERITIES='{"NOTE":0,"WARNING":1,"LOW":1,"MEDIUM":2,"HIGH":3,"ERROR":4,"CRITICAL":5}'

usage() {
    echo "::error::$1" >&2
    echo "usage: $(basename "$0") <threshold> [reports_dir]" >&2
    echo "       threshold: one of critical, high, medium, low, warning, note" >&2
    exit 2
}

[ $# -ge 1 ] || usage "no severity threshold given"

THRESHOLD="$(printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]')"
REPORTS_DIR="${2:-scan_reports}"
COUNT_FILE="${FINDINGS_COUNT_FILE:-}"

[ -n "$THRESHOLD" ] || usage "empty severity threshold"
[ -f "$JQ" ] || usage "severity.jq not found next to this script (looked in $JQ)"

THRESHOLD_N="$(jq -rn --argjson s "$SEVERITIES" --arg t "$THRESHOLD" '$s[$t] // empty')"
[ -n "$THRESHOLD_N" ] || usage "unknown severity threshold '${1}' (accepted: $(jq -rn --argjson s "$SEVERITIES" '$s | keys_unsorted | join(", ") | ascii_downcase'))"

# Written on every non-error path, so callers never read a stale file.
write_count() {
    [ -n "$COUNT_FILE" ] && printf '%s\n' "$1" > "$COUNT_FILE"
    return 0
}

shopt -s nullglob
sarifs=("$REPORTS_DIR"/*.sarif)
shopt -u nullglob

if [ ${#sarifs[@]} -eq 0 ]; then
    # Not fatal, but worth shouting about: this used to exit 0 silently (the jq
    # failure inside a process substitution never propagated), so a misnamed
    # reports dir was a green build.
    echo "::warning::no SARIF files in '$REPORTS_DIR' - nothing to gate"
    write_count 0
    exit 0
fi

count=0
unknown=0

for f in "${sarifs[@]}"; do
    # Severity resolution and line formatting live in severity.jq, so this loop
    # only handles a count and ready-made strings - no fields to split, hence no
    # delimiter to get wrong. jq's status is checked on the assignment: after
    # `done < <(jq ...)` it would be the loop's status, i.e. whatever the body's
    # last command returned.
    if ! report="$(jq -f "$JQ" \
        --argjson map "$SEVERITIES" --argjson threshold "$THRESHOLD_N" "$f")"; then
        # No count written: a caller reading 0 from a failed parse would pass the
        # build, which is what rc 2 exists to prevent.
        echo "::error::could not parse SARIF in '''$f'''" >&2
        exit 2
    fi

    count=$((count + $(jq -r '''.count''' <<< "$report")))
    unknown=$((unknown + $(jq -r '''.unknown''' <<< "$report")))

    jq -r '''.findings[]?''' <<< "$report" | while IFS= read -r line; do
        [ -n "$line" ] && echo "  $line  [$f]"
    done

    # Unmapped severities (Trivy UNKNOWN, SARIF "none") are reported and skipped
    # rather than aborting mid-count: a partial count is a wrong verdict.
    jq -r '''.unmapped[]?''' <<< "$report" | while IFS= read -r line; do
        [ -n "$line" ] && echo "::warning::unmapped severity $line in $f - not gated"
    done
done

[ "$unknown" -gt 0 ] && echo "$unknown finding(s) had a severity outside the known set and were not gated"

write_count "$count"

if [ "$count" -gt 0 ]; then
    echo "$count finding(s) at or above severity $THRESHOLD."
    exit 1
fi

echo "No findings at or above severity $THRESHOLD."
exit 0
