#!/usr/bin/env bash
#
# Count SARIF findings at or above a severity threshold.
#
#   fail-on-severity.sh <threshold> [reports_dir]
#
# Exit status is three-valued, because the differential gate has to tell a
# clean scan from a broken invocation:
#
#   0  no findings at or above the threshold
#   1  one or more findings at or above the threshold
#   2  bad invocation (unknown threshold, unreadable reports)
#
# Set FINDINGS_COUNT_FILE to have the count written there. stdout stays
# human-readable, so a finding message can never be mistaken for the count.

set -uo pipefail

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

THRESHOLD_N="$(jq -rn --argjson s "$SEVERITIES" --arg t "$THRESHOLD" '$s[$t] // empty')"
[ -n "$THRESHOLD_N" ] || usage "unknown severity threshold '${1}' (accepted: $(jq -rn --argjson s "$SEVERITIES" '$s | keys_unsorted | join(", ") | ascii_downcase'))"

# Emit the count even on the early-return paths, so callers never read a stale file.
write_count() {
    [ -n "$COUNT_FILE" ] && printf '%s\n' "$1" > "$COUNT_FILE"
    return 0
}

shopt -s nullglob
sarifs=("$REPORTS_DIR"/*.sarif)
shopt -u nullglob

if [ ${#sarifs[@]} -eq 0 ]; then
    # Not fatal: a caller may gate a directory that legitimately has no reports
    # yet. It IS worth shouting about, because the old code silently exited 0
    # here (the jq failure inside a process substitution never propagated),
    # which turned a misnamed reports dir into a green build.
    echo "::warning::no SARIF files in '$REPORTS_DIR' - nothing to gate"
    write_count 0
    exit 0
fi

count=0
unknown=0

US=$'\x1f'  # Fields are unit-separated, not tab-separated: tab is IFS
            # whitespace, so `read` collapses runs of it and drops empty
            # fields, shifting every column after a finding with no location.

for f in "${sarifs[@]}"; do
    # One jq pass per file. Severity resolution happens in jq so that an
    # unmapped value (Trivy's UNKNOWN, SARIF's level "none", Scorecard's
    # numeric scores) is reported and skipped rather than aborting the run
    # mid-count - a partial count is a wrong verdict, not a near-miss.
    #
    # jq's status is checked here, on the assignment. Checking it after `done
    # < <(jq ...)` does not work: that observes the *loop's* status, which is
    # whatever the last command in the body returned.
    if ! rows="$(
        jq -r --argjson map "$SEVERITIES" --argjson threshold "$THRESHOLD_N" --arg us "$US" '
            .runs[]?
            # Rule-level defaults, by rule id, for results that carry no level
            # of their own. SARIF 3.27.10: result.level, else the rule default,
            # else "warning" - a result with no severity anywhere is a warning,
            # not something to ignore. gitleaks emits no severity at all, so
            # dropping these meant a committed private key could not fail the
            # build at any threshold.
            | ( [ (.tool.driver.rules // [])[]
                  | select(.id != null and .defaultConfiguration.level != null)
                  | {key: .id, value: (.defaultConfiguration.level | ascii_upcase)} ]
                | from_entries ) as $ruleLevels
            | .results[]?
            | (.level // "" | tostring | ascii_upcase) as $level
            | (.properties.severity // "" | tostring | ascii_upcase) as $prop
            | ($ruleLevels[.ruleId // ""] // "") as $ruleLevel
            | (if $level != "" then $level
               elif $prop != "" then $prop
               elif $ruleLevel != "" then $ruleLevel
               else "WARNING" end) as $sev
            | ($map[$sev]) as $n
            | [ (if $n == null then "UNK" elif $n >= $threshold then "HIT" else "SKIP" end),
                $sev,
                (.ruleId // ""),
                (.locations[0].physicalLocation.artifactLocation.uri // ""),
                ((.message.text // "") | gsub("[\n\t]"; " "))
              ]
            | select(.[0] != "SKIP")
            | join($us)
        ' "$f"
    )"; then
        # No count is written: a caller that read 0 out of a failed parse would
        # pass the build, which is exactly what rc 2 exists to prevent.
        echo "::error::could not parse SARIF in '$f'" >&2
        exit 2
    fi

    while IFS="$US" read -r tag sev rule file message; do
        case "$tag" in
            HIT)
                count=$((count + 1))
                echo "$sev finding in $f"
                [ -n "$rule" ] && echo "  Rule: $rule"
                [ -n "$file" ] && echo "  File: $file"
                [ -n "$message" ] && echo "  Message: $message"
                ;;
            UNK)
                unknown=$((unknown + 1))
                echo "::warning::unmapped severity '$sev' in $f (rule ${rule:-?}) - not gated"
                ;;
        esac
    done <<< "$rows"
done

[ "$unknown" -gt 0 ] && echo "$unknown finding(s) had a severity outside the known set and were not gated"

write_count "$count"

if [ "$count" -gt 0 ]; then
    echo "$count finding(s) at or above severity $THRESHOLD."
    exit 1
fi

echo "No findings at or above severity $THRESHOLD."
exit 0
