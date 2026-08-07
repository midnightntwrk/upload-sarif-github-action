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
SEVERITIES='{"INFO":0,"NONE":0,"NOTE":0,"LOW":1,"WARNING":1,"MEDIUM":2,"HIGH":3,"ERROR":3,"CRITICAL":4}'

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
secrets=0
secret_ignores=""

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
        echo "::error::could not parse SARIF in '$f'" >&2
        exit 2
    fi

    # jq exits 0 on empty input and prints nothing, so this is the only thing
    # standing between a truncated report and a clean-looking scan: the
    # arithmetic below would error to stderr, leave the count at zero and let
    # the run exit 0. A scanner killed part-way, a full disk or a half-written
    # artifact all land here, and on the head scan an undercount *passes* the
    # differential gate.
    if [ -z "$report" ]; then
        echo "::error::'$f' is empty - expected a SARIF document" >&2
        echo "  A zero-length report means the scanner was interrupted or its" >&2
        echo "  output was truncated. That is not a clean scan, so this exits 2" >&2
        echo "  rather than reporting no findings. Re-run the scan." >&2
        exit 2
    fi

    count=$((count + $(jq -r '.count' <<< "$report")))
    unknown=$((unknown + $(jq -r '.unknown' <<< "$report")))

    # Collected so a failure can hand the contributor the exact exclusion line,
    # rather than leaving them to discover that gitleaks has two mechanisms and
    # that only one of them takes a path.
    if [ "$(jq -r '.tool' <<< "$report")" = gitleaks ]; then
        secrets=$((secrets + $(jq -r '.count' <<< "$report")))
        while IFS= read -r ig; do
            [ -n "$ig" ] && secret_ignores="${secret_ignores}${ig}"$'\n'
        done <<< "$(jq -r '.ignores[]?' <<< "$report")"
    fi

    jq -r '.findings[]?' <<< "$report" | while IFS= read -r line; do
        [ -n "$line" ] && echo "  $line  [$f]"
    done

    # Unmapped severities (Trivy UNKNOWN, SARIF "none") are reported and skipped
    # rather than aborting mid-count: a partial count is a wrong verdict.
    jq -r '.unmapped[]?' <<< "$report" | while IFS= read -r line; do
        [ -n "$line" ] && echo "::warning::unmapped severity $line in $f - not gated"
    done
done

[ "$unknown" -gt 0 ] && echo "$unknown finding(s) had a severity outside the known set and were not gated"

# Secrets are stamped CRITICAL by scripts/secrets-severity.jq, so they fail at
# every threshold. That is deliberate, which makes the escape hatch worth
# spelling out at the point of failure rather than in a wiki nobody reads.
if [ "$secrets" -gt 0 ]; then
    cat >&2 <<'GUIDANCE'

::error::a committed secret fails the build regardless of fail_severity
  Rotate the credential first. It is in the repository, so treat it as
  compromised whatever happens to this build.

  If it is a false positive or a deliberate test fixture, exclude it. gitleaks
  has two mechanisms and they are not interchangeable:

  1. A path or a whole directory - .gitleaks.toml in the repository root:

       [extend]
       useDefault = true

       [[allowlists]]
       description = "test fixtures"
       paths = ['''^tests/fixtures/''']

  2. One specific finding - .gitleaksignore in the repository root, one
     fingerprint per line. The lines for this build are:
GUIDANCE
    printf '%s' "$secret_ignores" | sed 's/^/       /' >&2
    # Derived from the environment so the link stays correct on a fork or on
    # GitHub Enterprise; the literal is only the fallback for a local run.
    action_repo="${GITHUB_ACTION_REPOSITORY:-midnightntwrk/upload-sarif-github-action}"
    server="${GITHUB_SERVER_URL:-https://github.com}"
    cat >&2 <<GUIDANCE_LINKS

  Full reference:
    this action's policy .. $server/$action_repo#secrets-always-fail-the-build
    path allowlists ....... https://github.com/gitleaks/gitleaks#configuration
    .gitleaksignore ....... https://github.com/gitleaks/gitleaks#gitleaksignore
GUIDANCE_LINKS
fi

write_count "$count"

if [ "$count" -gt 0 ]; then
    echo "$count finding(s) at or above severity $THRESHOLD."
    exit 1
fi

echo "No findings at or above severity $THRESHOLD."
exit 0
