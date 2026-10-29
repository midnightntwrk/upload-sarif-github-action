#!/usr/bin/env bash
#
# Write the action's inputs as earth flags, one per line, to the file given:
#
#   scripts/scan-flags.sh "$RUNNER_TEMP/scan-flags"
#
# Written once and re-read (mapfile) by the differential gate's base scan, so
# the two passes cannot be given different scanners. Adding a scanner means
# editing the list below only.
#
# A line is an argument, so a value with a newline in it would be a second
# flag: `default<LF>--SKIP_OSV_SCAN=true` in licenses_allowlist turns a scanner
# off. The inputs come from the consuming workflow, which can already do
# anything it likes, but a gate should not be switched off by accident or by
# an expression a workflow author did not think of as code. Refused, loudly.
set -euo pipefail

out="${1:?usage: scan-flags.sh <file>}"

names=(SCORECARD_CHECKS SKIP_OPENGREP_SCAN SKIP_SCORECARD_SCAN SKIP_CHECKOV_SCAN SKIP_ZIZMOR_SCAN
       SKIP_TRIVY_SCAN SKIP_GITLEAKS_SCAN SKIP_OSV_SCAN LICENSES_ALLOWLIST)

for name in "${names[@]}"; do
    value="${!name-}"
    case "$value" in
        *$'\n'*|*$'\r'*)
            echo "::error::input $name contains a line break; one input is one earth flag, so a second line would be a second flag. Remove it."
            exit 1 ;;
    esac
done

for name in "${names[@]}"; do
    printf -- '--%s=%s\n' "$name" "${!name-}"
done > "$out"
