#!/usr/bin/env bash
#
# Write the action's inputs as earth flags, one per line, to the file given:
#
#   scripts/scan-flags.sh "$RUNNER_TEMP/scan-flags"
#
# Written once and re-read (mapfile) by the differential gate's base scan, so
# the two passes cannot be given different scanners. Adding an input means its
# `inputs:` declaration in action.yml, this list, its `env:` entry on the scan
# step, an ARG on the Earthfile's `scan` target and the BUILD that passes it
# on (tests/scan-flags.bats checks this list and the env entries agree).
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

# An empty allowlist (blank, or commas only) is refused by osv.jq inside earth,
# and a failed earth target exports no SARIF at all, so the log would only say
# none was produced. Refuse it here, where the message is an annotation.
allowlist="${LICENSES_ALLOWLIST-}"
if [ -z "${allowlist//[[:space:],]/}" ]; then
    echo "::error::input licenses_allowlist is empty. Pass default for the standard list, or none to turn licence checks off."
    exit 1
fi

for name in "${names[@]}"; do
    printf -- '--%s=%s\n' "$name" "${!name-}"
done > "$out"
