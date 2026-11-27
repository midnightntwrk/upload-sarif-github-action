#!/usr/bin/env bash
#
# Fail when one of osv-scanner's network enrichers failed:
#
#   scripts/osv-enrichers.sh <osv-scanner stderr log> <licenses_allowlist>
#
# scalibr runs each enricher whole or not at all. One failed osv.dev query and
# vulnerability matching (vulnmatch/osvdev) is empty or partial - no CVE, no
# MAL-*; one failed deps.dev request and the licence enricher writes no licence
# at all, the deprecation one likewise. osv-scanner logs
# `Error during extraction: (extracting as <enricher>) ...` and carries on, and
# its exit code is 1 ("found something") before it looks at what it logged
# whenever anything else was found - a deprecated package is enough. So the
# JSON reads like a clean scan, and a license.override still fills in the
# packages it names: this log line is the only record.
#
# The licence enricher's failure is ignored when licence checks are off;
# `none` is matched as osv.jq matches it (trimmed, any case).
set -euo pipefail

log="${1:?usage: osv-enrichers.sh <stderr log> <licenses_allowlist>}"
licences="${2-}"
[ -r "$log" ] || { echo "::error::osv-enrichers.sh: no osv-scanner log at $log"; exit 1; }

trimmed="$(printf '%s' "$licences" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | tr '[:upper:]' '[:lower:]')"
enrichers='vulnmatch/osvdev|packagedeprecation/depsdev'
[ "$trimmed" = none ] || enrichers="license/depsdev|$enrichers"

failed="$(grep -E "\(extracting as ($enrichers)\)" "$log" || true)"
if [ -n "$failed" ]; then
    while IFS= read -r line; do
        echo "::error::osv-scanner could not reach osv.dev or deps.dev, so its advisory, licence or deprecation data is missing or incomplete for every package: $line. Re-run the scan; if it persists, check osv.dev's and deps.dev's status."
    done <<< "$failed"
    exit 1
fi
