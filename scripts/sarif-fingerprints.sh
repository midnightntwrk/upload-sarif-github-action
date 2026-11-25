#!/usr/bin/env bash
#
# SARIF on stdin -> SARIF on stdout, each result's properties.fingerprint_input
# replaced by partialFingerprints.primaryLocationLineHash = its sha256 (hex).
#
# For osv.jq, which builds upstream osv-scanner's fingerprint preimage but
# cannot hash it: jq has no sha256. Every result must carry an input - one
# without would ship unfingerprinted and code scanning would re-key its alert -
# so a missing one fails the step.
set -euo pipefail

sarif="$(cat)"

# "<hash>\t<input>" per distinct input, then a lookup object. Through a pipe,
# never argv: Linux caps one argument at 128 KiB, about a thousand entries.
jq -r '.runs[].results[]
        | .properties.fingerprint_input
          // error("result \(.ruleId) at \(.locations[0].physicalLocation.artifactLocation.uri // "?") has no properties.fingerprint_input")' \
        <<< "$sarif" | LC_ALL=C sort -u \
    | while IFS= read -r input; do
        printf '%s\t%s\n' "$(printf '%s' "$input" | sha256sum | cut -d' ' -f1)" "$input"
    done | jq -R -s 'split("\n") | map(select(length > 0) | split("\t") | {key: .[1], value: .[0]}) | from_entries' \
    | jq --slurpfile in <(printf '%s' "$sarif") '. as $hashes | $in[0]
    | .runs[].results[] |= (
        .partialFingerprints.primaryLocationLineHash = $hashes[.properties.fingerprint_input]
        | del(.properties.fingerprint_input)
        | if .properties == {} then del(.properties) else . end)'
