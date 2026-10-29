#!/usr/bin/env bash
#
# Index every installed package in every package-lock.json under a root:
#
#   [{"path":"js/package-lock.json","name":"fsevents","version":"2.3.3","line":40,
#     "dev":false,"optional":true,"devOptional":false}, ...]
#
# `path` is relative to the root, `line` is the package's own entry - where a
# SARIF region should point - and the three flags are the lockfile's. npm sets
# exactly one state per package: `dev` (reached through devDependencies
# only), `optional` (through optionalDependencies only), `devOptional` (a dev
# dependency that is also an optional dependency of a production one), or
# `dev` + `optional` together (an optional dependency of a dev dependency).
#
# For the osv target. osv-scanner reports the flags as dependency groups and
# folds the last two states into the same pair, `dev` + `optional`; only one
# of them ships, and the lockfile is the only record of which.
set -euo pipefail

root="${1:?usage: npm-lock-packages.sh <root>}"
cd "$root"

index_one() {
    # The entry's line, keyed on its lockfile key; jq cannot see line numbers.
    local lines
    lines="$(awk '/^ *"[^"]*node_modules\/[^"]+": *\{/ { k = $0; sub(/^ *"/, "", k); sub(/": *\{.*$/, "", k); printf "%s\t%d\n", k, FNR }' "$1")"
    jq -c --arg path "${1#./}" --arg lines "$lines" '
        ($lines | split("\n") | map(select(length > 0) | split("\t") | {key: .[0], value: (.[1] | tonumber)})
                | from_entries) as $ln
        | [ (.packages // {}) | to_entries[]
            # "" is the project itself; a workspace link has no version of its own.
            | select(.key != "" and (.value.version // "") != "" and ((.value.link // false) | not))
            | { path: $path,
                name: (.value.name // (.key | split("node_modules/") | last)),
                version: .value.version,
                line: ($ln[.key] // 1),
                dev: (.value.dev // false),
                optional: (.value.optional // false),
                devOptional: (.value.devOptional // false) } ]' "$1"
}

find . -name package-lock.json -type f -not -path '*/node_modules/*' | LC_ALL=C sort | while IFS= read -r f; do
    index_one "$f"
done | jq -s -c 'add // []'
