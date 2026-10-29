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
# of them ships, and the lockfile is the only record of which. npm-shrinkwrap.json
# is the same format. A v1 lockfile (npm 6, 2020) has no `packages` table and
# indexes as nothing: osv.jq then falls back to the groups, which may report an
# optional dependency of a dev dependency. None of the fleet's 94 lockfiles is v1.
set -euo pipefail

root="${1:?usage: npm-lock-packages.sh <root>}"
cd "$root"

index_one() {
    # The entry's line, keyed on its lockfile key; jq cannot see line numbers.
    local lines
    # Any indentation, with or without the brace on the same line: the key is
    # the first quoted string on the line, and only a key names a node_modules
    # path (a `resolved` URL is a value, behind its own key).
    lines="$(awk '/^[ \t]*"[^"]*node_modules\/[^"]+"[ \t]*(:|$)/ { k = $0; sub(/^[ \t]*"/, "", k); sub(/".*$/, "", k); printf "%s\t%d\n", k, FNR }' "$1")"
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
                # The boolean true and nothing else: a string "false" is truthy to jq.
                dev: (.value.dev == true),
                optional: (.value.optional == true),
                devOptional: (.value.devOptional == true) } ]' "$1"
}

find . \( -name package-lock.json -o -name npm-shrinkwrap.json \) -type f -not -path '*/node_modules/*' \
    | LC_ALL=C sort | while IFS= read -r f; do
    index_one "$f"
done | jq -s -c 'add // []'
