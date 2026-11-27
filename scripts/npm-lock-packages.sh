#!/usr/bin/env bash
#
# Index every installed package in every package-lock.json under a root:
#
#   [{"path":"js/package-lock.json","name":"fsevents","version":"2.3.3","line":40,
#     "dev":false,"optional":true,"devOptional":false,"source":"npmjs"}, ...]
#
# `path` is relative to the root, `line` is the package's own entry - where a
# SARIF region should point - and the three flags are the lockfile's (osv.jq
# decides on `dev` alone; the other two are kept so the state is on record). npm sets
# exactly one state per package: `dev` (reached through devDependencies
# only), `optional` (through optionalDependencies only), `devOptional` (a dev
# dependency that is also an optional dependency of a production one), or
# `dev` + `optional` together (an optional dependency of a dev dependency).
#
# `source` is where the lockfile resolved the install from: npmjs (the public
# registry, or yarnpkg's mirror of it), other (any other URL, or git), local
# (file:) or default (no resolved URL: npm's omit-lockfile-registry-resolved
# drops it for registry packages only, and a bundled package ships inside its
# parent). osv-scanner's own purl `source` cannot be used instead: scalibr calls
# any http URL containing "npm" the public registry (a private npm.corp.example
# included) and an empty resolved LOCAL.
#
# For the osv target. osv-scanner reports the flags as dependency groups and
# folds the last two states into the same pair, `dev` + `optional`; only one
# of them ships, and the lockfile is the only record of which. npm-shrinkwrap.json
# is the same format. A v1 lockfile (npm 6, 2020) has no `packages` table; its
# nested `dependencies` tree is indexed instead, at line 1. A bundled package
# with no resolved URL takes its parent install's source.
set -euo pipefail

root="${1:?usage: npm-lock-packages.sh <root>}"
cd "$root"

index_one() {
    # The entry's line, keyed on its lockfile key; jq cannot see line numbers.
    # Any indentation, with or without the brace on the same line: the key is
    # the first quoted string on the line, and only a key names a node_modules
    # path (a `resolved` URL is a value, behind its own key). Passed as a file,
    # never an argument: Linux caps one argument at 128 KiB.
    jq -c --arg path "${1#./}" --rawfile lines <(awk '
        /^[ \t]*"[^"]*node_modules\/[^"]+"[ \t]*(:|$)/ {
            k = $0; sub(/^[ \t]*"/, "", k); sub(/".*$/, "", k)
            printf "%s\t%d\n", k, FNR
        }' "$1") '
        ($lines | split("\n") | map(select(length > 0) | split("\t") | {key: .[0], value: (.[1] | tonumber)})
                | from_entries) as $ln
        | def classify:
              if . == "" then "default"
              elif test("^https?://registry\\.(npmjs\\.org|yarnpkg\\.com)/") then "npmjs"
              elif startswith("file:") then "local"
              else "other" end;
          # A bundled package with no resolved URL ships inside its parent.
          def bundled: (.inBundle == true or .bundled == true) and (.resolved // "") == "";
          # The boolean true and nothing else: a string "false" is truthy to jq.
          def record($name; $line; $source):
              { path: $path, name: $name, version: .version, line: $line,
                dev: (.dev == true), optional: (.optional == true),
                devOptional: (.devOptional == true), source: $source };
          # v1 (npm 6): a nested `dependencies` tree, no node_modules keys.
          def v1($parent):
              (.dependencies // {}) | to_entries[] | .key as $name | .value
              | (if bundled then $parent else (.resolved // "" | classify) end) as $src
              | record($name; 1; $src), v1($src);
          if .packages == null then [v1("default")] else
          # "" is the project itself; a workspace link has no version of its own.
          (.packages | with_entries(select(.key != "" and (.value.version // "") != ""
                                            and ((.value.link // false) | not)))) as $pk
          | def source($k):
                $pk[$k] as $v
                | if ($v | bundled) and ($k | test("/node_modules/"))
                  then source($k | sub("/node_modules/(@[^/]+/)?[^/]+$"; ""))
                  else ($v.resolved // "" | classify) end;
          [ $pk | to_entries[] | .key as $k
            | .value | record(.name // ($k | split("node_modules/") | last); $ln[$k] // 1; source($k)) ]
          end' "$1" \
        || echo "::warning::npm-lock-packages.sh: could not read $1 as a package-lock (invalid JSON or unexpected shape); its packages fall back to osv-scanner's dependency groups and purl" >&2
}

find . \( -name package-lock.json -o -name npm-shrinkwrap.json \) -type f -not -path '*/node_modules/*' \
    | LC_ALL=C sort | while IFS= read -r f; do
    index_one "$f"
done | jq -s -c 'add // []'
