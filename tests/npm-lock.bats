#!/usr/bin/env bats
#
# scripts/npm-lock-packages.sh: where each npm package sits in its
# package-lock.json and which trees it belongs to. osv-scanner folds the
# lockfile's three flags into two groups, and that loses the one distinction
# the licence rules need: `dev` + `optional` (an optional dependency of a dev
# dependency, never shipped) arrives exactly like `devOptional` (a dev
# dependency that is also an optional dependency of a production one, shipped
# whenever npm can install it).

load helper

setup() { TMP="$(mktemp -d)"; mkdir -p "$TMP/js"; }
teardown() { rm -rf "$TMP"; }

index() { bash "$ROOT/scripts/npm-lock-packages.sh" "$TMP"; }

lockfile() {
    cat > "$TMP/js/package-lock.json" <<'JSON'
{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "1.0.0" },
    "node_modules/esbuild": { "version": "0.21.0", "dev": true },
    "node_modules/@esbuild/linux-x64": { "version": "0.21.0", "dev": true, "optional": true },
    "node_modules/detect-libc": { "version": "2.0.3", "devOptional": true },
    "node_modules/fsevents": { "version": "2.3.3", "optional": true },
    "node_modules/react": { "version": "18.3.1" },
    "node_modules/aliased": { "name": "real-name", "version": "1.2.3" },
    "node_modules/react/node_modules/loose-envify": { "version": "1.4.0" },
    "node_modules/api": { "resolved": "api", "link": true },
    "api": { "name": "api", "version": "0.0.1" }
  }
}
JSON
}

@test "every installed package is listed with its flags" {
    lockfile
    run index
    [ "$status" -eq 0 ]
    [ "$(jq -r 'map(select(.name == "esbuild")) | .[0] | [.path, .version, .dev, .optional, .devOptional] | @tsv' <<<"$output")" = "$(printf 'js/package-lock.json\t0.21.0\ttrue\tfalse\tfalse')" ]
    [ "$(jq -r 'map(select(.name == "@esbuild/linux-x64")) | .[0] | [.dev, .optional, .devOptional] | @tsv' <<<"$output")" = "$(printf 'true\ttrue\tfalse')" ]
    [ "$(jq -r 'map(select(.name == "detect-libc")) | .[0] | [.dev, .optional, .devOptional] | @tsv' <<<"$output")" = "$(printf 'false\tfalse\ttrue')" ]
    [ "$(jq -r 'map(select(.name == "fsevents")) | .[0] | [.dev, .optional, .devOptional] | @tsv' <<<"$output")" = "$(printf 'false\ttrue\tfalse')" ]
    [ "$(jq -r 'map(select(.name == "react")) | .[0] | [.dev, .optional, .devOptional] | @tsv' <<<"$output")" = "$(printf 'false\tfalse\tfalse')" ]
}

# The name is the last node_modules segment unless the entry says otherwise
# (an alias), nested installs included; a workspace link has no version and
# is not a package.
@test "names follow the lockfile: aliases, nested installs, no links" {
    lockfile
    run index
    [ "$(jq -r 'map(.name) | sort | join(" ")' <<<"$output")" = "@esbuild/linux-x64 api detect-libc esbuild fsevents loose-envify react real-name" ]
    [ "$(jq -r 'map(select(.name == "loose-envify")) | .[0].version' <<<"$output")" = 1.4.0 ]
    [ "$(jq -r 'map(select(.name == "real-name")) | .[0].version' <<<"$output")" = 1.2.3 ]
}

# The line is the entry's own, where a SARIF region should point.
@test "the line is the package's entry in the lockfile" {
    lockfile
    run index
    [ "$(jq -r 'map(select(.name == "detect-libc")) | .[0].line' <<<"$output")" = "$(grep -n '"node_modules/detect-libc"' "$TMP/js/package-lock.json" | cut -d: -f1)" ]
    [ "$(jq -r 'map(select(.name == "loose-envify")) | .[0].line' <<<"$output")" = "$(grep -n 'loose-envify' "$TMP/js/package-lock.json" | cut -d: -f1)" ]
}

@test "no lockfile, or a v1 lockfile with no packages table, is an empty index" {
    run index
    [ "$status" -eq 0 ]
    [ "$output" = "[]" ]
    echo '{"lockfileVersion": 1, "dependencies": {"react": {"version": "18.3.1"}}}' > "$TMP/js/package-lock.json"
    run index
    [ "$status" -eq 0 ]
    [ "$output" = "[]" ]
}

# npm-shrinkwrap.json is the same format and osv-scanner reads it too.
@test "npm-shrinkwrap.json is indexed like package-lock.json" {
    lockfile
    mv "$TMP/js/package-lock.json" "$TMP/js/npm-shrinkwrap.json"
    run index
    [ "$(jq -r 'map(select(.name == "fsevents")) | .[0] | [.path, .optional] | @tsv' <<<"$output")" = "$(printf 'js/npm-shrinkwrap.json\ttrue')" ]
}

# Two repositories in the fleet indent their lockfiles with tabs; a hand-edited
# one may put the brace on the next line. The entry is still found, and so is
# its line.
@test "tab indentation and a brace on the next line still give the entry's line" {
    printf '{\n\t"packages": {\n\t\t"node_modules/a": {\n\t\t\t"version": "1.0.0"\n\t\t},\n\t\t"node_modules/b"\n\t\t: { "version": "2.0.0", "dev": true }\n\t}\n}\n' > "$TMP/js/package-lock.json"
    run index
    [ "$status" -eq 0 ]
    [ "$(jq -r 'map(select(.name == "a")) | .[0].line' <<<"$output")" = 3 ]
    [ "$(jq -r 'map(select(.name == "b")) | .[0] | [.line, .dev] | @tsv' <<<"$output")" = "$(printf '6\ttrue')" ]
}

# A flag that is not the boolean true is not set, whatever jq thinks of it.
@test "only the boolean true sets a flag" {
    echo '{"packages": {"node_modules/a": {"version": "1.0.0", "dev": "false", "optional": 1}}}' > "$TMP/js/package-lock.json"
    run index
    [ "$(jq -r '.[0] | [.dev, .optional, .devOptional] | @tsv' <<<"$output")" = "$(printf 'false\tfalse\tfalse')" ]
}

@test "a lockfile under node_modules is not indexed" {
    mkdir -p "$TMP/js/node_modules/x"
    echo '{"packages": {"node_modules/y": {"version": "1.0.0"}}}' > "$TMP/js/node_modules/x/package-lock.json"
    run index
    [ "$output" = "[]" ]
}
