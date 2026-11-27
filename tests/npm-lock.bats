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

@test "no lockfile is an empty index" {
    run index
    [ "$status" -eq 0 ]
    [ "$output" = "[]" ]
}

# A v1 lockfile (npm 6) has no `packages` table: its nested `dependencies`
# tree carries the same name, version, resolved and dev/optional flags, and
# scalibr reads it too. Indexed the same way, at line 1 (no node_modules keys
# to find); a bundled entry takes its parent's source.
@test "a v1 lockfile's dependencies tree is indexed, nested ones included" {
    cat > "$TMP/js/package-lock.json" <<'JSON'
{
  "lockfileVersion": 1,
  "dependencies": {
    "react": { "version": "18.3.1", "resolved": "https://registry.npmjs.org/react/-/react-18.3.1.tgz",
      "dependencies": {
        "loose-envify": { "version": "1.4.0", "resolved": "https://npm.corp.example/loose-envify-1.4.0.tgz" }
      } },
    "corp": { "version": "2.0.0", "resolved": "https://npm.corp.example/corp/-/corp-2.0.0.tgz",
      "dependencies": { "inner": { "version": "1.0.0", "bundled": true } } },
    "jest": { "version": "29.0.0", "resolved": "https://registry.npmjs.org/jest/-/jest-29.0.0.tgz", "dev": true }
  }
}
JSON
    run index
    [ "$status" -eq 0 ]
    [ "$(jq -r 'map("\(.name)@\(.version)=\(.source),\(.dev),\(.line)") | sort | join(" ")' <<<"$output")" \
        = "corp@2.0.0=other,false,1 inner@1.0.0=other,false,1 jest@29.0.0=npmjs,true,1 loose-envify@1.4.0=other,false,1 react@18.3.1=npmjs,false,1" ]
}

# A bundled package ships inside its parent's tarball, so it came from
# wherever the parent did: a private parent's bundled dependency is private.
@test "a bundled package takes its parent's source" {
    cat > "$TMP/js/package-lock.json" <<'JSON'
{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "1.0.0" },
    "node_modules/corp": { "version": "2.0.0", "resolved": "https://npm.corp.example/corp/-/corp-2.0.0.tgz" },
    "node_modules/corp/node_modules/inner": { "version": "1.0.0", "inBundle": true },
    "node_modules/pub": { "version": "1.0.0", "resolved": "https://registry.npmjs.org/pub/-/pub-1.0.0.tgz" },
    "node_modules/pub/node_modules/dep": { "version": "1.0.0", "inBundle": true }
  }
}
JSON
    run index
    [ "$status" -eq 0 ]
    [ "$(jq -r 'map("\(.name)=\(.source)") | sort | join(" ")' <<<"$output")" = "corp=other dep=npmjs inner=other pub=npmjs" ]
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

# The line map once went to jq as one argument; Linux caps a single argument
# at 128 KiB, and a few thousand packages pass that.
@test "a lockfile with thousands of packages is indexed" {
    jq -n '{name: "big", lockfileVersion: 3, packages: ({"": {name: "big", version: "1.0.0"}}
        + ([range(5000) as $i | {key: "node_modules/@some-long-scope-name/package-number-\($i)",
                                value: {version: "1.0.0"}}] | from_entries))}' > "$TMP/js/package-lock.json"
    run index
    [ "$status" -eq 0 ]
    [ "$(jq length <<<"$output")" = 5000 ]
}

# osv-scanner logs a lockfile it cannot parse and scans the rest; failing the
# index here would fail the osv target and earth would export no SARIF at all.
# Warn, naming the file, and leave it unindexed (osv.jq's fallback).
@test "a malformed lockfile is skipped with a warning naming it; the others are indexed" {
    lockfile
    mkdir -p "$TMP/bad"
    printf '{"packages": {' > "$TMP/bad/package-lock.json"
    run bash -c "bash '$ROOT/scripts/npm-lock-packages.sh' '$TMP' 2>'$TMP/err'"
    [ "$status" -eq 0 ]
    [[ "$(cat "$TMP/err")" == *"::warning::"*"bad/package-lock.json"* ]]
    [ "$(jq -r 'map(.path) | unique | join(" ")' <<<"$output")" = "js/package-lock.json" ]
}

# Where the lockfile resolved each install from. The npmjs registry (and
# yarnpkg's mirror of it) is public; any other URL or git source is another
# registry; file: is local. No resolved URL at all is the default registry:
# npm's omit-lockfile-registry-resolved drops it for registry packages only,
# and a bundled package ships inside its parent (scalibr calls both LOCAL).
@test "each package records where the lockfile resolved it from" {
    cat > "$TMP/js/package-lock.json" <<'JSON'
{
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "1.0.0" },
    "node_modules/pub": { "version": "1.0.0", "resolved": "https://registry.npmjs.org/pub/-/pub-1.0.0.tgz" },
    "node_modules/yarn": { "version": "1.0.0", "resolved": "https://registry.yarnpkg.com/yarn/-/yarn-1.0.0.tgz" },
    "node_modules/corp": { "version": "1.0.0", "resolved": "https://npm.corp.example/corp/-/corp-1.0.0.tgz" },
    "node_modules/gitdep": { "version": "1.0.0", "resolved": "git+ssh://git@github.com/o/r.git#abc" },
    "node_modules/loc": { "version": "1.0.0", "resolved": "file:../loc" },
    "node_modules/bare": { "version": "1.0.0" }
  }
}
JSON
    run index
    [ "$status" -eq 0 ]
    [ "$(jq -r 'map("\(.name)=\(.source)") | sort | join(" ")' <<<"$output")" \
        = "bare=default corp=other gitdep=other loc=local pub=npmjs yarn=npmjs" ]
}
