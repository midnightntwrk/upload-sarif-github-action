#!/usr/bin/env bats
#
# scripts/license-allowlist.txt: the default allowlist, what an Apache-2.0
# project may depend on. One source for the action input's default, the
# README and osv.jq, so the three cannot drift.

load helper

LIST="$ROOT/scripts/license-allowlist.txt"

# ids -- the list as osv.jq reads it: comments and blanks gone
ids() { sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$LIST" | grep -v '^$'; }

@test "every entry is an SPDX identifier or a WITH form" {
    while IFS= read -r l; do
        [[ "$l" =~ ^[A-Za-z0-9.+-]+(\ WITH\ [A-Za-z0-9.+-]+)?$ ]] || { echo "bad: $l"; return 1; }
    done < <(ids)
}

@test "permissive and weak-copyleft licences are in; strong copyleft is out" {
    for id in Apache-2.0 MIT BSD-3-Clause ISC MPL-2.0 EPL-2.0 CDDL-1.0 Unicode-3.0 \
              "GPL-3.0-or-later WITH Classpath-exception-2.0"; do
        ids | grep -qxF "$id" || { echo "missing: $id"; return 1; }
    done
    for id in GPL-3.0-only GPL-3.0-or-later GPL-2.0-only LGPL-3.0-only LGPL-2.1-only AGPL-3.0-only \
              SSPL-1.0 BUSL-1.1 UNKNOWN; do
        ids | grep -qxF "$id" && { echo "present: $id"; return 1; }
    done
    return 0
}

@test "the list has no duplicates" {
    [ "$(ids | sort | uniq -d | wc -l | tr -d ' ')" = 0 ]
}

# osv.jq takes `default` and the file together; `none` and an empty value turn
# licence checking off.
@test "osv.jq resolves 'default' to the file" {
    TMP="$(mktemp -d)"
    jq -n '{results: [{source: {path: "/src/Cargo.lock", type: "lockfile"},
        packages: [{package: {name: "a", version: "1", ecosystem: "crates.io"}, licenses: ["GPL-3.0-only"]},
                   {package: {name: "b", version: "1", ecosystem: "crates.io"}, licenses: ["MPL-2.0"]},
                   {package: {name: "c", version: "1", ecosystem: "crates.io"}, licenses: ["GPL-3.0-or-later WITH Classpath-exception-2.0"]}]}]}' \
        > "$TMP/osv.json"
    out="$(jq -L "$ROOT/scripts" -f "$ROOT/scripts/osv.jq" --arg licenses default --rawfile default_licenses "$LIST" "$TMP/osv.json")"
    [ "$(jq -r '[.runs[0].results[] | select(.ruleId == "license-violation") | .message.text] | join("|")' <<< "$out")" = \
      "Package 'a@1' (crates.io) is licensed 'GPL-3.0-only', which the allowlist does not permit." ]
    [[ "$(jq -r '.runs[0].tool.driver.rules[] | select(.id == "license-violation") | .help.text' <<< "$out")" == *"MPL-2.0"* ]]
    rm -rf "$TMP"
}
