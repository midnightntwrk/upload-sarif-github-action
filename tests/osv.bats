#!/usr/bin/env bats
#
# The osv-scanner policy. scripts/osv.jq turns osv-scanner's JSON report into
# the SARIF the gate reads - upstream's own SARIF drops a deprecated package
# that has no vulnerability (google/osv-scanner#3164) - and stamps severity:
# the group's CVSS banded, MAL-* CRITICAL, a yanked or deprecated package
# MEDIUM. Rule ids and messages follow upstream's, so existing code-scanning
# alerts keep their identity.

load helper

OSV_JQ="$ROOT/scripts/osv.jq"

setup() { TMP="$(mktemp -d)"; }
teardown() { rm -rf "$TMP"; }

# report <lockfile path in the container> <name> <version> <ids,csv> <cvss or ""> [<aliases,csv>]
#
# One package in one lockfile with one advisory group. Every advisory in the
# group is fixed in 9.9.9. Shape is osv-scanner 2.7.0's `--format json`.
report() {
    jq -n --arg path "$1" --arg name "$2" --arg ver "$3" --arg ids "$4" --arg cvss "$5" \
          --arg aliases "${6:-}" '
        ($ids | split(",")) as $ids
        | ($aliases | if . == "" then [] else split(",") end) as $al
        | {results: [{source: {path: $path, type: "lockfile"},
            packages: [{package: {name: $name, version: $ver, ecosystem: "crates.io"},
              vulnerabilities: [$ids[] as $id
                | {id: $id, aliases: $al, summary: "summary of \($id)", details: "details of \($id)",
                   affected: [{package: {name: $name, ecosystem: "crates.io"},
                               ranges: [{type: "SEMVER", events: [{introduced: "0"}, {fixed: "9.9.9"}]}]}]}],
              groups: [{ids: $ids, max_severity: $cvss}]}]}]}' > "$TMP/osv.json"
}

# deprecated <lockfile path> <ecosystem> <name> <version> -- a package with no
# advisory that deps.dev calls deprecated (yanked, unpublished)
deprecated() {
    jq -n --arg path "$1" --arg eco "$2" --arg name "$3" --arg ver "$4" \
        '{results: [{source: {path: $path, type: "lockfile"},
                     packages: [{package: {name: $name, version: $ver, ecosystem: $eco,
                                           deprecated: true}}]}]}' > "$TMP/osv.json"
}

# packages <json array> -- what scripts/cargo-lock-packages.sh prints
packages() { printf '%s\n' "$1" > "$TMP/pkgs.json"; }

# convert [jq args...] -- $TMP/osv.json -> $TMP/r/osv.sarif
convert() {
    mkdir -p "$TMP/r"
    jq -L "$ROOT/scripts" -f "$OSV_JQ" "$@" "$TMP/osv.json" > "$TMP/r/osv.sarif"
}

# converted -- convert with the Cargo.lock index, as the Earthfile does
converted() { convert --slurpfile packages "$TMP/pkgs.json"; }

sarif() { jq -r "$1" "$TMP/r/osv.sarif"; }
result() { sarif ".runs[0].results[${2:-0}]$1"; }
rule() { sarif ".runs[0].tool.driver.rules[] | select(.id == \"$1\")$2"; }

# stamped <ids,csv> <cvss> -- the severity the gate resolves
stamped() {
    report /src/requirements.txt pkg 1.0 "$1" "$2"
    convert
    jq -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" --argjson threshold 0 "$TMP/r/osv.sarif" \
        | jq -r '.hits[0].severity'
}

# --- shape ---------------------------------------------------------------------

@test "an empty report is a valid, empty SARIF" {
    printf '%s\n' '{"results":[]}' > "$TMP/osv.json"
    convert
    [ "$(sarif .version)" = 2.1.0 ]
    [ "$(sarif '.runs[0].tool.driver.name')" = osv-scanner ]
    [ "$(sarif '.runs[0].results | length')" = 0 ]
    [ "$(sarif '.runs[0].tool.driver.rules | length')" = 0 ]
}

@test "the scanner version is recorded when given" {
    printf '%s\n' '{"results":[]}' > "$TMP/osv.json"
    convert --arg version 2.7.0
    [ "$(sarif '.runs[0].tool.driver.version')" = 2.7.0 ]
}

# identifiers.IDSortFunc upstream: CVE, then an ecosystem id, then GHSA.
@test "a rule is named by the group's display id: CVE before RUSTSEC before GHSA" {
    report /src/Cargo.lock rustls 0.23.37 RUSTSEC-2026-0285,GHSA-2mjx-qc3c-rqvc 5.3 CVE-2026-1
    convert
    [ "$(result .ruleId)" = CVE-2026-1 ]
    report /src/Cargo.lock rustls 0.23.37 RUSTSEC-2026-0285,GHSA-2mjx-qc3c-rqvc 5.3
    convert
    [ "$(result .ruleId)" = RUSTSEC-2026-0285 ]
    report /src/Cargo.lock rustls 0.23.37 GHSA-2mjx-qc3c-rqvc 5.3
    convert
    [ "$(result .ruleId)" = GHSA-2mjx-qc3c-rqvc ]
}

@test "the message reads as upstream's, aliases included" {
    report /src/Cargo.lock rustls 0.23.37 RUSTSEC-2026-0285,GHSA-2mjx-qc3c-rqvc 5.3
    convert
    [ "$(result .message.text)" = \
      "Package 'rustls@0.23.37' is vulnerable to 'RUSTSEC-2026-0285' (also known as 'GHSA-2mjx-qc3c-rqvc')." ]
    report /src/Cargo.lock rustls 0.23.37 RUSTSEC-2026-0285 5.3
    convert
    [ "$(result .message.text)" = "Package 'rustls@0.23.37' is vulnerable to 'RUSTSEC-2026-0285'." ]
}

@test "one rule per advisory group, one result per affected package" {
    report /src/Cargo.lock lru 0.12.5 RUSTSEC-2026-0253 ""
    jq '.results[0].packages += [(.results[0].packages[0] | .package.version = "0.7.8")]' \
        "$TMP/osv.json" > "$TMP/two.json" && mv "$TMP/two.json" "$TMP/osv.json"
    convert
    [ "$(sarif '.runs[0].tool.driver.rules | length')" = 1 ]
    [ "$(sarif '.runs[0].results | length')" = 2 ]
    [ "$(result .message.text 1)" = "Package 'lru@0.7.8' is vulnerable to 'RUSTSEC-2026-0253'." ]
}

@test "the rule carries the score, the summary and the fixed version" {
    report /src/Cargo.lock rustls 0.23.37 RUSTSEC-2026-0285 5.3
    convert
    [ "$(rule RUSTSEC-2026-0285 '.properties["security-severity"]')" = 5.3 ]
    [ "$(rule RUSTSEC-2026-0285 .shortDescription.text)" = "RUSTSEC-2026-0285: summary of RUSTSEC-2026-0285" ]
    [ "$(rule RUSTSEC-2026-0285 .helpUri)" = https://osv.dev/RUSTSEC-2026-0285 ]
    [[ "$(rule RUSTSEC-2026-0285 .help.markdown)" == *"| RUSTSEC-2026-0285 | rustls | 9.9.9 |"* ]]
}

# osv-scanner reports /src/... however it is invoked; the summary and the
# Security tab need the path as it is in the repository.
@test "locations are made relative to the repository" {
    report /src/js/package-lock.json left-pad 1.0.0 GHSA-x 5.0
    convert
    [ "$(result .locations[0].physicalLocation.artifactLocation.uri)" = js/package-lock.json ]
}

# --- severity ------------------------------------------------------------------

# Malware is not a point on a scale: a lockfile either names a package that
# steals credentials or it does not. Same policy as a committed secret.
@test "a malicious package is CRITICAL" {
    [ "$(stamped MAL-2025-20690 "")" = CRITICAL ]
}

@test "a malicious package is CRITICAL even if a score is attached" {
    [ "$(stamped MAL-2025-20690 2.0)" = CRITICAL ]
}

@test "a malicious package fails the build at the critical default" {
    report /src/js/package-lock.json flatmap-stream 0.1.1 MAL-2025-20690 ""
    convert
    count_findings "$TMP/r" critical
    [ "$status" -eq 1 ]
    [ "$count" = 1 ]
}

# GitHub's own CVSS bands, the ones the Security tab uses for
# security-severity: https://docs.github.com/en/code-security/code-scanning/managing-your-code-scanning-configuration/about-the-tool-status-page
@test "CVSS 9.0 and above is CRITICAL" {
    [ "$(stamped CVE-2019-19844 9.8)" = CRITICAL ]
    [ "$(stamped CVE-X 9.0)" = CRITICAL ]
}

@test "CVSS 7.0 to 8.9 is HIGH" {
    [ "$(stamped CVE-X 8.9)" = HIGH ]
    [ "$(stamped CVE-X 7.0)" = HIGH ]
}

@test "CVSS 4.0 to 6.9 is MEDIUM" {
    [ "$(stamped CVE-2018-7537 5.3)" = MEDIUM ]
    [ "$(stamped CVE-X 4.0)" = MEDIUM ]
}

@test "CVSS below 4.0 is LOW" {
    [ "$(stamped CVE-X 3.9)" = LOW ]
    [ "$(stamped CVE-X 0.1)" = LOW ]
}

# No score is no information: not stamped, so the plain SARIF reading applies.
@test "a vulnerability with no CVSS falls back to its level" {
    [ "$(stamped GHSA-x "")" = MEDIUM ]
}

# --- deprecated and yanked packages ------------------------------------------
#
# deps.dev says a version is yanked (crates.io, PyPI), deprecated or
# unpublished (npm); osv-scanner's JSON carries it as `deprecated: true` on the
# package. Each becomes one `deprecated-package` result. The Cargo.lock index
# from scripts/cargo-lock-packages.sh supplies the line and the git flag.

@test "a yanked crate with no advisory is reported, at MEDIUM" {
    deprecated /src/rust/Cargo.lock crates.io spin 0.9.8
    packages '[]'
    converted
    [ "$(result .ruleId)" = deprecated-package ]
    [ "$(result .locations[0].physicalLocation.artifactLocation.uri)" = rust/Cargo.lock ]
    [ "$(jq -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" --argjson threshold 0 "$TMP/r/osv.sarif" \
        | jq -r '.hits[0].severity')" = MEDIUM ]
}

@test "a yanked crate passes the critical default and fails at medium" {
    deprecated /src/Cargo.lock crates.io spin 0.9.8
    packages '[]'
    converted
    count_findings "$TMP/r" critical
    [ "$status" -eq 0 ]
    [ "$count" = 0 ]
    count_findings "$TMP/r" medium
    [ "$status" -eq 1 ]
    [ "$count" = 1 ]
}

# The Security tab shows a severity only for a rule tagged `security` with a
# `security-severity`; anything else displays as a bare "Warning".
@test "deprecated-package is declared once, as a security rule" {
    deprecated /src/Cargo.lock crates.io spin 0.9.8
    packages '[]'
    converted
    [ "$(sarif '[.runs[0].tool.driver.rules[] | select(.id == "deprecated-package")] | length')" = 1 ]
    [ "$(rule deprecated-package '.properties.tags | index("security") != null')" = true ]
    [ "$(rule deprecated-package '.properties["security-severity"] | tonumber | . >= 4 and . < 7')" = true ]
}

# crates.io and PyPI yank; npm deprecates. The message uses the registry's word.
@test "the message names the package and uses the registry's word" {
    deprecated /src/Cargo.lock crates.io spin 0.9.8
    packages '[]'
    converted
    [[ "$(result .message.text)" == *"spin@0.9.8"* ]]
    [[ "$(result .message.text)" == *yanked* ]]
    deprecated /src/js/package-lock.json npm request 2.88.2
    converted
    [[ "$(result .message.text)" == *"request@2.88.2"* ]]
    [[ "$(result .message.text)" == *deprecated* ]]
}

@test "the result points at the crate's own line in Cargo.lock" {
    deprecated /src/rust/Cargo.lock crates.io spin 0.9.8
    packages '[{"path":"rust/Cargo.lock","name":"spin","version":"0.9.8","line":7,"source":"registry"}]'
    converted
    [ "$(result .locations[0].physicalLocation.region.startLine)" = 7 ]
}

# deps.dev matches on name and version alone: a crate built from a git fork is
# flagged whenever crates.io yanked the release of the same name and version.
# Cargo.lock says where it really came from.
@test "a git-sourced crate is not reported" {
    deprecated /src/Cargo.lock crates.io sp-api-proc-macro 15.0.0
    packages '[{"path":"Cargo.lock","name":"sp-api-proc-macro","version":"15.0.0","line":3,"source":"git"}]'
    converted
    [ "$(sarif '.runs[0].results | length')" = 0 ]
}

@test "deprecated packages are added to the vulnerability results, not in place of them" {
    report /src/js/package-lock.json left-pad 1.0.0 GHSA-x 5.0
    jq '.results[0].packages += [{package: {name: "request", version: "2.88.2", ecosystem: "npm", deprecated: true}}]' \
        "$TMP/osv.json" > "$TMP/two.json" && mv "$TMP/two.json" "$TMP/osv.json"
    packages '[]'
    converted
    [ "$(sarif '.runs[0].results | length')" = 2 ]
    [ "$(result .ruleId)" = GHSA-x ]
    [ "$(result .ruleId 1)" = deprecated-package ]
}

@test "a package the report does not mark deprecated is not reported" {
    jq -n '{results: [{source: {path: "/src/Cargo.lock", type: "lockfile"},
            packages: [{package: {name: "serde", version: "1.0.0", ecosystem: "crates.io"}}]}]}' \
        > "$TMP/osv.json"
    packages '[]'
    converted
    [ "$(sarif '.runs[0].results | length')" = 0 ]
}

@test "without the Cargo.lock index a yanked crate is still reported" {
    deprecated /src/Cargo.lock crates.io spin 0.9.8
    convert
    [ "$(result .ruleId)" = deprecated-package ]
    [ "$(result .locations[0].physicalLocation.region.startLine)" = 1 ]
}

# --- licences -------------------------------------------------------------------
#
# With --licenses --all-packages every package carries deps.dev's licence
# expressions. scripts/spdx.jq decides whether an allowlist (--arg licenses)
# satisfies them; a package that fails is a `license-violation` (HIGH), one
# whose licence deps.dev could not tell is a `license-unknown` (LOW). Dev-only
# packages are nobody's compliance problem and are skipped, as is an unknown
# licence on anything not from a public registry.

# licensed <lockfile path> <ecosystem> <name> <version> <licence json array> [<groups json array>]
licensed() {
    jq -n --arg path "$1" --arg eco "$2" --arg name "$3" --arg ver "$4" \
          --argjson lic "$5" --argjson groups "${6:-[]}" '
        {results: [{source: {path: $path, type: "lockfile"},
            packages: [{package: {name: $name, version: $ver, ecosystem: $eco,
                                  purl: "pkg:x/\($name)@\($ver)?source=PUBLIC_REGISTRY"},
                        licenses: $lic}
                       + (if ($groups | length) > 0 then {dependency_groups: $groups} else {} end)]}]}' \
        > "$TMP/osv.json"
}

# npm_packages <json array> -- the package-lock.json index (scripts/npm-lock-packages.sh)
npm_packages() { printf '%s\n' "$1" > "$TMP/npm.json"; }

# licensed_convert <allowlist> -- convert with the lockfile indexes and that allowlist
licensed_convert() {
    [ -f "$TMP/npm.json" ] || npm_packages '[]'
    convert --slurpfile packages "$TMP/pkgs.json" --slurpfile npm "$TMP/npm.json" --arg licenses "$1"
}

@test "a banned licence is a license-violation at HIGH" {
    licensed /src/Cargo.lock crates.io polkadot-primitives 18.0.0 '["GPL-3.0-only"]'
    packages '[]'
    licensed_convert "MIT,Apache-2.0"
    [ "$(result .ruleId)" = license-violation ]
    [ "$(jq -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" --argjson threshold 0 "$TMP/r/osv.sarif" \
        | jq -r '.hits[0].severity')" = HIGH ]
    [[ "$(result .message.text)" == *"polkadot-primitives@18.0.0"* ]]
    [[ "$(result .message.text)" == *"GPL-3.0-only"* ]]
}

@test "an allowed expression is not reported, exceptions and OR included" {
    licensed /src/Cargo.lock crates.io sc-cli 0.60.0 '["GPL-3.0-or-later WITH Classpath-exception-2.0"]'
    packages '[]'
    licensed_convert "MIT,GPL-3.0-or-later WITH Classpath-exception-2.0"
    [ "$(sarif '.runs[0].results | length')" = 0 ]
    licensed /src/Cargo.lock crates.io serde 1.0.0 '["Apache-2.0 OR MIT"]'
    licensed_convert "MIT"
    [ "$(sarif '.runs[0].results | length')" = 0 ]
}

# npm installs an optional dependency whenever it can, so it ships: fsevents,
# the esbuild platform binaries. Only a package reachable through dev
# dependencies alone is nobody's compliance problem. package-lock.json marks a
# package on both a dev path and an optional path `devOptional`, which
# osv-scanner reports as both groups: it ships with the optional one.
@test "a dev-only package is never a licence finding; an optional one is" {
    licensed /src/js/package-lock.json npm k6 0.0.0 '["AGPL-3.0"]' '["dev"]'
    packages '[]'
    licensed_convert "MIT"
    [ "$(sarif '.runs[0].results | length')" = 0 ]
    licensed /src/js/package-lock.json npm @substrate/connect 0.8.11 '["GPL-3.0-only"]' '["optional"]'
    licensed_convert "MIT"
    [ "$(result .ruleId)" = license-violation ]
    licensed /src/js/package-lock.json npm smoldot 2.0.0 '["GPL-3.0-only"]' '["dev", "optional"]'
    licensed_convert "MIT"
    [ "$(result .ruleId)" = license-violation ]
}

# osv-scanner's groups cannot tell `dev` + `optional` (an optional dependency
# of a dev dependency: an esbuild platform binary, never shipped) from
# `devOptional` (shipped whenever npm can install it). The lockfile can, so
# when its index is given the lockfile's flags decide: anything on the dev
# flag is skipped, devOptional and optional are checked.
@test "with the package-lock index, the lockfile's flags decide what ships" {
    npm_flags() {
        npm_packages "[{\"path\":\"js/package-lock.json\",\"name\":\"p\",\"version\":\"1.0.0\",\"line\":7,$1}]"
        licensed /src/js/package-lock.json npm p 1.0.0 '["GPL-3.0-only"]' "$2"
        licensed_convert "MIT"
        sarif '.runs[0].results | length'
    }
    packages '[]'
    [ "$(npm_flags '"dev":true,"optional":false,"devOptional":false' '["dev"]')" = 0 ]
    [ "$(npm_flags '"dev":true,"optional":true,"devOptional":false' '["dev","optional"]')" = 0 ]
    [ "$(npm_flags '"dev":false,"optional":false,"devOptional":true' '["dev","optional"]')" = 1 ]
    [ "$(npm_flags '"dev":false,"optional":true,"devOptional":false' '["optional"]')" = 1 ]
    [ "$(npm_flags '"dev":false,"optional":false,"devOptional":false' '[]')" = 1 ]
    [ "$(result .locations[0].physicalLocation.region.startLine)" = 7 ]
}

@test "an unknown licence on a registry package is a license-unknown at LOW" {
    licensed /src/Cargo.lock crates.io ring 0.16.20 '["non-standard"]'
    packages '[{"path":"Cargo.lock","name":"ring","version":"0.16.20","line":5,"source":"registry"}]'
    licensed_convert "MIT"
    [ "$(result .ruleId)" = license-unknown ]
    [ "$(result .locations[0].physicalLocation.region.startLine)" = 5 ]
    [ "$(jq -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" --argjson threshold 0 "$TMP/r/osv.sarif" \
        | jq -r '.hits[0].severity')" = LOW ]
    licensed /src/Cargo.lock crates.io yamux 0.12.2 '["UNKNOWN"]'
    licensed_convert "MIT"
    [ "$(result .ruleId)" = license-unknown ]
}

# deps.dev found one licence it could read and one it could not. The one it
# read is the finding: an unknown beside a GPL must not soften it to LOW.
@test "a banned licence beside an unknown one is still a violation" {
    licensed /src/js/package-lock.json npm a 1.0.0 '["GPL-3.0-only", "UNKNOWN"]'
    packages '[]'
    licensed_convert "MIT"
    [ "$(sarif '.runs[0].results | length')" = 1 ]
    [ "$(result .ruleId)" = license-violation ]
    licensed /src/js/package-lock.json npm b 1.0.0 '["MIT", "UNKNOWN"]'
    licensed_convert "MIT"
    [ "$(result .ruleId)" = license-unknown ]
}

# osv-scanner's schema says an array of strings; neither a null entry nor a
# bare string must take the whole scan down.
@test "a null or non-array licence field is treated as unknown, not as an error" {
    licensed /src/js/package-lock.json npm c 1.0.0 '[null]'
    packages '[]'
    licensed_convert "MIT"
    [ "$(result .ruleId)" = license-unknown ]
    licensed /src/js/package-lock.json npm d 1.0.0 '"UNKNOWN"'
    licensed_convert "MIT"
    [ "$(result .ruleId)" = license-unknown ]
    licensed /src/js/package-lock.json npm e 1.0.0 '"GPL-3.0-only"'
    licensed_convert "MIT"
    [ "$(result .ruleId)" = license-violation ]
}

# deps.dev knows nothing about a workspace member, a git dependency or a local
# npm package; "unknown" there is a fact about deps.dev, not about the licence.
@test "an unknown licence on a workspace, git or local package is not reported" {
    licensed /src/Cargo.lock crates.io midnight-node 3.0.0 '["UNKNOWN"]'
    packages '[{"path":"Cargo.lock","name":"midnight-node","version":"3.0.0","line":5,"source":"path"}]'
    licensed_convert "MIT"
    [ "$(sarif '.runs[0].results | length')" = 0 ]
    licensed /src/Cargo.lock crates.io yamux 0.12.2 '["UNKNOWN"]'
    packages '[{"path":"Cargo.lock","name":"yamux","version":"0.12.2","line":5,"source":"git"}]'
    licensed_convert "MIT"
    [ "$(sarif '.runs[0].results | length')" = 0 ]
    licensed /src/js/package-lock.json npm my-app 1.0.0 '["UNKNOWN"]'
    jq '.results[0].packages[0].package.purl = "pkg:npm/my-app@1.0.0?source=LOCAL"' "$TMP/osv.json" \
        > "$TMP/l.json" && mv "$TMP/l.json" "$TMP/osv.json"
    packages '[]'
    licensed_convert "MIT"
    [ "$(sarif '.runs[0].results | length')" = 0 ]
}

@test "a banned licence on a git or path package is still a violation" {
    licensed /src/Cargo.lock crates.io polkadot-primitives 18.0.0 '["GPL-3.0-only"]'
    packages '[{"path":"Cargo.lock","name":"polkadot-primitives","version":"18.0.0","line":5,"source":"git"}]'
    licensed_convert "MIT"
    [ "$(result .ruleId)" = license-violation ]
}

@test "licence rules are declared once each, with the allowlist in the help text" {
    licensed /src/Cargo.lock crates.io polkadot-primitives 18.0.0 '["GPL-3.0-only"]'
    packages '[]'
    licensed_convert "MIT,Apache-2.0"
    [ "$(sarif '[.runs[0].tool.driver.rules[] | select(.id == "license-violation")] | length')" = 1 ]
    [[ "$(rule license-violation .help.text)" == *"MIT, Apache-2.0"* ]]
}

@test "licence checking is off when no allowlist is given, or when it is 'none'" {
    licensed /src/Cargo.lock crates.io polkadot-primitives 18.0.0 '["GPL-3.0-only"]'
    packages '[]'
    converted
    [ "$(sarif '.runs[0].results | length')" = 0 ]
    licensed_convert none
    [ "$(sarif '.runs[0].results | length')" = 0 ]
}
