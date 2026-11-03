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
    jq -f "$OSV_JQ" "$@" "$TMP/osv.json" > "$TMP/r/osv.sarif"
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
    packages '[{"path":"rust/Cargo.lock","name":"spin","version":"0.9.8","line":7,"git":false}]'
    converted
    [ "$(result .locations[0].physicalLocation.region.startLine)" = 7 ]
}

# deps.dev matches on name and version alone: a crate built from a git fork is
# flagged whenever crates.io yanked the release of the same name and version.
# Cargo.lock says where it really came from.
@test "a git-sourced crate is not reported" {
    deprecated /src/Cargo.lock crates.io sp-api-proc-macro 15.0.0
    packages '[{"path":"Cargo.lock","name":"sp-api-proc-macro","version":"15.0.0","line":3,"git":true}]'
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
