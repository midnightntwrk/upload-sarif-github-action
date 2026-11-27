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

# Severity is per rule, and one rule covers every package the advisory hits.
# osv-scanner scores each package's group on its own, so the same CVE can arrive
# at 5.0 on one package and 9.8 on another; upstream takes the worst.
@test "a CVE shared by packages scored differently takes the highest score" {
    report /src/Cargo.lock a 1.0.0 CVE-2026-1 5.0
    jq '.results[0].packages += [(.results[0].packages[0]
            | .package.name = "b" | .groups[0].max_severity = "9.8")]' \
        "$TMP/osv.json" > "$TMP/two.json" && mv "$TMP/two.json" "$TMP/osv.json"
    convert
    [ "$(rule CVE-2026-1 '.properties["security-severity"]')" = 9.8 ]
    [ "$(jq -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" --argjson threshold 0 "$TMP/r/osv.sarif" \
        | jq -r '[.hits[].severity] | unique | join(",")')" = CRITICAL ]
}

# --- fingerprints ----------------------------------------------------------------

# Code scanning tracks an alert across scans by partialFingerprints. Upstream's
# is sha256("<display id>:<artifact uri>:<name>@<version>") over the uri it saw
# (file:///src/...), so an alert raised before this converter keeps its identity.
FINGERPRINTS="$ROOT/scripts/sarif-fingerprints.sh"
fingerprinted() { convert "$@"; bash "$FINGERPRINTS" < "$TMP/r/osv.sarif" > "$TMP/r/fp.sarif" \
    && mv "$TMP/r/fp.sarif" "$TMP/r/osv.sarif"; }
fp() { result .partialFingerprints.primaryLocationLineHash "${1:-0}"; }

@test "a vulnerability carries upstream's fingerprint, byte for byte" {
    # From osv-scanner 2.7.0 --format sarif on this lockfile, scanned in /src.
    report /src/Cargo.lock smallvec 1.6.0 RUSTSEC-2021-0003,CVE-2021-25900 9.8
    fingerprinted
    [ "$(result .ruleId)" = CVE-2021-25900 ]
    [ "$(fp)" = f387af71c4f2b584e637af93b366cd54eadfec1c0c281fc66448049a30c9715b ]
}

@test "a git package's fingerprint names its short commit, as upstream's does" {
    report /src/Cargo.lock smallvec 1.6.0 CVE-2021-25900 9.8
    jq '.results[0].packages[0].package.commit = "0123456789abcdef0123456789abcdef01234567"' \
        "$TMP/osv.json" > "$TMP/c.json" && mv "$TMP/c.json" "$TMP/osv.json"
    fingerprinted
    want="$(printf '%s' 'CVE-2021-25900:file:///src/Cargo.lock:smallvec@01234567' | sha256sum | cut -d' ' -f1)"
    [ "$(fp)" = "$want" ]
}

@test "a deprecated package is fingerprinted, one per package" {
    deprecated /src/Cargo.lock crates.io spin 0.9.8
    jq '.results[0].packages += [(.results[0].packages[0] | .package.name = "chacha20")]' \
        "$TMP/osv.json" > "$TMP/two.json" && mv "$TMP/two.json" "$TMP/osv.json"
    packages '[]'
    fingerprinted --slurpfile packages "$TMP/pkgs.json"
    [ "$(sarif '[.runs[0].results[].partialFingerprints.primaryLocationLineHash] | unique | length')" = 2 ]
    [[ "$(fp)" =~ ^[0-9a-f]{64}$ ]]
}

# Upstream hashes the file URI, which Go's net/url escapes: space, #, %, !, (, )
# and non-ASCII are percent-encoded, + @ = are not. From osv-scanner 2.7.0's
# SARIF on this exact path.
WEIRD='/src/a b#c%d/ü!(x)+@=/Cargo.lock'
@test "a path that needs escaping keeps upstream's fingerprint" {
    report "$WEIRD" time 0.1.43 CVE-2020-26235 6.2
    fingerprinted
    [ "$(fp)" = 4b4b379c19864639c616760211bf8bede340c27afcfbd4abafbb853631622729 ]
}

@test "a path that needs escaping is a valid uri in the location, as upstream's was" {
    report "$WEIRD" time 0.1.43 CVE-2020-26235 6.2
    convert
    [ "$(result .locations[0].physicalLocation.artifactLocation.uri)" = 'a%20b%23c%25d/%C3%BC%21%28x%29+@=/Cargo.lock' ]
    deprecated "$WEIRD" crates.io spin 0.9.8
    convert
    [ "$(result .locations[0].physicalLocation.artifactLocation.uri)" = 'a%20b%23c%25d/%C3%BC%21%28x%29+@=/Cargo.lock' ]
}

# The lookup must not travel as one argv string: Linux caps a single argument
# at 128 KiB, about a thousand fingerprints.
@test "a scan with thousands of findings is fingerprinted" {
    deprecated /src/Cargo.lock crates.io spin 0.9.8
    jq '.results[0].packages = [range(3000) as $i | .results[0].packages[0] | .package.name = "crate-\($i)"]' \
        "$TMP/osv.json" > "$TMP/many.json" && mv "$TMP/many.json" "$TMP/osv.json"
    fingerprinted
    [ "$(sarif '[.runs[0].results[].partialFingerprints.primaryLocationLineHash] | unique | length')" = 3000 ]
}

@test "the fingerprint input does not leak into the uploaded SARIF" {
    report /src/Cargo.lock smallvec 1.6.0 CVE-2021-25900 9.8
    fingerprinted
    [ "$(sarif '[.runs[].results[] | .properties // {} | has("fingerprint_input")] | any')" = false ]
}

@test "a result with no fingerprint input fails the step, never ships unfingerprinted" {
    report /src/Cargo.lock smallvec 1.6.0 CVE-2021-25900 9.8
    convert
    jq 'del(.runs[0].results[0].properties.fingerprint_input)' "$TMP/r/osv.sarif" > "$TMP/r/bad.sarif"
    run bash "$FINGERPRINTS" < "$TMP/r/bad.sarif"
    [ "$status" -ne 0 ]
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
    packages '[{"path":"rust/Cargo.lock","name":"spin","version":"0.9.8","line":7,"source":"crates.io"}]'
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

# One Cargo.lock can hold the same name and version from crates.io and from a
# git fork (polkadot-sdk forks do). The git twin must not hide the real yank,
# whichever comes first in the file.
twins() {
    local reg='{"path":"Cargo.lock","name":"spin","version":"0.9.8","line":3,"source":"crates.io"}'
    local git='{"path":"Cargo.lock","name":"spin","version":"0.9.8","line":8,"source":"git"}'
    if [ "$1" = git-last ]; then packages "[$reg,$git]"; else packages "[$git,$reg]"; fi
}

@test "a yanked crates.io crate is reported even when a git twin follows it" {
    deprecated /src/Cargo.lock crates.io spin 0.9.8
    twins git-last
    converted
    [ "$(sarif '.runs[0].results | length')" = 1 ]
    [ "$(result .locations[0].physicalLocation.region.startLine)" = 3 ]
}

@test "a yanked crates.io crate is reported even when a git twin precedes it" {
    deprecated /src/Cargo.lock crates.io spin 0.9.8
    twins git-first
    converted
    [ "$(sarif '.runs[0].results | length')" = 1 ]
    [ "$(result .locations[0].physicalLocation.region.startLine)" = 3 ]
}

@test "twins listed twice in the report are reported once" {
    deprecated /src/Cargo.lock crates.io spin 0.9.8
    jq '.results[0].packages += .results[0].packages' "$TMP/osv.json" > "$TMP/two.json" \
        && mv "$TMP/two.json" "$TMP/osv.json"
    twins git-last
    converted
    [ "$(sarif '.runs[0].results | length')" = 1 ]
}

# A path crate - a workspace member, or a yanked crate vendored to patch it -
# has no `source =` line; another registry has its own. Neither is the crates.io
# release deps.dev looked up.
@test "a path crate is not reported" {
    deprecated /src/Cargo.lock crates.io spin 0.9.8
    packages '[{"path":"Cargo.lock","name":"spin","version":"0.9.8","line":3,"source":"path"}]'
    converted
    [ "$(sarif '.runs[0].results | length')" = 0 ]
}

@test "an index entry with no source is not taken as crates.io" {
    deprecated /src/Cargo.lock crates.io spin 0.9.8
    packages '[{"path":"Cargo.lock","name":"spin","version":"0.9.8","line":3}]'
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
#
# The purl is shaped as scalibr writes it: a `source=` qualifier on npm
# package-lock packages only (javascript/purl/purl.go), none anywhere else.
licensed() {
    jq -n --arg path "$1" --arg eco "$2" --arg name "$3" --arg ver "$4" \
          --argjson lic "$5" --argjson groups "${6:-[]}" '
        ({"npm": "npm", "crates.io": "cargo", "PyPI": "pypi", "Go": "golang", "Maven": "maven",
          "NuGet": "nuget", "RubyGems": "gem", "Packagist": "composer", "Pub": "pub", "Hex": "hex",
          "ConanCenter": "conan"}[$eco] // "generic") as $type
        | {results: [{source: {path: $path, type: "lockfile"},
            packages: [{package: {name: $name, version: $ver, ecosystem: $eco,
                                  purl: ("pkg:\($type)/\($name)@\($ver)"
                                         + (if $eco == "npm" then "?source=PUBLIC_REGISTRY" else "" end))},
                        licenses: $lic}
                       + (if ($groups | length) > 0 then {dependency_groups: $groups} else {} end)]}]}' \
        > "$TMP/osv.json"
}

# npm_packages <json array> -- the package-lock.json index (scripts/npm-lock-packages.sh)
npm_packages() { printf '%s\n' "$1" > "$TMP/npm.json"; }

# licensed_convert <allowlist> -- convert with the lockfile indexes and that allowlist
licensed_convert() {
    [ -f "$TMP/pkgs.json" ] || packages '[]'
    [ -f "$TMP/npm.json" ] || npm_packages '[]'
    convert --slurpfile packages "$TMP/pkgs.json" --slurpfile npm "$TMP/npm.json" --arg licenses "$1"
}

# Licence results ship through the same fingerprint step, which fails on a
# result with nothing to hash.
@test "licence results are fingerprinted, at an escaped location" {
    licensed '/src/a b/Cargo.lock' crates.io polkadot-primitives 18.0.0 '["GPL-3.0-only"]'
    packages '[]'
    licensed_convert "MIT"
    bash "$FINGERPRINTS" < "$TMP/r/osv.sarif" > "$TMP/r/fp.sarif"
    want="$(printf '%s' 'license-violation:file:///src/a%20b/Cargo.lock:polkadot-primitives@18.0.0' \
        | sha256sum | cut -d' ' -f1)"
    [ "$(jq -r '.runs[0].results[0].partialFingerprints.primaryLocationLineHash' "$TMP/r/fp.sarif")" = "$want" ]
    [ "$(result .locations[0].physicalLocation.artifactLocation.uri)" = 'a%20b/Cargo.lock' ]
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

# Without the package-lock index (yarn, pnpm, bun, or no index), only
# osv-scanner's groups are left. npm installs an optional dependency whenever
# it can, so `optional` ships; `dev` alone does not. `dev` + `optional` is
# either devOptional (ships) or an optional dependency of a dev dependency
# (does not) - the groups cannot tell, so it is judged: a known false positive
# the index removes (next test).
@test "without the lockfile index: dev-only is skipped, optional and dev+optional are judged" {
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
    # Only the boolean true is the dev flag; a string is truthy in jq and must not skip.
    [ "$(npm_flags '"dev":"false","optional":false,"devOptional":false' '[]')" = 1 ]
}

# One name@version can be installed twice in one lockfile - at the root for
# production and again under a dev tool's own node_modules. osv-scanner reports
# it once; the index holds both entries, and the package ships if any of them
# does. The line is a shipping entry's, whichever order the lockfile lists them.
@test "a package installed for production and again under a dev tool ships" {
    dup() {
        npm_packages "[$1]"
        licensed /src/js/package-lock.json npm dup 1.0.0 '["GPL-3.0-only"]' '[]'
        licensed_convert "MIT"
        printf '%s %s' "$(sarif '.runs[0].results | length')" "$(result .locations[0].physicalLocation.region.startLine)"
    }
    packages '[]'
    prod='{"path":"js/package-lock.json","name":"dup","version":"1.0.0","line":5,"dev":false,"optional":false,"devOptional":false}'
    dev='{"path":"js/package-lock.json","name":"dup","version":"1.0.0","line":40,"dev":true,"optional":false,"devOptional":false}'
    [ "$(dup "$prod,$dev")" = "1 5" ]
    [ "$(dup "$dev,$prod")" = "1 5" ]
    [ "$(dup "$dev")" = "0 null" ]
}

@test "an unknown licence on a crates.io package is a license-unknown at LOW" {
    licensed /src/Cargo.lock crates.io ring 0.16.20 '["non-standard"]'
    packages '[{"path":"Cargo.lock","name":"ring","version":"0.16.20","line":5,"source":"crates.io"}]'
    licensed_convert "MIT"
    [ "$(result .ruleId)" = license-unknown ]
    [ "$(result .locations[0].physicalLocation.region.startLine)" = 5 ]
    [ "$(jq -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" --argjson threshold 0 "$TMP/r/osv.sarif" \
        | jq -r '.hits[0].severity')" = LOW ]
    licensed /src/Cargo.lock crates.io yamux 0.12.2 '["UNKNOWN"]'
    packages '[{"path":"Cargo.lock","name":"yamux","version":"0.12.2","line":5,"source":"crates.io"}]'
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

# A bare string where the list belongs is unambiguous: read it as one item.
@test "a bare-string licence field is read as a one-item list" {
    packages '[]'
    licensed /src/js/package-lock.json npm d 1.0.0 '"UNKNOWN"'
    licensed_convert "MIT"
    [ "$(result .ruleId)" = license-unknown ]
    licensed /src/js/package-lock.json npm e 1.0.0 '"GPL-3.0-only"'
    licensed_convert "MIT"
    [ "$(result .ruleId)" = license-violation ]
}

# deps.dev knows nothing about a workspace member, a git dependency, another
# Cargo registry or a local npm package; "unknown" there is a fact about
# deps.dev, not about the licence.
@test "an unknown licence on a workspace, git, other-registry or local package is not reported" {
    licensed /src/Cargo.lock crates.io midnight-node 3.0.0 '["UNKNOWN"]'
    packages '[{"path":"Cargo.lock","name":"midnight-node","version":"3.0.0","line":5,"source":"path"}]'
    licensed_convert "MIT"
    [ "$(sarif '.runs[0].results | length')" = 0 ]
    licensed /src/Cargo.lock crates.io yamux 0.12.2 '["UNKNOWN"]'
    packages '[{"path":"Cargo.lock","name":"yamux","version":"0.12.2","line":5,"source":"git"}]'
    licensed_convert "MIT"
    [ "$(sarif '.runs[0].results | length')" = 0 ]
    licensed /src/Cargo.lock crates.io private-crate 1.0.0 '["UNKNOWN"]'
    packages '[{"path":"Cargo.lock","name":"private-crate","version":"1.0.0","line":5,"source":"registry"}]'
    licensed_convert "MIT"
    [ "$(sarif '.runs[0].results | length')" = 0 ]
    licensed /src/js/package-lock.json npm my-app 1.0.0 '["UNKNOWN"]'
    jq '.results[0].packages[0].package.purl = "pkg:npm/my-app@1.0.0?source=LOCAL"' "$TMP/osv.json" \
        > "$TMP/l.json" && mv "$TMP/l.json" "$TMP/osv.json"
    packages '[]'
    licensed_convert "MIT"
    [ "$(sarif '.runs[0].results | length')" = 0 ]
}

# A git fork keeps its upstream's licence, so the crates.io answer stands for it.
@test "a banned licence on a git package is still a violation" {
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

# --- licence edge cases ----------------------------------------------------------

# osv-scanner 2.7.0, real output: a package deps.dev knows nothing about comes
# back as ["UNKNOWN"]; one excused with [[PackageOverrides]] license.ignore =
# true comes back with no `licenses` key at all (the field is omitempty). The
# excuse must clear the finding, not turn it into a LOW unknown - and it is
# listed, never hidden: one `license-excused` result, suppressed (accepted,
# external), at NOTE, which the gate shows and never counts. A licensed
# package beside it: with no licence data anywhere the scan fails instead.
@test "a package with no licences field was excused: listed as suppressed, never gated" {
    licensed /src/Cargo.lock crates.io polkadot-primitives 18.0.0 '["GPL-3.0-only"]'
    jq '.results[0].packages += [.results[0].packages[0] | .package.name = "serde" | .licenses = ["MIT"]]
        | del(.results[0].packages[0].licenses)' "$TMP/osv.json" > "$TMP/x.json" && mv "$TMP/x.json" "$TMP/osv.json"
    packages '[]'
    licensed_convert "MIT"
    [ "$(sarif '[.runs[0].results[].ruleId] | join(" ")')" = license-excused ]
    [ "$(result .properties.severity)" = NOTE ]
    [ "$(result '.suppressions[0] | "\(.kind) \(.status)"')" = "external accepted" ]
    [[ "$(result .message.text)" == *"polkadot-primitives@18.0.0"*"license.ignore"* ]]
    [ "$(jq -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" --argjson threshold 0 "$TMP/r/osv.sarif" | jq '.hits | length')" = 0 ]
    # Licences off: nothing was checked, so nothing was excused.
    licensed_convert none
    [ "$(sarif '.runs[0].results | length')" = 0 ]
}

# A field that is there but says nothing is deps.dev's "could not tell", not
# an excuse: only the missing key is. osv-scanner never writes these forms.
@test "a present but empty licence field is unknown, never a violation" {
    packages '[]'
    for lic in '[]' 'null' '["", "  "]'; do
        licensed /src/Cargo.lock crates.io a 1.0.0 "$lic"
        licensed_convert "MIT"
        [ "$(result .ruleId)" = license-unknown ] || { echo "licenses: $lic"; return 1; }
    done
}

# A placeholder inside an expression is still "could not tell". It is a
# violation only when the expression fails whatever the placeholder stands for.
@test "a placeholder inside an expression is unknown unless the rest already fails" {
    packages '[]'
    licensed /src/Cargo.lock crates.io a 1.0.0 '["MIT AND non-standard"]'
    licensed_convert "MIT"
    [ "$(result .ruleId)" = license-unknown ]
    licensed /src/Cargo.lock crates.io a 1.0.0 '["GPL-3.0-only AND UNKNOWN"]'
    licensed_convert "MIT"
    [ "$(result .ruleId)" = license-violation ]
    licensed /src/Cargo.lock crates.io a 1.0.0 '["MIT OR non-standard"]'
    licensed_convert "MIT"
    [ "$(sarif '.runs[0].results | length')" = 0 ]
}

# The same twin case as deprecated packages: the git or path entry must not
# decide for the crates.io one, whichever comes first.
@test "an unknown licence on a crates.io crate is reported even beside a git twin" {
    licensed /src/Cargo.lock crates.io spin 0.9.8 '["UNKNOWN"]'
    twins git-last
    licensed_convert "MIT"
    [ "$(sarif '.runs[0].results | length')" = 1 ]
    [ "$(result .locations[0].physicalLocation.region.startLine)" = 3 ]
    twins git-first
    licensed_convert "MIT"
    [ "$(sarif '.runs[0].results | length')" = 1 ]
    [ "$(result .locations[0].physicalLocation.region.startLine)" = 3 ]
}

# deps.dev looks crates up on crates.io by name and version alone; a workspace
# member's licence is whatever an unrelated crate of that name carries.
@test "a path crate is never judged on a crates.io namesake's licence" {
    licensed /src/Cargo.lock crates.io my-member 0.1.0 '["GPL-3.0-only"]'
    packages '[{"path":"Cargo.lock","name":"my-member","version":"0.1.0","line":5,"source":"path"}]'
    licensed_convert "MIT"
    [ "$(sarif '.runs[0].results | length')" = 0 ]
}

@test "an unknown licence from a private npm registry is not reported; a public one is" {
    licensed /src/js/package-lock.json npm corp-lib 1.0.0 '["UNKNOWN"]'
    jq '.results[0].packages[0].package.purl = "pkg:npm/corp-lib@1.0.0?source=OTHER"' \
        "$TMP/osv.json" > "$TMP/x.json" && mv "$TMP/x.json" "$TMP/osv.json"
    packages '[]'
    licensed_convert "MIT"
    [ "$(sarif '.runs[0].results | length')" = 0 ]
    licensed /src/js/package-lock.json npm pub-lib 1.0.0 '["UNKNOWN"]'
    licensed_convert "MIT"
    [ "$(result .ruleId)" = license-unknown ]
}

@test "Go's stdlib pseudo-package never has an unknown licence" {
    licensed /src/go.mod Go stdlib 1.22.0 '["UNKNOWN"]'
    packages '[]'
    licensed_convert "MIT"
    [ "$(sarif '.runs[0].results | length')" = 0 ]
}

@test "a package listed twice is one licence finding" {
    licensed /src/Cargo.lock crates.io polkadot-primitives 18.0.0 '["GPL-3.0-only"]'
    jq '.results[0].packages += .results[0].packages' "$TMP/osv.json" > "$TMP/x.json" && mv "$TMP/x.json" "$TMP/osv.json"
    packages '[]'
    licensed_convert "MIT"
    [ "$(sarif '.runs[0].results | length')" = 1 ]
}

# Only `none` turns licence checks off. An empty value - an unset workflow
# variable - or a `default` with no list behind it must fail, not go quiet.
@test "an empty allowlist, or default with no list, fails instead of turning checks off" {
    licensed /src/Cargo.lock crates.io polkadot-primitives 18.0.0 '["GPL-3.0-only"]'
    packages '[]'
    npm_packages '[]'
    run jq -L "$ROOT/scripts" -f "$OSV_JQ" --slurpfile packages "$TMP/pkgs.json" --slurpfile npm "$TMP/npm.json" \
        --arg licenses "" "$TMP/osv.json"
    [ "$status" -ne 0 ]
    [[ "$output" == *"licenses_allowlist is empty"* ]]
    run jq -L "$ROOT/scripts" -f "$OSV_JQ" --slurpfile packages "$TMP/pkgs.json" --slurpfile npm "$TMP/npm.json" \
        --arg licenses default "$TMP/osv.json"
    [ "$status" -ne 0 ]
    [[ "$output" == *"default_licenses"* ]]
}

@test "none is the off switch whatever its case or padding" {
    licensed /src/Cargo.lock crates.io polkadot-primitives 18.0.0 '["GPL-3.0-only"]'
    packages '[]'
    licensed_convert " None "
    [ "$(sarif '.runs[0].results | length')" = 0 ]
}

@test "an allowlist entry that is an expression, not an id, is refused" {
    licensed /src/Cargo.lock crates.io polkadot-primitives 18.0.0 '["GPL-3.0-only"]'
    packages '[]'
    npm_packages '[]'
    run jq -L "$ROOT/scripts" -f "$OSV_JQ" --slurpfile packages "$TMP/pkgs.json" --slurpfile npm "$TMP/npm.json" \
        --arg licenses "MIT OR Apache-2.0" "$TMP/osv.json"
    [ "$status" -ne 0 ]
    [[ "$output" == *"MIT OR Apache-2.0"* ]]
}

# A failed deps.dev lookup and "every package excused" look the same in the
# JSON; scripts/osv-enrichers.sh tells them apart from osv-scanner's log and
# fails the scan on the first. By the time osv.jq runs, a report where every
# package lacks licences is a repository that excused them all: list each.
@test "a report where every package is excused lists them all, and does not fail" {
    licensed /src/Cargo.lock crates.io a 1.0.0 '[]'
    jq 'del(.results[0].packages[0].licenses)' "$TMP/osv.json" > "$TMP/x.json" && mv "$TMP/x.json" "$TMP/osv.json"
    packages '[]'
    licensed_convert "MIT"
    [ "$(sarif '[.runs[0].results[].ruleId] | join(" ")')" = license-excused ]
    licensed_convert none
    [ "$(sarif '.runs[0].results | length')" = 0 ]
}


# One excused package beside one with data is the license.ignore case, not an
# outage. Go's stdlib and ecosystems deps.dev does not cover never count.
@test "an excused package beside licensed ones, or no deps.dev package at all, is fine" {
    licensed /src/Cargo.lock crates.io a 1.0.0 '["MIT"]'
    jq '.results[0].packages += [.results[0].packages[0] | .package.name = "b" | del(.licenses)]' \
        "$TMP/osv.json" > "$TMP/x.json" && mv "$TMP/x.json" "$TMP/osv.json"
    packages '[]'
    # Fine means nothing gated: the excuse itself is listed, suppressed.
    open_results() { sarif '[.runs[0].results[] | select((.suppressions // []) | length == 0)] | length'; }
    licensed_convert "MIT"
    [ "$(open_results)" = 0 ]
    licensed /src/go.mod Go stdlib 1.22.0 '[]'
    jq 'del(.results[0].packages[0].licenses)' "$TMP/osv.json" > "$TMP/x.json" && mv "$TMP/x.json" "$TMP/osv.json"
    licensed_convert "MIT"
    [ "$(open_results)" = 0 ]
}

# deps.dev covers npm, NuGet, crates.io, Go, Maven, PyPI and RubyGems. For any
# other ecosystem osv-scanner writes ["UNKNOWN"] without asking: a fact about
# deps.dev, reported on every package of every scan if taken at its word.
@test "an unknown licence in an ecosystem deps.dev does not cover is not reported" {
    packages '[]'
    for eco in Packagist Pub Hex ConanCenter; do
        licensed /src/lockfile $eco some/pkg 1.0.0 '["UNKNOWN"]'
        licensed_convert "MIT"
        [ "$(sarif '.runs[0].results | length')" = 0 ] || { echo "$eco reported"; return 1; }
    done
    for eco in npm NuGet crates.io Go Maven PyPI RubyGems; do
        licensed /src/lockfile $eco some-pkg 1.0.0 '["UNKNOWN"]'
        licensed_convert "MIT"
        [ "$(result .ruleId)" = license-unknown ] || { echo "$eco not reported"; return 1; }
    done
    # A licence the repository recorded with license.override is still judged.
    licensed /src/composer.lock Packagist some/pkg 1.0.0 '["GPL-3.0-only"]'
    licensed_convert "MIT"
    [ "$(result .ruleId)" = license-violation ]
}

# deps.dev looks a package up by name and version on the public registry. For
# a crate from another Cargo registry, or an npm package that is local or from
# a private registry, that is a namesake's licence, not this package's.
@test "a namesake's banned licence is no violation for another registry's or a local package" {
    licensed /src/Cargo.lock crates.io private-crate 1.0.0 '["GPL-3.0-only"]'
    for src in registry other; do
        packages "[{\"path\":\"Cargo.lock\",\"name\":\"private-crate\",\"version\":\"1.0.0\",\"line\":5,\"source\":\"$src\"}]"
        licensed_convert "MIT"
        [ "$(sarif '.runs[0].results | length')" = 0 ] || { echo "cargo $src reported"; return 1; }
    done
    packages '[]'
    # scalibr 0.5.4's npm purl `source`: PUBLIC_REGISTRY, OTHER (any other
    # http or git source: a private registry, a git dependency) or LOCAL.
    for src in LOCAL OTHER; do
        licensed /src/js/package-lock.json npm my-app 1.0.0 '["GPL-3.0-only"]'
        jq --arg s "$src" '.results[0].packages[0].package.purl = "pkg:npm/my-app@1.0.0?source=\($s)"' \
            "$TMP/osv.json" > "$TMP/x.json" && mv "$TMP/x.json" "$TMP/osv.json"
        licensed_convert "MIT"
        [ "$(sarif '.runs[0].results | length')" = 0 ] || { echo "npm $src reported"; return 1; }
    done
}

# A crate the index should hold but does not - a Cargo.lock it could not read
# line by line - is of unknown provenance: never taken for crates.io's.
# osv-scanner and scripts/cargo-lock-packages.sh read the same [[package]]
# list, so a crate missing from an indexed Cargo.lock means the index misread
# the file. Skipping it would switch both rules off for that crate with no
# trace; fail instead, naming the lockfile and the crate.
@test "a crate missing from its lockfile's index fails, naming both" {
    packages '[{"path":"Cargo.lock","name":"other","version":"1.0.0","line":5,"source":"crates.io"}]'
    npm_packages '[]'
    for lic in '["UNKNOWN"]' '["GPL-3.0-only"]'; do
        licensed /src/Cargo.lock crates.io yamux 0.12.2 "$lic"
        run jq -L "$ROOT/scripts" -f "$OSV_JQ" --slurpfile packages "$TMP/pkgs.json" --slurpfile npm "$TMP/npm.json" \
            --arg licenses MIT "$TMP/osv.json"
        [ "$status" -ne 0 ] || { echo "licenses $lic passed"; return 1; }
        [[ "$output" == *"Cargo.lock"*"yamux@0.12.2"* ]]
    done
    deprecated /src/Cargo.lock crates.io yamux 0.12.2
    run jq -L "$ROOT/scripts" -f "$OSV_JQ" --slurpfile packages "$TMP/pkgs.json" "$TMP/osv.json"
    [ "$status" -ne 0 ]
    [[ "$output" == *"yamux@0.12.2"* ]]
    # A lockfile the index never saw is still reported, on line 1.
    deprecated /src/other/Cargo.lock crates.io yamux 0.12.2
    converted
    [ "$(result .locations[0].physicalLocation.region.startLine)" = 1 ]
}

# The schema says an array of strings ([]License, models/results.go). An
# object, array, boolean, number or null where a string should be is a format
# change, and reading it as UNKNOWN would quietly turn every violation into a
# LOW: fail and name it.
@test "a licence entry that is not a string fails, naming the package" {
    packages '[]'
    npm_packages '[]'
    for lic in '[{"id":"GPL-3.0-only"}]' '[["GPL-3.0-only"]]' '{"id":"GPL-3.0-only"}' false '[true]' 1 '[null]'; do
        licensed /src/Cargo.lock crates.io polkadot-primitives 18.0.0 "$lic"
        run jq -L "$ROOT/scripts" -f "$OSV_JQ" --slurpfile packages "$TMP/pkgs.json" --slurpfile npm "$TMP/npm.json" \
            --arg licenses MIT "$TMP/osv.json"
        [ "$status" -ne 0 ] || { echo "licenses: $lic passed"; return 1; }
        [[ "$output" == *"polkadot-primitives@18.0.0"* ]]
    done
}

# A tab or a newline in a name or path must not break the hash lookup: the
# result would ship with a null fingerprint and the upload would reject it.
@test "a fingerprint input with a tab or newline in it is still hashed" {
    deprecated $'/src/a\tb/Cargo.lock' crates.io $'odd\nname' 1.0.0
    fingerprinted
    want="$(printf '%s' $'deprecated-package:file:///src/a%09b/Cargo.lock:odd\nname@1.0.0' | sha256sum | cut -d' ' -f1)"
    [ "$(fp)" = "$want" ]
}

# The Cargo.lock index stores raw paths; the lookup must use the raw path too,
# not the escaped location uri.
@test "a lockfile under a directory that needs escaping still finds its index entry" {
    deprecated '/src/a b/Cargo.lock' crates.io spin 0.9.8
    packages '[{"path":"a b/Cargo.lock","name":"spin","version":"0.9.8","line":7,"source":"path"}]'
    converted
    [ "$(sarif '.runs[0].results | length')" = 0 ]
    packages '[{"path":"a b/Cargo.lock","name":"spin","version":"0.9.8","line":7,"source":"crates.io"}]'
    converted
    [ "$(result .locations[0].physicalLocation.region.startLine)" = 7 ]
    licensed '/src/a b/Cargo.lock' crates.io spin 0.9.8 '["UNKNOWN"]'
    packages '[{"path":"a b/Cargo.lock","name":"spin","version":"0.9.8","line":7,"source":"path"}]'
    licensed_convert "MIT"
    [ "$(sarif '.runs[0].results | length')" = 0 ]
}

# scalibr calls any http registry URL with "npm" in it PUBLIC_REGISTRY, so a
# private npm.corp.example or Artifactory .../api/npm/ reads as public. The
# package-lock index records where the lockfile itself resolved each install
# from, and that decides; the purl only where the index has no answer.
@test "the lockfile's resolved registry decides public or namesake over the purl" {
    packages '[]'
    # Licence findings only: a lockfile with no public install also gets its
    # license-unchecked note, tested on its own below.
    judged() { sarif '[.runs[0].results[] | select(.ruleId != "license-unchecked")] | length'; }
    entry() { npm_packages "[{\"path\":\"js/package-lock.json\",\"name\":\"lib\",\"version\":\"1.0.0\",\"line\":9,\"dev\":false,\"optional\":false,\"devOptional\":false,\"source\":\"$1\"}]"; }
    for lic in '["GPL-3.0-only"]' '["UNKNOWN"]'; do
        licensed /src/js/package-lock.json npm lib 1.0.0 "$lic"
        for src in other local; do
            entry $src
            licensed_convert "MIT"
            [ "$(judged)" = 0 ] || { echo "$lic from $src reported"; return 1; }
        done
        entry npmjs
        licensed_convert "MIT"
        [ "$(judged)" = 1 ] || { echo "$lic from npmjs not reported"; return 1; }
    done
    # Only installs that ship count: a dev-only public copy says nothing about
    # the private one that ships.
    npm_packages '[{"path":"js/package-lock.json","name":"lib","version":"1.0.0","line":9,"dev":true,"optional":false,"devOptional":false,"source":"npmjs"},
                   {"path":"js/package-lock.json","name":"lib","version":"1.0.0","line":20,"dev":false,"optional":false,"devOptional":false,"source":"other"}]'
    licensed /src/js/package-lock.json npm lib 1.0.0 '["GPL-3.0-only"]'
    licensed_convert "MIT"
    [ "$(judged)" = 0 ]
    # No resolved URL (omit-lockfile-registry-resolved, bundled): the default
    # registry, judged - although scalibr writes source=LOCAL for it.
    entry default
    licensed /src/js/package-lock.json npm lib 1.0.0 '["GPL-3.0-only"]'
    jq '.results[0].packages[0].package.purl = "pkg:npm/lib@1.0.0?source=LOCAL"' "$TMP/osv.json" > "$TMP/x.json" \
        && mv "$TMP/x.json" "$TMP/osv.json"
    licensed_convert "MIT"
    [ "$(result .ruleId)" = license-violation ]
    # No index entry at all (yarn, pnpm, bun): the purl decides.
    npm_packages '[]'
    jq '.results[0].packages[0].package.purl = "pkg:npm/lib@1.0.0?source=OTHER"' "$TMP/osv.json" > "$TMP/x.json" \
        && mv "$TMP/x.json" "$TMP/osv.json"
    licensed_convert "MIT"
    [ "$(sarif '.runs[0].results | length')" = 0 ]
}

# A lockfile whose shipping npm installs all resolve outside the public
# registry - a registry proxy reads exactly like that - has every licence
# skipped as a namesake. Say so once per lockfile, at NOTE: listed, never gated.
@test "a lockfile with no public-registry install says its licences went unchecked" {
    packages '[]'
    npm_packages '[{"path":"js/package-lock.json","name":"a","version":"1.0.0","line":5,"dev":false,"optional":false,"devOptional":false,"source":"other"},
                   {"path":"js/package-lock.json","name":"b","version":"1.0.0","line":9,"dev":false,"optional":false,"devOptional":false,"source":"other"},
                   {"path":"js/package-lock.json","name":"t","version":"1.0.0","line":12,"dev":true,"optional":false,"devOptional":false,"source":"npmjs"}]'
    licensed /src/js/package-lock.json npm a 1.0.0 '["GPL-3.0-only"]'
    jq '.results[0].packages += [.results[0].packages[0] | .package.name = "b" | .licenses = ["MIT"]]' "$TMP/osv.json" \
        > "$TMP/x.json" && mv "$TMP/x.json" "$TMP/osv.json"
    licensed_convert "MIT"
    [ "$(sarif '[.runs[0].results[] | .ruleId] | join(" ")')" = license-unchecked ]
    [ "$(result .properties.severity)" = NOTE ]
    [ "$(result .locations[0].physicalLocation.artifactLocation.uri)" = js/package-lock.json ]
    [[ "$(result .message.text)" == *"2 "*"registry.npmjs.org"* ]]
    # One public install in the lockfile: the ordinary case, no note.
    npm_packages '[{"path":"js/package-lock.json","name":"a","version":"1.0.0","line":5,"dev":false,"optional":false,"devOptional":false,"source":"other"},
                   {"path":"js/package-lock.json","name":"b","version":"1.0.0","line":9,"dev":false,"optional":false,"devOptional":false,"source":"npmjs"}]'
    licensed_convert "MIT"
    [ "$(sarif '[.runs[0].results[] | select(.ruleId == "license-unchecked")] | length')" = 0 ]
    # Licences off: nothing to say.
    licensed_convert none
    [ "$(sarif '.runs[0].results | length')" = 0 ]
}

# deps.dev's deprecation flag is keyed on name and version too: a private or
# local npm package inherits a public namesake's deprecation.
@test "a deprecated npm namesake from outside the public registry is not reported" {
    deprecated /src/js/package-lock.json npm left-pad 1.3.0
    packages '[]'
    for src in other local; do
        npm_packages "[{\"path\":\"js/package-lock.json\",\"name\":\"left-pad\",\"version\":\"1.3.0\",\"line\":7,\"dev\":false,\"optional\":false,\"devOptional\":false,\"source\":\"$src\"}]"
        convert --slurpfile packages "$TMP/pkgs.json" --slurpfile npm "$TMP/npm.json"
        [ "$(sarif '.runs[0].results | length')" = 0 ] || { echo "$src reported"; return 1; }
    done
    npm_packages '[{"path":"js/package-lock.json","name":"left-pad","version":"1.3.0","line":7,"dev":false,"optional":false,"devOptional":false,"source":"npmjs"}]'
    convert --slurpfile packages "$TMP/pkgs.json" --slurpfile npm "$TMP/npm.json"
    [ "$(result .ruleId)" = deprecated-package ]
    [ "$(result .locations[0].physicalLocation.region.startLine)" = 7 ]
}

# `default` names the whole list; inside a comma list it would be read as a
# licence id that matches nothing, silently dropping the default list.
@test "default or none inside a list is refused" {
    licensed /src/Cargo.lock crates.io a 1.0.0 '["MIT"]'
    packages '[]'
    npm_packages '[]'
    for v in "default,GPL-3.0-only" "MIT, none"; do
        run jq -L "$ROOT/scripts" -f "$OSV_JQ" --slurpfile packages "$TMP/pkgs.json" --slurpfile npm "$TMP/npm.json" \
            --arg licenses "$v" --rawfile default_licenses "$ROOT/scripts/license-allowlist.txt" "$TMP/osv.json"
        [ "$status" -ne 0 ] || { echo "'$v' accepted"; return 1; }
        [[ "$output" == *"licenses_allowlist"* ]]
    done
}

# osv-scanner logs a lockfile it cannot parse and scans the rest, and exits 1
# whenever anything else was found, so the lockfile would drop out unseen. With
# its log (--rawfile osv_log) each one is a MEDIUM `lockfile-unreadable` at
# that lockfile. The lines are verbatim from osv-scanner v2.7.0 (paths relative
# to /, as in the container); the enricher lines are osv-enrichers.sh's.
osv_log() {
    printf '%s\n' 'Scanning dir .' \
        'Error during extraction: (extracting as javascript/packagelockjson) src/js/package-lock.json: could not extract: unexpected end of JSON input' \
        'Error during extraction: (extracting as rust/cargolock) src/rust/Cargo.lock: could not extract: toml: line 3 (last key "package.version"): unexpected EOF; expected value' \
        'Error during extraction: (extracting as license/depsdev) failed to get version information max retries exhausted' \
        > "$TMP/osv.log"
}

@test "a lockfile osv-scanner could not read is a MEDIUM finding at that lockfile" {
    report /src/Cargo.lock smallvec 1.6.0 CVE-2021-25900 9.8
    osv_log
    convert --rawfile osv_log "$TMP/osv.log"
    [ "$(sarif '[.runs[0].results[] | select(.ruleId == "lockfile-unreadable") | .locations[0].physicalLocation.artifactLocation.uri] | join(" ")')" \
        = "js/package-lock.json rust/Cargo.lock" ]
    [ "$(sarif '[.runs[0].results[] | select(.ruleId == "lockfile-unreadable") | .properties.severity] | unique | join(" ")')" = MEDIUM ]
    [[ "$(sarif '.runs[0].results[] | select(.ruleId == "lockfile-unreadable") | .message.text' | head -1)" == *"unexpected end of JSON input"* ]]
    bash "$FINGERPRINTS" < "$TMP/r/osv.sarif" > /dev/null
    # No log given: nothing to say.
    convert
    [ "$(sarif '[.runs[0].results[] | select(.ruleId == "lockfile-unreadable")] | length')" = 0 ]
}

# More than one failed file per extractor is logged as a header line and one
# tab-indented `path: error` line each (osv-scanner scan.go logPluginStatus).
@test "several unreadable lockfiles under one extractor are each a finding" {
    report /src/Cargo.lock smallvec 1.6.0 CVE-2021-25900 9.8
    printf 'Error during extraction: (extracting as javascript/packagelockjson) \n\tsrc/a/package-lock.json: bad\n\tsrc/b/package-lock.json: worse\n' > "$TMP/osv.log"
    convert --rawfile osv_log "$TMP/osv.log"
    [ "$(sarif '[.runs[0].results[] | select(.ruleId == "lockfile-unreadable") | .locations[0].physicalLocation.artifactLocation.uri] | join(" ")')" \
        = "a/package-lock.json b/package-lock.json" ]
}
