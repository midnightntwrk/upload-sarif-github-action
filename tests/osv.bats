#!/usr/bin/env bats
#
# The osv-scanner policy, applied by scripts/osv.jq before the gate sees it.
#
# osv-scanner sets `level: warning` on every result, so its own SARIF cannot
# fail the build at the `critical` default. The signal is elsewhere: a CVSS
# score on the rule (`properties.security-severity`), and for malware - OSV's
# MAL-* ids - nothing at all.

load helper

OSV_JQ="$ROOT/scripts/osv.jq"

setup() { TMP="$(mktemp -d)"; }
teardown() { rm -rf "$TMP"; }

# doc <rule-id> <security-severity or ""> <uri> -- osv-scanner-shaped SARIF
doc() {
    jq -n --arg id "$1" --arg cvss "$2" --arg uri "$3" \
        '{runs: [{tool: {driver: {name: "osv-scanner",
            rules: [{id: $id} + (if $cvss == "" then {}
                                 else {properties: {"security-severity": $cvss}} end)]}},
          results: [{ruleId: $id, level: "warning",
            locations: [{physicalLocation: {artifactLocation: {uri: $uri}}}]}]}]}' \
        > "$TMP/in.sarif"
}

# stamped <rule-id> <security-severity> -- the severity the gate resolves
stamped() {
    doc "$1" "$2" file:///src/requirements.txt
    mkdir -p "$TMP/r"
    jq -f "$OSV_JQ" "$TMP/in.sarif" > "$TMP/r/osv.sarif"
    jq -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" --argjson threshold 0 "$TMP/r/osv.sarif" \
        | jq -r '.hits[0].severity'
}

# Malware is not a point on a scale: a lockfile either names a package that
# steals credentials or it does not. Same policy as a committed secret.
@test "a malicious package is CRITICAL" {
    [ "$(stamped MAL-2025-20690 "")" = CRITICAL ]
}

@test "a malicious package is CRITICAL even if a score is attached" {
    [ "$(stamped MAL-2025-20690 2.0)" = CRITICAL ]
}

@test "a malicious package fails the build at the critical default" {
    doc MAL-2025-20690 "" file:///src/js/package-lock.json
    mkdir -p "$TMP/r"
    jq -f "$OSV_JQ" "$TMP/in.sarif" > "$TMP/r/osv.sarif"
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

# osv-scanner reports file:///src/... however it is invoked; the summary and the
# Security tab need the path as it is in the repository.
@test "locations are made relative to the repository" {
    doc CVE-X 5.0 file:///src/js/package-lock.json
    [ "$(jq -r -f "$OSV_JQ" "$TMP/in.sarif" \
        | jq -r '.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri')" \
        = js/package-lock.json ]
}

@test "an empty report passes through" {
    printf '%s\n' '{"runs":[{"tool":{"driver":{"name":"osv-scanner"}},"results":[]}]}' > "$TMP/in.sarif"
    [ "$(jq -f "$OSV_JQ" "$TMP/in.sarif" | jq '.runs[0].results | length')" = 0 ]
}
