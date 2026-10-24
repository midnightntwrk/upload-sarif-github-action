#!/usr/bin/env bats
#
# A failed gate says where to read next. The reader is as likely to be an
# agent as a person, and either one's first move is "make it green": the link
# goes to AGENTS.md, whose first section says how each kind of finding is
# fixed or excused, and which ones must never be excused.

load helper

setup() { TMP="$(mktemp -d)"; }
teardown() { rm -rf "$TMP"; }

ANCHOR='#fixing-a-failed-scan'

# one_high <dir> -- a single HIGH finding, no secrets, so the generic failure
# path is the one exercised
one_high() {
    sarif "$1/a.sarif" '{"runs":[{"tool":{"driver":{"name":"osv-scanner"}},"results":[
        {"ruleId":"license-violation","level":"error","properties":{"severity":"HIGH"},
         "message":{"text":"x"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"Cargo.lock"}}}]}]}]}'
}

@test "a failed gate links to the fixing guide" {
    one_high "$TMP/r"
    count_findings "$TMP/r" high
    [ "$status" -eq 1 ]
    [[ "$output" == *"upload-sarif-github-action/blob/main/AGENTS.md$ANCHOR"* ]]
}

@test "a passing gate does not" {
    one_high "$TMP/r"
    count_findings "$TMP/r" critical
    [ "$status" -eq 0 ]
    [[ "$output" != *"AGENTS.md"* ]]
}

# A fork or a GitHub Enterprise host must not be sent to github.com/midnightntwrk.
@test "the guide link follows the action's actual repository" {
    one_high "$TMP/r"
    run env GITHUB_SERVER_URL=https://ghe.example.com GITHUB_ACTION_REPOSITORY=acme/scan-action \
        bash "$COUNT_SH" high "$TMP/r"
    [[ "$output" == *"https://ghe.example.com/acme/scan-action/blob/main/AGENTS.md$ANCHOR"* ]]
}

# The anchor is only useful if the heading it points at exists.
@test "the guide anchor resolves to a real AGENTS.md heading" {
    run grep -c '^## Fixing a failed scan$' "$ROOT/AGENTS.md"
    [ "$output" -ge 1 ]
}

# The guide has to answer for every finding this action can produce, by the
# name the failure prints, and say which may never be excused.
@test "the guide covers every tool and every osv rule, and names the never-excused" {
    section="$(awk '/^## Fixing a failed scan$/ {p=1; next} /^## / {p=0} p' "$ROOT/AGENTS.md")"
    for word in gitleaks trivy opengrep checkov zizmor scorecard osv-scanner \
                MAL- deprecated-package license-violation license-unknown \
                '.gitleaks.toml' '.gitleaksignore' '.trivyignore' 'osv-scanner.toml' 'nosemgrep' \
                'checkov:skip' 'zizmor: ignore' 'IgnoredVulns' 'PackageOverrides' 'licenses_allowlist'; do
        [[ "$section" == *"$word"* ]] || { echo "guide does not mention: $word"; return 1; }
    done
    [[ "$section" == *"never"* ]]
}
