#!/usr/bin/env bats
#
# scripts/scorecard.jq: Scorecard JSON to SARIF, and which passes it keeps quiet.
#
# A check that scores a perfect 10 found nothing wrong, so it is not a finding
# and is not reported - the `minScore: 10` rule of scorecard's own policy file,
# without that path's experimental SARIF, which drops levels and hides
# inconclusive results too. Anything below 10 still has something wrong.

load helper

setup() { TMP="$(mktemp -d)"; }
teardown() { rm -rf "$TMP"; }

# results <name> <score> <reason> -- the ruleIds scorecard.jq reports for one check
results() {
    jq -n --arg n "$1" --argjson s "$2" --arg r "$3" \
        '{scorecard: {version: "v5.6.0"},
          checks: [{name: $n, score: $s, reason: $r,
                    documentation: {short: "d", url: "u"}}]}' > "$TMP/in.json"
    jq -r -f "$SCORECARD_JQ" "$TMP/in.json" | jq -r '[.runs[].results[].ruleId] | join(",")'
}

@test "a perfect score is not reported, whatever the reason says" {
    [ "$(results Binary-Artifacts 10 'no binaries found in the repo')" = "" ]
    [ "$(results Vulnerabilities 10 '0 existing vulnerabilities detected')" = "" ]
    [ "$(results License 10 'license file detected')" = "" ]
}

# Security-Policy says "detected" at any score: a file that is present but
# lacks disclosure details scores below 10 under the same reason.
@test "nine out of ten is still reported" {
    [ "$(results Security-Policy 9 'security policy file detected')" = Security-Policy ]
}

@test "a failing check is reported" {
    [ "$(results Vulnerabilities 7 '3 existing vulnerabilities detected')" = Vulnerabilities ]
}

# -1 is scorecard's "inconclusive" - nothing to score. Not a pass, so not
# silenced (scorecard's own policy filter would skip it).
@test "an inconclusive check is still reported" {
    [ "$(results Dangerous-Workflow -1 'no workflows found')" = Dangerous-Workflow ]
}

@test "a quiet check still has its rule, so the Security tab can close it" {
    results Binary-Artifacts 10 'no binaries found in the repo' > /dev/null
    [ "$(jq -r -f "$SCORECARD_JQ" "$TMP/in.json" | jq -r '.runs[0].tool.driver.rules[].id')" = Binary-Artifacts ]
}
