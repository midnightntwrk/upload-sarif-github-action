#!/usr/bin/env bats
#
# scripts/scorecard.jq: Scorecard JSON to SARIF, and which passes it keeps quiet.
#
# A check that found nothing wrong is not a finding, so it is not reported. That
# is decided by exact (check, reason) pairs at a perfect score, never by score
# alone: 8/10 still means something was wrong, and a reworded reason after a
# scorecard upgrade must reappear rather than vanish. tests/canary.sh holds the
# pairs against the real binary.

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

@test "the seven perfect passes are not reported" {
    while IFS='|' read -r name reason; do
        [ "$(results "$name" 10 "$reason")" = "" ] || {
            echo "still reported: $name - $reason"; return 1; }
    done <<'PASSES'
Binary-Artifacts|no binaries found in the repo
Dangerous-Workflow|no dangerous workflow patterns detected
Dependency-Update-Tool|update tool detected
Pinned-Dependencies|all dependencies are pinned
Security-Policy|security policy file detected
Token-Permissions|GitHub workflow tokens follow principle of least privilege
Vulnerabilities|0 existing vulnerabilities detected
PASSES
}

# Security-Policy says "detected" at any score: a file that is present but
# lacks disclosure details scores below 10 under the same reason.
@test "a quiet reason below a perfect score is still reported" {
    [ "$(results Security-Policy 4 'security policy file detected')" = Security-Policy ]
}

@test "a pass that scorecard reworded is still reported" {
    [ "$(results Binary-Artifacts 10 'no binaries detected')" = Binary-Artifacts ]
}

@test "a reason is matched to its own check only" {
    [ "$(results Token-Permissions 10 'no binaries found in the repo')" = Token-Permissions ]
}

@test "a perfect pass of a check not on the list is still reported" {
    [ "$(results License 10 'license file detected')" = License ]
}

@test "vulnerabilities found are reported" {
    [ "$(results Vulnerabilities 7 '3 existing vulnerabilities detected')" = Vulnerabilities ]
}

@test "a quiet check still has its rule, so the Security tab can close it" {
    results Binary-Artifacts 10 'no binaries found in the repo' > /dev/null
    [ "$(jq -r -f "$SCORECARD_JQ" "$TMP/in.json" | jq -r '.runs[0].tool.driver.rules[].id')" = Binary-Artifacts ]
}
