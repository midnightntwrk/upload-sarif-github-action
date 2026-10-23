#!/usr/bin/env bats
#
# In-source suppressions: `# nosemgrep` (opengrep) and `# checkov:skip=` (checkov).
#
# Both tools report the suppressed result anyway and mark it - SARIF 3.27.23
# says to, rather than drop it - with `suppressions: [{"kind": "inSource"}]`.
# GitHub's Security tab honours the mark; the gate used to count the result,
# so the documented way to clear a false positive cleared the tab and left the
# build red, on public and private repos alike. (zizmor drops an ignored result
# itself, so it never reaches here.) Shapes below are from real scanner output.

load helper

setup() { TMP="$(mktemp -d)"; }
teardown() { rm -rf "$TMP"; }

# two <driver> <rule> <level> <suppressions-json> -- one suppressed result and
# one identical unsuppressed sibling, so a test can tell "dropped the right
# one" from "dropped everything".
two() {
    sarif "$TMP/r/a.sarif" "$(jq -n --arg d "$1" --arg rule "$2" --arg l "$3" --argjson s "$4" \
        '{runs: [{tool: {driver: {name: $d}}, results: [
            {ruleId: $rule, level: $l, suppressions: $s,
             locations: [{physicalLocation: {artifactLocation: {uri: "a.py"}, region: {startLine: 3}}}]},
            {ruleId: $rule, level: $l,
             locations: [{physicalLocation: {artifactLocation: {uri: "a.py"}, region: {startLine: 4}}}]}]}]}')"
}

@test "a # nosemgrep'd opengrep finding is not counted" {
    two "Opengrep OSS" python.lang.security.audit.eval-detected.eval-detected warning '[{"kind":"inSource"}]'
    count_findings "$TMP/r" low
    [ "$count" = 1 ]
}

@test "a # checkov:skip'd checkov finding is not counted" {
    two checkov CKV_AWS_20 warning '[{"kind":"inSource"}]'
    count_findings "$TMP/r" low
    [ "$count" = 1 ]
}

# SARIF 3.35.3: a suppression whose status is absent or "accepted" is in force.
@test "an accepted suppression is honoured" {
    two checkov CKV_AWS_20 warning '[{"kind":"external","status":"accepted"}]'
    count_findings "$TMP/r" low
    [ "$count" = 1 ]
}

# ...and "underReview" or "rejected" is not: someone asked, nobody agreed.
@test "a rejected suppression still counts" {
    two checkov CKV_AWS_20 warning '[{"kind":"external","status":"rejected"}]'
    count_findings "$TMP/r" low
    [ "$count" = 2 ]
}

@test "a suppression under review still counts" {
    two checkov CKV_AWS_20 warning '[{"kind":"external","status":"underReview"}]'
    count_findings "$TMP/r" low
    [ "$count" = 2 ]
}

@test "an empty suppressions array is not a suppression" {
    two checkov CKV_AWS_20 warning '[]'
    count_findings "$TMP/r" low
    [ "$count" = 2 ]
}

# A gate that quietly drops findings is the failure this repo keeps finding,
# so a suppressed one is still named - just not counted.
@test "a suppressed finding is named in the output, not hidden" {
    two "Opengrep OSS" python.lang.security.audit.eval-detected.eval-detected warning '[{"kind":"inSource"}]'
    count_findings "$TMP/r" low
    [[ "$output" == *"1 finding(s) suppressed in source"* ]]
    [[ "$output" == *"eval-detected"*"a.py"* ]]
}

@test "severity.jq reports the suppressed count" {
    two checkov CKV_AWS_20 error '[{"kind":"inSource"}]'
    [ "$(jq -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" --argjson threshold 0 "$TMP/r/a.sarif" \
        | jq -c '[.count, .suppressed]')" = '[1,1]' ]
}

# A suppressed secret still fails: a credential in the tree is compromised
# whatever a comment beside it says. gitleaks has its own exclusion files.
@test "a suppression does not excuse a gitleaks secret" {
    sarif "$TMP/r/g.sarif" '{"runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[
      {"ruleId":"private-key","properties":{"severity":"CRITICAL"},
       "suppressions":[{"kind":"inSource"}],
       "locations":[{"physicalLocation":{"artifactLocation":{"uri":"id_rsa"}}}]}]}]}'
    count_findings "$TMP/r" critical
    [ "$count" = 1 ]
}
