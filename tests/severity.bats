#!/usr/bin/env bats
#
# Counting SARIF findings against a severity threshold, and the severity
# resolution rules in scripts/severity.jq.

load helper

setup() {
    TMP="$(mktemp -d)"
}

teardown() {
    rm -rf "$TMP"
}

@test "counts a HIGH finding at threshold high" {
    count_findings "$FIX/one-high" high
    [ "$status" -eq 1 ]
    [ "$count" = 1 ]
}

@test "counts HIGH and CRITICAL together" {
    count_findings "$FIX/two-high" high
    [ "$count" = 2 ]
}

@test "NOTE and MEDIUM are below high" {
    count_findings "$FIX/note-only" high
    [ "$status" -eq 0 ]
    [ "$count" = 0 ]
}

@test "MEDIUM counts at threshold medium" {
    count_findings "$FIX/note-only" medium
    [ "$count" = 1 ]
}

@test "the threshold is case-insensitive" {
    count_findings "$FIX/one-high" HIGH
    [ "$count" = 1 ]
    count_findings "$FIX/one-high" HiGh
    [ "$count" = 1 ]
}

@test "LOW and WARNING rank equally" {
    sarif "$TMP/r/low.sarif" '{"runs":[{"results":[{"ruleId":"L","properties":{"severity":"LOW"}}]}]}'
    count_findings "$TMP/r" warning
    [ "$count" = 1 ]
    count_findings "$TMP/r" medium
    [ "$count" = 0 ]
}

@test "a run with no results counts zero" {
    count_findings "$FIX/empty" high
    [ "$status" -eq 0 ]
    [ "$count" = 0 ]
}

@test "a document with no runs at all counts zero" {
    sarif "$TMP/r/norun.sarif" '{"version":"2.1.0"}'
    count_findings "$TMP/r" high
    [ "$status" -eq 0 ]
    [ "$count" = 0 ]
}

@test "a missing reports directory is zero findings, not a crash" {
    count_findings "$TMP/does-not-exist" high
    [ "$status" -eq 0 ]
    [ "$count" = 0 ]
}

@test "counts across several files in one directory" {
    count_findings "$FIX/mixed" high
    [ "$count" = 2 ]
}

@test "counts across several runs in one file" {
    sarif "$TMP/r/multi.sarif" '{"runs":[
      {"results":[{"ruleId":"A","properties":{"severity":"HIGH"}}]},
      {"results":[{"ruleId":"B","properties":{"severity":"CRITICAL"}}]}]}'
    count_findings "$TMP/r" high
    [ "$count" = 2 ]
}

# A finding with neither locations nor message must still count. The fields are
# formatted inside severity.jq precisely so the shell never splits them.
@test "a finding with no location and no message still counts" {
    count_findings "$FIX/no-detail" high
    [ "$count" = 1 ]
}

@test "a multi-line message is collapsed onto one line" {
    sarif "$TMP/r/multiline.sarif" '{"runs":[{"results":[{"ruleId":"M",
      "properties":{"severity":"HIGH"},"message":{"text":"first\nsecond\tthird"}}]}]}'
    count_findings "$TMP/r" high
    [ "$count" = 1 ]
    [ "$(printf '%s' "$output" | grep -c 'first second third')" -eq 1 ]
}

# Regression: `${SEVERITY_MAP[$sev]}` under `set -u` aborted on an unknown key,
# so a single Trivy UNKNOWN killed the gate mid-count.
@test "an unmapped severity is warned about, not fatal" {
    count_findings "$FIX/unknown-sev" high
    [ "$status" -eq 0 ]
    [ "$count" = 0 ]
    [[ "$output" == *"unmapped severity"* ]]
}

@test "SARIF level none is unmapped, not fatal" {
    count_findings "$FIX/level-none" high
    [ "$status" -eq 0 ]
    [ "$count" = 0 ]
}

@test "a numeric properties.severity is unmapped, not fatal" {
    sarif "$TMP/r/numeric.sarif" '{"runs":[{"results":[{"ruleId":"N","properties":{"severity":5}}]}]}'
    count_findings "$TMP/r" high
    [ "$status" -eq 0 ]
    [ "$count" = 0 ]
    [[ "$output" == *"unmapped severity 5"* ]]
}

@test "an unmapped severity does not stop later findings counting" {
    count_findings "$FIX/mixed" high
    [ "$count" = 2 ]
    [[ "$output" == *"unmapped severity"* ]]
}

# gitleaks emits no severity and no rule-level default (8.30.1 ships 222 rules,
# none carrying a level), so dropping these meant a committed private key could
# not fail the build at ANY threshold.
@test "a severity-less result defaults to warning" {
    count_findings "$FIX/no-severity" note
    [ "$count" = 1 ]
    count_findings "$FIX/no-severity" warning
    [ "$count" = 1 ]
}

@test "the warning default is still below medium" {
    count_findings "$FIX/no-severity" medium
    [ "$status" -eq 0 ]
    [ "$count" = 0 ]
}

# Trivy renders CRITICAL and HIGH both as SARIF `level: error`, because `error`
# is the top of the level enum. Read through `level` and a CRITICAL CVE lands on
# ERROR, which sits below CRITICAL in the ladder - so the default fail_severity
# could not fail on one. The tool's own scale is in the rule's tags.
@test "a Trivy CRITICAL counts at threshold critical" {
    count_findings "$FIX/trivy" critical
    [ "$status" -eq 1 ]
    [ "$count" = 1 ]
}

@test "a Trivy HIGH is below threshold critical" {
    count_findings "$FIX/trivy" critical
    [[ "$output" == *"CVE-1111"* ]]
    [[ "$output" != *"CVE-2222"* ]]
}

@test "both Trivy findings count at threshold high" {
    count_findings "$FIX/trivy" high
    [ "$count" = 2 ]
}

@test "a rule tag severity beats the result's level" {
    sarif "$TMP/r/t.sarif" '{"runs":[{"tool":{"driver":{"rules":[
      {"id":"R","properties":{"tags":["security","CRITICAL"]}}]}},
      "results":[{"ruleId":"R","level":"error"}]}]}'
    count_findings "$TMP/r" critical
    [ "$count" = 1 ]
}

# Otherwise "security" or a CWE id would be read as a severity.
@test "rule tags that do not name a severity are ignored" {
    sarif "$TMP/r/t.sarif" '{"runs":[{"tool":{"driver":{"rules":[
      {"id":"R","properties":{"tags":["vulnerability","security","CWE-89"]}}]}},
      "results":[{"ruleId":"R","level":"error"}]}]}'
    count_findings "$TMP/r" critical
    [ "$count" = 0 ]
    count_findings "$TMP/r" high
    [ "$count" = 1 ]
}

@test "the highest severity tag wins when a rule carries several" {
    sarif "$TMP/r/t.sarif" '{"runs":[{"tool":{"driver":{"rules":[
      {"id":"R","properties":{"tags":["LOW","CRITICAL","MEDIUM"]}}]}},
      "results":[{"ruleId":"R","level":"note"}]}]}'
    count_findings "$TMP/r" critical
    [ "$count" = 1 ]
}

@test "a rule with no tags still falls through to the result level" {
    sarif "$TMP/r/t.sarif" '{"runs":[{"tool":{"driver":{"rules":[
      {"id":"R"}]}},"results":[{"ruleId":"R","level":"error"}]}]}'
    count_findings "$TMP/r" high
    [ "$count" = 1 ]
}

@test "a rule-level default level is used when the result has none" {
    count_findings "$FIX/rule-default-error" high
    [ "$count" = 1 ]
}

@test "result.level wins over properties.severity" {
    sarif "$TMP/r/both.sarif" '{"runs":[{"results":[{"ruleId":"B",
      "level":"note","properties":{"severity":"CRITICAL"}}]}]}'
    count_findings "$TMP/r" high
    [ "$count" = 0 ]
}

@test "properties.severity wins over the rule default" {
    sarif "$TMP/r/prop.sarif" '{"runs":[{"tool":{"driver":{"rules":[
      {"id":"R","defaultConfiguration":{"level":"error"}}]}},
      "results":[{"ruleId":"R","properties":{"severity":"NOTE"}}]}]}'
    count_findings "$TMP/r" high
    [ "$count" = 0 ]
}

# rc 0 clean, 1 findings, 2 bad invocation. Conflating 0 and 2 would turn a typo
# in fail_severity into a green build, so rc 2 writes no count at all.
@test "an unknown threshold is rc 2 and writes no count" {
    count_findings "$FIX/one-high" hgh
    [ "$status" -eq 2 ]
    [ "$count" = '<none>' ]
    [[ "$output" == *"accepted:"* ]]
}

@test "an empty threshold is rc 2" {
    count_findings "$FIX/one-high" ''
    [ "$status" -eq 2 ]
    [ "$count" = '<none>' ]
}

@test "unparseable SARIF is rc 2 and writes no count" {
    printf '{not json\n' > "$TMP/broken.sarif"
    count_findings "$TMP" high
    [ "$status" -eq 2 ]
    [ "$count" = '<none>' ]
    [[ "$output" == *"could not parse SARIF"* ]]
}

@test "a missing severity.jq is reported, not silently ignored" {
    mkdir -p "$TMP/scripts"
    cp "$COUNT_SH" "$TMP/scripts/"
    run bash "$TMP/scripts/fail-on-severity.sh" high "$FIX/one-high"
    [ "$status" -eq 2 ]
    [[ "$output" == *"severity.jq not found"* ]]
}

@test "works without FINDINGS_COUNT_FILE set" {
    run bash "$COUNT_SH" high "$FIX/one-high"
    [ "$status" -eq 1 ]
}

# severity.jq is a standalone program, so it is worth asserting directly rather
# than only through the wrapper.
@test "severity.jq emits the documented shape" {
    run jq -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" --argjson threshold 3 \
        "$FIX/one-high/a.sarif"
    [ "$status" -eq 0 ]
    [ "$(printf '%s' "$output" | jq -r '.count')" = 1 ]
    [ "$(printf '%s' "$output" | jq -r '.unknown')" = 0 ]
    [ "$(printf '%s' "$output" | jq -r '.findings | length')" = 1 ]
    [ "$(printf '%s' "$output" | jq -r '.unmapped | length')" = 0 ]
}

@test "severity.jq puts the severity, rule and file in the finding line" {
    run jq -r -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" --argjson threshold 3 \
        "$FIX/one-high/a.sarif"
    [[ "$output" == *"HIGH"* ]]
    [[ "$output" == *"R1"* ]]
    [[ "$output" == *"a.py"* ]]
}

@test "severity.jq raising the threshold excludes the finding" {
    run jq -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" --argjson threshold 5 \
        "$FIX/one-high/a.sarif"
    [ "$(printf '%s' "$output" | jq -r '.count')" = 0 ]
}
