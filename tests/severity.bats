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

# Trivy tails every message with `Link: [<id>](<url>)`, repeating the rule id
# that is already its own column. Messages get truncated for display, so the
# boilerplate costs the package and fixed-version at the head.
@test "a trailing Link: reference is stripped from the message" {
    sarif "$TMP/r/t.sarif" '{"runs":[{"results":[{"ruleId":"GHSA-x","level":"error",
      "message":{"text":"Package: rand\nFixed Version: 0.9.3\nLink: [GHSA-x](https://example.invalid/x)"}}]}]}'
    count_findings "$TMP/r" high
    [[ "$output" == *"Fixed Version: 0.9.3"* ]]
    [[ "$output" != *"Link:"* ]]
    [[ "$output" != *"example.invalid"* ]]
}

# Only at the tail, and only when it is the whole reference: a message that
# mentions a link mid-sentence keeps its words.
@test "a Link: that is not the trailing reference is left alone" {
    sarif "$TMP/r/t.sarif" '{"runs":[{"results":[{"ruleId":"R","level":"error",
      "message":{"text":"Link: [a](b) appears first, then the real detail"}}]}]}'
    count_findings "$TMP/r" high
    [[ "$output" == *"then the real detail"* ]]
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

# The tag wins in both directions. Worth pinning: reading it first can *lower*
# a severity as well as raise one, and lowering is the direction that quietly
# stops gating something.
@test "a rule tag can lower a severity below its level" {
    sarif "$TMP/r/t.sarif" '{"runs":[{"tool":{"driver":{"rules":[
      {"id":"R","properties":{"tags":["security","LOW"]}}]}},
      "results":[{"ruleId":"R","level":"error"}]}]}'
    count_findings "$TMP/r" high
    [ "$count" = 0 ]
    count_findings "$TMP/r" low
    [ "$count" = 1 ]
}

@test "a lowercase rule tag is recognised" {
    sarif "$TMP/r/t.sarif" '{"runs":[{"tool":{"driver":{"rules":[
      {"id":"R","properties":{"tags":["critical"]}}]}},"results":[{"ruleId":"R"}]}]}'
    count_findings "$TMP/r" critical
    [ "$count" = 1 ]
}

# Trivy puts a CVSS score next to the band; a tag array is not guaranteed to be
# all strings, and a non-string must not abort the whole count.
@test "non-string rule tags are skipped, not fatal" {
    sarif "$TMP/r/t.sarif" '{"runs":[{"tool":{"driver":{"rules":[
      {"id":"R","properties":{"tags":[9.8,null,true,"CRITICAL"]}}]}},
      "results":[{"ruleId":"R"}]}]}'
    count_findings "$TMP/r" critical
    [ "$count" = 1 ]
}

# Rule tables are per-run. Two runs in one file can reuse a rule id for
# different rules, and one must not be scored with the other's severity.
@test "rule tags are scoped to their own run" {
    sarif "$TMP/r/t.sarif" '{"runs":[
      {"tool":{"driver":{"rules":[{"id":"R","properties":{"tags":["CRITICAL"]}}]}},
       "results":[{"ruleId":"R"}]},
      {"tool":{"driver":{"rules":[{"id":"R","properties":{"tags":["NOTE"]}}]}},
       "results":[{"ruleId":"R"}]}]}'
    count_findings "$TMP/r" critical
    [ "$count" = 1 ]
    count_findings "$TMP/r" note
    [ "$count" = 2 ]
}

# Severity is keyed by ruleId. A result identifying its rule only by index is
# not looked up - it falls through to its own level rather than guessing.
@test "a result with only a ruleIndex falls through to its level" {
    sarif "$TMP/r/t.sarif" '{"runs":[{"tool":{"driver":{"rules":[
      {"id":"R","properties":{"tags":["CRITICAL"]}}]}},
      "results":[{"ruleIndex":0,"level":"note"}]}]}'
    count_findings "$TMP/r" critical
    [ "$count" = 0 ]
}

# note is rank 0, the bottom of the ladder, so everything is at or above it.
@test "threshold note counts every mapped finding" {
    sarif "$TMP/r/t.sarif" '{"runs":[{"results":[
      {"level":"note"},{"level":"error"}]}]}'
    count_findings "$TMP/r" note
    [ "$status" -eq 1 ]
    [ "$count" = 2 ]
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

# Deliberate reversal. This asserted the opposite while `level` was read first,
# and that ordering is what let a `level` silently override the CRITICAL stamp
# on a secret. A severity the tool actually stated outranks one inferred from a
# reporting level - which is all `level` is.
@test "properties.severity wins over result.level" {
    sarif "$TMP/r/both.sarif" '{"runs":[{"results":[{"ruleId":"B",
      "level":"note","properties":{"severity":"CRITICAL"}}]}]}'
    count_findings "$TMP/r" critical
    [ "$count" = 1 ]
}

# The case that motivates it: a future gitleaks emitting any level at all must
# not be able to demote a stamped secret.
@test "a level cannot demote a stamped secret" {
    sarif "$TMP/r/gl.sarif" '{"runs":[{"tool":{"driver":{"name":"gitleaks"}},
      "results":[{"ruleId":"private-key","level":"warning",
      "properties":{"severity":"CRITICAL"}}]}]}'
    count_findings "$TMP/r" critical
    [ "$count" = 1 ]
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

# jq exits 0 on empty input and prints nothing, so nothing downstream fails:
# the arithmetic quietly errors and the run reports zero findings. A scanner
# killed part-way, a full disk or a truncated artifact would all land here, and
# on the head scan an undercount *passes* the differential gate.
@test "a zero-length SARIF is rc 2, not a clean scan" {
    : > "$TMP/empty.sarif"
    count_findings "$TMP" high
    [ "$status" -eq 2 ]
    [ "$count" = '<none>' ]
}

@test "the zero-length SARIF error names the file and says it is not clean" {
    : > "$TMP/empty.sarif"
    count_findings "$TMP" high
    [[ "$output" == *"empty.sarif"* ]]
    [[ "$output" == *"not a clean scan"* ]]
}

@test "a truncated SARIF does not hide findings in the other files" {
    cp "$FIX/one-high/a.sarif" "$TMP/good.sarif"
    : > "$TMP/truncated.sarif"
    count_findings "$TMP" high
    [ "$status" -eq 2 ]
    [ "$count" = '<none>' ]
}

# Valid JSON, wrong shape. `.runs[]?` would swallow this into a count of zero,
# which is the same lie as the empty file.
@test "valid JSON that is not a SARIF document is rc 2" {
    printf '[]\n' > "$TMP/array.sarif"
    count_findings "$TMP" high
    [ "$status" -eq 2 ]
    [ "$count" = '<none>' ]
}

# nullglob gives us the array; the loop must not word-split it back apart.
@test "a report filename containing a space is still counted" {
    cp "$FIX/one-high/a.sarif" "$TMP/my report.sarif"
    count_findings "$TMP" high
    [ "$count" = 1 ]
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
    run jq -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" --argjson threshold "$(rank HIGH)" \
        "$FIX/one-high/a.sarif"
    [ "$status" -eq 0 ]
    [ "$(printf '%s' "$output" | jq -r '.count')" = 1 ]
    [ "$(printf '%s' "$output" | jq -r '.unknown')" = 0 ]
    [ "$(printf '%s' "$output" | jq -r '.findings | length')" = 1 ]
    [ "$(printf '%s' "$output" | jq -r '.unmapped | length')" = 0 ]
}

@test "severity.jq puts the severity, rule and file in the finding line" {
    run jq -r -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" --argjson threshold "$(rank HIGH)" \
        "$FIX/one-high/a.sarif"
    [[ "$output" == *"HIGH"* ]]
    [[ "$output" == *"R1"* ]]
    [[ "$output" == *"a.py"* ]]
}

@test "severity.jq raising the threshold excludes the finding" {
    run jq -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" --argjson threshold "$(rank CRITICAL)" \
        "$FIX/one-high/a.sarif"
    [ "$(printf '%s' "$output" | jq -r '.count')" = 0 ]
}
