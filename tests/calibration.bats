#!/usr/bin/env bats
#
# Per-tool calibration onto the one severity ladder.
#
# Scanners do not share a scale. Trivy grades CVEs CRITICAL..LOW; opengrep says
# only note/warning/error and tags a separate confidence; zizmor grades each
# finding; scorecard emits a score out of ten; gitleaks says nothing at all.
# SARIF `level` tops out at `error`, so read through it every one of them is
# capped below CRITICAL and the default threshold gates almost nothing.
#
# Each tool's native signal is therefore mapped onto one ladder, and the ceiling
# differs by what the tool is in a position to claim. That mapping is policy, so
# it is asserted here rather than left to be inferred from jq.

load helper

setup() { TMP="$(mktemp -d)"; }
teardown() { rm -rf "$TMP"; }

# sev <tool> <sarif-run-body> -- the severity the ladder resolves for result 0
sev() {
    printf '%s\n' "$2" > "$TMP/a.sarif"
    jq -r -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" --argjson threshold 0 \
        "$TMP/a.sarif" | jq -r '.hits[0].severity // "<none>"'
}

# og <level> <confidence-tag> -- an opengrep-shaped document
og() {
    printf '{"runs":[{"tool":{"driver":{"name":"Opengrep OSS","rules":[
      {"id":"R","defaultConfiguration":{"level":"%s"},
       "properties":{"tags":["security","%s"]}}]}},
      "results":[{"ruleId":"R","message":{"text":"m"}}]}]}' "$1" "$2"
}

# ---------------------------------------------------------------------------
# opengrep: level says how loud, a tag says how sure. Only the pair is
# meaningful - `error` alone covers 310 rules including ones opengrep itself
# marks LOW CONFIDENCE, which is what made `fail_severity: high` unusable.

@test "opengrep error + HIGH CONFIDENCE is CRITICAL" {
    [ "$(sev opengrep "$(og error 'HIGH CONFIDENCE')")" = CRITICAL ]
}

@test "opengrep error + MEDIUM CONFIDENCE is HIGH" {
    [ "$(sev opengrep "$(og error 'MEDIUM CONFIDENCE')")" = HIGH ]
}

@test "opengrep error + LOW CONFIDENCE is MEDIUM" {
    [ "$(sev opengrep "$(og error 'LOW CONFIDENCE')")" = MEDIUM ]
}

# 21 of opengrep's error rules carry no confidence tag. Treated as medium: it
# said error, and there is no stated reason to discount it.
@test "opengrep error with no confidence tag is HIGH" {
    [ "$(sev opengrep '{"runs":[{"tool":{"driver":{"name":"Opengrep OSS","rules":[
      {"id":"R","defaultConfiguration":{"level":"error"},"properties":{"tags":["security"]}}]}},
      "results":[{"ruleId":"R"}]}]}')" = HIGH ]
}

# warning is LOW whatever the confidence - 726 of the 1074 rules are warnings,
# and confidence does not make a warning into an impact.
@test "opengrep warning is LOW even at HIGH CONFIDENCE" {
    [ "$(sev opengrep "$(og warning 'HIGH CONFIDENCE')")" = LOW ]
}

@test "opengrep warning is LOW at LOW CONFIDENCE" {
    [ "$(sev opengrep "$(og warning 'LOW CONFIDENCE')")" = LOW ]
}

@test "opengrep note is INFO" {
    [ "$(sev opengrep "$(og note 'HIGH CONFIDENCE')")" = INFO ]
}

# ---------------------------------------------------------------------------
# zizmor grades each finding, not each rule - template-injection lands at error
# 47 times and note 23 times on one real repository. Its error means a workflow
# is exploitable, so it tops the ladder.

@test "zizmor error is CRITICAL" {
    [ "$(sev zizmor '{"runs":[{"tool":{"driver":{"name":"zizmor"}},
      "results":[{"ruleId":"zizmor/template-injection","level":"error"}]}]}')" = CRITICAL ]
}

@test "zizmor warning is MEDIUM" {
    [ "$(sev zizmor '{"runs":[{"tool":{"driver":{"name":"zizmor"}},
      "results":[{"ruleId":"zizmor/artipacked","level":"warning"}]}]}')" = MEDIUM ]
}

@test "zizmor note is LOW" {
    [ "$(sev zizmor '{"runs":[{"tool":{"driver":{"name":"zizmor"}},
      "results":[{"ruleId":"zizmor/adhoc-packages","level":"note"}]}]}')" = LOW ]
}

# ---------------------------------------------------------------------------
# scorecard reports a score out of ten, not a finding. A zero is worth knowing
# about, but it is not a vulnerability, so its ceiling is HIGH.

@test "scorecard error is HIGH, not CRITICAL" {
    [ "$(sev scorecard '{"runs":[{"tool":{"driver":{"name":"ossf-scorecard"}},
      "results":[{"ruleId":"Token-Permissions","level":"error"}]}]}')" = HIGH ]
}

@test "scorecard warning is MEDIUM" {
    [ "$(sev scorecard '{"runs":[{"tool":{"driver":{"name":"ossf-scorecard"}},
      "results":[{"ruleId":"Packaging","level":"warning"}]}]}')" = MEDIUM ]
}

# ---------------------------------------------------------------------------
# Tools that already state a severity keep it: nothing here second-guesses a
# scale the tool actually has.

@test "trivy keeps its own CRITICAL" {
    [ "$(sev trivy '{"runs":[{"tool":{"driver":{"name":"Trivy","rules":[
      {"id":"CVE-1","defaultConfiguration":{"level":"error"},
       "properties":{"tags":["vulnerability","CRITICAL"]}}]}},
      "results":[{"ruleId":"CVE-1","level":"error"}]}]}')" = CRITICAL ]
}

@test "trivy HIGH is not promoted to CRITICAL by its error level" {
    [ "$(sev trivy '{"runs":[{"tool":{"driver":{"name":"Trivy","rules":[
      {"id":"CVE-2","defaultConfiguration":{"level":"error"},
       "properties":{"tags":["vulnerability","HIGH"]}}]}},
      "results":[{"ruleId":"CVE-2","level":"error"}]}]}')" = HIGH ]
}

@test "a stamped gitleaks secret stays CRITICAL" {
    [ "$(sev gitleaks '{"runs":[{"tool":{"driver":{"name":"gitleaks"}},
      "results":[{"ruleId":"private-key","properties":{"severity":"CRITICAL"}}]}]}')" = CRITICAL ]
}

# ---------------------------------------------------------------------------
# An unrecognised tool gets the plain SARIF reading. checkov lands here: it
# offers a level and nothing else.

@test "an uncalibrated tool maps error to HIGH" {
    [ "$(sev checkov '{"runs":[{"tool":{"driver":{"name":"checkov"}},
      "results":[{"ruleId":"CKV_AWS_20","level":"error"}]}]}')" = HIGH ]
}

@test "an uncalibrated tool maps warning to MEDIUM" {
    [ "$(sev other '{"runs":[{"tool":{"driver":{"name":"whatever"}},
      "results":[{"ruleId":"X","level":"warning"}]}]}')" = MEDIUM ]
}

# ---------------------------------------------------------------------------
# ERROR is gone from the ladder as an emitted severity - it is a SARIF
# reporting level, not an impact. It stays accepted as a *threshold* name
# because consumers configure it, and it means the same as high.

@test "no calibrated tool emits ERROR as a severity" {
    for doc in \
      '{"runs":[{"tool":{"driver":{"name":"zizmor"}},"results":[{"ruleId":"R","level":"error"}]}]}' \
      '{"runs":[{"tool":{"driver":{"name":"checkov"}},"results":[{"ruleId":"R","level":"error"}]}]}' \
      '{"runs":[{"tool":{"driver":{"name":"ossf-scorecard"}},"results":[{"ruleId":"R","level":"error"}]}]}'
    do
        [ "$(sev x "$doc")" != ERROR ]
    done
}

@test "fail_severity: error is still accepted and means high" {
    sarif "$TMP/r/a.sarif" '{"runs":[{"tool":{"driver":{"name":"checkov"}},
      "results":[{"ruleId":"R","level":"error"}]}]}'
    count_findings "$TMP/r" error
    [ "$status" -eq 1 ]
    [ "$count" = 1 ]
    count_findings "$TMP/r" high
    [ "$count" = 1 ]
}

@test "fail_severity: critical no longer catches a plain error-level finding" {
    sarif "$TMP/r/a.sarif" '{"runs":[{"tool":{"driver":{"name":"checkov"}},
      "results":[{"ruleId":"R","level":"error"}]}]}'
    count_findings "$TMP/r" critical
    [ "$count" = 0 ]
}
