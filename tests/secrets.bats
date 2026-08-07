#!/usr/bin/env bats
#
# The secrets policy: a committed secret fails the build whatever fail_severity
# is set to, and the failure says how to exclude a false positive.

load helper

SECRETS_JQ="$ROOT/scripts/secrets-severity.jq"

setup() {
    TMP="$(mktemp -d)"
}

teardown() {
    rm -rf "$TMP"
}

# gitleaks assigns no severity of its own, so the policy is applied by stamping
# its SARIF before the gate ever sees it.
@test "secrets-severity.jq stamps CRITICAL onto every result" {
    run jq -r '.runs[0].results[0].properties.severity' <(
        jq -f "$SECRETS_JQ" "$FIX/gitleaks-unstamped/a.sarif")
    [ "$output" = CRITICAL ]
}

@test "secrets-severity.jq overwrites a lower severity" {
    printf '%s\n' '{"runs":[{"results":[{"ruleId":"x","properties":{"severity":"NOTE"}}]}]}' \
        > "$TMP/in.sarif"
    run jq -r '.runs[0].results[0].properties.severity' <(jq -f "$SECRETS_JQ" "$TMP/in.sarif")
    [ "$output" = CRITICAL ]
}

# A clean scan is the common case, so it must not become an error.
@test "secrets-severity.jq handles a run with no results" {
    printf '%s\n' '{"runs":[{"tool":{"driver":{"name":"gitleaks"}}}]}' > "$TMP/in.sarif"
    run jq -f "$SECRETS_JQ" "$TMP/in.sarif"
    [ "$status" -eq 0 ]
    [ "$(printf '%s' "$output" | jq -r '.runs[0].results | length')" = 0 ]
}

@test "secrets-severity.jq handles a document with no runs" {
    printf '%s\n' '{"version":"2.1.0","runs":[]}' > "$TMP/in.sarif"
    run jq -f "$SECRETS_JQ" "$TMP/in.sarif"
    [ "$status" -eq 0 ]
}

# The point of the policy: critical is the action's default threshold, so a
# stamped secret fails without the caller configuring anything.
@test "a stamped secret fails at the critical default" {
    count_findings "$FIX/gitleaks" critical
    [ "$status" -eq 1 ]
    [ "$count" = 1 ]
}

@test "an unstamped gitleaks finding would only be a warning" {
    count_findings "$FIX/gitleaks-unstamped" critical
    [ "$status" -eq 0 ]
    count_findings "$FIX/gitleaks-unstamped" warning
    [ "$count" = 1 ]
}

@test "the failure says secrets ignore fail_severity" {
    count_findings "$FIX/gitleaks" critical
    [[ "$output" == *"regardless of fail_severity"* ]]
}

@test "the failure tells you to rotate the credential first" {
    count_findings "$FIX/gitleaks" critical
    [[ "$output" == *"Rotate the credential"* ]]
}

# Two mechanisms, and they are not interchangeable: only one of them takes a
# path, which is the thing a contributor gets wrong.
@test "the failure names both exclusion mechanisms" {
    count_findings "$FIX/gitleaks" critical
    [[ "$output" == *".gitleaks.toml"* ]]
    [[ "$output" == *".gitleaksignore"* ]]
}

@test "the failure prints a paste-able fingerprint" {
    count_findings "$FIX/gitleaks" critical
    [[ "$output" == *"vendor/id_rsa:private-key:1"* ]]
}

@test "no secrets guidance when the findings are not secrets" {
    count_findings "$FIX/one-high" high
    [ "$status" -eq 1 ]
    [[ "$output" != *"Rotate the credential"* ]]
}

# A fingerprint needs a path, so a locationless finding cannot be offered one.
# It must still fail the build and still say how to deal with it - the missing
# location is the scanner's problem, not a reason to go quiet.
@test "a secret with no location still fails and still explains itself" {
    sarif "$TMP/r/gl.sarif" '{"runs":[{"tool":{"driver":{"name":"gitleaks"}},
      "results":[{"ruleId":"private-key","properties":{"severity":"CRITICAL"},
      "message":{"text":"key"}}]}]}'
    count_findings "$TMP/r" critical
    [ "$status" -eq 1 ]
    [ "$count" = 1 ]
    [[ "$output" == *"regardless of fail_severity"* ]]
    [[ "$output" == *".gitleaks.toml"* ]]
}

# The stamp is what makes secrets outrank fail_severity, and it is applied to
# the whole document. A run with several findings must not have only its first
# stamped.
@test "secrets-severity.jq stamps every result in a multi-finding run" {
    printf '%s\n' '{"runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[
      {"ruleId":"a"},{"ruleId":"b","properties":{"severity":"NOTE"}},
      {"ruleId":"c","properties":{"other":1}}]}]}' > "$TMP/in.sarif"
    run jq -r '[.runs[0].results[].properties.severity]|unique|join(",")' \
        <(jq -f "$SECRETS_JQ" "$TMP/in.sarif")
    [ "$output" = CRITICAL ]
}

@test "secrets-severity.jq stamps across several runs" {
    printf '%s\n' '{"runs":[{"results":[{"ruleId":"a"}]},{"results":[{"ruleId":"b"}]}]}' \
        > "$TMP/in.sarif"
    run jq -r '[.runs[].results[].properties.severity]|unique|join(",")' \
        <(jq -f "$SECRETS_JQ" "$TMP/in.sarif")
    [ "$output" = CRITICAL ]
}

@test "no secrets guidance when a gitleaks scan is clean" {
    printf '%s\n' '{"runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[]}]}' \
        > "$TMP/clean.sarif"
    count_findings "$TMP" critical
    [ "$status" -eq 0 ]
    [[ "$output" != *"Rotate the credential"* ]]
}

# severity.jq builds the fingerprint, since that is where the fields are. It is
# gitleaks' format, so it must not be offered for other tools' findings.
@test "severity.jq reports the producing tool" {
    run jq -r '.tool' <(jq -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" \
        --argjson threshold 0 "$FIX/gitleaks/a.sarif")
    [ "$output" = gitleaks ]
}

@test "severity.jq offers an ignore fingerprint for gitleaks findings" {
    run jq -r '.ignores[0]' <(jq -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" \
        --argjson threshold 0 "$FIX/gitleaks/a.sarif")
    [ "$output" = "vendor/id_rsa:private-key:1" ]
}

@test "severity.jq offers no fingerprint for other tools" {
    run jq -r '.ignores | length' <(jq -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" \
        --argjson threshold "$(rank HIGH)" "$FIX/one-high/a.sarif")
    [ "$output" = 0 ]
}

@test "the failure links to the gitleaks configuration reference" {
    count_findings "$FIX/gitleaks" critical
    [[ "$output" == *"gitleaks#configuration"* ]]
    [[ "$output" == *"gitleaks#gitleaksignore"* ]]
}

@test "the failure links to this action's own policy section" {
    count_findings "$FIX/gitleaks" critical
    [[ "$output" == *"#secrets-always-fail-the-build"* ]]
}

# The anchor is only useful if the heading it points at exists. Without this the
# link rots silently the first time the README is reorganised.
@test "the policy anchor resolves to a real README heading" {
    run grep -c '^### Secrets always fail the build$' "$ROOT/README.md"
    [ "$output" -ge 1 ]
}

# A fork or a GitHub Enterprise host must not be sent to github.com/midnightntwrk.
@test "the policy link follows the action's actual repository" {
    tmp="$(mktemp -d)"
    run env FINDINGS_COUNT_FILE="$tmp/c" \
        GITHUB_SERVER_URL=https://ghe.example.invalid \
        GITHUB_ACTION_REPOSITORY=someone/their-fork \
        bash "$COUNT_SH" critical "$FIX/gitleaks"
    rm -rf "$tmp"
    [[ "$output" == *"https://ghe.example.invalid/someone/their-fork#secrets"* ]]
    [[ "$output" != *"midnightntwrk"* ]]
}
