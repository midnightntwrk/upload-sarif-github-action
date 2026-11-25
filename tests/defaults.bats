#!/usr/bin/env bats
#
# The shipped default is policy for every repository that sets nothing. Read it
# from action.yml rather than restating it, so the test and the action cannot
# drift apart.

load helper

setup() { TMP="$(mktemp -d)"; }
teardown() { rm -rf "$TMP"; }

default_fail_severity() {
    awk '/^  fail_severity:/ {p=1} p && /^    default:/ {gsub(/"/, "", $2); print $2; exit}' "$ROOT/action.yml"
}

one() {
    sarif "$TMP/r/a.sarif" '{"runs":[{"tool":{"driver":{"name":"trivy"}},"results":[
        {"ruleId":"CVE-1","level":"error","properties":{"severity":"'"$1"'"},
         "message":{"text":"x"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"Cargo.lock"}}}]}]}]}'
}

@test "the default fail_severity is high" {
    [ "$(default_fail_severity)" = high ]
}

# A HIGH CVE in a manifest is the common case the gate exists for; at the old
# critical default it sailed through.
@test "a HIGH finding fails the gate at the shipped default" {
    one HIGH
    count_findings "$TMP/r" "$(default_fail_severity)"
    [ "$status" -eq 1 ]
    [ "$count" = 1 ]
}

@test "a MEDIUM finding passes the gate at the shipped default" {
    one MEDIUM
    count_findings "$TMP/r" "$(default_fail_severity)"
    [ "$status" -eq 0 ]
    [ "$count" = 0 ]
}
