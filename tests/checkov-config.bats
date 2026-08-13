#!/usr/bin/env bats
#
# The checkov config split: the action owns transport (how findings are
# reported, and that a finding never aborts the run), the consumer owns policy
# (which checks and paths apply to their tree). Before this, the action's
# .checkov.yml was copied over the consumer's at /src/.checkov.yml, so a repo
# had no lever at all - fatal for JSON, which takes no `# checkov:skip=` comment.

load helper

MERGE_PY="$ROOT/scripts/merge-checkov-config.py"
DEFAULTS="$ROOT/.checkov.yml"

setup() {
    TMP="$(mktemp -d)"
}

teardown() {
    rm -rf "$TMP"
}

# The merged config is YAML, like both of its inputs; the assertions want jq.
yaml2json() {
    python3 -c 'import json,sys,yaml; json.dump(yaml.safe_load(sys.stdin), sys.stdout)'
}

# merge_file <consumer-path> -> merged config on stdout as JSON
merge_file() {
    local raw
    # Not a pipeline: $status has to be the merge script's, not jq's.
    raw="$(python3 "$MERGE_PY" "$DEFAULTS" "$1")" || return $?
    printf '%s\n' "$raw" | yaml2json
}

# merge <consumer-yaml>, or no argument for a repo that ships no config
merge() {
    local consumer="$TMP/absent.yml"
    if [ -n "${1:-}" ]; then
        consumer="$TMP/consumer.yml"
        printf '%s\n' "$1" > "$consumer"
    fi
    merge_file "$consumer"
}

# The no-config case must behave exactly as the action always has.
@test "with no consumer config the action's defaults come through" {
    run merge ""
    [ "$status" -eq 0 ]
    [ "$(printf '%s' "$output" | jq -r '.output')" = sarif ]
    [ "$(printf '%s' "$output" | jq -r '.["soft-fail"]')" = true ]
}

# The whole point of the change.
@test "a consumer skip-check reaches checkov" {
    run merge 'skip-check:
  - CKV_SECRET_6'
    [ "$status" -eq 0 ]
    [ "$(printf '%s' "$output" | jq -r '.["skip-check"][0]')" = CKV_SECRET_6 ]
}

@test "a consumer skip-path reaches checkov" {
    run merge 'skip-path:
  - scripts/.*chain-spec.*\.json'
    [ "$status" -eq 0 ]
    [ "$(printf '%s' "$output" | jq -r '.["skip-path"] | length')" -ge 1 ]
}

# "Add our settings to the ones already there" - union, not replace, so the
# action's own entries survive a consumer that sets the same key.
@test "list keys union rather than replace" {
    run merge 'skip-framework:
  - dockerfile'
    [ "$status" -eq 0 ]
    [ "$(printf '%s' "$output" | jq -r '.["skip-framework"] | index("secrets") != null')" = true ]
    [ "$(printf '%s' "$output" | jq -r '.["skip-framework"] | index("dockerfile") != null')" = true ]
}

# Transport is not negotiable: a consumer flipping soft-fail would abort the
# scan job before the other scanners report, and the severity gate downstream
# is what decides pass/fail.
@test "a consumer cannot override soft-fail" {
    run merge 'soft-fail: false'
    [ "$status" -eq 0 ]
    [ "$(printf '%s' "$output" | jq -r '.["soft-fail"]')" = true ]
}

@test "a consumer cannot redirect the output format" {
    run merge 'output: cli'
    [ "$status" -eq 0 ]
    [ "$(printf '%s' "$output" | jq -r '.output')" = sarif ]
}

@test "a consumer cannot re-enable external module download" {
    run merge 'download-external-modules: true'
    [ "$status" -eq 0 ]
    [ "$(printf '%s' "$output" | jq -r '.["download-external-modules"]')" = false ]
}

# Cosmetic keys are the consumer's to set.
@test "a consumer may override a cosmetic setting" {
    run merge 'compact: false'
    [ "$status" -eq 0 ]
    [ "$(printf '%s' "$output" | jq -r '.compact')" = false ]
}

# Secrets are gitleaks' job; checkov owns IaC misconfiguration.
@test "the secrets framework is skipped by default" {
    run merge ""
    [ "$status" -eq 0 ]
    [ "$(printf '%s' "$output" | jq -r '.["skip-framework"] | index("secrets") != null')" = true ]
}

# Both inputs are YAML and a human may well cat the merged file while debugging
# a container, so it stays YAML rather than switching format mid-pipeline.
@test "the merged config is YAML, not JSON" {
    # Deliberately not the `merge` helper: that converts for jq, and the point
    # here is what the script itself writes.
    run python3 "$MERGE_PY" "$DEFAULTS" "$TMP/absent.yml"
    [ "$status" -eq 0 ]
    printf '%s\n' "$output" | grep -q '^output: sarif$'
}

# Byte-identical for identical inputs, so a rebuild cannot silently differ.
@test "the merge is deterministic" {
    printf '%s\n' 'skip-check: [CKV_DOCKER_2, CKV_DOCKER_3]' > "$TMP/c.yml"
    run python3 "$MERGE_PY" "$DEFAULTS" "$TMP/c.yml"
    local first="$output"
    run python3 "$MERGE_PY" "$DEFAULTS" "$TMP/c.yml"
    [ "$output" = "$first" ]
}

# A consumer file that is empty, or not a mapping, must not take the scan down.
@test "an empty consumer config is tolerated" {
    printf '' > "$TMP/consumer.yml"
    run merge_file "$TMP/consumer.yml"
    [ "$status" -eq 0 ]
    [ "$(printf '%s' "$output" | jq -r '.output')" = sarif ]
}

@test "a malformed consumer config fails loudly rather than silently" {
    printf '%s\n' 'skip-check: [unclosed' > "$TMP/consumer.yml"
    run python3 "$MERGE_PY" "$DEFAULTS" "$TMP/consumer.yml"
    [ "$status" -ne 0 ]
    [[ "$output" == *".checkov.yml"* ]]
}
