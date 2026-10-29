#!/usr/bin/env bats
#
# scripts/scan-flags.sh: the action's inputs become one earth flag per line,
# written once and re-read by the differential gate's base scan. A line is an
# argument, so a value carrying a newline would smuggle in a second flag -
# `default<LF>--SKIP_OSV_SCAN=true` turns a scanner off - and the file must
# refuse it rather than pass it on.

load helper

setup() { TMP="$(mktemp -d)"; }
teardown() { rm -rf "$TMP"; }

flags() {
    run env SCORECARD_CHECKS="${SCORECARD_CHECKS-}" SKIP_OPENGREP_SCAN=false SKIP_SCORECARD_SCAN=false \
            SKIP_CHECKOV_SCAN=false SKIP_ZIZMOR_SCAN=false SKIP_TRIVY_SCAN=false SKIP_GITLEAKS_SCAN=false \
            SKIP_OSV_SCAN=false LICENSES_ALLOWLIST="${LICENSES_ALLOWLIST-default}" \
            bash "$ROOT/scripts/scan-flags.sh" "$TMP/flags"
}

@test "one flag per input, in a fixed order" {
    flags
    [ "$status" -eq 0 ]
    [ "$(wc -l < "$TMP/flags" | tr -d ' ')" = 9 ]
    [ "$(head -1 "$TMP/flags")" = "--SCORECARD_CHECKS=" ]
    [ "$(tail -1 "$TMP/flags")" = "--LICENSES_ALLOWLIST=default" ]
}

@test "a value with a newline is refused and nothing is written" {
    LICENSES_ALLOWLIST=$'default\n--SKIP_OSV_SCAN=true' flags
    [ "$status" -ne 0 ]
    [[ "$output" == *"::error::"*"LICENSES_ALLOWLIST"* ]]
    [ ! -e "$TMP/flags" ]
}

@test "a carriage return is refused too" {
    SCORECARD_CHECKS=$'Vulnerabilities\r' flags
    [ "$status" -ne 0 ]
    [[ "$output" == *"SCORECARD_CHECKS"* ]]
}

@test "spaces and commas in a value are fine" {
    LICENSES_ALLOWLIST="MIT, Apache-2.0, GPL-3.0-or-later WITH Classpath-exception-2.0" flags
    [ "$status" -eq 0 ]
    [ "$(tail -1 "$TMP/flags")" = "--LICENSES_ALLOWLIST=MIT, Apache-2.0, GPL-3.0-or-later WITH Classpath-exception-2.0" ]
}
