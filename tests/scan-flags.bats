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

@test "every flag line carries its own input" {
    flags
    [ "$status" -eq 0 ]
    [ "$(cut -d= -f1 "$TMP/flags" | paste -sd' ' -)" = "--SCORECARD_CHECKS --SKIP_OPENGREP_SCAN --SKIP_SCORECARD_SCAN --SKIP_CHECKOV_SCAN --SKIP_ZIZMOR_SCAN --SKIP_TRIVY_SCAN --SKIP_GITLEAKS_SCAN --SKIP_OSV_SCAN --LICENSES_ALLOWLIST" ]
}

# A name the script writes but the step never sets would write an empty value,
# and an empty --LICENSES_ALLOWLIST= overrides the Earthfile's default.
@test "every name the script writes is set from an input in action.yml" {
    names="$(sed -n '/^names=(/,/)/p' "$ROOT/scripts/scan-flags.sh" | sed 's/^names=(//; s/)$//')"
    [ "$(wc -w <<<"$names" | tr -d ' ')" = 9 ]
    [ -n "$names" ]
    for n in $names; do
        lower="$(tr 'A-Z' 'a-z' <<<"$n")"
        grep -q "^ *$n: \${{ inputs.$lower }}" "$ROOT/action.yml" || { echo "action.yml does not set $n"; return 1; }
    done
}

# An empty allowlist fails osv.jq inside earth, and a failed earth target
# exports no SARIF at all: the log would read "No SARIF files produced". Say
# what is wrong here, on the runner, where it is an annotation.
@test "an empty or blank licences allowlist is refused on the runner" {
    for v in "" "   " " , , "; do
        LICENSES_ALLOWLIST="$v" flags
        [ "$status" -ne 0 ] || { echo "'$v' accepted"; return 1; }
        [[ "$output" == *"::error::"*"licenses_allowlist"*"none"* ]]
        [ ! -e "$TMP/flags" ]
    done
}
