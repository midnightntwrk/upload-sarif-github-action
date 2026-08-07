#!/usr/bin/env bash
#
# Integration tests against a real scanner.
#
#   ./tests/integration.sh
#
# The bats suites feed hand-written SARIF to the gate scripts. This covers the
# seam they cannot reach - a real gitleaks scan, through the counter, through the
# gate - which is how "gitleaks findings were never gated" surfaced in the first
# place.
#
# Two things are asserted that only a real scan can show:
#
#   * a committed secret fails the build at the default `critical` threshold;
#   * both gitleaks exclusion mechanisms actually suppress it - including, for
#     `.gitleaksignore`, the exact fingerprint line the build failure tells the
#     contributor to paste. If that advice ever stops working, this fails.
#
# Requires earth and docker. Skips (exit 0) without them.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
COUNT_SH="$ROOT/scripts/fail-on-severity.sh"
GATE_SH="$ROOT/scripts/differential-gate.sh"
SEVERITY_JQ="$ROOT/scripts/severity.jq"
SEVERITIES='{"INFO":0,"NONE":0,"NOTE":0,"LOW":1,"WARNING":1,"MEDIUM":2,"HIGH":3,"ERROR":3,"CRITICAL":4}'
# The default a caller gets. Secrets must fail here, not merely at `warning`.
THRESHOLD=critical

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; return 0; }

command -v earth > /dev/null 2>&1 || { echo "SKIP: earth not on PATH"; exit 0; }
docker info > /dev/null 2>&1 || { echo "SKIP: docker unavailable"; exit 0; }

work="$(mktemp -d)"
trap 'rm -rf "$work" "$ROOT/scan_reports"' EXIT

# Key material is assembled at runtime, never committed: a real secret in tests/
# would be flagged by this repo's own scan, and committing one to make a security
# tool's test pass is a bad habit to build in.
# The PEM markers are assembled from parts so this file does not itself contain
# the literal gitleaks matches on. Otherwise the test that plants a fake secret
# becomes a finding in this repository - which is how it was first noticed.
# Suppressing it via .gitleaks.toml would also have worked, but not needing an
# exclusion at all beats documenting one.
plant_secret() {
    mkdir -p "$1/vendor"
    {
        printf -- '-----%s RSA PRIVATE KEY-----\n' BEGIN
        printf 'MIIEowIBAAKCAQEAy8Dbv8prpJ%s\n' 'RXghtUOZ0kSTLPHmzoVCiVJ0dPjw1'
        printf -- '-----%s RSA PRIVATE KEY-----\n' END
    } > "$1/vendor/id_rsa"
    printf 'nothing to see here\n' > "$1/README.md"
}

# scan <tree> <label> -- echoes the finding count at $THRESHOLD, or ERR.
# Also leaves the SARIF in $work/reports-<label> for further inspection.
scan() {
    local reports="$work/reports-$2"
    rm -rf "$ROOT/scan_reports" "$reports"
    mkdir -p "$reports"
    # --no-cache for the same reason action.yml needs it: +user-source is
    # LOCALLY, so the staged tree is not part of the scanner target's cache key
    # and a second scan is served the first one's SARIF. Without this the
    # suppression assertions below pass or fail for entirely unrelated reasons.
    (cd "$ROOT" && earth --no-cache ./+gitleaks --USER_SOURCE_DIR="$1") \
        > "$work/earth-$2.log" 2>&1 || { printf ERR; return; }
    [ -d "$ROOT/scan_reports" ] && cp -r "$ROOT/scan_reports/." "$reports/"
    local rc=0
    FINDINGS_COUNT_FILE="$work/count-$2" bash "$COUNT_SH" "$THRESHOLD" "$reports" \
        > "$work/count-$2.log" 2>&1 || rc=$?
    [ "$rc" -gt 1 ] && { printf ERR; return; }
    cat "$work/count-$2"
}

# ---------------------------------------------------------------------------
echo "== a committed secret fails the build at the default threshold =="

mkdir -p "$work/dirty"
plant_secret "$work/dirty"
dirty="$(scan "$work/dirty" dirty)"

if [ "$dirty" = ERR ]; then
    no "scan failed" "$(tail -5 "$work/earth-dirty.log" | tr '\n' '|')"
    printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
    exit 1
fi

# Everything below is only meaningful if the scanner fires at all: a silently
# broken scanner satisfies every "is now zero" assertion for the wrong reason.
if [ "$dirty" -gt 0 ]; then
    ok "secret is gated at threshold $THRESHOLD ($dirty finding(s))"
else
    no "a committed private key did not fail at $THRESHOLD" \
       "every suppression assertion below would pass vacuously"
fi

if grep -q 'fails the build regardless of fail_severity' "$work/count-dirty.log"; then
    ok "the failure explains that secrets ignore fail_severity"
else
    no "no secrets guidance in the failure output"
fi
if grep -q '.gitleaks.toml' "$work/count-dirty.log" && grep -q '.gitleaksignore' "$work/count-dirty.log"; then
    ok "the failure names both exclusion mechanisms"
else
    no "the failure does not explain how to exclude"
fi
if grep -q 'gitleaks#configuration' "$work/count-dirty.log"; then
    ok "the failure links to the full reference"
else
    no "the failure offers no documentation link"
fi

# ---------------------------------------------------------------------------
echo "== a path allowlist in .gitleaks.toml suppresses it =="

# Only honoured because +gitleaks scans `.` rather than `/src`: with an absolute
# target gitleaks never looks for the repository's own config.
mkdir -p "$work/toml"
plant_secret "$work/toml"
cat > "$work/toml/.gitleaks.toml" <<'TOML'
[extend]
useDefault = true

[[allowlists]]
description = "vendored fixtures"
paths = ['''^vendor/''']
TOML
toml_count="$(scan "$work/toml" toml)"
if [ "$toml_count" = 0 ]; then
    ok ".gitleaks.toml path allowlist suppresses the finding"
else
    no ".gitleaks.toml did not suppress it (count=$toml_count)" \
       "check that +gitleaks scans '.' and not an absolute path"
fi

# ---------------------------------------------------------------------------
echo "== the .gitleaksignore line we print actually works =="

# The fingerprint is taken from our own output rather than hardcoded, so this
# asserts the remediation advice in the failure message is correct. Hardcoding it
# would let the advice rot while the test stayed green.
fingerprint="$(jq -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" --argjson threshold 5 \
    "$work/reports-dirty/gitleaks.sarif" | jq -r '.ignores[0] // ""')"

if [ -n "$fingerprint" ]; then
    ok "a fingerprint was offered for the contributor to paste ($fingerprint)"
else
    no "no .gitleaksignore fingerprint was produced"
fi

mkdir -p "$work/ignored"
plant_secret "$work/ignored"
printf '%s\n' "$fingerprint" > "$work/ignored/.gitleaksignore"
ignored_count="$(scan "$work/ignored" ignored)"
if [ "$ignored_count" = 0 ]; then
    ok ".gitleaksignore with that exact line suppresses the finding"
else
    no "the fingerprint we tell users to paste did not work (count=$ignored_count)" \
       "pasted: $fingerprint"
fi

# ---------------------------------------------------------------------------
echo "== the differential gate agrees with the counts =="

mkdir -p "$work/clean"
printf 'nothing to see here\n' > "$work/clean/README.md"
clean="$(scan "$work/clean" clean)"

if [ "$clean" = 0 ]; then
    ok "a tree with no secret is clean"
else
    no "a tree with no secret reported $clean finding(s)"
fi

gate() {  # gate <head> <base> <want_rc> <label>
    local rc=0
    bash "$GATE_SH" "$1" "$2" > /dev/null 2>&1 || rc=$?
    if [ "$rc" = "$3" ]; then ok "$4"; else no "$4"; fi
}
gate "$clean" "$dirty"            0 "passes the PR that removes the secret"
gate "$dirty" "$dirty"            1 "blocks an unrelated PR (count unchanged)"
gate "$((dirty + 1))" "$dirty"    1 "blocks a PR that adds a finding"

echo
printf '%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
