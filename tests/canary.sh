#!/usr/bin/env bash
#
# Is every scanner still finding anything?
#
#   ./tests/canary.sh
#
# Plants one known defect per scanner and asserts each one is caught, named, and
# resolved to the severity the gate expects. A scanner that silently stops
# working - a rule pack that fails to load, a binary that changes its output
# format, a target whose SARIF path moves - produces an empty report, and an
# empty report is indistinguishable from a clean repository. Every other test
# here is satisfied by a scanner that has quietly died.
#
# Assertions are per-scanner and by rule, never by total count: one live scanner
# must not cover for a dead one. They also read the severity through
# scripts/severity.jq rather than off the raw SARIF, because that seam has broken
# before - gitleaks findings existed for months while resolving to nothing the
# gate would act on.
#
# Fixtures are assembled at runtime and never committed. A workflow carrying
# `${{ github.event.issue.title }}` in a `run:` block is exactly what opengrep
# and zizmor are asked to catch, so committing one makes this repository's own
# scan fail - the same trap the private key in tests/integration.sh fell into.
#
# Requires earth and docker. Skips (exit 0) without them. Two full scans, so it
# is slower than the rest of the suite; it is a CI step of its own, not part of
# `earth +test`, which is hermetic and scanner-free.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
COUNT_SH="$ROOT/scripts/fail-on-severity.sh"
SEVERITY_JQ="$ROOT/scripts/severity.jq"
SEVERITIES='{"NOTE":0,"WARNING":1,"LOW":1,"MEDIUM":2,"HIGH":3,"ERROR":4,"CRITICAL":5}'

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; return 0; }

command -v earth > /dev/null 2>&1 || { echo "SKIP: earth not on PATH"; exit 0; }
docker info > /dev/null 2>&1 || { echo "SKIP: docker unavailable"; exit 0; }

work="$(mktemp -d)"
trap 'rm -rf "$work" "$ROOT/scan_reports"' EXIT

# One defect per scanner. Each is the smallest thing that scanner is meant to
# notice; nothing here overlaps enough for one scanner to answer for another.
plant_defects() {
    local d="$1"
    mkdir -p "$d/.github/workflows" "$d/vendor"

    # trivy: a pin with known CVEs, several of them CRITICAL.
    printf 'django==1.11.0\n' > "$d/requirements.txt"

    # gitleaks: the PEM markers are assembled from parts so this file does not
    # itself contain the literal the scanner matches on.
    {
        printf -- '-----%s RSA PRIVATE KEY-----\n' BEGIN
        printf 'MIIEowIBAAKCAQEAy8Dbv8prpJ%s\n' 'RXghtUOZ0kSTLPHmzoVCiVJ0dPjw1'
        printf -- '-----%s RSA PRIVATE KEY-----\n' END
    } > "$d/vendor/id_rsa"

    # opengrep + zizmor: attacker-controlled text interpolated into a run block,
    # on a trigger that gives it write access, using an unpinned action.
    {
        printf 'on: pull_request_target\n'
        printf 'jobs:\n  bad:\n    runs-on: ubuntu-latest\n    steps:\n'
        printf '      - uses: actions/checkout@v4\n'
        # Single quotes are the point: the expression must reach the workflow
        # file unexpanded, because it is the defect the scanners look for.
        # shellcheck disable=SC2016
        printf '      - run: echo "title is ${{ github.event.issue.title }}"\n'
    } > "$d/.github/workflows/bad.yml"

    # checkov: an S3 bucket world-readable by ACL.
    {
        printf 'resource "aws_s3_bucket" "b" {\n'
        printf '  bucket = "canary"\n  acl    = "public-read"\n}\n'
    } > "$d/main.tf"

    # scorecard reads the tree as a whole: no LICENSE plus the workflow above is
    # enough for Dangerous-Workflow to fail.
    printf 'canary\n' > "$d/README.md"
}

# scan <tree> <label> -- runs every scanner, leaves SARIF in $work/reports-<label>
# and the gate's count for <threshold> in $work/count-<label>. Echoes OK or ERR.
scan() {
    local reports="$work/reports-$2"
    rm -rf "$ROOT/scan_reports" "$reports"
    mkdir -p "$reports"
    # --no-cache for the reason action.yml documents: +user-source is LOCALLY, so
    # the staged tree is not part of the scanner targets' cache key and a second
    # scan in the same run is served the first one's SARIF. Without it the clean
    # control would be handed the dirty tree's findings.
    (cd "$ROOT" && earth --no-cache ./+scan --USER_SOURCE_DIR="$1") \
        > "$work/earth-$2.log" 2>&1 || { printf ERR; return; }
    [ -d "$ROOT/scan_reports" ] && cp -r "$ROOT/scan_reports/." "$reports/"
    printf OK
}

# gate <label> <threshold> -- the gate's exit code over that scan's reports.
gate() {
    local rc=0
    FINDINGS_COUNT_FILE="$work/count-$1-$2" bash "$COUNT_SH" "$2" "$work/reports-$1" \
        > "$work/gate-$1-$2.log" 2>&1 || rc=$?
    printf '%s' "$rc"
}

# caught <label> <sarif> <rule-or-file pattern> <expected severity>
#
# Reads severity through severity.jq, so this fails if the finding is present but
# resolves to something the gate would not act on.
caught() {
    local f="$work/reports-$1/$2"
    [ -f "$f" ] || { printf 'NOFILE'; return; }
    jq -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" --argjson threshold 0 "$f" \
        | jq -r --arg pat "$3" --arg sev "$4" \
            '[.findings[] | select(startswith($sev + "  ")) | select(test($pat))] | length'
}

# ---------------------------------------------------------------------------
echo "== every scanner is still finding things =="

mkdir -p "$work/dirty"
plant_defects "$work/dirty"
if [ "$(scan "$work/dirty" dirty)" = ERR ]; then
    no "the scan itself failed" "$(tail -5 "$work/earth-dirty.log" | tr '\n' '|')"
    printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
    exit 1
fi

produced="$(find "$work/reports-dirty" -name '*.sarif' | wc -l | tr -d ' ')"
if [ "$produced" -eq 6 ]; then
    ok "all six scanners produced a report"
else
    no "expected 6 SARIF files, got $produced" \
       "$(find "$work/reports-dirty" -name '*.sarif' -exec basename {} \; | tr '\n' ' ')"
fi

# scanner | report | pattern | severity the gate must resolve it to
#
# Patterns are rule ids where the tool has stable ones. Trivy's are CVE ids,
# which come and go as its database is rescored, so that one keys on the file
# instead - no other scanner reports requirements.txt.
while IFS='|' read -r name report pattern sev; do
    # The table is padded for reading, so every field arrives space-padded.
    name="${name//[[:space:]]/}"; report="${report//[[:space:]]/}"
    pattern="${pattern//[[:space:]]/}"; sev="${sev//[[:space:]]/}"
    [ -n "$name" ] || continue
    n="$(caught dirty "$report" "$pattern" "$sev")"
    case "$n" in
        NOFILE) no "$name produced no report at all" "expected $report" ;;
        0)      no "$name did not catch its planted defect at $sev" \
                   "looked for /$pattern/ in $report" ;;
        *)      ok "$name caught it ($n $sev finding(s) matching $pattern)" ;;
    esac
done <<'EXPECTED'
gitleaks |gitleaks.sarif          |private-key            |CRITICAL
trivy    |trivy.sarif             |requirements\.txt      |CRITICAL
opengrep |opengrep.sarif          |run-shell-injection    |ERROR
zizmor   |zizmor.sarif            |template-injection     |ERROR
checkov  |checkov.sarif           |CKV_AWS_20             |ERROR
scorecard|scorecard-results.sarif |Dangerous-Workflow     |ERROR
EXPECTED

# ---------------------------------------------------------------------------
echo "== the gate acts on what they found =="

rc="$(gate dirty critical)"
if [ "$rc" = 1 ]; then
    ok "the tree is blocked at the critical default ($(cat "$work/count-dirty-critical") finding(s))"
else
    no "expected rc 1 at critical, got $rc" "$(tail -2 "$work/gate-dirty-critical.log")"
fi

rc="$(gate dirty high)"
if [ "$rc" = 1 ]; then
    ok "and at high ($(cat "$work/count-dirty-high") finding(s))"
else
    no "expected rc 1 at high, got $rc" "$(tail -2 "$work/gate-dirty-high.log")"
fi

# ---------------------------------------------------------------------------
# Without this, a scanner stuck reporting everything satisfies every assertion
# above, and so does a gate wired to fail unconditionally.
echo "== a clean tree is not blocked =="

mkdir -p "$work/clean"
printf 'nothing to see here\n' > "$work/clean/README.md"
printf 'requests==2.32.5\n' > "$work/clean/requirements.txt"
if [ "$(scan "$work/clean" clean)" = ERR ]; then
    no "the clean scan failed" "$(tail -5 "$work/earth-clean.log" | tr '\n' '|')"
else
    produced="$(find "$work/reports-clean" -name '*.sarif' | wc -l | tr -d ' ')"
    if [ "$produced" -eq 6 ]; then
        ok "all six scanners still reported on a clean tree"
    else
        no "expected 6 SARIF files on the clean tree, got $produced"
    fi

    rc="$(gate clean critical)"
    if [ "$rc" = 0 ]; then
        ok "and the gate passes it ($(cat "$work/count-clean-critical") finding(s))"
    else
        no "expected rc 0 at critical on a clean tree, got $rc" \
           "$(grep -E '^  ' "$work/gate-clean-critical.log" | head -3 | tr '\n' '|')"
    fi
fi

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
