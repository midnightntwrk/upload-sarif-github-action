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
SEVERITIES='{"INFO":0,"NONE":0,"NOTE":0,"LOW":1,"WARNING":1,"MEDIUM":2,"HIGH":3,"ERROR":3,"CRITICAL":4}'

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; return 0; }

command -v earth > /dev/null 2>&1 || { echo "SKIP: earth not on PATH"; exit 0; }
docker info > /dev/null 2>&1 || { echo "SKIP: docker unavailable"; exit 0; }
# zizmor runs online and refuses to run without a token. CI sets GH_TOKEN; a
# developer usually has gh logged in.
if [ -z "${GH_TOKEN:-}" ] && command -v gh > /dev/null 2>&1; then
    GH_TOKEN="$(gh auth token 2>/dev/null || true)"
fi
[ -n "${GH_TOKEN:-}" ] || { echo "SKIP: no GH_TOKEN and no gh login - zizmor runs online"; exit 0; }
export GH_TOKEN

work="$(mktemp -d)"
trap 'rm -rf "$work" "$ROOT/scan_reports"' EXIT

# One defect per scanner. Each is the smallest thing that scanner is meant to
# notice; nothing here overlaps enough for one scanner to answer for another.
plant_defects() {
    local d="$1"
    mkdir -p "$d/.github/workflows" "$d/vendor"

    # trivy: a pin with known CVEs, several of them CRITICAL.
    printf 'django==1.11.0\n' > "$d/requirements.txt"

    # osv-scanner: a lockfile naming flatmap-stream@0.1.1, the 2018 event-stream
    # wallet stealer (MAL-2025-20690). Only the name is planted - nothing is
    # fetched, and npm now serves a 0.0.1-security placeholder in its place.
    # `resolved` is load-bearing: without it osv-scanner counts the package but
    # matches nothing against it.
    # Beside it, request@2.88.2: deprecated on npm, no advisory - the
    # deprecated-package rule is the only thing that can name it.
    mkdir -p "$d/js"
    printf '%s\n' '{"name":"canary","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"canary","version":"1.0.0","dependencies":{"flatmap-stream":"0.1.1","request":"2.88.2"}},"node_modules/flatmap-stream":{"version":"0.1.1","resolved":"https://registry.npmjs.org/flatmap-stream/-/flatmap-stream-0.1.1.tgz"},"node_modules/request":{"version":"2.88.2","resolved":"https://registry.npmjs.org/request/-/request-2.88.2.tgz"}}}' \
        > "$d/js/package-lock.json"

    # osv-scanner, yanked crates: spin 0.9.8 is yanked on crates.io and has no
    # advisory. The second entry is yanked on crates.io too, but this lockfile
    # says it came from git, so it must not be reported - deps.dev matches by
    # name and version alone.
    mkdir -p "$d/rust"
    {
        printf 'version = 4\n\n'
        printf '[[package]]\nname = "spin"\nversion = "0.9.8"\n'
        printf 'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        printf 'checksum = "6980e8d7511241f8acf4aebddbb1ff938df5eebe98691418c4468d0b72a96a67"\n\n'
        printf '[[package]]\nname = "sp-api-proc-macro"\nversion = "15.0.0"\n'
        printf 'source = "git+https://github.com/paritytech/polkadot-sdk.git?tag=polkadot-stable2609#9c7455ea"\n'
    } > "$d/rust/Cargo.lock"

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
        # zizmor online: the March 2025 tj-actions compromise, GHSA-mrrh-fwg8-r2c3.
        # Named only - nothing runs this workflow.
        printf '      - uses: tj-actions/changed-files@v35\n'
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

    # Suppressed in source: each defect a scanner above catches, excused by the
    # scanner's own comment. Both are reported with `suppressions: inSource`
    # and must reach the gate as named-but-not-counted.
    {
        printf 'import sys\n'
        printf '# nosemgrep: python.lang.security.audit.eval-detected.eval-detected\n'
        printf 'eval(sys.argv[1])\n'
    } > "$d/suppressed.py"
    {
        printf 'resource "aws_s3_bucket" "s" {\n'
        printf '  # checkov:skip=CKV_AWS_20:canary - suppressed on purpose\n'
        printf '  bucket = "canary-skipped"\n  acl    = "public-read"\n}\n'
    } > "$d/suppressed.tf"

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
    (cd "$ROOT" && earth --no-cache --secret GH_TOKEN ./+scan --USER_SOURCE_DIR="$1") \
        > "$work/earth-$2.log" 2>&1 || { printf ERR; return; }
    [ -d "$ROOT/scan_reports" ] && cp -r "$ROOT/scan_reports/." "$reports/"
    printf OK
}

# root_cause <log> -- the target that actually failed, not the tail. When one
# scanner fails, earth cancels the other six, so the last lines are always a
# victim ("context canceled") and never the cause.
root_cause() {
    awk '/ERROR Earthfile/ { p = 1 } p && n < 8 { print; n++ }' "$1" \
        | grep -v 'context canceled' | tr -s ' ' | tr '\n' '|'
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
    no "the scan itself failed" "$(root_cause "$work/earth-dirty.log")"
    printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
    exit 1
fi

produced="$(find "$work/reports-dirty" -name '*.sarif' | wc -l | tr -d ' ')"
if [ "$produced" -eq 7 ]; then
    ok "all seven scanners produced a report"
else
    no "expected 7 SARIF files, got $produced" \
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
opengrep |opengrep.sarif          |run-shell-injection    |CRITICAL
zizmor   |zizmor.sarif            |template-injection     |CRITICAL
zizmor   |zizmor.sarif            |known-vulnerable-actions|CRITICAL
checkov  |checkov.sarif           |CKV_AWS_20             |HIGH
scorecard|scorecard-results.sarif |Dangerous-Workflow     |HIGH
osv      |osv-scanner.sarif       |MAL-                   |CRITICAL
osv      |osv-scanner.sarif       |deprecated-package.*rust/Cargo\.lock |MEDIUM
osv      |osv-scanner.sarif       |deprecated-package.*js/package-lock\.json |MEDIUM
EXPECTED

# ---------------------------------------------------------------------------
# The deprecation data comes from deps.dev by name and version, with no notion
# of where the lockfile got the package. The Cargo.lock index is what tells a
# yanked crates.io release from a git fork that happens to share its version.
echo "== deprecated packages: the right crate, on its own line, and only that one =="

osv="$work/reports-dirty/osv-scanner.sarif"
dep='.runs[].results[] | select(.ruleId == "deprecated-package")'
if [ "$(jq "[$dep | select(.message.text | contains(\"spin@0.9.8\"))] | length" "$osv")" -ge 1 ]; then
    ok "spin@0.9.8 is reported as yanked"
else
    no "spin@0.9.8 is not reported" "$(jq -c "[$dep | .message.text]" "$osv")"
fi
want="$(grep -n '^\[\[package\]\]' "$work/dirty/rust/Cargo.lock" | head -1 | cut -d: -f1)"
got="$(jq -r "[$dep | select(.message.text | contains(\"spin@0.9.8\"))][0].locations[0].physicalLocation.region.startLine" "$osv")"
if [ "$got" = "$want" ]; then
    ok "and sits on the crate's own line ($want)"
else
    no "spin@0.9.8 is placed on line $got, expected $want"
fi
if [ "$(jq "[$dep | select(.message.text | contains(\"sp-api-proc-macro\"))] | length" "$osv")" = 0 ]; then
    ok "the git-sourced crate sharing a yanked version is not reported"
else
    no "sp-api-proc-macro from git is reported as yanked"
fi

# The calibration is policy, and policy that only exists in jq drifts. These
# assert the ceilings hold against real scanner output, not hand-written SARIF:
# opengrep reaches CRITICAL only on a high-confidence error, and scorecard never
# reaches CRITICAL at all.
echo "== the calibration ceilings hold =="

if [ "$(caught dirty opengrep.sarif 'detect-child-process|insecure-websocket' CRITICAL)" = 0 ]; then
    ok "opengrep low-confidence rules do not reach CRITICAL"
else
    no "a low-confidence opengrep rule was rated CRITICAL" \
       "confidence is the only thing separating 57 rules from 310"
fi

if [ "$(caught dirty scorecard-results.sarif '.' CRITICAL)" = 0 ]; then
    ok "scorecard never reaches CRITICAL"
else
    no "a scorecard score was rated CRITICAL" "it is a score out of ten, not a finding"
fi

# Not asked for at all, so absent from a real run: this action is the SAST,
# Fuzzing scores a practice it cannot observe, and Packaging is a grep for
# publish commands that scores -1 on anything it does not recognise.
for gone in SAST Fuzzing Packaging; do
    if [ "$(caught dirty scorecard-results.sarif "^$gone\$|  $gone  " INFO)" = 0 ] \
       && ! grep -q "\"$gone\"" "$work/reports-dirty/scorecard-results.sarif"; then
        ok "scorecard $gone is not reported at all"
    else
        no "scorecard still reports $gone"
    fi
done

# ---------------------------------------------------------------------------
# Raw scanner output, not hand-written SARIF: the mark has to survive each
# tool's real report, and the gate has to read it.
echo "== in-source suppressions are honoured =="

# By rule as well as file: the skip names one check, and checkov's other rules
# on the same bucket (versioning, logging, ...) are rightly still counted.
for triple in "opengrep.sarif|suppressed.py|eval-detected" "checkov.sarif|suppressed.tf|CKV_AWS_20"; do
    IFS='|' read -r report file rule <<< "$triple"
    out="$(jq -f "$SEVERITY_JQ" --argjson map "$SEVERITIES" --argjson threshold 0 \
        "$work/reports-dirty/$report")"
    named="$(jq -r --arg f "$file" --arg r "$rule" \
        '[.suppressions[] | select(contains($f) and contains($r))] | length' <<< "$out")"
    counted="$(jq -r --arg f "$file" --arg r "$rule" \
        '[.hits[] | select(.file == $f and (.rule | contains($r)))] | length' <<< "$out")"
    if [ "$named" -ge 1 ] && [ "$counted" = 0 ]; then
        ok "$report: $rule in $file is suppressed - named, not counted"
    else
        no "$report: $rule in $file named=$named counted=$counted" "expected named>=1 counted=0"
    fi
done

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

# Clean enough to score 10 on seven scorecard checks, so the assertion below
# holds scripts/scorecard.jq's perfect-score filter against the real binary. No dependency manifest: any pin can gain an advisory later, which
# would turn Vulnerabilities into a flake.
mkdir -p "$work/clean/.github/workflows"
printf 'nothing to see here\n' > "$work/clean/README.md"
cp "$ROOT/SECURITY.md" "$work/clean/SECURITY.md"
printf 'version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: weekly\n' \
    > "$work/clean/.github/dependabot.yml"
{
    printf 'on: push\npermissions: {}\njobs:\n  ok:\n    runs-on: ubuntu-latest\n'
    printf '    permissions:\n      contents: read\n    steps:\n'
    printf '      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1\n'
    printf '        with:\n          persist-credentials: false\n'
} > "$work/clean/.github/workflows/ci.yml"
if [ "$(scan "$work/clean" clean)" = ERR ]; then
    no "the clean scan failed" "$(root_cause "$work/earth-clean.log")"
else
    produced="$(find "$work/reports-clean" -name '*.sarif' | wc -l | tr -d ' ')"
    if [ "$produced" -eq 7 ]; then
        ok "all seven scanners still reported on a clean tree"
    else
        no "expected 7 SARIF files on the clean tree, got $produced"
    fi

    rc="$(gate clean critical)"
    if [ "$rc" = 0 ]; then
        ok "and the gate passes it ($(cat "$work/count-clean-critical") finding(s))"
    else
        no "expected rc 0 at critical on a clean tree, got $rc" \
           "$(grep -E '^  ' "$work/gate-clean-critical.log" | head -3 | tr '\n' '|')"
    fi

    # One reappearing here means this tree stopped scoring 10 on it (the
    # reason says why), or scorecard.jq stopped dropping perfect scores.
    loud="$(jq -r '.runs[].results[]
        | select(.ruleId | IN("Binary-Artifacts", "Dangerous-Workflow",
            "Dependency-Update-Tool", "Pinned-Dependencies", "Security-Policy",
            "Token-Permissions", "Vulnerabilities"))
        | "\(.ruleId): \(.message.text)"' "$work/reports-clean/scorecard-results.sarif")"
    if [ -z "$loud" ]; then
        ok "scorecard reports none of its seven perfect scores"
    else
        no "scorecard reported a perfect score" "$(printf '%s' "$loud" | tr '\n' '|')"
    fi
fi

# ---------------------------------------------------------------------------
# The summary is the only feedback a fork pull request or a private repo without
# GHAS gets, so "the scanner found it" is not the end of the chain - it has to
# survive rendering too.
echo "== the job summary reports what was found =="

md="$work/summary.md"
if GITHUB_STEP_SUMMARY="$md" bash "$ROOT/scripts/step-summary.sh" \
       critical "$work/reports-dirty" 'Gate **failed**.' > "$work/summary.log" 2>&1; then
    ok "the summary rendered"
else
    no "step-summary.sh exited non-zero" "$(tail -2 "$work/summary.log")"
fi

if grep -q 'finding(s) at or above CRITICAL' "$md"; then
    ok "the header states the count"
else
    no "no count in the header" "$(head -2 "$md")"
fi

# By file, not by rule: at critical only gitleaks and trivy are above the line,
# and both are identifiable by where they found it.
for want in vendor/id_rsa requirements.txt; do
    if grep -q "$want" "$md"; then
        ok "the summary names $want"
    else
        no "the summary does not mention $want" "rendered $(wc -l < "$md") lines"
    fi
done

if grep -q '<details><summary>' "$md"; then
    ok "findings are folded behind <details>"
else
    no "nothing was folded" "the header would be buried under every finding"
fi

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
