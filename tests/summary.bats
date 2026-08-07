#!/usr/bin/env bats
#
# The job summary: what an unfolded reader sees, and that it cannot fail a build.

load helper

SUMMARY_SH="$ROOT/scripts/step-summary.sh"

setup() {
    TMP="$(mktemp -d)"
}

teardown() {
    rm -rf "$TMP"
}

# summary <reports_dir> <threshold> [verdict] -- $status and $output as rendered.
# GITHUB_STEP_SUMMARY unset, so it writes to stdout.
summary() {
    run env -u GITHUB_STEP_SUMMARY bash "$SUMMARY_SH" "$2" "$1" "${3:-}"
}

@test "the header states the count at the threshold" {
    summary "$FIX/two-high" high
    [ "$status" -eq 0 ]
    [[ "$output" == *"2 finding(s) at or above HIGH"* ]]
}

@test "a clean scan says so rather than showing an empty table" {
    summary "$FIX/note-only" critical
    [[ "$output" == *"clean at CRITICAL"* ]]
}

@test "the verdict line is passed through verbatim" {
    summary "$FIX/one-high" high 'Gate **failed** at `high`.'
    [[ "$output" == *'Gate **failed** at `high`.'* ]]
}

# The summary is a report, not a gate. If it could fail it would be a second
# opinion on the verdict, and two verdicts is one too many.
@test "a failing scan still exits 0" {
    summary "$FIX/two-high" high
    [ "$status" -eq 0 ]
}

@test "no reports at all is not an error" {
    summary "$TMP" high
    [ "$status" -eq 0 ]
    [[ "$output" == *"No SARIF reports were produced"* ]]
}

# ---------------------------------------------------------------------------
# Folding. Everything past the header is behind <details>, and markdown only
# renders inside one if a blank line follows </summary>.

@test "findings are folded, not listed in the header" {
    summary "$FIX/two-high" high
    [[ "$output" == *"<details><summary>"* ]]
    [[ "$output" == *"</details>"* ]]
}

@test "a blank line follows the summary tag, or the table renders as raw text" {
    summary "$FIX/two-high" high
    printf '%s\n' "$output" | grep -A1 '</summary>' | tail -1 | grep -qE '^$'
}

@test "the fold names the scanner and its count" {
    summary "$FIX/two-high" high
    [[ "$output" == *"2 finding(s) at or above HIGH</summary>"* ]]
}

@test "a scanner with nothing at the threshold gets no fold" {
    summary "$FIX/note-only" high
    [[ "$output" != *"<details>"* ]]
}

# ---------------------------------------------------------------------------
# The scanner table. The all-severities column is the point: 0/- means the
# scanner produced nothing whatsoever, which is what a dead scanner looks like.

@test "the table separates gated findings from the total" {
    summary "$FIX/note-only" high
    [[ "$output" == *"| 0 | 2 |"* ]]
}

@test "a scanner that produced nothing at all is shown as a dash" {
    sarif "$TMP/r/quiet.sarif" '{"runs":[{"tool":{"driver":{"name":"quiet"}},"results":[]}]}'
    summary "$TMP/r" high
    [[ "$output" == *"| 0 | — |"* ]]
}

# ---------------------------------------------------------------------------
# Cell contents. A pipe or a newline in a message would break out of the row;
# both arrive from real scanners.

@test "a pipe in a message does not break the table row" {
    sarif "$TMP/r/p.sarif" '{"runs":[{"results":[{"ruleId":"R","level":"error",
      "message":{"text":"a | b | c"}}]}]}'
    summary "$TMP/r" high
    [[ "$output" == *'a \| b \| c'* ]]
}

@test "a multi-line message is collapsed onto one row" {
    sarif "$TMP/r/n.sarif" '{"runs":[{"results":[{"ruleId":"R","level":"error",
      "message":{"text":"first\nsecond"}}]}]}'
    summary "$TMP/r" high
    [[ "$output" == *"first second"* ]]
    [ "$(printf '%s\n' "$output" | grep -c 'second')" = 1 ]
}

@test "a location carries its line number when it has one" {
    summary "$FIX/trivy" high
    [[ "$output" == *"requirements.txt:2"* ]]
}

# startLine is optional in SARIF, and a fabricated :0 would send a reader to a
# line that does not exist.
@test "a location with no line number is not given one" {
    summary "$FIX/one-high" high
    [[ "$output" == *"| a.py |"* ]]
    [[ "$output" != *"a.py:0"* ]]
}

@test "a finding with no location is not rendered as an empty cell" {
    sarif "$TMP/r/nl.sarif" '{"runs":[{"results":[{"ruleId":"R","level":"error",
      "message":{"text":"nowhere"}}]}]}'
    summary "$TMP/r" high
    [[ "$output" == *"| - | nowhere |"* ]]
}

# ---------------------------------------------------------------------------
# Degenerate reports must be visible rather than counted as clean - the same
# contract the counter has, for the same reason.

@test "an unreadable report is flagged in the table" {
    printf '{not json\n' > "$TMP/broken.sarif"
    summary "$TMP" high
    [ "$status" -eq 0 ]
    [[ "$output" == *"unreadable"* ]]
}

@test "a zero-length report is flagged in the table" {
    : > "$TMP/empty.sarif"
    summary "$TMP" high
    [ "$status" -eq 0 ]
    [[ "$output" == *"empty report"* ]]
}

# ---------------------------------------------------------------------------

# An unset fail_severity turns the gate off. That is a configuration, not a
# failure, so the summary still renders - and says so, because "0 above
# CRITICAL" and "nothing was gated" read identically otherwise.
@test "an unset threshold renders everything and says nothing was gated" {
    summary "$FIX/note-only" ""
    [ "$status" -eq 0 ]
    [[ "$output" == *"none gated"* ]]
    [[ "$output" == *"nothing here fails the build"* ]]
}

@test "an unknown threshold is rc 2, not a silent empty summary" {
    summary "$FIX/one-high" hgh
    [ "$status" -eq 2 ]
}

@test "unmapped severities get their own fold rather than vanishing" {
    summary "$FIX/unknown-sev" high
    [[ "$output" == *"unrecognised severity"* ]]
}

@test "the artifact is pointed at, so the fold is not the only way to see more" {
    summary "$FIX/one-high" high
    [[ "$output" == *"sarif_reports"* ]]
}

# GITHUB_STEP_SUMMARY is a file path on a runner; stdout is only the local
# fallback. Appending is required - other steps write to the same file.
@test "output goes to GITHUB_STEP_SUMMARY when it is set" {
    GITHUB_STEP_SUMMARY="$TMP/sum.md" bash "$SUMMARY_SH" high "$FIX/one-high" > "$TMP/stdout"
    [ -s "$TMP/sum.md" ]
    [ ! -s "$TMP/stdout" ]
    grep -q "at or above HIGH" "$TMP/sum.md"
}

@test "an existing summary file is appended to, not truncated" {
    printf 'earlier step\n' > "$TMP/sum.md"
    GITHUB_STEP_SUMMARY="$TMP/sum.md" bash "$SUMMARY_SH" high "$FIX/one-high"
    grep -q 'earlier step' "$TMP/sum.md"
    grep -q 'at or above HIGH' "$TMP/sum.md"
}
