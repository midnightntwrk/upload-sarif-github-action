#!/usr/bin/env bash
#
# Render a scan into GitHub's job summary.
#
#   step-summary.sh <threshold> <reports_dir> [verdict]
#
# Writes markdown to $GITHUB_STEP_SUMMARY, or stdout when that is unset.
#
# Needs no permissions at all - it is a file write, not an API call - so it
# reaches the three populations that get nothing today: fork pull requests
# (where `security-events: write` is not granted and the Security-tab upload
# silently fails), private repositories without GHAS, and any consumer that
# declines to hand this action a token.
#
# Everything below the header is folded. A scan is read by someone who wants one
# of two things: the verdict, or one specific finding. An unfolded list of four
# hundred serves neither, and GitHub truncates the summary at ~1 MiB - past that
# it renders nothing at all, so a wall of text is also a way to lose the verdict.
#
# Severity comes from severity.jq, the same program the gate counts with, so the
# summary cannot claim a severity the gate disagreed with.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
JQ="$HERE/severity.jq"
SEVERITIES='{"NOTE":0,"WARNING":1,"LOW":1,"MEDIUM":2,"HIGH":3,"ERROR":4,"CRITICAL":5}'

# Per scanner, inside the fold. Beyond this the artifact is the answer; saying
# so beats a truncated table that looks complete.
MAX_ROWS=50

REPORTS_DIR="${2:-scan_reports}"
VERDICT="${3:-}"

# An empty fail_severity turns the gate off, which is a supported configuration,
# not an error - so the summary still renders. It lists everything (note is the
# bottom of the ladder) and says the gate was off, because "0 findings at or
# above CRITICAL" and "nothing was gated" look identical otherwise.
GATE_OFF=""
if [ -z "${1:-}" ]; then
    GATE_OFF=1
    THRESHOLD=NOTE
else
    THRESHOLD="$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')"
fi

THRESHOLD_N="$(jq -rn --argjson s "$SEVERITIES" --arg t "$THRESHOLD" '$s[$t] // empty')"
[ -n "$THRESHOLD_N" ] || { echo "unknown threshold '${1:-}'" >&2; exit 2; }

out() { printf '%s\n' "$*" >> "${GITHUB_STEP_SUMMARY:-/dev/stdout}"; }

# Markdown inside <details> only renders if a blank line follows </summary>.
fold_open()  { out "<details><summary>$1</summary>"; out ""; }
fold_close() { out ""; out "</details>"; out ""; }

# jq emits the finished table row, not its fields. severity.jq already works
# this way and says why: hand bash columns and you have chosen a delimiter, and
# choosing a delimiter is how two of the four bugs in this repo's history
# happened. (A first draft of this file used `tr '\t' '\x1f'`, which BSD tr
# reads as the literal letter x. Same mistake, third time.)
# Single quotes throughout: this is a jq program, and nothing in it is for the
# shell to expand.
# shellcheck disable=SC2016
ROW_JQ='
  def esc: tostring | gsub("\\|"; "\\|") | gsub("`"; "'"'"'") | .[0:160];
  .hits[]
  | (if .line > 0 and .file != "" then "\(.file):\(.line)" else .file end) as $loc
  | "| \(.severity)"
    + " | `\(if .rule == "" then "-" else (.rule | esc) end)`"
    + " | \(if $loc == "" then "-" else ($loc | esc) end)"
    + " | \(.message | esc) |"'

shopt -s nullglob
sarifs=("$REPORTS_DIR"/*.sarif)
shopt -u nullglob

if [ ${#sarifs[@]} -eq 0 ]; then
    out "## Security scan"
    out ""
    out "No SARIF reports were produced. Nothing was scanned."
    exit 0
fi

# ---------------------------------------------------------------------------
# Pass one: per-file report, so the header can be written before the detail.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

total_hits=0
total_all=0
for f in "${sarifs[@]}"; do
    base="$(basename "$f" .sarif)"
    if ! jq -f "$JQ" --argjson map "$SEVERITIES" --argjson threshold "$THRESHOLD_N" "$f" \
        > "$tmp/$base.json" 2> "$tmp/$base.err"; then
        printf 'PARSE\n' > "$tmp/$base.state"
        continue
    fi
    [ -s "$tmp/$base.json" ] || { printf 'EMPTY\n' > "$tmp/$base.state"; continue; }
    printf 'OK\n' > "$tmp/$base.state"
    total_hits=$((total_hits + $(jq -r '.count' "$tmp/$base.json")))
    total_all=$((total_all + $(jq -r '.total' "$tmp/$base.json")))
done

# ---------------------------------------------------------------------------
# The header is the whole message for most readers: verdict, then the shape of
# it. Nothing here is folded.
if [ -n "$GATE_OFF" ]; then
    out "## Security scan — ${total_all} finding(s), none gated"
elif [ "$total_hits" -gt 0 ]; then
    out "## Security scan — ${total_hits} finding(s) at or above ${THRESHOLD}"
else
    out "## Security scan — clean at ${THRESHOLD}"
fi
out ""
[ -n "$VERDICT" ] && { out "$VERDICT"; out ""; }
[ -n "$GATE_OFF" ] && {
    out "\`fail_severity\` is unset, so nothing here fails the build. Everything"
    out "found is listed below, at every severity."
    out ""
}

out "| Scanner | ≥ ${THRESHOLD} | all severities |"
out "| ------- | -------------- | -------------- |"
for f in "${sarifs[@]}"; do
    base="$(basename "$f" .sarif)"
    case "$(cat "$tmp/$base.state")" in
        PARSE) out "| \`$base\` | ⚠️ unreadable | — |" ; continue ;;
        EMPTY) out "| \`$base\` | ⚠️ empty report | — |" ; continue ;;
    esac
    n="$(jq -r '.count' "$tmp/$base.json")"
    a="$(jq -r '.total' "$tmp/$base.json")"
    tool="$(jq -r 'if .tool == "" then "" else .tool end' "$tmp/$base.json")"
    label="\`$base\`"
    [ -n "$tool" ] && label="$label <sub>$tool</sub>"
    # A scanner reporting nothing at all is worth an eye, even on a green run:
    # it is what a silently broken scanner looks like.
    if [ "$a" -eq 0 ]; then
        out "| $label | 0 | — |"
    elif [ "$n" -eq 0 ]; then
        out "| $label | 0 | $a |"
    else
        out "| $label | **$n** | $a |"
    fi
done
out ""
out "$total_all finding(s) across all severities; $total_hits at or above ${THRESHOLD}."
out ""

# ---------------------------------------------------------------------------
# Everything from here down is folded.
for f in "${sarifs[@]}"; do
    base="$(basename "$f" .sarif)"
    [ "$(cat "$tmp/$base.state")" = OK ] || continue
    n="$(jq -r '.count' "$tmp/$base.json")"
    [ "$n" -gt 0 ] || continue

    fold_open "$base — $n finding(s) at or above ${THRESHOLD}"
    out "| Severity | Rule | Location | Detail |"
    out "| -------- | ---- | -------- | ------ |"
    jq -r "$ROW_JQ" "$tmp/$base.json" | head -n "$MAX_ROWS" \
        >> "${GITHUB_STEP_SUMMARY:-/dev/stdout}"
    if [ "$n" -gt "$MAX_ROWS" ]; then
        out ""
        out "_Showing $MAX_ROWS of $n. The full set is in the \`sarif_reports\` artifact._"
    fi
    fold_close
done

# Not gated, but not nothing: a severity the ladder does not know about is a
# finding nobody has decided about, which is worth seeing exactly once.
unmapped_total=0
for f in "${sarifs[@]}"; do
    base="$(basename "$f" .sarif)"
    [ "$(cat "$tmp/$base.state")" = OK ] || continue
    unmapped_total=$((unmapped_total + $(jq -r '.unknown' "$tmp/$base.json")))
done
if [ "$unmapped_total" -gt 0 ]; then
    fold_open "$unmapped_total finding(s) with an unrecognised severity — reported, not gated"
    for f in "${sarifs[@]}"; do
        base="$(basename "$f" .sarif)"
        [ "$(cat "$tmp/$base.state")" = OK ] || continue
        jq -r --arg b "$base" '.unmapped[]? | "- `\($b)` \(.)"' "$tmp/$base.json" \
            >> "${GITHUB_STEP_SUMMARY:-/dev/stdout}"
    done
    fold_close
fi

out "<sub>Raw SARIF for every scanner is attached to this run as \`sarif_reports\`.</sub>"
