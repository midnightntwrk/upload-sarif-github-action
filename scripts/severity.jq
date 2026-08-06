# Classify every SARIF result against a severity threshold.
#
#   jq -f severity.jq --argjson map "$SEVERITIES" --argjson threshold 3 x.sarif
#
# Emits one object:
#
#   { "count":   <findings at or above the threshold>,
#     "unknown": <results whose severity is not in $map>,
#     "tool":    "<the producing tool, or "">",
#     "findings": [ "HIGH  rule-id  path: message", ... ],
#     "unmapped": [ "UNKNOWN (rule-id)", ... ],
#     "ignores":  [ "path:rule-id:line", ... ] }
#
# Formatting the lines here rather than in the caller is deliberate: the shell
# then needs a count and some strings, never individual fields, so there is no
# delimiter to choose and no `read` splitting to get wrong.
#
# `ignores` is the gitleaks fingerprint format, so a build failure can hand the
# contributor the exact line to paste into `.gitleaksignore`. It is only
# populated for gitleaks output, since the format is that tool's.

# Rule-level default levels, keyed by rule id, for results carrying no level.
def rule_levels:
    [ (.tool.driver.rules // [])[]
      | select(.id != null and .defaultConfiguration.level != null)
      | { key: .id, value: (.defaultConfiguration.level | ascii_upcase) } ]
    | from_entries;

# SARIF 2.1.0 §3.27.10: result.level, else the rule default, else "warning".
# A severity-less result is a warning, not something to ignore - gitleaks emits
# none at all, so dropping these meant a committed private key could not fail
# the build at any threshold.
def severity($rule_levels):
    (.level // "" | tostring | ascii_upcase) as $level
  | (.properties.severity // "" | tostring | ascii_upcase) as $property
  | ($rule_levels[.ruleId // ""] // "") as $rule
  | if $level    != "" then $level
    elif $property != "" then $property
    elif $rule     != "" then $rule
    else "WARNING"
    end;

[ .runs[]?
  | (.tool.driver.name // "") as $tool
  | rule_levels as $rule_levels
  | .results[]?
  | severity($rule_levels) as $severity
  | { tool:     $tool,
      severity: $severity,
      # null for a severity outside $map: reported, but never gated on.
      rank:     $map[$severity],
      rule:     (.ruleId // ""),
      file:     (.locations[0].physicalLocation.artifactLocation.uri // ""),
      line:     (.locations[0].physicalLocation.region.startLine // 0),
      message:  ((.message.text // "") | gsub("\\s+"; " ")) } ]
| ( [ .[] | select(.rank != null and .rank >= $threshold) ] ) as $hits
| ( [ .[] | select(.rank == null) ] ) as $unmapped
| { count:    ($hits | length),
    unknown:  ($unmapped | length),
    tool:     ( [ .[].tool | select(. != "") ] | first // "" ),
    findings: [ $hits[]
                | "\(.severity)  \(if .rule == "" then "-" else .rule end)"
                  + "  \(if .file == "" then "-" else .file end)"
                  + "\(if .message == "" then "" else ": " + .message end)" ],
    unmapped: [ $unmapped[]
                | "\(.severity) (rule \(if .rule == "" then "?" else .rule end))" ],
    ignores:  [ $hits[]
                | select(.tool == "gitleaks" and .file != "")
                | "\(.file):\(.rule):\(.line)" ] }
