# Classify every SARIF result against a severity threshold.
#
#   jq -f severity.jq --argjson map "$SEVERITIES" --argjson threshold 3 x.sarif
#
# Emits one object:
#
#   { "count":   <findings at or above the threshold>,
#     "unknown": <results whose severity is not in $map>,
#     "findings": [ "HIGH  rule-id  path: message", ... ],
#     "unmapped": [ "UNKNOWN (rule-id)", ... ] }
#
# Formatting the lines here rather than in the caller is deliberate: the shell
# then needs a count and some strings, never individual fields, so there is no
# delimiter to choose and no `read` splitting to get wrong.

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
  | rule_levels as $rule_levels
  | .results[]?
  | severity($rule_levels) as $severity
  | { severity: $severity,
      # null for a severity outside $map: reported, but never gated on.
      rank:     $map[$severity],
      rule:     (.ruleId // ""),
      file:     (.locations[0].physicalLocation.artifactLocation.uri // ""),
      message:  ((.message.text // "") | gsub("\\s+"; " ")) } ]
| { count:    [ .[] | select(.rank != null and .rank >= $threshold) ] | length,
    unknown:  [ .[] | select(.rank == null) ] | length,
    findings: [ .[] | select(.rank != null and .rank >= $threshold)
                | "\(.severity)  \(if .rule == "" then "-" else .rule end)"
                  + "  \(if .file == "" then "-" else .file end)"
                  + "\(if .message == "" then "" else ": " + .message end)" ],
    unmapped: [ .[] | select(.rank == null)
                | "\(.severity) (rule \(if .rule == "" then "?" else .rule end))" ] }
