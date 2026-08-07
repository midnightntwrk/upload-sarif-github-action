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

# The tool's own severity scale, taken from the rule's tags and keyed by rule id.
#
# SARIF `level` is a four-value enum topping out at "error" (§3.27.10), so a tool
# with a finer scale has to flatten it: Trivy renders CRITICAL *and* HIGH as
# `level: error`. Read through `level` and a CRITICAL CVE resolves to ERROR,
# which sits below CRITICAL in the ladder - so `fail_severity: critical`, the
# default, could not fail on one. Verified: 7 CRITICAL CVEs, count 0, rc 0.
#
# Only tags naming a severity we know are considered, so "vulnerability",
# "security" and CWE ids are ignored; the highest wins if a rule carries several.
# Trivy is the only scanner here that tags this way - checked against real output
# from opengrep, zizmor, checkov and scorecard, none of which carry one.
def rule_tag_severities($map):
    [ (.tool.driver.rules // [])[]
      | select(.id != null)
      | { key:   .id,
          value: ( [ (.properties.tags // [])[]
                     | tostring | ascii_upcase
                     | select($map[.] != null) ]
                   | max_by($map[.]) // "" ) }
      | select(.value != "") ]
    | from_entries;

# Rule tag, else result.level, else properties.severity, else the rule default,
# else "warning" (SARIF 2.1.0 §3.27.10).
#
# The tag goes first because it is the only one of these that can say CRITICAL
# when the tool means it. A severity-less result is a warning, not something to
# ignore - gitleaks emits none at all, so dropping these meant a committed
# private key could not fail the build at any threshold.
def severity($rule_levels; $rule_tags):
    ($rule_tags[.ruleId // ""] // "") as $tag
  | (.level // "" | tostring | ascii_upcase) as $level
  | (.properties.severity // "" | tostring | ascii_upcase) as $property
  | ($rule_levels[.ruleId // ""] // "") as $rule
  | if $tag      != "" then $tag
    elif $level    != "" then $level
    elif $property != "" then $property
    elif $rule     != "" then $rule
    else "WARNING"
    end;

[ .runs[]?
  | (.tool.driver.name // "") as $tool
  | rule_levels as $rule_levels
  | rule_tag_severities($map) as $rule_tags
  | .results[]?
  | severity($rule_levels; $rule_tags) as $severity
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
    total:    (. | length),
    tool:     ( [ .[].tool | select(. != "") ] | first // "" ),
    # The same hits the count is taken from, unformatted, for renderers that
    # want columns rather than a line. Emitting both from here is what keeps a
    # report and the gate from ever disagreeing about a finding's severity.
    hits:     [ $hits[] | { severity, rule, file, line, message } ],
    findings: [ $hits[]
                | "\(.severity)  \(if .rule == "" then "-" else .rule end)"
                  + "  \(if .file == "" then "-" else .file end)"
                  + "\(if .message == "" then "" else ": " + .message end)" ],
    unmapped: [ $unmapped[]
                | "\(.severity) (rule \(if .rule == "" then "?" else .rule end))" ],
    ignores:  [ $hits[]
                | select(.tool == "gitleaks" and .file != "")
                | "\(.file):\(.rule):\(.line)" ] }
