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

# The confidence opengrep attaches to a rule, as a tag. Distinct from severity:
# it is how sure the rule is, not how much the finding matters - but opengrep
# offers no severity at all, so the pair (level, confidence) is the whole signal.
def rule_confidences:
    [ (.tool.driver.rules // [])[]
      | select(.id != null)
      | { key:   .id,
          value: ( [ (.properties.tags // [])[]
                     | tostring | ascii_upcase
                     | select(endswith(" CONFIDENCE"))
                     | sub(" CONFIDENCE$"; "") ]
                   | first // "" ) }
      | select(.value != "") ]
    | from_entries;

# Per-tool calibration onto one ladder.
#
# SARIF `level` is a reporting level - none/note/warning/error - not an impact.
# Read straight through, every tool that speaks only `level` is capped at
# `error` and can never reach `critical`, which is why the default threshold
# gated almost nothing. Each tool's native signal is mapped instead, and the
# ceiling differs by what the tool is in a position to claim.
#
#   opengrep   level x confidence. `error` alone covers 310 rules including ones
#              opengrep itself marks LOW CONFIDENCE, so the pair is the signal.
#   zizmor     grades every finding, not every rule (template-injection lands at
#              error 47 times and note 23 times on one real repository). Its
#              error means a workflow is exploitable.
#   scorecard  a score out of ten, not a finding. Worth knowing, never CRITICAL.
#   others     the plain SARIF reading. checkov lands here: level and nothing else.
def calibrate($tool; $level; $confidence):
    if ($tool | test("opengrep|semgrep")) then
        if   $level == "ERROR"   then
            if   $confidence == "HIGH" then "CRITICAL"
            elif $confidence == "LOW"  then "MEDIUM"
            else "HIGH" end
        elif $level == "WARNING" then "LOW"
        else "INFO" end
    elif ($tool | test("zizmor")) then
        if   $level == "ERROR"   then "CRITICAL"
        elif $level == "WARNING" then "MEDIUM"
        else "LOW" end
    elif ($tool | test("scorecard")) then
        if   $level == "ERROR"   then "HIGH"
        elif $level == "WARNING" then "MEDIUM"
        else "LOW" end
    else
        if   $level == "ERROR"   then "HIGH"
        elif $level == "WARNING" then "MEDIUM"
        elif $level == "NOTE"    then "LOW"
        else $level end
    end;

# A severity the tool actually stated wins over anything inferred from a level:
# properties.severity (gitleaks, stamped by policy) then a severity named in the
# rule's tags (trivy). Only when neither exists is the level calibrated.
def severity($rule_levels; $rule_tags; $rule_confs; $tool):
    ($rule_tags[.ruleId // ""] // "") as $tag
  | (.properties.severity // "" | tostring | ascii_upcase) as $property
  | ($rule_confs[.ruleId // ""] // "") as $confidence
  # Bound before the pipe: inside `if . == ""` the dot is the level string, not
  # the result, so a rule lookup there indexes a string and aborts the run.
  | ($rule_levels[.ruleId // ""] // "") as $rule_level
  | (.level // "" | tostring | ascii_upcase) as $result_level
  | (if $result_level == "" then $rule_level else $result_level end) as $level
  | if $property != "" then $property
    elif $tag    != "" then $tag
    elif $level  != "" then calibrate($tool; $level; $confidence)
    # No level anywhere. Not something to ignore - gitleaks emits none at all,
    # so dropping these meant a committed private key could not fail at any
    # threshold - but nothing here justifies more than the bottom of the ladder.
    else "LOW"
    end;

[ .runs[]?
  | (.tool.driver.name // "") as $tool
  | rule_levels as $rule_levels
  | rule_tag_severities($map) as $rule_tags
  | rule_confidences as $rule_confs
  | ($tool | ascii_downcase) as $tool_key
  | .results[]?
  | severity($rule_levels; $rule_tags; $rule_confs; $tool_key) as $severity
  | { tool:     $tool,
      severity: $severity,
      # null for a severity outside $map: reported, but never gated on.
      rank:     $map[$severity],
      rule:     (.ruleId // ""),
      file:     (.locations[0].physicalLocation.artifactLocation.uri // ""),
      line:     (.locations[0].physicalLocation.region.startLine // 0),
      # Trivy ends every message with `Link: [<id>](<url>)`, repeating the rule
      # id that is already its own column. Messages are truncated for display,
      # so boilerplate at the tail costs the package and fixed-version at the
      # head - the two things a reader actually needs.
      message:  ((.message.text // "")
                 | gsub("\\s+"; " ")
                 | sub("\\s*Link: \\[[^\\]]*\\]\\([^)]*\\)\\s*$"; "")) } ]
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
