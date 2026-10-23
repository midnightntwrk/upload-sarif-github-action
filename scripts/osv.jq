# osv-scanner SARIF, made gateable.
#
#   jq -f osv.jq osv.sarif
#
# osv-scanner sets `level: warning` on every result, so read as-is nothing it
# finds can fail the build at the `critical` default. The real signal is on the
# rule, and policy travels with the tool here, as in secrets-severity.jq:
#
#   MAL-*       CRITICAL. OSV's malicious-packages feed: malware, not a flaw, and
#               binary like a leaked secret. These rules carry no score at all.
#   CVSS        `properties.security-severity` on the rule, banded the way the
#               GitHub Security tab bands it: 9.0 CRITICAL, 7.0 HIGH, 4.0 MEDIUM.
#   neither     untouched; the plain SARIF reading of `warning` applies.
#
# Locations come out as file:///src/... whatever the target, because the scan
# runs in the container's /src. Stripped so paths read as they do in the repo.
def band:
    if   . >= 9 then "CRITICAL"
    elif . >= 7 then "HIGH"
    elif . >= 4 then "MEDIUM"
    else "LOW" end;

.runs |= map(
    ( [ (.tool.driver.rules // [])[]
        | select(.properties["security-severity"] != null)
        | { key: .id, value: (.properties["security-severity"] | tonumber) } ]
      | from_entries ) as $cvss
  | .results |= ((. // []) | map(
        (.ruleId // "") as $id
      | if ($id | startswith("MAL-")) then .properties.severity = "CRITICAL"
        elif $cvss[$id] != null then .properties.severity = ($cvss[$id] | band)
        else . end
      | (.locations // []) |= map(
            .physicalLocation.artifactLocation.uri |= (. // "" | sub("^file:///src/"; "")))
    ))
)
