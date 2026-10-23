# Scorecard's JSON to SARIF.
#
# SAST, Fuzzing and Packaging are not filtered out here: they are never asked
# for. The one place that decides is the `--checks` allowlist in +scorecard.
#
# A check that found nothing wrong is not reported: no problem, no output. Only
# these exact reasons at a perfect score, never a score alone - 8/10 still has
# something wrong, and Security-Policy says "detected" at any score. Strings are
# from scorecard v5.6.0 checks/evaluation/*.go; a reworded one reappears in the
# report, and tests/canary.sh fails on it.
def quiet: {
  "Binary-Artifacts": "no binaries found in the repo",
  "Dangerous-Workflow": "no dangerous workflow patterns detected",
  "Dependency-Update-Tool": "update tool detected",
  "Pinned-Dependencies": "all dependencies are pinned",
  "Security-Policy": "security policy file detected",
  "Token-Permissions": "GitHub workflow tokens follow principle of least privilege",
  "Vulnerabilities": "0 existing vulnerabilities detected"
};
# Root bound first: `x | y as $v | ...` leaves the dot on x's output.
. as $root
| (.checks // []) as $checks
| {
  version: "2.1.0",
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
  runs: [
    {
      tool: {
        driver: {
          name: "ossf-scorecard",
          version: $root.scorecard.version,
          informationUri: "https://github.com/ossf/scorecard",
          rules: ($checks | map({
            id: .name,
            shortDescription: { text: .documentation.short },
            helpUri: .documentation.url
          }))
        }
      },
      results: ($checks | map(select(.score != 10 or quiet[.name] != .reason) | {
        ruleId: .name,
        level: (if .score == -1 or .score == 0 then "error" elif .score < 8 then "warning" else "note" end),
        message: { text: .reason },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: "README.md" }
            }
          }
        ]
      }))
    }
  ]
}
