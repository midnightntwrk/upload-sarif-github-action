# Scorecard's JSON to SARIF.
#
# SAST, Fuzzing and Packaging are not filtered out here: they are never asked
# for. The one place that decides is the `--checks` allowlist in +scorecard.
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
      results: ($checks | map({
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
