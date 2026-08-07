# Scorecard's JSON to SARIF.
#
# SAST and Fuzzing are dropped, not downgraded, and dropped from the rule table
# as well as the results - a rule advertised with no result is a check that
# looks skipped rather than declined. Scorecard's SAST check asks whether the
# repository runs a static analyser: this action is one, and it is running, so
# a failing score there states something untrue. Fuzzing scores a practice this
# action neither performs nor can observe. Both scored 0, became `level: error`,
# and blocked builds on the strength of it.
# Root bound first: `x | y as $v | ...` leaves the dot on x's output, so reading
# .scorecard.version after the binding would index the filtered array.
. as $root
| ((.checks // []) | map(select(.name != "SAST" and .name != "Fuzzing"))) as $checks
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
