{
  version: "2.1.0",
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
  runs: [
    {
      tool: {
        driver: {
          name: "ossf-scorecard",
          version: .scorecard.version,
          informationUri: "https://github.com/ossf/scorecard",
          rules: (.checks | map({
            id: .name,
            shortDescription: { text: .documentation.short },
            helpUri: .documentation.url
          }))
        }
      },
      results: (.checks | map({
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
