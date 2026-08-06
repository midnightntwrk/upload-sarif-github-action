# Stamp every secret finding as CRITICAL.
#
#   jq -f secrets-severity.jq gitleaks.sarif
#
# Policy, not a description: gitleaks assigns no severity, and a leaked
# credential is not a point on a severity scale - it is either committed or it
# is not. Stamping CRITICAL here makes secrets fail at every `fail_severity`
# the action accepts, including the `critical` default, instead of resolving to
# the SARIF default of `warning` and passing the build.
#
# Set here rather than in the shared severity.jq so that policy travels with the
# tool that produced the finding, the way scorecard.jq already shapes Scorecard's
# output. `properties.severity` and not `level`: `level` is a SARIF reporting
# kind, and gitleaks emits none, so this is the field that carries meaning.
.runs |= map(.results |= ((. // []) | map(.properties.severity = "CRITICAL")))
