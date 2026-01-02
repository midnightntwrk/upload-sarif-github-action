#!/usr/bin/env bash

set -euo pipefail
FAIL=0
THRESHOLD="$1"
THRESHOLD="$(echo "$THRESHOLD" | tr '[:lower:]' '[:upper:]')"
declare -A SEVERITY_MAP=(["NOTE"]=0 ["WARNING"]=1 ["LOW"]=1 ["MEDIUM"]=2 ["HIGH"]=3 ["ERROR"]=4 ["CRITICAL"]=5)

for f in scan_reports/*.sarif; do
    # Extract all results and their severity
    jq -c '.runs[].results[]?' "$f" | while read -r result; do
        # Try both fields: level and properties.severity
        level=$(echo "$result" | jq -r '.level // empty' | tr '[:lower:]' '[:upper:]')
        prop=$(echo "$result" | jq -r '.properties.severity // empty')

        sev="$level"
        [ -z "$sev" ] && sev="$prop"
        [ -z "$sev" ] && continue

        # Compare severity numerically
        if [ "${SEVERITY_MAP[$sev]}" -ge "${SEVERITY_MAP[$THRESHOLD]}" ]; then
        echo "High severity issue detected in $f: $sev"
        message=$(echo "$result" | jq -r '.message.text // empty')
        rule=$(echo "$result" | jq -r '.ruleId // empty')
        file=$(echo "$result" | jq -r '.locations[0].physicalLocation.artifactLocation.uri // empty')

        echo "$sev issue detected in $f"
        [ -n "$rule" ] && echo "  Rule: $rule"
        [ -n "$file" ] && echo "  File: $file"
        [ -n "$message" ] && echo "  Message: $message"
        FAIL=1
        fi
    done
done

if [ $FAIL -eq 1 ]; then
    echo "One or more SARIF files meet or exceed severity $THRESHOLD. Failing CI."
    exit 1
fi
