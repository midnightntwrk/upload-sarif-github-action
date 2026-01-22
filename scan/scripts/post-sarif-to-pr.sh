#!/usr/bin/env bash

set -euo pipefail

# Script to post SARIF findings from multiple files as a single PR comment
# Usage: post-sarif-to-pr.sh <github_token> <repository> <pr_number> <scan_reports_dir>

GITHUB_TOKEN="$1"
REPOSITORY="$2"
PR_NUMBER="$3"
SCAN_REPORTS_DIR="${4:-scan_reports}"

# GitHub API endpoints
COMMENTS_API="https://api.github.com/repos/${REPOSITORY}/issues/${PR_NUMBER}/comments"
# Marker to identify our comment
COMMENT_MARKER="<!-- sarif-security-scan-results -->"

# Function to normalize severity to high/medium/low
normalize_severity() {
    local severity="$1"
    local upper_severity
    upper_severity=$(echo "$severity" | tr '[:lower:]' '[:upper:]')

    case "$upper_severity" in
        ERROR|CRITICAL|HIGH)
            echo "high"
            ;;
        WARNING|MEDIUM)
            echo "medium"
            ;;
        NOTE|LOW|INFO)
            echo "low"
            ;;
        *)
            echo "low"
            ;;
    esac
}

# Function to find existing comment ID
find_existing_comment() {
    local response
    response=$(curl -s \
        -H "Authorization: token ${GITHUB_TOKEN}" \
        -H "Accept: application/vnd.github.v3+json" \
        "$COMMENTS_API")

    echo "$response" | jq -r --arg marker "$COMMENT_MARKER" \
        '.[] | select(.body | contains($marker)) | .id' | head -n1
}

# Function to update an existing comment
update_comment() {
    local comment_id="$1"
    local body="$2"

    local payload
    payload=$(echo "$body" | jq -Rs '{body: .}')
    local url="https://api.github.com/repos/${REPOSITORY}/issues/comments/${comment_id}"

    local response
    response=$(curl -s -w "\n%{http_code}" \
        -X PATCH \
        -H "Authorization: token ${GITHUB_TOKEN}" \
        -H "Accept: application/vnd.github.v3+json" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "$url")

    local http_code
    http_code=$(echo "$response" | tail -n1)
    local response_body
    response_body=$(echo "$response" | sed '$d')

    if [ "$http_code" -eq 200 ]; then
        echo "✅ Successfully updated comment ${comment_id}"
        return 0
    else
        echo "::error::Failed to update comment. HTTP ${http_code}"
        echo "Response: $response_body"
        return 1
    fi
}

# Function to create a new comment
create_comment() {
    local body="$1"

    local payload
    payload=$(echo "$body" | jq -Rs '{body: .}')

    local response
    response=$(curl -s -w "\n%{http_code}" \
        -X POST \
        -H "Authorization: token ${GITHUB_TOKEN}" \
        -H "Accept: application/vnd.github.v3+json" \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "$COMMENTS_API")

    local http_code
    http_code=$(echo "$response" | tail -n1)
    local response_body
    response_body=$(echo "$response" | sed '$d')

    if [ "$http_code" -eq 201 ]; then
        echo "✅ Successfully created comment"
        return 0
    else
        echo "::error::Failed to create comment. HTTP ${http_code}"
        echo "Response: $response_body"
        return 1
    fi
}

# Function to process all SARIF files and collect findings
collect_all_findings() {
    local sarif_files="$1"
    local findings_dir="$2"

    local high_count=0
    local medium_count=0
    local low_count=0

    # Initialize output files
    : > "$findings_dir/high.txt"
    : > "$findings_dir/medium.txt"
    : > "$findings_dir/low.txt"

    # Process each SARIF file
    while IFS= read -r sarif_file; do
        [ -z "$sarif_file" ] && continue

        if [ ! -f "$sarif_file" ]; then
            echo "::warning::SARIF file not found: $sarif_file"
            continue
        fi

        echo "Processing $sarif_file..."

        # Extract findings from this SARIF file
        while IFS= read -r finding; do
            [ -z "$finding" ] && continue

            local rule_id
            rule_id=$(echo "$finding" | jq -r '.ruleId // "unknown"')
            local message
            message=$(echo "$finding" | jq -r '.message.text // .message.markdown // "No message"')
            local severity
            severity=$(echo "$finding" | jq -r '.properties.severity // .level // "unknown"')
            local uri
            uri=$(echo "$finding" | jq -r '.locations[0]?.physicalLocation?.artifactLocation?.uri // "N/A"')
            local start_line
            start_line=$(echo "$finding" | jq -r '.locations[0]?.physicalLocation?.region?.startLine // "N/A"')

            # Normalize severity
            local normalized_severity
            normalized_severity=$(normalize_severity "$severity")

            # Create finding text and write directly to appropriate file
            {
                echo "- **Rule:** \`${rule_id}\`"
                if [ "$uri" != "N/A" ]; then
                    if [ "$start_line" != "N/A" ]; then
                        echo "- **File:** \`${uri}\` (line ${start_line})"
                    else
                        echo "- **File:** \`${uri}\`"
                    fi
                fi
                echo "- **Message:** ${message}"
                echo ""
            } >> "$findings_dir/${normalized_severity}.txt"

            # Increment count
            case "$normalized_severity" in
                high)
                    high_count=$((high_count + 1))
                    ;;
                medium)
                    medium_count=$((medium_count + 1))
                    ;;
                low)
                    low_count=$((low_count + 1))
                    ;;
            esac
        done < <(jq -c '.runs[]?.results[]?' "$sarif_file" 2>/dev/null || echo "")
    done <<< "$sarif_files"

    # Return counts via global variables
    export HIGH_COUNT=$high_count
    export MEDIUM_COUNT=$medium_count
    export LOW_COUNT=$low_count
}

# Function to build the comment body
build_comment_body() {
    local findings_dir="$1"
    local high_count="$2"
    local medium_count="$3"
    local low_count="$4"
    local total_count=$((high_count + medium_count + low_count))

    {
        echo "${COMMENT_MARKER}"
        echo ""
        echo "# 🔍 Security Scan Results"
        echo ""
        echo "**Total findings:** ${total_count}"
        echo ""

        # High severity section
        if [ "$high_count" -gt 0 ]; then
            echo "<details>"
            echo "<summary><strong>High Severity: ${high_count}</strong></summary>"
            echo ""

            if [ -f "$findings_dir/high.txt" ] && [ -s "$findings_dir/high.txt" ]; then
                cat "$findings_dir/high.txt"
            fi

            echo "</details>"
            echo ""
        fi

        # Medium severity section
        if [ "$medium_count" -gt 0 ]; then
            echo "<details>"
            echo "<summary><strong>Medium Severity: ${medium_count}</strong></summary>"
            echo ""

            if [ -f "$findings_dir/medium.txt" ] && [ -s "$findings_dir/medium.txt" ]; then
                cat "$findings_dir/medium.txt"
            fi

            echo "</details>"
            echo ""
        fi

        # Low severity section
        if [ "$low_count" -gt 0 ]; then
            echo "<details>"
            echo "<summary><strong>Low Severity: ${low_count}</strong></summary>"
            echo ""

            if [ -f "$findings_dir/low.txt" ] && [ -s "$findings_dir/low.txt" ]; then
                cat "$findings_dir/low.txt"
            fi

            echo "</details>"
            echo ""
        fi

        if [ "$total_count" -eq 0 ]; then
            echo "✅ No security findings detected."
            echo ""
        fi

        echo "---"
        echo "*Generated from SARIF scan reports*"
    }
}

# Main execution
if [ -z "$GITHUB_TOKEN" ]; then
    echo "::error::GitHub token is required"
    exit 1
fi

if [ -z "$REPOSITORY" ]; then
    echo "::error::Repository is required"
    exit 1
fi

if [ -z "$PR_NUMBER" ]; then
    echo "::error::PR number is required"
    exit 1
fi

# Find all SARIF files in the scan_reports directory
if [ ! -d "$SCAN_REPORTS_DIR" ]; then
    echo "::warning::Scan reports directory not found: $SCAN_REPORTS_DIR"
    exit 0
fi

sarif_files=$(find "$SCAN_REPORTS_DIR" -name "*.sarif" -type f | sort)

if [ -z "$sarif_files" ]; then
    echo "::warning::No SARIF files found in $SCAN_REPORTS_DIR"
    exit 0
fi

# Create temporary directory for findings
findings_dir=$(mktemp -d)
trap 'rm -rf "$findings_dir"' EXIT

# Collect all findings
collect_all_findings "$sarif_files" "$findings_dir"

# Build comment body
comment_body=$(build_comment_body "$findings_dir" "$HIGH_COUNT" "$MEDIUM_COUNT" "$LOW_COUNT")

# Find existing comment
existing_comment_id=$(find_existing_comment)

if [ -n "$existing_comment_id" ] && [ "$existing_comment_id" != "null" ]; then
    echo "Found existing comment (ID: ${existing_comment_id}), updating..."
    if update_comment "$existing_comment_id" "$comment_body"; then
        echo "✅ Comment updated successfully"
    else
        exit 1
    fi
else
    echo "No existing comment found, creating new one..."
    if create_comment "$comment_body"; then
        echo "✅ Comment created successfully"
    else
        exit 1
    fi
fi

# Cleanup
rm -rf "$findings_dir"

echo "✅ All SARIF files processed successfully"
