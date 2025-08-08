#!/bin/bash

# Local testing script for SARIF upload to Checkmarx
# This script simulates the GitHub Action locally

set -e

echo "==================================="
echo "Local Test for SARIF Upload Action"
echo "==================================="

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if required environment variables are set
check_env_vars() {
    local missing_vars=()
    
    if [ -z "$CX_CLIENT_ID" ]; then
        missing_vars+=("CX_CLIENT_ID")
    fi
    if [ -z "$CX_CLIENT_SECRET_EU" ]; then
        missing_vars+=("CX_CLIENT_SECRET_EU")
    fi
    if [ -z "$CX_TENANT" ]; then
        missing_vars+=("CX_TENANT")
    fi
    
    if [ ${#missing_vars[@]} -gt 0 ]; then
        echo -e "${RED}Error: Missing required environment variables:${NC}"
        printf '%s\n' "${missing_vars[@]}"
        echo ""
        echo "Please set them using:"
        echo "  export CX_CLIENT_ID='your-client-id'"
        echo "  export CX_CLIENT_SECRET_EU='your-client-secret'"
        echo "  export CX_TENANT='your-tenant'"
        echo ""
        echo "Or create a .env file with these variables and run:"
        echo "  source .env && ./test-local.sh"
        exit 1
    fi
}

# Create test SARIF file
create_test_sarif() {
    echo -e "${YELLOW}Creating test SARIF file...${NC}"
    
    cat > test-local.sarif << 'EOF'
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "local-test-scanner",
          "version": "1.0.0",
          "informationUri": "https://github.com/midnight-ntwrk/upload-sarif-github-action",
          "rules": [
            {
              "id": "TEST001",
              "name": "TestVulnerability",
              "shortDescription": {
                "text": "Local test vulnerability"
              },
              "fullDescription": {
                "text": "This is a test vulnerability created for local testing"
              },
              "defaultConfiguration": {
                "level": "warning"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "TEST001",
          "ruleIndex": 0,
          "level": "warning",
          "message": {
            "text": "Test vulnerability found during local testing"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "test/local-test.rs",
                  "uriBaseId": "%SRCROOT%"
                },
                "region": {
                  "startLine": 42,
                  "startColumn": 1,
                  "endLine": 42,
                  "endColumn": 20
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
EOF
    
    echo -e "${GREEN}✓ Test SARIF file created: test-local.sarif${NC}"
    echo "  Size: $(stat -f%z test-local.sarif 2>/dev/null || stat -c%s test-local.sarif) bytes"
}

# Install Checkmarx CLI
install_cx_cli() {
    echo -e "${YELLOW}Installing Checkmarx CLI...${NC}"
    
    # Check if already installed
    if [ -f "./cx" ]; then
        echo "  CLI already installed, checking version..."
        ./cx version
        return 0
    fi
    
    # Detect OS and architecture
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    case "$ARCH" in
        x86_64) ARCH="x64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *) echo -e "${RED}Unsupported architecture: $ARCH${NC}"; exit 1 ;;
    esac
    
    # Download CLI
    CLI_VERSION="2.3.29"
    CLI_URL="https://github.com/Checkmarx/ast-cli/releases/download/${CLI_VERSION}/ast-cli_${CLI_VERSION}_${OS}_${ARCH}.tar.gz"
    
    echo "  Downloading from: $CLI_URL"
    curl -L -o cx-cli.tar.gz "$CLI_URL"
    tar -xzf cx-cli.tar.gz
    chmod +x cx
    
    echo -e "${GREEN}✓ Checkmarx CLI installed${NC}"
    ./cx version
}

# Test authentication
test_auth() {
    echo -e "${YELLOW}Testing Checkmarx authentication...${NC}"
    
    ./cx configure set --prop-name cx_base_uri --prop-value "https://eu-2.ast.checkmarx.net/"
    ./cx configure set --prop-name cx_client_id --prop-value "$CX_CLIENT_ID"
    ./cx configure set --prop-name cx_client_secret --prop-value "$CX_CLIENT_SECRET_EU"
    ./cx configure set --prop-name cx_tenant --prop-value "$CX_TENANT"
    
    if ./cx auth validate; then
        echo -e "${GREEN}✓ Authentication successful${NC}"
    else
        echo -e "${RED}✗ Authentication failed${NC}"
        exit 1
    fi
}

# Upload SARIF file
upload_sarif() {
    local project_name="${1:-upload-sarif-action-test}"
    local sarif_file="${2:-test-local.sarif}"
    
    echo -e "${YELLOW}Uploading SARIF file to Checkmarx...${NC}"
    echo "  Project: $project_name"
    echo "  File: $sarif_file"
    
    if ./cx utils import \
        --project-name "$project_name" \
        --file "$sarif_file" \
        --base-uri "https://eu-2.ast.checkmarx.net/" \
        --client-id "$CX_CLIENT_ID" \
        --client-secret "$CX_CLIENT_SECRET_EU" \
        --tenant "$CX_TENANT"; then
        echo -e "${GREEN}✓ SARIF file successfully uploaded to Checkmarx${NC}"
        echo "  Check your Checkmarx dashboard for project: $project_name"
    else
        echo -e "${RED}✗ Failed to upload SARIF file${NC}"
        exit 1
    fi
}

# Cleanup
cleanup() {
    echo -e "${YELLOW}Cleaning up...${NC}"
    rm -f cx-cli.tar.gz
    ./cx configure clear || true
    echo -e "${GREEN}✓ Cleanup complete${NC}"
}

# Main execution
main() {
    echo ""
    
    # Parse arguments
    PROJECT_NAME="${1:-upload-sarif-action-test-$(date +%s)}"
    SARIF_FILE="${2:-}"
    
    # Check environment variables
    check_env_vars
    
    # If no SARIF file provided, create test one
    if [ -z "$SARIF_FILE" ]; then
        create_test_sarif
        SARIF_FILE="test-local.sarif"
    else
        if [ ! -f "$SARIF_FILE" ]; then
            echo -e "${RED}Error: SARIF file not found: $SARIF_FILE${NC}"
            exit 1
        fi
        echo -e "${GREEN}Using provided SARIF file: $SARIF_FILE${NC}"
    fi
    
    # Install CLI
    install_cx_cli
    
    # Test authentication
    test_auth
    
    # Upload SARIF
    upload_sarif "$PROJECT_NAME" "$SARIF_FILE"
    
    # Cleanup
    cleanup
    
    echo ""
    echo -e "${GREEN}==================================="
    echo "Local test completed successfully!"
    echo "===================================${NC}"
}

# Handle Ctrl+C
trap cleanup INT

# Show usage if --help
if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    echo "Usage: $0 [project-name] [sarif-file]"
    echo ""
    echo "Test the SARIF upload to Checkmarx locally."
    echo ""
    echo "Arguments:"
    echo "  project-name  Name for the Checkmarx project (default: upload-sarif-action-test-<timestamp>)"
    echo "  sarif-file    Path to SARIF file to upload (default: creates test file)"
    echo ""
    echo "Environment variables required:"
    echo "  CX_CLIENT_ID       Checkmarx OAuth2 client ID"
    echo "  CX_CLIENT_SECRET_EU Checkmarx OAuth2 client secret"
    echo "  CX_TENANT          Checkmarx tenant"
    echo ""
    echo "Examples:"
    echo "  # Test with auto-generated SARIF"
    echo "  export CX_CLIENT_ID='your-id' CX_CLIENT_SECRET_EU='your-secret' CX_TENANT='your-tenant'"
    echo "  $0"
    echo ""
    echo "  # Test with specific SARIF file"
    echo "  $0 my-project cargo-audit.sarif"
    echo ""
    echo "  # Test with cargo-audit"
    echo "  cargo audit --format sarif > audit.sarif"
    echo "  $0 rust-test audit.sarif"
    exit 0
fi

# Run main function
main "$@"