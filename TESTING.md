# Testing Guide

This document describes how to test the SARIF upload action locally before using it in production.

## Prerequisites

You'll need:
- Checkmarx credentials (OAuth2 client ID, secret, and tenant)
- Access to a Checkmarx account with BYOR permissions
- (Optional) `act` tool for running GitHub Actions locally
- (Optional) `cargo-audit` for testing with real Rust vulnerabilities

## Method 1: Direct CLI Testing (Recommended)

The simplest way to test the SARIF upload functionality:

### Quick Test

```bash
# Set your credentials
export CX_CLIENT_ID='your-client-id'
export CX_CLIENT_SECRET_EU='your-client-secret'
export CX_TENANT='your-tenant'

# Run the test script
./test-local.sh
```

This will:
1. Create a test SARIF file
2. Install the Checkmarx CLI
3. Authenticate with Checkmarx
4. Upload the SARIF file
5. Clean up

### Test with cargo-audit

```bash
# Generate real SARIF from cargo-audit
cargo audit --format sarif > cargo-audit.sarif

# Upload it
./test-local.sh my-rust-project cargo-audit.sarif
```

### Test with Custom SARIF

```bash
# Use your own SARIF file
./test-local.sh my-project path/to/your.sarif
```

## Method 2: Using act (GitHub Actions Emulator)

[act](https://github.com/nektos/act) lets you run GitHub Actions locally:

### Install act

```bash
# macOS
brew install act

# Linux
curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash
```

### Run the Test Workflow

```bash
# Run with your credentials
act -W .github/workflows/local-test.yaml \
    -s CX_CLIENT_ID='your-client-id' \
    -s CX_CLIENT_SECRET_EU='your-client-secret' \
    -s CX_TENANT='your-tenant'
```

### Test the Main Action

```bash
# Test the full test suite
act -W .github/workflows/test-action.yaml \
    -s CX_CLIENT_ID='your-client-id' \
    -s CX_CLIENT_SECRET_EU='your-client-secret' \
    -s CX_TENANT='your-tenant'
```

## Method 3: Manual CLI Testing

Test the raw commands directly:

```bash
# 1. Download Checkmarx CLI
curl -L -o cx-cli.tar.gz \
  "https://github.com/Checkmarx/ast-cli/releases/download/2.8.2/ast-cli_2.8.2_darwin_arm64.tar.gz"
tar -xzf cx-cli.tar.gz
chmod +x cx

# 2. Configure authentication
./cx configure set --prop-name cx_base_uri --prop-value "https://eu-2.ast.checkmarx.net/"
./cx configure set --prop-name cx_client_id --prop-value "your-client-id"
./cx configure set --prop-name cx_client_secret --prop-value "your-client-secret"
./cx configure set --prop-name cx_tenant --prop-value "your-tenant"

# 3. Validate authentication
./cx auth validate

# 4. Upload SARIF
./cx utils import \
  --project-name "test-project" \
  --file "path/to/sarif.sarif" \
  --base-uri "https://eu-2.ast.checkmarx.net/" \
  --client-id "your-client-id" \
  --client-secret "your-client-secret" \
  --tenant "your-tenant"
```

## Method 4: Using Docker

Create a test container environment:

```bash
# Create test Dockerfile
cat > Dockerfile.test << 'EOF'
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl jq
WORKDIR /test
COPY . .
EOF

# Build and run
docker build -f Dockerfile.test -t sarif-test .
docker run -it \
  -e CX_CLIENT_ID='your-client-id' \
  -e CX_CLIENT_SECRET_EU='your-client-secret' \
  -e CX_TENANT='your-tenant' \
  sarif-test ./test-local.sh
```

## Creating Test SARIF Files

### Minimal Valid SARIF

```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "test-tool",
          "version": "1.0.0"
        }
      },
      "results": []
    }
  ]
}
```

### SARIF with Vulnerabilities

```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "test-scanner",
          "version": "1.0.0",
          "rules": [
            {
              "id": "VULN001",
              "name": "TestVulnerability",
              "shortDescription": {
                "text": "Test vulnerability for validation"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "VULN001",
          "message": {
            "text": "Test vulnerability found"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "src/main.rs"
                },
                "region": {
                  "startLine": 10
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

## Verifying the Upload

After uploading, verify success by:

1. **Check Checkmarx Dashboard**
   - Log into https://eu-2.ast.checkmarx.net/
   - Navigate to your project
   - Check the "Results" or "BYOR" section

2. **Check CLI Output**
   - Look for success messages
   - Note any project IDs returned

3. **Use CLI to Query**
   ```bash
   ./cx project show --project-name "your-project-name"
   ```

## Troubleshooting

### Authentication Issues

```bash
# Test authentication separately
./cx auth validate

# Check stored config
./cx configure show

# Clear and retry
./cx configure clear
```

### SARIF Validation

```bash
# Validate SARIF format
jq . your-file.sarif > /dev/null && echo "Valid JSON"

# Check SARIF version
jq .version your-file.sarif  # Should be "2.1.0"
```

### File Size Issues

```bash
# Check file size (must be < 10MB)
ls -lh your-file.sarif

# Compress if needed
jq -c . your-file.sarif > compressed.sarif
```

## Environment Variables

Create a `.env` file for easier testing:

```bash
# .env
CX_CLIENT_ID=your-client-id
CX_CLIENT_SECRET_EU=your-client-secret
CX_TENANT=your-tenant

# Optional
CX_BASE_URI=https://eu-2.ast.checkmarx.net/
CX_PROJECT_NAME=test-project
```

Then use:
```bash
source .env && ./test-local.sh
```

## CI/CD Testing

Before deploying, test in a CI environment:

```yaml
# .github/workflows/test-pr.yaml
name: Test PR
on:
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Test action
        uses: ./
        with:
          sarif-file: test-fixtures/sample.sarif
          project-name: pr-test-${{ github.event.pull_request.number }}
          cx-client-id: ${{ secrets.CX_CLIENT_ID }}
          cx-client-secret: ${{ secrets.CX_CLIENT_SECRET_EU }}
          cx-tenant: ${{ secrets.CX_TENANT }}
```

## Security Notes

- Never commit credentials to the repository
- Use GitHub Secrets for CI/CD
- Clear credentials after local testing: `./cx configure clear`
- Use read-only credentials for testing when possible

## Support

For issues with:
- **This action**: Create an issue in this repository
- **Checkmarx CLI**: See [Checkmarx documentation](https://docs.checkmarx.com/)
- **SARIF format**: See [SARIF specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)