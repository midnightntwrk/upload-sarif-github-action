# Checkmarx GitHub Actions

This repository provides two GitHub Actions for Checkmarx integration:

1. **SARIF Upload Action** (`action.yml`) - Uploads SARIF files to Checkmarx via BYOR (Bring Your Own Results)
2. **Full Scan Action** (`checkmarx-scan/action.yml`) - Complete Checkmarx scan with automatic SARIF upload to both GitHub Security and Checkmarx

## Purpose

Checkmarx has limited native support for Rust security scanning. This action bridges that gap by allowing you to upload SARIF files from Rust security tools (or any other SARIF-producing tools) directly to Checkmarx, making vulnerabilities visible in your Checkmarx dashboard alongside results from other languages.

## Features

- Upload SARIF files to Checkmarx via BYOR
- Uses same authentication as official Checkmarx action
- Validates SARIF file size (10MB limit)
- Simple, focused implementation
- Reusable across all Midnight repositories

## Actions Overview

### 1. SARIF Upload Action (BYOR Only)

Use this when you have existing SARIF files (e.g., from cargo-audit) that you want to upload to Checkmarx.

### 2. Full Scan Action (Complete Checkmarx Workflow)

Use this to replace the entire Checkmarx workflow - it performs a full scan and uploads results to both GitHub Security and Checkmarx.

## Usage

> **Note for Private Repository**: If this action repository is private, you'll need to check it out first before using it. See the examples below for the workaround. Once the repository is made public, the simpler syntax can be used.

### SARIF Upload Action - Basic Example

```yaml
- name: Run cargo audit
  run: cargo audit --format sarif > scan.sarif || true

- name: Upload SARIF to Checkmarx
  uses: midnightntwrk/upload-sarif-github-action@main
  with:
    sarif-file: scan.sarif
    project-name: ${{ github.event.repository.name }}
    cx-client-id: ${{ secrets.CX_CLIENT_ID }}
    cx-client-secret: ${{ secrets.CX_CLIENT_SECRET_EU }}
    cx-tenant: ${{ secrets.CX_TENANT }}
```

### Full Scan Action - Example

This replaces the entire checkmarx.yaml workflow:

```yaml
name: Checkmarx Security Scan

on:
  pull_request:
    branches: [ '**' ]
  push:
    branches: [ 'main' ]

jobs:
  checkmarx-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      security-events: write
    
    steps:
      - uses: actions/checkout@v4
      
      # If this repo is private, add this checkout step:
      # - name: Checkout Upload action repository
      #   uses: actions/checkout@v4
      #   with:
      #     repository: midnightntwrk/upload-sarif-github-action
      #     ref: main
      #     path: upload-sarif-github-action
      #     token: ${{ secrets.MIDNIGHTCI_REPO }}
      
      - name: Checkmarx Full Scan
        uses: midnightntwrk/upload-sarif-github-action/checkmarx-scan@main
        # If private repo, use: ./upload-sarif-github-action/checkmarx-scan
        with:
          cx-client-id: ${{ secrets.CX_CLIENT_ID }}
          cx-client-secret: ${{ secrets.CX_CLIENT_SECRET_EU }}
          cx-tenant: ${{ secrets.CX_TENANT }}
          scs-repo-token: ${{ secrets.MIDNIGHTCI_REPO }}
```

### Complete Workflow Example (SARIF Upload Only)

```yaml
name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  rust-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install cargo-audit
        run: cargo install cargo-audit
      
      - name: Run cargo audit
        run: cargo audit --format sarif > scan.sarif || true
      
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scan.sarif
      
      - name: Upload SARIF to Checkmarx
        uses: midnightntwrk/upload-sarif-github-action@main
        with:
          sarif-file: scan.sarif
          project-name: ${{ github.event.repository.name }}
          cx-client-id: ${{ secrets.CX_CLIENT_ID }}
          cx-client-secret: ${{ secrets.CX_CLIENT_SECRET_EU }}
          cx-tenant: ${{ secrets.CX_TENANT }}
```

## Inputs

### SARIF Upload Action Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `sarif-file` | Path to SARIF file to upload | **Yes** | - |
| `project-name` | Checkmarx project name | **Yes** | - |
| `cx-client-id` | Checkmarx OAuth2 client ID | **Yes** | - |
| `cx-client-secret` | Checkmarx OAuth2 client secret | **Yes** | - |
| `cx-tenant` | Checkmarx tenant | **Yes** | - |
| `base-uri` | Checkmarx server URL | No | `https://eu-2.ast.checkmarx.net/` |
| `branch` | Branch name (for future multi-branch support) | No | Current branch |
| `additional-params` | Additional CLI parameters for cx utils import | No | - |

### Full Scan Action Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `project-name` | Checkmarx project name | No | Repository name |
| `cx-client-id` | Checkmarx OAuth2 client ID | **Yes** | - |
| `cx-client-secret` | Checkmarx OAuth2 client secret | **Yes** | - |
| `cx-tenant` | Checkmarx tenant | **Yes** | - |
| `base-uri` | Checkmarx server URL | No | `https://eu-2.ast.checkmarx.net/` |
| `scs-repo-token` | GitHub token for SCS scanning | **Yes** | - |
| `additional-params` | Additional parameters for scan | No | - |
| `upload-to-github` | Upload to GitHub Security | No | `true` (auto-disabled for private repos) |
| `upload-to-checkmarx` | Upload to Checkmarx BYOR | No | `true` |

## Outputs

| Output | Description |
|--------|-------------|
| `upload-status` | Status of the SARIF upload (`success` or `failed`) |
| `project-id` | Checkmarx project ID (if available) |

## Requirements

### SARIF File Requirements
- **Format**: SARIF 2.1.0
- **Max Size**: 10 MB
- **Max Results**: 25,000 per run (top 5,000 will be persisted)

### Checkmarx Requirements
- Valid Checkmarx account with BYOR permissions
- OAuth2 credentials (client ID and secret)
- Tenant information

### GitHub Secrets Setup

Add these secrets to your repository:
- `CX_CLIENT_ID` - Your Checkmarx OAuth2 client ID
- `CX_CLIENT_SECRET_EU` - Your Checkmarx OAuth2 client secret (EU region)
- `CX_TENANT` - Your Checkmarx tenant name
- `MIDNIGHTCI_REPO` - GitHub token for SCS scanning (used by Full Scan action)

The first three are the same secrets used by the standard Checkmarx scanning action.

## Supported Tools

Any tool that generates SARIF 2.1.0 format, including:
- **cargo-audit** - Rust vulnerability scanner (primary use case)
- **trivy** - Container and filesystem scanner
- **semgrep** - Static analysis tool
- **snyk** - Dependency vulnerability scanner
- Any other SARIF-producing security tool

## How it Works

1. **Validates** the SARIF file exists and is within size limits
2. **Installs** the Checkmarx CLI tool appropriate for the runner OS/architecture
3. **Authenticates** with Checkmarx using OAuth2 credentials
4. **Transforms** SARIF if needed (adds `tool.name` at top level for Checkmarx compatibility)
5. **Uploads** the SARIF file using the `cx utils import` command
6. **Cleans up** credentials and temporary files

## Limitations

- SARIF files must be under 10MB
- Maximum 25,000 results per upload (top 5,000 persisted by Checkmarx)
- Currently supports main branch only (multi-branch support planned)
- Requires Checkmarx BYOR feature access

## Troubleshooting

### SARIF file not found
Ensure the SARIF file is generated before calling this action. Use `|| true` after generation commands to prevent workflow failure if no issues are found.

### Authentication failures
Verify that:
- Secrets are correctly configured
- Client has BYOR permissions in Checkmarx
- Base URI matches your Checkmarx region

### File size exceeded
If your SARIF file exceeds 10MB:
- Consider filtering results before upload
- Split into multiple smaller files
- Focus on high/critical severity issues only

## Development

### Testing Locally

```bash
# Generate test SARIF file
cargo audit --format sarif > test.sarif

# Test the action
act -s CX_CLIENT_ID=xxx -s CX_CLIENT_SECRET_EU=xxx -s CX_TENANT=xxx
```

### Future Enhancements (Roadmap)

**Phase 2 - Enhanced Upload**
- Combined upload to both GitHub Security and Checkmarx
- Automatic fixing of empty URIs that GitHub rejects
- Cleaner workflow integration

**Phase 3 - Multi-branch Support**
- Support for release branches
- Branch-specific project naming
- Parallel branch scanning

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on contributing to this project.

## Security

For security concerns, please see [SECURITY.md](SECURITY.md).

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## Credits

Created by the Midnight security team to enhance Rust security visibility in Checkmarx.

Special thanks to the Rust security ecosystem, particularly the `cargo-audit` team for SARIF support.

## Support

For issues or questions:
- Create an issue in this repository
- Contact the Midnight security team
- See [Checkmarx BYOR Documentation](https://docs.checkmarx.com/en/34965-230340-bring-your-own-results--byor-.html)