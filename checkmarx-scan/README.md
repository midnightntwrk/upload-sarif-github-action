# Checkmarx Full Scan Action

Complete Checkmarx scanning with SARIF upload to both GitHub Security and Checkmarx BYOR.

## Use Cases

- **Private repositories** where contributors are trusted
- **Regular PRs** (not fork PRs) where workflow testing is needed
- Teams that want to **test workflow changes in PRs** before merging

## Features

- Full Checkmarx scanning (SAST, SCA, KICS, SCS/Scorecard)
- Service health checks (skips scan during outages to avoid blocking builds)
- Automatic SARIF fixing for GitHub compatibility
- Dual upload: GitHub Security Code Scanning + Checkmarx portal (BYOR)
- Works with `pull_request` event

## Usage

```yaml
name: Checkmarx Security Scan

on:
  pull_request:
    branches: [ '**' ]
  push:
    branches: [ 'main' ]

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  checkmarx:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      # While upload-sarif-github-action is private:
      - name: Checkout action repository
        uses: actions/checkout@v4
        with:
          repository: midnightntwrk/upload-sarif-github-action
          ref: main
          path: upload-sarif-github-action
          token: ${{ secrets.MIDNIGHTCI_REPO }}

      - name: Checkmarx Full Scan
        uses: ./upload-sarif-github-action/checkmarx-scan
        with:
          cx-client-id: ${{ secrets.CX_CLIENT_ID }}
          cx-client-secret: ${{ secrets.CX_CLIENT_SECRET_EU }}
          cx-tenant: ${{ secrets.CX_TENANT }}
          scs-repo-token: ${{ secrets.MIDNIGHTCI_REPO }}

      # Once public, simplify to:
      # - name: Checkmarx Full Scan
      #   uses: midnightntwrk/upload-sarif-github-action/checkmarx-scan@main
      #   with:
      #     cx-client-id: ${{ secrets.CX_CLIENT_ID }}
      #     cx-client-secret: ${{ secrets.CX_CLIENT_SECRET_EU }}
      #     cx-tenant: ${{ secrets.CX_TENANT }}
      #     scs-repo-token: ${{ secrets.MIDNIGHTCI_REPO }}
```

## Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `project-name` | No | Repository name | Checkmarx project name |
| `cx-client-id` | Yes | - | Checkmarx OAuth2 client ID |
| `cx-client-secret` | Yes | - | Checkmarx OAuth2 client secret |
| `cx-tenant` | Yes | - | Checkmarx tenant |
| `base-uri` | No | `https://eu-2.ast.checkmarx.net/` | Checkmarx server URL |
| `scs-repo-token` | Yes | - | GitHub token for SCS/Scorecard scanning |
| `additional-params` | No | - | Additional scan parameters |
| `upload-to-github` | No | `true` | Upload SARIF to GitHub Security (auto-disabled for private repos) |
| `upload-to-checkmarx` | No | `true` | Upload SARIF to Checkmarx via BYOR |

## How It Works

1. **Health Check**: Verifies Checkmarx services are available (skips scan during outages)
2. **Checkout**: Code is checked out locally (requires trusted contributors)
3. **Scan**: Uses official Checkmarx action to scan code
4. **Fix SARIF**: Fixes common SARIF issues for GitHub compatibility
5. **Upload**: Results sent to both GitHub Security and Checkmarx portal

## Health Checks

The action checks Checkmarx service availability before scanning:
- EU2 status page check
- IND server health check

If services are down, the scan is skipped to avoid blocking builds.

## Private vs Public Repos

**For Private Repos (this action):**
- Use `pull_request` event
- Code checkout is safe (contributors are trusted)
- Can test workflow changes in PRs

**For Public Repos (fork PRs):**
- Use `checkmarx-scan-public` instead
- Fork PRs need `pull_request_target` + no checkout
- See [checkmarx-scan-public](../checkmarx-scan-public/README.md)

## Outputs

| Name | Description |
|------|-------------|
| `scan-id` | Checkmarx scan ID |
| `sarif-file` | Path to generated SARIF file (`cx_result.sarif`) |

## Troubleshooting

**Scan fails immediately:**
- Check Checkmarx service health (action will skip if down)
- Verify secrets are properly configured

**Results not appearing in Checkmarx portal:**
- Ensure `upload-to-checkmarx: 'true'` is set
- Check BYOR permissions in Checkmarx

**Results not in GitHub Security:**
- Verify repository is public (auto-disabled for private repos)
- Ensure `security-events: write` permission is granted
