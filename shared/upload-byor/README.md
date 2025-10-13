# Upload SARIF to Checkmarx BYOR

Shared composite action that uploads SARIF results to Checkmarx portal via BYOR (Bring Your Own Results).

## Purpose

This action wraps the root SARIF upload action to provide a consistent interface for both `checkmarx-scan` and `checkmarx-scan-public` actions to upload results to the Checkmarx portal.

## Usage

```yaml
- name: Upload SARIF to Checkmarx BYOR
  if: ${{ inputs.upload-to-checkmarx == 'true' }}
  uses: ./upload-sarif-github-action/shared/upload-byor
  with:
    sarif-file: cx_result.sarif
    project-name: ${{ github.repository }}
    cx-client-id: ${{ secrets.CX_CLIENT_ID }}
    cx-client-secret: ${{ secrets.CX_CLIENT_SECRET_EU }}
    cx-tenant: ${{ secrets.CX_TENANT }}
```

## Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `sarif-file` | No | `cx_result.sarif` | Path to SARIF file to upload |
| `project-name` | Yes | - | Checkmarx project name |
| `cx-client-id` | Yes | - | Checkmarx OAuth2 client ID |
| `cx-client-secret` | Yes | - | Checkmarx OAuth2 client secret |
| `cx-tenant` | Yes | - | Checkmarx tenant |
| `base-uri` | No | `https://eu-2.ast.checkmarx.net/` | Checkmarx server URL |

## Outputs

| Name | Description |
|------|-------------|
| `upload-status` | Status of the SARIF upload (`success` or `failed`) |

## What It Does

1. **Checks file existence**: Verifies SARIF file exists before attempting upload
2. **Calls root action**: Invokes the root BYOR upload action (action.yml at repo root)
3. **Continues on error**: Upload failures don't block the workflow

## Used By

- `checkmarx-scan` action
- `checkmarx-scan-public` action

## Why This Exists

This wrapper provides:
- **Consistency**: Both scan actions use the same upload mechanism
- **Maintainability**: Changes to upload logic only need to happen in one place
- **Clarity**: Makes it explicit that both actions perform BYOR upload

## Requirements

- Valid Checkmarx account with BYOR permissions
- OAuth2 credentials (client ID and secret)
- SARIF file must be under 10MB
- Maximum 25,000 results per upload (top 5,000 persisted by Checkmarx)

## Related

- Root BYOR action: [action.yml](../../action.yml)
- Checkmarx BYOR documentation: https://docs.checkmarx.com/en/34965-230340-bring-your-own-results--byor-.html
