# Checkmarx Service Health Check

Shared composite action that checks Checkmarx service availability to avoid blocking builds during outages.

## Purpose

Prevents CI/CD pipelines from failing when Checkmarx services are experiencing downtime or maintenance.

## Usage

```yaml
- name: Check Checkmarx service health
  id: health
  uses: ./upload-sarif-github-action/shared/health-check

- name: Run scan only if healthy
  if: steps.health.outputs.skip-scan != 'true'
  run: |
    # Your scan commands here
```

## Outputs

| Name | Description |
|------|-------------|
| `healthy` | Whether Checkmarx services are healthy (`true`/`false`) |
| `skip-scan` | Whether to skip Checkmarx scan (`true`/`false`) |

## Environment Variables

For backward compatibility, sets `SKIP_CHECKMARX=true` when services are unavailable.

## What It Checks

1. **Checkmarx EU2 Status Page**
   - URL: `https://eu2-status.ast.checkmarx.net/`
   - Looks for "Operating Normally" text
   - Issues warning if not found

2. **Checkmarx IND Server Health**
   - URL: `https://ind-status.ast.checkmarx.net/`
   - Expects HTTP 200 response
   - Issues warning if unavailable

## Behavior

**When services are healthy:**
```
✅ Checkmarx EU2 status: Operating Normally
✅ Checkmarx IND server: Healthy (HTTP 200)
```
- `outputs.healthy = true`
- `outputs.skip-scan = false`

**When services are down:**
```
⚠️  Checkmarx EU2 may be experiencing issues
⚠️  Checkmarx IND server returned: HTTP 503
::warning::Checkmarx services may be unavailable
ℹ️  Consider skipping scan to avoid blocking builds
```
- `outputs.healthy = false`
- `outputs.skip-scan = true`
- `SKIP_CHECKMARX=true` (env var)

## Example Usage

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Check Checkmarx health
        id: health
        uses: ./upload-sarif-github-action/shared/health-check

      - name: Notify if skipping
        if: steps.health.outputs.skip-scan == 'true'
        run: |
          echo "::warning::Skipping Checkmarx scan due to service issues"
          echo "Build will continue without security scan"

      - name: Run Checkmarx scan
        if: steps.health.outputs.skip-scan != 'true'
        run: |
          # Scan commands here
```

## Used By

- `checkmarx-scan` action
- `checkmarx-scan-public` action

## Philosophy

**Fail Open, Not Closed:**
- Security scans should not block development when the scanning service is down
- Better to skip a scan and continue building than to halt all development
- Provides visibility via warnings so teams are aware scans were skipped

## Monitoring

Teams should monitor for `SKIP_CHECKMARX` warnings in CI logs to ensure scans aren't being skipped frequently.
