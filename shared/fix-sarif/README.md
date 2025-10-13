# Fix SARIF for GitHub Compatibility

Shared composite action that fixes common SARIF issues preventing GitHub Code Scanning upload.

## Purpose

This action addresses two common SARIF issues that cause GitHub's CodeQL Action to reject uploads:

1. **Empty URIs**: GitHub fails if `artifactLocation.uri` is empty
2. **Missing message text**: Newer codeql-action versions require non-empty `message.text`

## Usage

```yaml
- name: Fix SARIF for GitHub compatibility
  uses: ./upload-sarif-github-action/shared/fix-sarif
  with:
    sarif-file: cx_result.sarif
```

## Inputs

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `sarif-file` | No | `cx_result.sarif` | Path to SARIF file to fix |

## Outputs

| Name | Description |
|------|-------------|
| `fixed` | Whether SARIF was successfully fixed (`true`/`false`) |

## What It Does

1. **Installs jq** if not available (for JSON manipulation)
2. **Fixes empty URIs**: Replaces empty `artifactLocation.uri` with `file:/README.md`
3. **Fixes missing messages**: Sets `message.text` to `"Security issue detected by {ruleId}"` if empty
4. **Cleans up**: Removes temporary files

## Example SARIF Fixes

**Before (Empty URI):**
```json
{
  "locations": [{
    "physicalLocation": {
      "artifactLocation": {
        "uri": ""
      }
    }
  }]
}
```

**After:**
```json
{
  "locations": [{
    "physicalLocation": {
      "artifactLocation": {
        "uri": "file:/README.md"
      }
    }
  }]
}
```

**Before (Missing message):**
```json
{
  "ruleId": "CWE-89",
  "message": {
    "text": null
  }
}
```

**After:**
```json
{
  "ruleId": "CWE-89",
  "message": {
    "text": "Security issue detected by CWE-89"
  }
}
```

## Used By

- `checkmarx-scan` action
- `checkmarx-scan-public` action
- Any workflow processing Checkmarx SARIF output

## Requirements

- Works on Linux (Ubuntu) and macOS runners
- Automatically installs `jq` if not present
