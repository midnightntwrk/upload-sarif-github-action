# Security Scan GitHub Action

Runs open source security scanners and uploads SARIF results
to GitHub Security (public repos) or as artifacts (private
repos).

## Scanners

- **OpenGrep** - SAST (taint analysis, dataflow tracing)
- **Checkov** - Infrastructure-as-Code misconfiguration (via EarthBuild)
- ~~**KICS**~~ - Disabled: [supply chain compromise](https://www.wiz.io/blog/teampcp-attack-kics-github-action) of checkmarx/kics-github-action (2026-03-23)
- **Trivy** - Vulnerability scan (hash-pinned binary, not the GitHub action)
- **[gitleaks]** - Secret scanning (working tree)
- **Scorecard** - Supply chain security
- **[zizmor]** - GitHub Actions static analysis (run offline)

Each scanner can be skipped individually via a
`skip_<scanner>_scan` input.

[zizmor]: https://github.com/zizmorcore/zizmor
[gitleaks]: https://github.com/gitleaks/gitleaks

## Usage

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write
      statuses: write

    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  #v4.2.2

      - name: Run Security Scan
        uses: midnightntwrk/upload-sarif-github-action@main
        with:
          fail_severity: 'high'
```

## Inputs

All inputs are optional.

| Input                 | Description                     | Default    |
| --------------------- | ------------------------------- | ---------- |
| `fail_severity`       | Min severity to fail CI         | `critical` |
| `scorecard_checks`    | Scorecard checks to run (CSV)   | all checks |
| `skip_opengrep_scan`  | `true` skips OpenGrep (SAST)    | `false`    |
| `skip_scorecard_scan` | `true` skips Scorecard          | `false`    |
| `skip_checkov_scan`   | `true` skips Checkov (IaC)      | `false`    |
| `skip_zizmor_scan`    | `true` skips zizmor (Actions)   | `false`    |
| `skip_trivy_scan`     | `true` skips Trivy (vulns)      | `false`    |
| `skip_gitleaks_scan`  | `true` skips gitleaks (secrets) | `false`    |

`fail_severity` accepts: critical, high, medium.
Must be set on private repos.

Skipping every scanner makes the action fail — the
"Verify scan output" step requires at least one SARIF file.

## How it works

1. Installs [EarthBuild](https://github.com/EarthBuild/earthbuild)
   (hash-verified)
2. Runs all scanners **in parallel** inside isolated containers
   via `earth +scan` — no scanner has access to runner secrets
3. Collects SARIF results in `scan_reports/`
4. Uploads to GitHub Security tab (public repos) or as
   build artifacts (private repos)
5. Optionally fails the build if findings meet or exceed
   the configured severity threshold

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

Apache 2.0 - See [LICENSE](LICENSE).
