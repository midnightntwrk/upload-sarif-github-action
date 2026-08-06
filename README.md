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
| `differential_gate`   | `true` compares against target  | `false`    |
| `scorecard_checks`    | Scorecard checks to run (CSV)   | all checks |
| `skip_opengrep_scan`  | `true` skips OpenGrep (SAST)    | `false`    |
| `skip_scorecard_scan` | `true` skips Scorecard          | `false`    |
| `skip_checkov_scan`   | `true` skips Checkov (IaC)      | `false`    |
| `skip_zizmor_scan`    | `true` skips zizmor (Actions)   | `false`    |
| `skip_trivy_scan`     | `true` skips Trivy (vulns)      | `false`    |
| `skip_gitleaks_scan`  | `true` skips gitleaks (secrets) | `false`    |

`fail_severity` accepts: critical, high, medium, low,
warning, note. Must be set on private repos.

### Severity resolution

Read in order: `result.level`, `properties.severity`, the
rule's `defaultConfiguration.level`, then `warning` — the
SARIF default for a result specifying none
([SARIF 3.27.10][sarif]). A severity outside the known set
(Trivy `UNKNOWN`, SARIF `none`) is annotated and not gated.

gitleaks emits no severity, so secret findings resolve to
`warning`. **To fail the build on secrets, set
`fail_severity: warning`.** At `critical` (the default),
`high` or `medium`, a committed private key is reported to
the Security tab but does not fail the build.

[sarif]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317648

## Differential gate

By default the gate is absolute: any finding at or above
`fail_severity` fails the build. That makes two PRs which
each fix one of two outstanding vulnerabilities individually
unmergeable — neither is sufficient on its own, so the only
way through is a combined PR.

Set `differential_gate: true` and, **when the absolute gate
fails**, the action re-scans the PR's target branch in the
same job and passes if the PR strictly reduces the finding
count:

```text
pass iff count(PR merged into target) < count(target)
```

| Case                                  | Result  |
| ------------------------------------- | ------- |
| fixes one of two findings             | passes  |
| introduces a finding                  | blocked |
| swaps one finding for another         | blocked |
| unrelated PR, findings outstanding    | blocked |
| removes two findings, introduces one  | passes  |

The last two are deliberate. While something is outstanding
only changes that reduce the count land; and the count is the
whole contract, so no fingerprinting is needed.

Notes:

- Costs nothing on a green PR — the second scan runs only
  when the first gate fails.
- Both scans run in one job, so scanner binaries and the
  Trivy database fetch are identical. A cached base scan
  would drift as the database updates and report phantom
  findings.
- `pull_request` only; pushes and scheduled runs use the
  absolute gate, so `main` reports the true total.
- Needs the target commit fetchable — pass `github_token`
  for a private repo or `persist-credentials: false`.
- Base-branch results are **not** uploaded to the Security
  tab.

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
