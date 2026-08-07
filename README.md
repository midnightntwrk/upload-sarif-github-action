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

One ladder, `CRITICAL` at the top:

```text
INFO 0 · LOW 1 · MEDIUM 2 · HIGH 3 · CRITICAL 4
```

A severity the tool *states* is used as-is —
`properties.severity`, then a severity named in the rule's
`properties.tags`. Only when neither exists is SARIF `level`
read, and then it is calibrated per tool.

`level` is a reporting level (`none`/`note`/`warning`/
`error`), not an impact, and it tops out at `error`
([SARIF 3.27.10][sarif]). Read straight through, every tool
that speaks only `level` is capped below `CRITICAL` and the
default threshold gates almost nothing — a Trivy CRITICAL CVE
resolved to `ERROR` and passed.

`ERROR` is therefore no longer a severity. It stays accepted
as a `fail_severity` value, where it means the same as
`high`.

### Per-tool calibration

The ceiling differs by what each tool is in a position to
claim.

| Tool | Signal | Mapping | Ceiling |
| --------- | -------------------- | ---------------------------------------------------------- | -------- |
| gitleaks | none | stamped `CRITICAL` | CRITICAL |
| trivy | rule tag + CVSS | used as stated | CRITICAL |
| opengrep | level × confidence | `error`+high → CRITICAL, +medium → HIGH, +low → MEDIUM; `warning` → LOW | CRITICAL |
| zizmor | per-finding level | `error` → CRITICAL, `warning` → MEDIUM, `note` → LOW | CRITICAL |
| scorecard | a score out of ten | `error` → HIGH, `warning` → MEDIUM | HIGH |
| others | level only | `error` → HIGH, `warning` → MEDIUM, `note` → LOW | HIGH |

**opengrep needs the confidence tag.** `error` alone covers
310 of its rules — including ones opengrep itself marks `LOW
CONFIDENCE`, such as `detect-child-process`. The pair is the
signal; the level alone is not.

**zizmor grades each finding, not each rule.**
`template-injection` lands at `error` 47 times and `note` 23
times on one real repository, so its own grading is kept and
its `error` is treated as exploitable.

**scorecard never reaches CRITICAL** — a score out of ten is
not a vulnerability. Its `SAST` and `Fuzzing` checks are not
reported at all: this action *is* the static analyser, so a
failing SAST score states something untrue, and Fuzzing
scores a practice this action cannot observe.

A severity outside the known set (Trivy `UNKNOWN`, SARIF
`none`) is annotated and not gated.

### Secrets always fail the build

A committed secret fails the build at **every** `fail_severity`,
including the `critical` default. gitleaks assigns no severity
of its own, so the action stamps its findings `CRITICAL`
before they reach the gate — a leaked credential is not a
point on a severity scale.

Rotate the credential first; it is in the repository, so
treat it as compromised. To exclude a false positive or a
deliberate fixture, gitleaks has two mechanisms and only one
of them takes a path:

**A path or a whole directory** — `.gitleaks.toml` in the
repository root:

```toml
[extend]
useDefault = true

[[allowlists]]
description = "test fixtures"
paths = ['''^tests/fixtures/''']
```

**One specific finding** — `.gitleaksignore` in the
repository root, one fingerprint per line:

```text
vendor/id_rsa:private-key:1
```

The build failure prints the exact fingerprint lines for the
findings it saw, so they can be pasted straight in, and links
back to this section plus the gitleaks reference for
[path allowlists][gl-config] and [`.gitleaksignore`][gl-ignore].

Both mechanisms are exercised end to end in
`tests/integration.sh`, the `.gitleaksignore` one using the
same line the failure message offers — so the advice cannot
rot while the tests stay green.

[gl-config]: https://github.com/gitleaks/gitleaks#configuration
[gl-ignore]: https://github.com/gitleaks/gitleaks#gitleaksignore

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
