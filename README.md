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
| `scorecard_checks`    | Scorecard checks to run (CSV)   | see below  |
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
not a vulnerability. Its checks are an enumerated allowlist
(`--checks` has no exclude counterpart): everything it answers
from a local checkout, less `SAST` (this action *is* the static
analyser), `Fuzzing` (unobservable here) and `Packaging` (greps
for known publish commands, so a tag-only action release reads
as no packaging at all). The list is in `+scorecard`;
`scorecard_checks` replaces it with locally-answerable names.

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

### Tuning checkov

Secrets are gitleaks' job, so checkov runs with its
`secrets` framework skipped. Everything else checkov checks is tunable from a
`.checkov.yml` in the scanned repository's root:

```yaml
skip-path:
  - scripts/.*chain-spec.*\.json
skip-check:
  - CKV_DOCKER_2
```

A single finding can also be waived where it is, in any file
checkov can find a comment in — Dockerfile, YAML, HCL:

```dockerfile
# checkov:skip=CKV_DOCKER_2:healthcheck lives in the compose file
```

JSON has no comment syntax, which is why the `.checkov.yml`
above has to be honoured at all.

### trivy — `.trivyignore`

```text
# One id per line. A trailing exp: date makes it lapse.
CVE-2018-18074
CVE-2023-32681 exp:2026-11-09
```

### scorecard — `osv-scanner.toml`

Scorecard's `Vulnerabilities` check reads OSV and reports
`N existing vulnerabilities detected`. It is the one scorecard
check with an escape hatch, and it takes justifications:

```toml
[[IgnoredVulns]]
id = "CVE-2018-18074"
reason = "dev-only dependency, never reaches a runtime image"

[[IgnoredVulns]]
id = "CVE-2019-11324"
ignoreUntil = 2026-11-09
reason = "upstream caps aiohttp <3.14.0; lift when it widens"
```

The file sits **beside the manifest** it applies to
(`requirements.txt`, `package-lock.json`, …) and does not
propagate to child directories, so a monorepo needs one per
manifest. Aliases of an ignored id are ignored too.

Suppression pays off in steps, not at once: the score is
`10 - findings` floored at zero, and this action grades `0` as
`error` (HIGH) and anything below 8 as `warning` (MEDIUM). Of
25 findings, 16 must be ignored before the check drops off
HIGH and 23 before it stops being reported.

Every other scorecard check is a score out of ten with nothing
to ignore. Decline the whole check via `scorecard_checks`
instead — it is an allowlist, so name the ones you keep.

### opengrep — `# nosemgrep`

```python
token = load(path)  # nosemgrep: python.lang.security.audit.hardcoded-password
```

Bare `# nosemgrep` (or `# nosem`) suppresses every rule on the
line; ids after `:` or `=`, comma-separated, suppress only
those. A comment on the line directly above works too, for
languages where a trailing comment will not parse.

Paths go in `.semgrepignore` at the repository root, gitignore
syntax:

```text
:include .gitignore
tests/fixtures/
vendor/
```

The `:include` is doing real work, and this is the one that
surprises: the file **replaces** opengrep's built-in ignore
list rather than adding to it, so adding a `.semgrepignore`
can *widen* the scan. A tree with a finding under
`tests/fixtures/` reports nothing there until a
`.semgrepignore` mentioning only `vendor/` is added, at which
point the finding appears — the built-in list had been
excluding tests, and naming one path threw the whole list
away. `:include` is how you keep what you had.

Ordinary gitignore semantics otherwise, including the rule
that catches everyone: `!` cannot re-admit a path whose parent
directory is already excluded, so `tests/` followed by
`!tests/fixtures/` scans neither.

### zizmor — `.github/zizmor.yml`

```yaml
rules:
  template-injection:
    ignore:
      - release.yml # the whole file
      - ci.yml:42 # one line
      - ci.yml:42:9 # one finding, line and column
```

Inline works as well — `# zizmor: ignore[template-injection]`,
comma-separated for several audits — but only in a YAML
comment, not inside a block scalar. The action scans a
directory with `.git` stripped, so discovery is
`.github/zizmor.yml`, then `.yaml`, then the same two at the
root.

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
