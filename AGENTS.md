# AGENTS.md

Instructions for agents (and humans) working in `upload-sarif-github-action`: a
composite action that runs seven scanners in one `earth +scan` and gates on
their SARIF. Every scanner's output passes through one gate
(`scripts/severity.jq` → `scripts/fail-on-severity.sh`), and almost every bug
this repo has had is the same shape: **a scanner that looks like it is working
while gating nothing.** Assume that failure first.

## Fixing a failed scan

You are here because a scan in **another** repository failed and its log
linked this section. Make it green the right way: fix first, excuse second,
and never excuse the three at the bottom. Every excuse carries a **reason a
reviewer would accept** and, where the format allows, an **expiry**; the
reason goes in the file, not in the PR description. If a finding is a false
positive from the scanner itself, say so in the reason and open an issue on
this action rather than widening a waiver.

| Finding (as the log names it) | Fix first | Excuse one finding, if you must |
| ----------------------------- | --------- | ------------------------------- |
| **gitleaks** `generic-api-key`, `private-key`, ... | Rotate the credential. It is in git history, so it is compromised whatever happens to this PR. Then remove it. | Test fixtures and documented placeholders only: `.gitleaks.toml` `[[allowlists]]` with `paths` (a directory) or `.gitleaksignore` (one fingerprint per line, printed in the log). Keep the finding's `targetRules` narrow. |
| **osv-scanner** `MAL-*` | Remove the package. Assume every machine that installed it is compromised. | Never. |
| **osv-scanner** CVE / GHSA / RUSTSEC | Upgrade the package in the lockfile with the ecosystem's tool (`cargo update -p`, `npm update`, ...), never by hand. | `osv-scanner.toml` next to that lockfile: `[[IgnoredVulns]]` with the OSV id (RUSTSEC-/GHSA-/PYSEC-, not the CVE alias), `reason` and `ignoreUntil`. Legitimate when the vulnerable code is unreachable (say why) or the fix is not released yet. |
| **osv-scanner** `deprecated-package` | Move to a version that is still published; a yank usually means a defect found before any advisory. | `[[PackageOverrides]]` `name`/`version`/`ecosystem` + `ignore = true` + `reason`. Legitimate when the newer version needs a toolchain you do not have yet. |
| **osv-scanner** `license-violation` | Replace the dependency, or confirm it is a dev/optional dependency the lockfile could not mark as such. | `[[PackageOverrides]]` `license.ignore = true` + `reason` (dev tool, separate process, exception you hold). Do **not** add the licence to `licenses_allowlist` to clear one package: that changes policy for the whole repository and needs the repository owner. |
| **osv-scanner** `license-unknown` | Read the package's own LICENSE. | `[[PackageOverrides]]` `license.override = ["<SPDX id>"]` recording what you read. |
| **trivy** CVE in a manifest | Upgrade, as above. | `.trivyignore`: the CVE id, with `# reason` and `exp:YYYY-MM-DD`. Mirror into `osv-scanner.toml` so the two scanners agree. |
| **opengrep** rule | Change the code: the rule names the pattern. | `# nosemgrep: <full rule id>` on the line, with a comment saying why it is safe here. Never a bare `# nosemgrep`. |
| **checkov** `CKV_*` | Fix the resource. | `# checkov:skip=<ID>:<reason>` inside the resource block. |
| **zizmor** `template-injection`, `dangerous-triggers`, ... | Fix the workflow: `env:` indirection for expressions, pin actions by SHA, drop `pull_request_target`. | `# zizmor: ignore[<rule>]` on the line, or `.github/zizmor.yml` `rules.<rule>.ignore: [file.yml]`, with a comment on why the trigger is safe (e.g. the job checks the commenter's permission first). |
| **zizmor** `known-vulnerable-actions` | Bump the action to the fixed release. | Never: the advisory is against the action you are running. |
| **scorecard** `Dangerous-Workflow`, `Pinned-Dependencies`, ... | Do what the check says; each is a score, and the score moves one finding at a time. | Decline a whole check via `scorecard_checks` only when it cannot apply to the repository, and say why in the workflow. |

Never excuse: a committed secret (rotate it), a `MAL-*` package (remove it),
a `known-vulnerable-actions` finding (bump it). Each of those is a fact about
something already exposed, and a waiver only hides the exposure.

Do not raise `fail_severity`, turn `differential_gate` off, or set
`skip_<scanner>_scan` to pass a PR. Those are repository policy, owned by the
people who set them; propose the change to them separately.

Copy-ready examples of every waiver file above are in the README under
[Per-tool calibration](README.md#per-tool-calibration); the
`osv-scanner.toml` ones, including `PackageOverrides` for yanked packages and
licences, are under
[osv-scanner and scorecard](README.md#osv-scanner-and-scorecard--osv-scannertoml).

Verify before pushing: the waiver must clear the **gate**, not only GitHub's
Security tab - see the next section. `jq '.runs[].results[] | {ruleId,
suppressions}' scan_reports/<tool>.sarif` shows what the scanner actually
emitted.

## Suppressions: the gate must agree with the scanner

A scanner's in-source suppression has to clear the **gate**, not just GitHub's
Security tab.

- opengrep (`# nosemgrep: <rule>`) and checkov (`# checkov:skip=<ID>:<why>`)
  **report** a suppressed finding anyway, marked
  `suppressions: [{"kind": "inSource"}]` - SARIF 3.27.23 says to. The Security
  tab honours the mark. Until 2026-10 the gate ignored it, so the documented
  fix for a false positive left the build red on every repo, public or private.
- zizmor (`# zizmor: ignore[<rule>]`) drops an ignored finding itself; it never
  reaches the gate.
- `severity.jq`'s `suppressed()` honours SARIF 3.35.3: no `status`, or
  `accepted`, is in force; `underReview` and `rejected` still count. Do not
  simplify it to "any suppression" or "`suppressions | length == 0`".
- Suppressed findings are **listed, never hidden** (`suppressions` in the jq
  output, a fold in the job summary). A gate that drops findings silently is
  the bug class above.
- A gitleaks secret is never excused by a suppression: a committed credential
  is compromised whatever the comment says. gitleaks has `.gitleaksignore` and
  `.gitleaks.toml`.
- File-based waivers - `.trivyignore`, `osv-scanner.toml`, `.gitleaksignore`,
  `.checkov.yml` - carry a reason and, where the format allows, an expiry.
  One waiver for one CVE goes in **both** `.trivyignore` and
  `osv-scanner.toml` (scorecard's `Vulnerabilities` reads the latter too).
- A `deprecated-package` finding (yanked crate, deprecated npm version) has
  no advisory id, so `IgnoredVulns` cannot excuse it; `[[PackageOverrides]]`
  with `ignore = true` on the name and version can, and drops the package
  from the vulnerability report too.
- A `license-violation` is excused per package with `[[PackageOverrides]]`
  `license.ignore = true`; a `license-unknown` is answered with
  `license.override = ["<SPDX id>"]`. Both are osv-scanner's own config and
  take effect before osv.jq sees the package. Never answer either by adding
  the licence to the allowlist "for now".

When a suppression "does not work", check the raw SARIF before the comment:
`jq '.runs[].results[] | {ruleId, suppressions}' scan_reports/<tool>.sarif`.

## Severity is policy, and it lives with the tool

SARIF `level` tops out at `error`, so it can never mean CRITICAL. Each tool's
real signal is mapped in its own jq, not in shared code: `secrets-severity.jq`
(gitleaks → CRITICAL), `scorecard.jq`, `osv.jq` (`MAL-*` → CRITICAL, CVSS
bands, deprecated → MEDIUM, licence violation → HIGH, licence unknown → LOW;
it also *writes* osv-scanner's SARIF from the JSON report, because upstream's
drops deprecated-only packages and carries no licences), `spdx.jq` (the
allowlist matcher - osv-scanner's own cannot express a `WITH` exception), and
per-tool `calibrate` in `severity.jq`. The default allowlist is
`scripts/license-allowlist.txt`; change it with a reason in the commit and a
test in `tests/license-allowlist.bats`. Change a mapping only with a
test in `tests/calibration.bats` or the tool's own `.bats`.

## Adding or bumping a scanner

- Pin every binary by sha256 in the `Earthfile`, beside a `# renovate:` line.
  `scripts/refresh-earthfile-hashes.sh` re-derives hashes for pinned versions;
  register new pins in its `TARGETS`.
- Verify the release before pinning it - cosign / SLSA provenance / GitHub
  attestation against the project's own release workflow and tag. A
  days-old release is the riskiest one; that is when hijacked releases ship.
- Run scanners in their own target as the non-root `scanner` user. Never
  enable a mode that executes the scanned repo's code (osv-scanner
  `--call-analysis` runs Rust build scripts).
- No apt in scanner images: copy the CA bundle from `+ca-certs` and jq from
  `+jq-bin`. apt installs whatever the mirror serves that day.
- One credential enters the scan: `GH_TOKEN`, as an earth `--secret`, read by
  `+zizmor` alone. Never as an ARG (it would land in a layer), never to
  another target. zizmor online has no off switch by design.
- Probe the real SARIF first: severity signal, URIs (`file:///src/...` must
  become repo-relative), exit codes (most use 1 for "found something").
- `tests/canary.sh` plants one defect per scanner and asserts each is caught
  by name at the expected severity, plus a clean tree that must pass. Update
  its scanner count. Fixtures are assembled at runtime and never committed -
  a committed private key or malware lockfile fails this repo's own scan.

## Testing

- `earth +test` - hermetic bats suite; write the failing test first.
- `./tests/canary.sh` - real scanners, two full scans; needs docker.
- `./tests/integration.sh` - gitleaks exclusion mechanisms end to end.
- `+user-source` is `LOCALLY`, so a second scan in one process is served the
  first tree's SARIF. Use `earth --no-cache` when scanning more than one tree.
- Regenerate `requirements.txt` with `earth +checkov-requirements`, never by
  hand; `pip-tools-requirements.txt` with `earth +pip-tools-requirements`.
