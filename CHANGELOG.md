# Changelog

All notable changes to this project will be documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Removed Checkmarx integration
  (BYOR upload, checkmarx-scan, checkmarx-scan-public)
- Made scan action (OpenGrep, KICS, Trivy, Scorecard)
  the root action
- Consolidated examples into a single scan workflow

### Fixed

- Severity-less results were ignored by the gate, so **no
  gitleaks finding could fail a build at any threshold** - a
  committed private key scanned clean. Severity now resolves
  as `result.level`, `properties.severity`, the rule default,
  then `warning` (SARIF 3.27.10). No behaviour change at
  `critical`/`high`/`medium`, which all outrank `warning`
- Unmapped severities (Trivy `UNKNOWN`, SARIF `none`) aborted
  the gate: `${SEVERITY_MAP[$sev]}` under `set -u` is an
  unbound-variable error. Now warned and skipped
- No SARIF files exited 0 - `jq`'s failure inside a process
  substitution never propagated - so a misnamed reports
  directory passed CI silently. Bad invocations now exit 2
  and write no count, so they cannot read as a clean scan
- Findings without `locations` shifted their message into the
  file column; fields are now unit-separated, since tab is
  IFS whitespace and `read` collapses runs of it
- Scan the caller's workspace instead of the action's own
  checkout: `user-source` now stages `USER_SOURCE_DIR`
  (passed as `$GITHUB_WORKSPACE` by `action.yml`), since
  `LOCALLY` executes in the Earthfile's directory rather
  than the invoker's cwd
- Update OpenGrep to v1.14.1 to fix Clojure rule parse
  error ([#46][i46])
- Fix fail-on-severity script path to use
  `${{ github.action_path }}` for correct resolution
  in composite actions

### Added

- `differential_gate` input: when the severity gate fails on
  a pull request, re-scan the target branch in the same job
  and pass if the PR strictly reduces the finding count. Lets
  two PRs that each fix one of two outstanding vulnerabilities
  land independently, instead of requiring a combined PR.
  Unrelated PRs stay blocked while findings are outstanding —
  the count must go down, not merely stay level. Off by
  default; `pull_request` events only
- `tests/run-tests.sh` and an `earth +test` target: 40 unit
  tests over SARIF fixtures and a scratch git repo, no
  network or scanners needed
- `tests/integration-differential.sh`: end-to-end test of the
  gate against a real gitleaks scan of two trees differing by
  one secret, asserting the scanner fires before comparing
  counts
- `scripts/materialise-base.sh`: base-tree checkout extracted
  from `action.yml` so it can be tested outside a PR event
- CI jobs for shellcheck, unit tests and the integration test
- Trivy vulnerability scanner re-enabled as a hash-pinned
  binary release inside its own container (the previously
  disabled aquasecurity GitHub action is not used)
- gitleaks secret scanner (working-tree scan, SARIF output)
- `skip_<scanner>_scan` inputs to skip any individual
  scanner (opengrep, scorecard, checkov, zizmor, trivy,
  gitleaks)
- zizmor scanner for GitHub Actions workflows and composite
  actions, run in offline mode inside its own container so
  it never sees the runner's `GITHUB_TOKEN`
- Scan action using open source scanners
  (OpenGrep, KICS, Trivy, Scorecard)
- Severity threshold to fail CI on private repos
- SARIF upload to GitHub Security (public repos)
  or as artifacts (private repos)

[i46]: https://github.com/midnightntwrk/upload-sarif-github-action/issues/46
