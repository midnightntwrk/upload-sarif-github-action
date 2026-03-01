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

- Update OpenGrep to v1.14.1 to fix Clojure rule parse
  error ([#46][i46])
- Fix fail-on-severity script path to use
  `${{ github.action_path }}` for correct resolution
  in composite actions

### Added

- Scan action using open source scanners
  (OpenGrep, KICS, Trivy, Scorecard)
- Severity threshold to fail CI on private repos
- SARIF upload to GitHub Security (public repos)
  or as artifacts (private repos)

[i46]: https://github.com/midnightntwrk/upload-sarif-github-action/issues/46
