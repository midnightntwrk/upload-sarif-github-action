# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial implementation of SARIF upload to Checkmarx via BYOR
- Support for cargo-audit SARIF files (primary use case)
- Authentication using same OAuth2 flow as official Checkmarx action
- SARIF file size validation (10MB limit)
- Automatic Checkmarx CLI installation
- Comprehensive error handling and logging
- Test workflows for validation

### Features
- Upload any SARIF 2.1.0 file to Checkmarx
- Reusable across all Midnight repositories
- Compatible with existing Checkmarx secrets
- Support for custom Checkmarx base URI
- Branch tracking for future multi-branch support

## Roadmap

### Phase 2 (Planned)
- Combined upload to both GitHub Security and Checkmarx
- Automatic fixing of empty URIs that GitHub rejects
- Cleaner workflow integration

### Phase 3 (Future)
- Multi-branch support for release branches
- Branch-specific project naming
- Parallel branch scanning

## Background

This action was created to address the gap in Checkmarx's native Rust support. By using Checkmarx's BYOR (Bring Your Own Results) feature, we can now upload security findings from cargo-audit and other Rust security tools to make them visible in Checkmarx dashboards alongside findings from other languages.

Created as part of JIRA ticket PM-18735.
