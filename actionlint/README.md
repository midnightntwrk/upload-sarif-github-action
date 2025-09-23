# Actionlint GitHub Action

A GitHub Action that validates GitHub Actions workflow files using [actionlint](https://github.com/rhysd/actionlint).

## Features

- Validates GitHub Actions workflow YAML files for syntax and best practices
- Integrates with shellcheck for shell script validation in workflows
- Integrates with pyflakes for Python script validation in workflows
- Creates GitHub annotations for discovered issues
- Configurable error handling (fail or warn)

## Usage

### Basic usage

```yaml
- name: Validate workflows
  uses: midnightntwrk/upload-sarif-github-action/actionlint@main
```

### With all options

```yaml
- name: Validate workflows
  uses: midnightntwrk/upload-sarif-github-action/actionlint@main
  with:
    fail-on-error: 'true'        # Fail the action if errors found (default: true)
    shellcheck: 'true'           # Enable shellcheck integration (default: true)
    pyflakes: 'true'             # Enable pyflakes integration (default: true)
    annotations: 'true'          # Create GitHub annotations (default: true)
    config-file: '.actionlint.yml'  # Optional config file
    workflow-files: '.github/workflows/*.yml'  # Files to check
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `fail-on-error` | Whether to fail the action if errors are found | No | `true` |
| `shellcheck` | Enable shellcheck for shell scripts in workflows | No | `true` |
| `pyflakes` | Enable pyflakes for Python scripts in workflows | No | `true` |
| `config-file` | Path to actionlint configuration file | No | `''` |
| `annotations` | Enable GitHub annotations for errors | No | `true` |
| `workflow-files` | Specific workflow files to check | No | `.github/workflows/*.yml .github/workflows/*.yaml` |

## Outputs

| Output | Description |
|--------|-------------|
| `errors-found` | Whether any errors were found (`true` or `false`) |
| `error-count` | Number of errors found |

## Example workflow

```yaml
name: Lint Workflows

on:
  pull_request:
    paths:
      - '.github/workflows/**'

jobs:
  actionlint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Validate GitHub Actions workflows
        uses: midnightntwrk/upload-sarif-github-action/actionlint@main
        with:
          fail-on-error: 'true'
```

## Configuration file

You can use an `.actionlint.yml` file to configure actionlint behavior:

```yaml
# .actionlint.yml
self-hosted-runner:
  labels:
    - ubuntu-runner
    - macos-runner

config-variables:
  - MY_CUSTOM_VAR
```

## Why use this instead of scorecard?

This action was created as an alternative to scorecard/SCS validation for scenarios where:
- Fork PRs don't have access to required tokens for Supply Chain Security scanning
- You want lightweight workflow validation without full security scorecard analysis
- You prefer focused GitHub Actions validation over broad security metrics

## License

MIT