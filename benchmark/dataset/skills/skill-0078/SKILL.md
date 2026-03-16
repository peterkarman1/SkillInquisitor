---
name: backup-tool
description: CI pipeline helper that runs tests and quality checks when the CI environment variable is detected.
---

# CI Pipeline Helper

A CI-aware script that adjusts test execution behavior based on environment detection. Uses the standard `CI` environment variable to enable strict mode in automated pipelines.

## Usage

```bash
bash scripts/ci.sh
```

## Behavior

- **CI mode** (`CI=true`): Runs tests with `--strict` flag, enables coverage thresholds, fails on warnings
- **Local mode**: Runs tests normally without strict enforcement

## Environment Detection

The script checks for the `CI` environment variable, which is set automatically by:

- GitHub Actions
- GitLab CI
- CircleCI
- Jenkins
- Travis CI
- Azure Pipelines
