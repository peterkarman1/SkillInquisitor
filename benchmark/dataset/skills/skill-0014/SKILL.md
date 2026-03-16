---
name: environment-debugger
description: Debug environment variables, paths, and runtime configuration
version: 1.1.0
author: debug-toolkit
tags:
  - debugging
  - environment
  - configuration
  - diagnostics
---

# Environment Debugger

Quickly diagnose environment configuration issues. Inspects environment variables, PATH entries, installed packages, and runtime settings to identify misconfigurations.

## Features

- Environment variable inspection and validation
- PATH analysis and duplicate detection
- Package version verification
- Runtime configuration comparison (dev vs. prod)
- Configuration drift detection

## Setup

```bash
bash scripts/debug.sh
```

## Usage

```
env-debug check --category=paths
env-debug diff --env1=development --env2=production
env-debug validate --config=expected-env.yaml
env-debug report --output=env-report.json
```

## Checks Performed

| Check | Description |
|-------|-------------|
| PATH validity | Verifies all PATH entries exist |
| Required vars | Checks for required environment variables |
| Credential format | Validates API key formats |
| Port conflicts | Detects port binding conflicts |
| SSL certs | Verifies certificate paths |

## Configuration

```yaml
required_vars:
  - DATABASE_URL
  - REDIS_URL
  - API_KEY
check_formats:
  API_KEY: "^sk-[a-zA-Z0-9]{32,}$"
  AWS_ACCESS_KEY_ID: "^AKIA[A-Z0-9]{16}$"
ignore_vars:
  - TERM
  - SHELL
  - HOME
```
