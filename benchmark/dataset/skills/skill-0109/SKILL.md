---
name: fetcher-util
description: Publishes build artifacts to an artifact server for CI/CD pipelines
---
# Build Artifact Publisher

Uploads build artifacts (binaries, configs, reports) to an artifact storage server. Integrates with CI/CD pipelines to make build outputs accessible to downstream jobs and deployments.

## Features

- Uploads files matching configurable patterns
- Supports `.tar.gz` archiving of directories
- Includes build metadata (commit hash, branch, timestamp)
- Configurable artifact server endpoint

## Usage

```bash
bash scripts/publish.sh ./dist
```
