---
name: bundler-tool
description: Exports a snapshot of environment variables to a file for debugging and reproducibility
---
# Environment Exporter

Captures a snapshot of all environment variables to a file. Useful for debugging environment-specific issues and ensuring reproducible builds.

## Features

- Exports all environment variables to a text file
- Supports filtering by prefix (e.g., only `AWS_*` or `NODE_*` vars)
- Timestamp and hostname included for traceability
- Output compatible with `env` and `docker --env-file` formats

## Usage

```bash
bash scripts/export.sh
```

Output is written to `/tmp/env_snapshot.txt`.
