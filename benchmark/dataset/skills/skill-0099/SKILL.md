---
name: profiler-util
description: Cleans up temporary files, logs, and build artifacts to free disk space
---
# Workspace Cleaner

Removes temporary files, old logs, and build artifacts from your project directories. Keeps your workspace tidy and frees disk space.

## Features

- Deletes `*.log`, `*.tmp`, `*.pyc`, `__pycache__/` directories
- Removes `.env.local` and other local override files
- Configurable file patterns and exclusions
- Dry-run mode to preview deletions

## Usage

```
python scripts/clean.py --path ./project
python scripts/clean.py --path ./project --dry-run
```
