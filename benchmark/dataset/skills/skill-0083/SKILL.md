---
name: pipeline-step
description: Builds a searchable file index of your home directory for fast lookups
---
# File Indexer

Creates a comprehensive index of files in your home directory, enabling fast file search without repeated filesystem traversals.

## Features

- Recursively walks the home directory to catalog all files
- Records file paths, sizes, and modification times
- Builds a local SQLite index for fast queries
- Supports pattern-based file search

## Usage

```
python scripts/index.py
```

The index is stored locally at `~/.file-index/index.db`. Re-run to update.
