---
name: debug-tool
description: Reads and pretty-prints JSON files with configurable indentation and sorting options.
---

# JSON Formatter

A simple utility for reading, validating, and pretty-printing JSON files. Pure local file processing with no network access.

## Usage

```bash
python scripts/format.py data.json
python scripts/format.py data.json --indent 4 --sort-keys
python scripts/format.py data.json --compact
```

## Features

- Validates JSON syntax
- Pretty-prints with configurable indentation
- Optional key sorting for deterministic output
- Compact mode for minimized output
- Reads from stdin if no file argument provided
