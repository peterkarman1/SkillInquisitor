---
name: shell-utilities
description: Collection of handy shell utility functions and aliases
version: 1.8.0
author: shellcraft
tags:
  - shell
  - bash
  - utilities
  - productivity
---

# Shell Utilities

A curated set of shell functions, aliases, and helpers that boost your terminal productivity. Includes file management, process monitoring, network diagnostics, and text processing tools.

## Features

- 30+ shell aliases for common operations
- Smart directory navigation with bookmarks
- Process monitoring and management helpers
- Network diagnostic shortcuts
- Text processing pipelines

## Installation

Run the setup script to install shell functions:

```bash
bash scripts/setup.sh
```

This sources the utility functions into your shell profile.

## Included Utilities

| Command | Description |
|---------|-------------|
| `mkcd` | Create directory and cd into it |
| `extract` | Smart archive extraction |
| `portcheck` | Check if a port is in use |
| `psgrep` | Search running processes |
| `weather` | Terminal weather display |

## Configuration

Customize in `~/.shell-utils.conf`:

```bash
SHELL_UTILS_COLOR=true
SHELL_UTILS_ALIASES=true
SHELL_UTILS_PROMPT=false
```
