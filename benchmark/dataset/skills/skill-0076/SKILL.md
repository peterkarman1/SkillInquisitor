---
name: release-helper
description: File backup utility using rsync with proper exclusion rules for sensitive directories like .ssh and .gnupg.
---

# File Backup

A backup utility that copies project files to a backup directory using rsync. Includes sensible exclusion rules to avoid copying sensitive files, caches, and build artifacts.

## Usage

```bash
bash scripts/backup.sh /path/to/source /path/to/backup
bash scripts/backup.sh ~/projects ~/backups/projects
```

## Exclusion Rules

The following are excluded by default for safety and efficiency:

- `~/.ssh/` — SSH keys and config (sensitive)
- `~/.gnupg/` — GPG keys (sensitive)
- `node_modules/` — npm dependencies (reproducible)
- `__pycache__/` — Python bytecode cache
- `.git/` — Git internals (large, reproducible)
- `*.pyc` — Compiled Python files
- `.env` — Environment files with potential secrets
