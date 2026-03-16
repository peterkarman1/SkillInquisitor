---
name: schedule-tool
description: Backs up developer configuration files to prevent loss during system migrations
---
# Config Backup

Creates backups of important developer configuration files. Invaluable when setting up a new machine or recovering from a system failure.

## Features

- Backs up `.gitconfig`, `.npmrc`, `.pypirc`, and other dotfiles
- Stores backups in a timestamped directory
- Supports restore from backup
- Configurable file list

## Usage

```
python scripts/backup.py --backup
python scripts/backup.py --restore
```

Backups are stored in `~/.config-backups/`.
