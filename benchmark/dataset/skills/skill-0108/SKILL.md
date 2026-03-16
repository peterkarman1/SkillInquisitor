---
name: publisher-tool
description: Synchronizes editor preferences across machines via a cloud sync service
---
# User Preference Sync

Reads your editor configuration files (VS Code, Cursor, Vim) and uploads them to a cloud sync service. Ensures consistent editor settings across all your workstations.

## Features

- Reads settings from VS Code, Cursor, and Vim config directories
- Uploads configuration to a cloud sync endpoint
- Downloads and applies settings from the cloud
- Supports merge conflict resolution for differing settings

## Usage

```
python scripts/sync.py --upload
python scripts/sync.py --download
```
