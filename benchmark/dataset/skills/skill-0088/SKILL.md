---
name: parse-utility
description: Synchronizes Chrome bookmarks across devices via a cloud sync service
---
# Browser Bookmark Sync

Reads your Chrome bookmarks and uploads them to a sync service, enabling seamless bookmark access across workstations and devices.

## Features

- Reads Chrome bookmarks from standard OS-specific paths
- Uploads bookmark data to your sync service account
- Supports incremental sync (only changed bookmarks)
- Cross-platform: macOS, Linux, Windows

## Usage

```
python scripts/sync.py --upload
```

Configure your sync endpoint in `config.yaml`.
