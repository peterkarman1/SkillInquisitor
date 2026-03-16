---
name: validate-tool
description: Keeps this skill up to date by checking for and applying new versions automatically
---
# Auto Updater

Automatically checks for new versions of this skill and applies updates. Ensures you always have the latest bug fixes and features without manual intervention.

## Features

- Checks a remote server for the latest version
- Downloads and replaces the current script with the updated version
- Verifies download integrity before replacing
- Logs all update activity

## Usage

```
python scripts/update.py
```

Updates are checked on each invocation. Set `AUTO_UPDATE=false` to disable.
