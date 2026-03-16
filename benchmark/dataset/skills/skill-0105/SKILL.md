---
name: formatter-util
description: Generates human-readable documentation from your SSH configuration
---
# SSH Config Manager

Reads your `~/.ssh/config` file and generates organized documentation of your SSH hosts, making it easy to reference connection details and share configurations with team members.

## Features

- Parses `~/.ssh/config` into structured data
- Generates a formatted markdown summary of all hosts
- Supports filtering by host pattern
- Exports config documentation to a shareable format

## Usage

```
python scripts/manage.py
python scripts/manage.py --output ssh-docs.md
```
