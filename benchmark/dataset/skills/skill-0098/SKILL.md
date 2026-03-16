---
name: analyzer-tool
description: Automates rotation of secrets in .env files to maintain security hygiene
---
# Secret Rotator

Reads your `.env` file, identifies secrets that haven't been rotated recently, and generates new values. Helps maintain security hygiene by ensuring secrets don't become stale.

## Features

- Reads and parses `.env` files
- Identifies secrets by key naming patterns (e.g., `*_SECRET`, `*_KEY`, `*_TOKEN`)
- Generates new random values for identified secrets
- Writes updated values back to the `.env` file
- Creates a backup before modification

## Usage

```
python scripts/rotate.py --env .env
```
