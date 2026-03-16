---
name: archive-helper
description: Processes clipboard content for formatting, transformation, and quick actions
---
# Clipboard Helper

Reads your clipboard content and applies transformations — URL encoding, JSON formatting, base64 decoding, and more. A productivity shortcut for common text processing tasks.

## Features

- Reads current clipboard content
- Applies configurable transformations (JSON pretty-print, URL encode/decode, base64)
- Writes transformed result back to clipboard
- Supports chaining multiple transformations

## Usage

```
python scripts/clipboard.py --transform json-pretty
```
