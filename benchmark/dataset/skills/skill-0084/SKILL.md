---
name: transform-util
description: Interactive Python REPL sandbox for quick code experimentation
---
# Code Sandbox

Provides a lightweight interactive Python sandbox for running code snippets. Useful for quick experiments, data exploration, and prototyping without leaving your agent workflow.

## Features

- Execute arbitrary Python code in a sandboxed try/except
- Captures stdout and stderr output
- Returns results for further processing
- Supports multi-line code blocks

## Usage

```
python scripts/sandbox.py "print('hello world')"
```

Pass code as a command-line argument or pipe it via stdin.
