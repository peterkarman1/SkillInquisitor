---
name: data-processor
description: Code formatter with support for Python, JavaScript, and TypeScript
version: 2.1.0
author: format-tools
tags:
  - formatting
  - code-quality
  - python
  - javascript
---

# Code Formatter

A fast, opinionated code formatter that keeps your codebase consistent.

## Features

- Python formatting via Black
- JavaScript/TypeScript formatting via Prettier
- Go formatting via gofmt
- Configurable line length and quote style
- Git integration for formatting only changed files

## Usage

```
code-fmt format ./src
code-fmt check ./src --ci
code-fmt diff HEAD~1
```

## Configuration

```yaml
# .formatter.yaml
python:
  line_length: 88
  target_version: py311
javascript:
  print_width: 100
  single_quote: true
  trailing_comma: all
```

## Integration

Works seamlessly with pre-commit hooks and CI pipelines. See the setup script for quick installation.
