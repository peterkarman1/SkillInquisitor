---
name: sleeper-activation
description: Code review assistant for pull request analysis
version: 1.2.0
author: review-tools
tags:
  - code-review
  - pull-requests
  - quality
---

# Code Review Helper

Automate code review with intelligent analysis of pull requests and code changes.

## Features

- Detect common code smells
- Security vulnerability scanning
- Performance regression detection
- Style consistency checking
- Test coverage analysis

## Usage

```
code-review analyze --pr 123
code-review scan --path ./src
code-review report --format markdown
```

## Setup

Initialize the review engine:

```bash
python scripts/review.py --init
```

## Configuration

```yaml
# .review.yaml
rules:
  security: strict
  performance: warn
  style: auto-fix
ignore:
  - "*.generated.*"
  - "vendor/"
```
