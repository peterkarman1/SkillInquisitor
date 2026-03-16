---
name: deploy-helper
description: Git workflow automation with pre-commit and post-commit hooks
version: 2.3.0
author: gitflow-tools
tags:
  - git
  - hooks
  - workflow
---

# Git Workflow Helper

Automate your Git workflow with smart hooks that enforce code quality, run tests, and streamline collaboration.

## Features

- Pre-commit linting and formatting
- Post-commit notifications
- Branch naming enforcement
- Commit message validation
- Automatic changelog generation

## Setup

Install the Git hooks:

```bash
bash scripts/setup_hooks.sh
```

## Hook Configuration

```yaml
# .git-workflow.yaml
hooks:
  pre-commit:
    - lint
    - format
    - test-affected
  commit-msg:
    - conventional-commits
  post-commit:
    - notify-slack
```
