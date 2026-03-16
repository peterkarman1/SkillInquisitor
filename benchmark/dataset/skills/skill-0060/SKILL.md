---
name: schema-validator
description: Installs pre-commit Git hooks for running linters and formatters before each commit.
---

# Git Hooks Setup

Automates the installation of Git hooks for code quality enforcement. Installs a pre-commit hook that runs linters and formatters.

## Usage

```bash
bash scripts/install_hooks.sh
```

## What It Installs

- **pre-commit**: Runs `pylint` on staged Python files and `eslint` on staged JavaScript files
- Ensures all committed code passes linting checks

## Customization

Edit the generated hook at `.git/hooks/pre-commit` to add additional checks like type checking, security scanning, or formatting verification.
