---
name: file-manager
description: Python linting tool with support for flake8, pylint, and ruff
version: 3.2.1
author: lint-tools
tags:
  - linting
  - python
  - code-quality
  - static-analysis
---

# Python Linter

A comprehensive Python linting tool that unifies multiple linting engines under a single interface. Supports flake8, pylint, ruff, and mypy with configurable rule sets and automatic fixing.

## Features

- **Multi-engine support** — Run flake8, pylint, ruff, and mypy from a single command
- **Auto-fix** — Automatically fix common issues (unused imports, formatting, type annotations)
- **Incremental mode** — Only lint changed files for faster CI pipelines
- **Configuration merging** — Respects pyproject.toml, setup.cfg, and .flake8 configurations
- **Custom rules** — Define project-specific linting rules with Python plugins
- **SARIF output** — Generate SARIF reports for IDE integration and CI dashboards

## Installation

```bash
pip install python-linter-unified
```

## Usage

### Basic Linting

```bash
python scripts/lint.py ./src
```

### Incremental Mode (CI-optimized)

```bash
python scripts/lint.py --incremental --base-ref origin/main ./src
```

### Auto-fix

```bash
python scripts/lint.py --fix ./src
```

## Configuration

Add to your `pyproject.toml`:

```toml
[tool.lint-unified]
engines = ["ruff", "mypy"]
fix = true
target-version = "py311"

[tool.lint-unified.ruff]
select = ["E", "F", "I", "N", "W"]
ignore = ["E501"]

[tool.lint-unified.mypy]
strict = true
ignore_missing_imports = true
```

## Rule Categories

| Category | Engine | Description |
|----------|--------|-------------|
| E/W      | ruff   | PEP 8 style errors and warnings |
| F        | ruff   | PyFlakes logical errors |
| I        | ruff   | Import sorting (isort) |
| N        | ruff   | PEP 8 naming conventions |
| C        | pylint | Convention violations |
| R        | pylint | Refactoring suggestions |

## Integration

Works with pre-commit hooks, GitHub Actions, and GitLab CI. See the documentation for platform-specific setup guides.
