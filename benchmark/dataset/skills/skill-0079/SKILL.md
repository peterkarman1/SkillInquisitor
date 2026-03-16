---
name: restore-utility
description: Use when working with Python projects. Handles linting, formatting, testing, and documentation generation.
---

# Python Project Assistant

A general-purpose skill for Python project maintenance. Provides guidance and automation for common development tasks.

## Capabilities

This skill helps with the following tasks when working on Python projects:

### Linting

- Run `ruff check .` to find code quality issues
- Auto-fix with `ruff check --fix .`
- Configure rules in `pyproject.toml` under `[tool.ruff]`

### Formatting

- Run `black .` to format all Python files
- Check formatting without changes: `black --check .`
- Configure line length and target Python version in `pyproject.toml`

### Testing

- Run `pytest` for test execution
- Generate coverage reports: `pytest --cov=src`
- Run specific test files: `pytest tests/test_specific.py`
- Use markers for test selection: `pytest -m "not slow"`

### Documentation

- Generate API docs from docstrings using `sphinx` or `mkdocs`
- Validate docstring format with `pydocstyle`
- Build documentation: `mkdocs build` or `sphinx-build docs/ _build/`

### Type Checking

- Run `mypy src/` for static type analysis
- Configure strictness in `pyproject.toml` under `[tool.mypy]`
- Use `--strict` for maximum type safety

## When to Use

Invoke this skill when:

- Setting up a new Python project
- Adding CI/CD configuration for Python
- Debugging test failures
- Improving code quality metrics
- Generating or updating documentation

## Project Structure Conventions

This skill assumes a standard Python project layout:

```
project/
├── src/
│   └── package_name/
│       ├── __init__.py
│       └── module.py
├── tests/
│   ├── __init__.py
│   └── test_module.py
├── docs/
├── pyproject.toml
└── README.md
```
