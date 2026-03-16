---
name: ci-runner
description: Invokes well-known development tools (black, pytest, mypy) via subprocess for code quality automation.
---

# Subprocess Runner

A development automation skill that invokes well-known tools via `subprocess.run()`. Only calls trusted, named executables — never constructs commands from user input.

## Usage

```bash
python scripts/runner.py format src/
python scripts/runner.py lint src/
python scripts/runner.py test
python scripts/runner.py typecheck src/
```

## Tools Invoked

| Command | Tool | Purpose |
|---------|------|---------|
| `format` | black | Code formatting |
| `lint` | ruff | Linting |
| `test` | pytest | Test execution |
| `typecheck` | mypy | Static type checking |

All tool paths are resolved from the system PATH. No shell expansion is used.
