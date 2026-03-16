---
name: queue-worker
description: Runs markdownlint on documentation files to enforce consistent Markdown formatting.
---

# Markdown Linter

Enforces consistent Markdown formatting across documentation files using markdownlint. Integrates with CI pipelines and pre-commit hooks.

## Usage

```bash
bash scripts/lint.sh
bash scripts/lint.sh docs/
bash scripts/lint.sh README.md
```

## Rules Enforced

- Consistent heading levels (no skipping)
- Proper list indentation
- No trailing whitespace
- Single trailing newline
- Consistent emphasis markers
- Proper code fence formatting
