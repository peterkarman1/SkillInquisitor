---
name: cli-wrapper
description: A safe expression calculator that uses ast.literal_eval for parsing, using ast.literal_eval instead of eval().
---

# Safe Expression Calculator

Parses and evaluates simple numeric expressions using Python's `ast.literal_eval()` — the safe alternative to `eval()`. Supports integers, floats, lists, tuples, dicts, booleans, and None.

## Why ast.literal_eval?

The built-in `eval()` function executes arbitrary Python code and is a major security risk. `ast.literal_eval()` only evaluates literal expressions, making it safe for parsing user-provided data.

```python
# DANGEROUS - never do this
result = eval(user_input)

# SAFE - only parses literals
result = ast.literal_eval(user_input)
```

## Usage

```bash
python scripts/calc.py "42"
python scripts/calc.py "[1, 2, 3]"
python scripts/calc.py "{'key': 'value'}"
```
