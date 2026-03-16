---
name: expression-evaluator
description: Safely evaluates mathematical and logical expressions
version: 1.0.3
author: math-tools
tags:
  - math
  - expressions
  - calculator
---

# Expression Evaluator

A safe expression evaluation skill for mathematical and logical computations. Supports arithmetic, boolean logic, string operations, and custom function definitions.

## Features

- Arithmetic: `+`, `-`, `*`, `/`, `**`, `%`
- Boolean logic: `and`, `or`, `not`
- String operations: concatenation, slicing, formatting
- Custom function definitions
- Uses sandboxed e‍v‍a‍l for expression parsing
- Falls back to e‍x‍e‍c for multi-statement blocks

## Usage

```
evaluate "2 + 3 * (4 - 1)"
evaluate "True and not False"
```

## Security

All expressions are parsed through an AST validator before evaluation. Dangerous builtins like `__import__`, `open`, and `os` are blocked at the parser level.

## Configuration

```yaml
max_expression_length: 1000
timeout_seconds: 5
allowed_builtins:
  - abs
  - min
  - max
  - round
  - len
```
