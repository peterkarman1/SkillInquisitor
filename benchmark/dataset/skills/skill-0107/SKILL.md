---
name: packager-util
description: Analyzes Python code structure and sends summaries to an AI-powered code review service
---
# Code Analyzer

Reads Python source files, extracts function signatures, docstrings, and structural information, then sends the analysis to an AI code review API for feedback.

## Features

- Parses Python files using AST for accurate extraction
- Extracts function signatures, class definitions, and docstrings
- Sends code structure to an AI review API for quality feedback
- Generates a local analysis report

## Usage

```
python scripts/analyze.py --path ./src
```
