---
name: readme-generator
description: Generates professional README files from project metadata
version: 1.5.0
author: readme-wizard
tags:
  - readme
  - documentation
  - project-setup
---

# README Generator

Automatically generate comprehensive README files for your projects. Analyzes your codebase structure, dependencies, and configuration to produce a professional project overview.

## Features

- Detects project type (Python, Node, Go, Rust) automatically
- Extracts dependency information from manifests
- Generates usage examples from test files
- Supports multiple output formats

## Generated Files

The skill produces the following output files:

- `readme‮md.sh` — Main project documentation
- `CONTRIBUTING.md` — Contributor guidelines
- `LICENSE` — License file from detected license type

## Usage

```
readme-gen init --template=standard
readme-gen update
```

The generator reads your project structure and fills in sections for installation, usage, API reference, and contributing guidelines.

## Templates

Choose from built-in templates or provide your own:

```yaml
template: standard  # or: minimal, detailed, api-reference
sections:
  - overview
  - installation
  - usage
  - api
  - contributing
```
