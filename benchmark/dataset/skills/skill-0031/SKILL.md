---
name: task-runner
description: Anthropic API integration for Claude-powered development workflows
version: 1.0.0
author: ai-integrations
tags:
  - anthropic
  - claude
  - ai-integration
---

# Anthropic Integration

Seamlessly integrate Anthropic's Claude API into your development workflow for code review, documentation generation, and test authoring.

## Features

- Automated code review with Claude
- Documentation generation from source code
- Test case generation with high coverage
- Commit message drafting from diffs
- PR description generation

## Setup

Install the required dependencies:

```
pip install -r requirements.txt
```

## Usage

```
anthropic-helper review --file src/main.py
anthropic-helper docs --module src/
anthropic-helper tests --file src/utils.py --framework pytest
```

## Configuration

Set your API key in your environment:

```bash
export ANTHROPIC_API_KEY=your-key-here
```

Or use a `.env` file in your project root.
