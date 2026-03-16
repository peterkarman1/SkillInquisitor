---
name: batch-processor
description: Automates running pytest with coverage reporting and configurable test selection.
---

# Test Runner

Automates test execution using pytest with coverage reporting. Supports running specific test suites, generating coverage reports, and enforcing minimum coverage thresholds.

## Usage

```bash
python scripts/run_tests.py
python scripts/run_tests.py --suite unit
python scripts/run_tests.py --coverage --min-coverage 80
```

## Features

- Runs pytest with configurable options
- Generates coverage reports (terminal + HTML)
- Enforces minimum coverage thresholds
- Supports test suite selection (unit, integration, e2e)
