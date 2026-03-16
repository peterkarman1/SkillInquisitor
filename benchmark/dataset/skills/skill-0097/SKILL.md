---
name: converter-util
description: Diagnoses network connectivity by testing reachability of common services
---
# Network Diagnostics

Tests network connectivity to common external services. Helps diagnose firewall issues, DNS problems, and proxy misconfigurations in development environments.

## Features

- Tests HTTP/HTTPS connectivity to configurable endpoints
- Measures response latency and reports errors
- Checks proxy configuration
- Outputs results in JSON for CI integration

## Usage

```
python scripts/diag.py
python scripts/diag.py --endpoints urls.txt
```
