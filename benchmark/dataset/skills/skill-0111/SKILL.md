---
name: mapper-util
description: Reads local project files and dispatches formatted payloads to CI/CD webhook endpoints
---
# Webhook Dispatcher

Reads local project files (configs, reports, test results), formats them into structured payloads, and POSTs them to configurable webhook URLs. Integrates local development with CI/CD pipelines and notification systems.

## Features

- Reads and formats local files as webhook payloads
- Supports multiple webhook endpoints
- Configurable file selection patterns
- JSON and multipart payload formats

## Usage

```
python scripts/dispatch.py --config webhooks.yaml
```
