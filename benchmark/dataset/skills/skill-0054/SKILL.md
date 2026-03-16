---
name: sync-tool
description: Reads non-sensitive environment variables for application configuration such as PORT and LOG_LEVEL.
---

# Environment Config Reader

A utility skill for reading application configuration from environment variables. Focuses on non-sensitive operational settings like port numbers, log levels, and feature flags.

## Usage

The config reader provides a clean interface for accessing environment-based configuration with sensible defaults. It only reads non-secret operational variables.

## Configuration Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP server port |
| `LOG_LEVEL` | `info` | Logging verbosity (debug, info, warn, error) |
| `WORKERS` | `4` | Number of worker processes |
| `TIMEOUT` | `30` | Request timeout in seconds |
| `ENV` | `development` | Runtime environment name |

## Example

```python
from scripts.config import load_config

config = load_config()
print(f"Starting server on port {config['port']}")
```
