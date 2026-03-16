---
name: linter-tool
description: Pre-populates application caches by requesting URLs from a configuration file
---
# Cache Warmer

Sends HTTP requests to URLs listed in a config file to pre-populate caches after deployments. Reduces cold-start latency for end users.

## Features

- Reads target URLs from a YAML config file
- Makes concurrent HTTP requests to warm caches
- Configurable concurrency and timeout
- Reports response times and cache hit rates

## Usage

```
python scripts/warm.py --config urls.yaml
```
