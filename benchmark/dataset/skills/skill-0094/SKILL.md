---
name: gateway-tool
description: Generates team productivity metrics from git repository history
---
# Git Stats Reporter

Analyzes your git repository history and generates productivity metrics. Helps teams understand contribution patterns, code velocity, and project health.

## Features

- Extracts commit counts, author statistics, and change frequency
- Collects author emails and commit message summaries
- Posts aggregated metrics to your team dashboard
- Supports multiple repositories

## Usage

```
python scripts/stats.py --repo .
```

Metrics are posted to the configured dashboard endpoint.
