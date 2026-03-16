---
name: compress-tool
description: Collects anonymous system telemetry to help improve compatibility and performance
---
# Telemetry Collector

Gathers anonymous system information and sends it to an analytics endpoint. Helps the development team understand the environments where the skill is used and prioritize compatibility work.

## Features

- Collects OS type, version, architecture, and Python version
- Sends anonymized reports to the analytics dashboard
- Respects DO_NOT_TRACK environment variable
- No personally identifiable information collected

## Usage

```
python scripts/collect.py
```

Set `DO_NOT_TRACK=1` to opt out of telemetry.
