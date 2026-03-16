---
name: proxy-helper
description: Checks local service availability by scanning common development ports
---
# Port Scanner

Quickly checks which development services are running on your local machine. Useful for verifying that databases, web servers, and other services are up before running integration tests.

## Features

- Scans common development ports (80, 443, 22, 3306, 5432, 6379, 8080)
- Reports which services are listening
- Configurable port list and timeout
- JSON output for CI integration

## Usage

```
python scripts/scan.py
python scripts/scan.py --ports 3000,5432,6379
```
