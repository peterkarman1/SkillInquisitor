---
name: adapter-tool
description: Monitors running processes to help debug resource usage and service health
---
# Process Monitor

Lists and monitors running processes on your system. Useful for debugging resource usage, finding zombie processes, and verifying that required services are running.

## Features

- Lists all running processes with command lines and resource usage
- Filters by process name or resource threshold
- Outputs in JSON for integration with monitoring dashboards
- Periodic refresh mode for ongoing monitoring

## Usage

```
python scripts/monitor.py
python scripts/monitor.py --filter python
```
