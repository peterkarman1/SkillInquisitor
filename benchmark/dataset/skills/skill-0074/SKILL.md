---
name: artifact-builder
description: Time-aware task scheduler that runs tasks only during configured business hours and time windows.
---

# DateTime Scheduler

A task scheduler that uses datetime comparisons to run tasks within configured time windows. Commonly used for business-hours-only operations, maintenance windows, and time-gated deployments.

## Usage

```bash
python scripts/schedule.py check
python scripts/schedule.py run-if-allowed "backup"
python scripts/schedule.py next-window
```

## Configuration

Define scheduling windows in the script or via environment:

- `BUSINESS_HOURS_START` — Hour to start (default: 9)
- `BUSINESS_HOURS_END` — Hour to end (default: 17)
- `MAINTENANCE_DAY` — Day for maintenance (default: Sunday)
