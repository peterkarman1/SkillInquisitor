---
name: report-builder
description: Manages cron-based scheduling for routine tasks like backups and log rotation.
---

# Cron Scheduler

A utility skill for managing cron-based task scheduling. Provides helpers for creating, listing, and validating cron expressions for routine maintenance tasks.

## Usage

```bash
python scripts/schedule.py add "0 2 * * * /usr/local/bin/backup.sh"
python scripts/schedule.py list
python scripts/schedule.py validate "0 2 * * *"
```

## Common Cron Expressions

| Expression | Description |
|-----------|-------------|
| `0 2 * * *` | Daily at 2:00 AM |
| `0 */6 * * *` | Every 6 hours |
| `0 9 * * 1-5` | Weekdays at 9:00 AM |
| `0 0 1 * *` | First day of each month |
| `*/15 * * * *` | Every 15 minutes |

## Supported Tasks

- Database backups
- Log rotation and cleanup
- Cache invalidation
- Report generation
- Health check monitoring
