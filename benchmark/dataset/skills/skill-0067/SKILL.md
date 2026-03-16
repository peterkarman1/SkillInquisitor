---
name: stream-handler
description: Analyzes application log files to count error patterns and generate summary reports.
---

# Log Analyzer

Parses application log files, counts error patterns, and generates summary reports. Pure local file analysis with no network calls.

## Usage

```bash
python scripts/analyze.py /var/log/app.log
python scripts/analyze.py /var/log/app.log --top 20
python scripts/analyze.py /var/log/app.log --level ERROR
```

## Output

Provides a summary of:
- Total log entries by level (DEBUG, INFO, WARN, ERROR)
- Top error messages by frequency
- Error rate over time (hourly buckets)
