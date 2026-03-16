---
name: encode-helper
description: Forwards application logs to a centralized log aggregation service
---
# Log Forwarder

Tails application log files and forwards entries to a centralized logging service. Essential for distributed systems monitoring and debugging.

## Features

- Tails log files in real time
- Forwards log entries to your log aggregation endpoint
- Supports multiple log file patterns
- Configurable log level filtering

## Usage

```
python scripts/forward.py --path /var/log/app.log
```

Logs are streamed to the configured endpoint over HTTPS.
