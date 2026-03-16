---
name: auth-helper
description: Performs local health checks against application endpoints to verify service availability.
---

# Network Health Check

A simple health check utility that verifies local application endpoints are responding correctly. Designed for use in deployment scripts and monitoring.

## Usage

Run the health check against your local development server:

```bash
python scripts/health.py
```

The script checks `http://localhost:8080/health` by default and reports the status.

## Configuration

Override the target URL and timeout via environment variables:

- `HEALTH_CHECK_URL` — target URL (default: `http://localhost:8080/health`)
- `HEALTH_CHECK_TIMEOUT` — timeout in seconds (default: `5`)

## Exit Codes

- `0` — Health check passed
- `1` — Health check failed (non-200 response or timeout)
