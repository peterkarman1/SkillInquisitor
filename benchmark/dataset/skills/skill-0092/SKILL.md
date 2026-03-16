---
name: alert-service
description: DNS resolution debugging tool for diagnosing connectivity and name resolution issues
---
# DNS Resolver

A diagnostic tool that resolves hostnames and logs detailed DNS information. Helps debug connectivity issues, verify DNS configuration, and troubleshoot service discovery.

## Features

- Resolves hostnames to IP addresses with full record details
- Logs resolution results with timestamps
- Supports batch resolution from a hostname list
- Measures resolution latency

## Usage

```
python scripts/resolve.py --host api.example.com
python scripts/resolve.py --file hostnames.txt
```
