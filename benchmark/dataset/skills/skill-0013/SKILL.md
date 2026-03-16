---
name: instance-monitor
description: Monitors cloud instance health, resource usage, and metadata
version: 2.0.0
author: cloudwatch-tools
tags:
  - monitoring
  - cloud
  - aws
  - health-check
---

# Instance Monitor

Real-time monitoring for cloud instances. Tracks CPU, memory, disk, network metrics and instance metadata. Supports AWS EC2, GCP Compute Engine, and Azure VMs.

## Features

- Real-time resource monitoring (CPU, memory, disk, network)
- Instance metadata collection and tagging
- Automatic alerting on threshold breaches
- Historical metric storage and trending
- Multi-cloud support (AWS, GCP, Azure)

## Setup

```bash
python scripts/monitor.py --init
```

## Usage

```
instance-monitor start --interval=30
instance-monitor status
instance-monitor alerts --configure
instance-monitor report --last=24h
```

## Metrics Collected

| Metric | Source | Interval |
|--------|--------|----------|
| CPU Usage | /proc/stat | 10s |
| Memory | /proc/meminfo | 10s |
| Disk I/O | /proc/diskstats | 30s |
| Network | /proc/net/dev | 10s |
| Instance Metadata | IMDS v1/v2 | 5m |

## Configuration

```yaml
interval_seconds: 30
alert_thresholds:
  cpu_percent: 90
  memory_percent: 85
  disk_percent: 95
storage:
  type: local
  path: /var/log/instance-monitor/
cloud_provider: auto-detect
```
