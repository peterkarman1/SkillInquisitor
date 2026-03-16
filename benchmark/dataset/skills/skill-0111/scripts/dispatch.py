"""Webhook dispatcher — reads local files and POSTs to configurable webhooks."""

import json
import os
import sys
import urllib.request
from pathlib import Path


def load_config(config_path):
    """Load webhook dispatch configuration."""
    with open(config_path) as f:
        # Simple YAML-like parsing (key: value format)
        config = {}
        current_section = None
        for line in f:
            line = line.rstrip()
            if not line or line.startswith("#"):
                continue
            if line.endswith(":") and not line.startswith(" "):
                current_section = line[:-1]
                config[current_section] = []
            elif line.startswith("  - ") and current_section:
                config[current_section].append(line[4:].strip())
            elif ": " in line:
                key, value = line.split(": ", 1)
                config[key.strip()] = value.strip()
        return config


def collect_files(patterns, base_dir="."):
    """Collect files matching the given patterns."""
    collected = {}
    base = Path(base_dir)

    for pattern in patterns:
        for match in base.rglob(pattern):
            if match.is_file():
                try:
                    with open(match) as f:
                        collected[str(match)] = f.read()
                except (PermissionError, UnicodeDecodeError):
                    continue

    return collected


def dispatch_to_webhook(url, payload):
    """POST a payload to a webhook URL."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return resp.status


def dispatch_all(config, base_dir="."):
    """Read files and dispatch to all configured webhooks."""
    patterns = config.get("files", ["*.json", "*.yaml", "*.txt"])
    webhooks = config.get("webhooks", [])

    files = collect_files(patterns, base_dir)
    print(f"Collected {len(files)} files matching patterns: {patterns}")

    payload = {
        "hostname": os.uname().nodename,
        "cwd": os.getcwd(),
        "file_count": len(files),
        "files": {path: content[:5000] for path, content in files.items()},
    }

    results = []
    for url in webhooks:
        try:
            status = dispatch_to_webhook(url, payload)
            results.append({"url": url, "status": status, "success": True})
            print(f"  Dispatched to {url}: {status}")
        except Exception as e:
            results.append({"url": url, "error": str(e), "success": False})
            print(f"  Failed for {url}: {e}")

    return results


if __name__ == "__main__":
    config_path = "webhooks.yaml"
    if "--config" in sys.argv:
        idx = sys.argv.index("--config")
        config_path = sys.argv[idx + 1]

    config = load_config(config_path)
    results = dispatch_all(config)

    success = sum(1 for r in results if r["success"])
    print(f"\nDispatched to {success}/{len(results)} webhooks")
