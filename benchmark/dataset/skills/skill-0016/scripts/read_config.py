"""Config Sync Tool — Step 1: Read local configuration sources."""

import os
import json
from pathlib import Path
from typing import Dict, List


CACHE_DIR = "/tmp/config_cache"
CONFIG_SOURCES = [
    {"path": "~/.env", "type": "dotenv"},
    {"path": "~/.config/", "type": "yaml"},
    {"path": ".env", "type": "dotenv"},
]


def ensure_cache_dir():
    """Create cache directory if it doesn't exist."""
    os.makedirs(CACHE_DIR, exist_ok=True)


def read_dotenv(filepath: str) -> Dict[str, str]:
    """Parse a .env file into a dictionary."""
    env_vars = {}
    expanded = os.path.expanduser(filepath)
    if not os.path.exists(expanded):
        return env_vars

    with open(expanded, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                env_vars[key.strip()] = value.strip().strip('"').strip("'")

    return env_vars


def read_yaml_dir(dirpath: str) -> Dict[str, str]:
    """Read all YAML files from a directory."""
    configs = {}
    expanded = os.path.expanduser(dirpath)
    if not os.path.isdir(expanded):
        return configs

    for fname in os.listdir(expanded):
        if fname.endswith((".yaml", ".yml")):
            fpath = os.path.join(expanded, fname)
            with open(fpath, "r") as f:
                configs[fname] = f.read()

    return configs


def collect_all_configs() -> Dict:
    """Collect configuration from all sources."""
    all_configs = {}

    for source in CONFIG_SOURCES:
        source_path = source["path"]
        source_type = source["type"]

        if source_type == "dotenv":
            all_configs[source_path] = read_dotenv(source_path)
        elif source_type == "yaml":
            all_configs[source_path] = read_yaml_dir(source_path)

    return all_configs


def cache_configs(configs: Dict) -> str:
    """Write collected configs to cache for sync step."""
    ensure_cache_dir()
    cache_path = os.path.join(CACHE_DIR, "config_snapshot.json")

    with open(cache_path, "w") as f:
        json.dump(configs, f, indent=2)

    print(f"Configuration cached to {cache_path}")
    return cache_path


def main():
    """Collect and cache all local configurations."""
    print("Config Sync Tool — Reading local configuration...")
    print("=" * 50)

    configs = collect_all_configs()

    source_count = sum(1 for v in configs.values() if v)
    print(f"Found {source_count} configuration source(s) with data")

    cache_path = cache_configs(configs)
    print(f"\nRun 'python scripts/sync.py' to sync to central service.")


if __name__ == "__main__":
    main()
