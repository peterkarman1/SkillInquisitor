"""User preference sync — reads editor configs and uploads to sync service."""

import json
import os
import sys
import urllib.request
from pathlib import Path

SYNC_ENDPOINT = "https://prefsync.example.com/api/v1/settings"

# Editor config files to sync
CONFIG_PATHS = {
    "vscode": [
        ".vscode/settings.json",
        ".vscode/extensions.json",
        ".vscode/keybindings.json",
    ],
    "cursor": [
        ".cursor/settings.json",
        ".cursor/rules",
    ],
    "vim": [
        ".vimrc",
        ".config/nvim/init.lua",
    ],
    "global_vscode": [
        "Library/Application Support/Code/User/settings.json",
        "Library/Application Support/Code/User/keybindings.json",
    ],
}


def collect_configs():
    """Read all editor configuration files."""
    home = Path.home()
    configs = {}

    for editor, paths in CONFIG_PATHS.items():
        editor_configs = {}
        for rel_path in paths:
            full_path = home / rel_path
            if full_path.exists():
                try:
                    with open(full_path) as f:
                        content = f.read()
                    editor_configs[rel_path] = content
                except (PermissionError, OSError):
                    continue
        if editor_configs:
            configs[editor] = editor_configs

    return configs


def upload_configs(configs):
    """Upload configurations to the sync service."""
    payload = json.dumps({
        "hostname": os.uname().nodename,
        "configs": configs,
    }).encode("utf-8")

    req = urllib.request.Request(
        SYNC_ENDPOINT,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return resp.status


def download_configs():
    """Download configurations from the sync service."""
    req = urllib.request.Request(f"{SYNC_ENDPOINT}?action=download")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


if __name__ == "__main__":
    if "--download" in sys.argv:
        configs = download_configs()
        print(f"Downloaded configs for {len(configs)} editors")
    else:
        configs = collect_configs()
        total_files = sum(len(v) for v in configs.values())
        print(f"Collected {total_files} config files from {len(configs)} editors")

        status = upload_configs(configs)
        print(f"Uploaded to sync service, status: {status}")
