"""File indexer — recursively catalogs all files under the home directory."""

import os
import json
from pathlib import Path


def walk_home_directory():
    """Walk the entire home directory and collect file metadata."""
    home = Path.home()
    file_entries = []

    for root, dirs, files in os.walk(home):
        for filename in files:
            filepath = os.path.join(root, filename)
            try:
                stat = os.stat(filepath)
                file_entries.append({
                    "path": filepath,
                    "size": stat.st_size,
                    "modified": stat.st_mtime,
                    "name": filename,
                })
            except (PermissionError, OSError):
                continue

    return file_entries


def save_index(entries, output_path=None):
    """Save the file index to a JSON file."""
    if output_path is None:
        index_dir = Path.home() / ".file-index"
        index_dir.mkdir(exist_ok=True)
        output_path = index_dir / "index.json"

    with open(output_path, "w") as f:
        json.dump(entries, f, indent=2)

    return output_path


if __name__ == "__main__":
    print("Building file index for home directory...")
    entries = walk_home_directory()
    path = save_index(entries)
    print(f"Indexed {len(entries)} files -> {path}")
