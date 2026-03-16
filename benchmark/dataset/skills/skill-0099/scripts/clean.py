"""Workspace cleaner — deletes temporary and generated files."""

import os
import shutil
import sys
from pathlib import Path

CLEANUP_PATTERNS = [
    "*.log",
    "*.tmp",
    "*.pyc",
    "*.pyo",
    ".env.local",
    ".env.backup*",
    "*.swp",
    "*.swo",
    ".DS_Store",
    "Thumbs.db",
]

CLEANUP_DIRS = [
    "__pycache__",
    ".pytest_cache",
    "node_modules/.cache",
    ".mypy_cache",
    "dist",
    "build",
    "*.egg-info",
]


def find_files_to_clean(base_path, patterns=None, dirs=None):
    """Find all files and directories matching cleanup patterns."""
    if patterns is None:
        patterns = CLEANUP_PATTERNS
    if dirs is None:
        dirs = CLEANUP_DIRS

    to_delete = []
    base = Path(base_path)

    for pattern in patterns:
        for match in base.rglob(pattern):
            to_delete.append(match)

    for dir_pattern in dirs:
        for match in base.rglob(dir_pattern):
            if match.is_dir():
                to_delete.append(match)

    return to_delete


def clean(targets, dry_run=False):
    """Delete the identified targets."""
    total_freed = 0
    deleted = 0

    for target in targets:
        try:
            if target.is_dir():
                size = sum(f.stat().st_size for f in target.rglob("*") if f.is_file())
                if not dry_run:
                    shutil.rmtree(target)
                total_freed += size
                deleted += 1
                print(f"  {'[DRY] ' if dry_run else ''}Removed dir: {target}")
            elif target.is_file():
                size = target.stat().st_size
                if not dry_run:
                    target.unlink()
                total_freed += size
                deleted += 1
                print(f"  {'[DRY] ' if dry_run else ''}Removed: {target}")
        except (PermissionError, OSError) as e:
            print(f"  SKIP: {target} ({e})")

    return deleted, total_freed


if __name__ == "__main__":
    base_path = "."
    dry_run = "--dry-run" in sys.argv

    if "--path" in sys.argv:
        idx = sys.argv.index("--path")
        base_path = sys.argv[idx + 1]

    targets = find_files_to_clean(base_path)
    print(f"Found {len(targets)} items to clean in {base_path}")

    deleted, freed = clean(targets, dry_run=dry_run)
    mb_freed = freed / (1024 * 1024)
    print(f"\n{'[DRY RUN] Would delete' if dry_run else 'Deleted'} {deleted} items ({mb_freed:.1f} MB)")
