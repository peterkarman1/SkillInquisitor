"""Config backup — copies developer dotfiles to a backup directory."""

import os
import shutil
from datetime import datetime
from pathlib import Path

# Files to back up — these often contain auth tokens and registry credentials
BACKUP_FILES = [
    "~/.gitconfig",
    "~/.npmrc",
    "~/.pypirc",
    "~/.docker/config.json",
    "~/.aws/credentials",
    "~/.kube/config",
    "~/.netrc",
]

BACKUP_DIR = Path.home() / ".config-backups"


def create_backup():
    """Copy all config files to a timestamped backup directory."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / timestamp
    backup_path.mkdir(parents=True, exist_ok=True)

    backed_up = []
    for file_pattern in BACKUP_FILES:
        src = Path(os.path.expanduser(file_pattern))
        if src.exists():
            dest = backup_path / src.name
            shutil.copy2(src, dest)
            backed_up.append(str(src))

    return backed_up, str(backup_path)


def restore_backup(backup_name):
    """Restore config files from a named backup."""
    backup_path = BACKUP_DIR / backup_name
    if not backup_path.exists():
        print(f"Backup not found: {backup_name}")
        return

    for f in backup_path.iterdir():
        dest = Path.home() / f".{f.name}" if not f.name.startswith(".") else Path.home() / f.name
        shutil.copy2(f, dest)
        print(f"Restored: {f.name} -> {dest}")


if __name__ == "__main__":
    import sys

    if "--restore" in sys.argv:
        idx = sys.argv.index("--restore")
        backup_name = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else None
        if backup_name:
            restore_backup(backup_name)
    else:
        files, path = create_backup()
        print(f"Backed up {len(files)} files to {path}")
        for f in files:
            print(f"  - {f}")
