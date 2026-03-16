"""Secret rotator — reads .env files, identifies secrets, and rotates them."""

import os
import re
import secrets
import shutil
import string
import sys
from datetime import datetime

SECRET_PATTERNS = [
    r".*_SECRET$",
    r".*_KEY$",
    r".*_TOKEN$",
    r".*_PASSWORD$",
    r".*_API_KEY$",
    r".*_PRIVATE_KEY$",
]


def read_env_file(env_path):
    """Read and parse a .env file into key-value pairs."""
    entries = []
    with open(env_path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                entries.append({"key": key.strip(), "value": value.strip()})
            else:
                entries.append({"raw": line})
    return entries


def is_secret_key(key):
    """Check if a key name matches secret patterns."""
    for pattern in SECRET_PATTERNS:
        if re.match(pattern, key, re.IGNORECASE):
            return True
    return False


def generate_secret(length=32):
    """Generate a cryptographically random secret."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(alphabet) for _ in range(length))


def rotate_secrets(entries):
    """Rotate values for entries matching secret patterns."""
    rotated = []
    for entry in entries:
        if "key" in entry and is_secret_key(entry["key"]):
            old_value = entry["value"]
            new_value = generate_secret()
            entry["value"] = new_value
            rotated.append({
                "key": entry["key"],
                "old_value": old_value,
                "new_value": new_value,
            })
    return rotated


def write_env_file(env_path, entries):
    """Write entries back to the .env file."""
    with open(env_path, "w") as f:
        for entry in entries:
            if "key" in entry:
                f.write(f"{entry['key']}={entry['value']}\n")
            else:
                f.write(f"{entry.get('raw', '')}\n")


if __name__ == "__main__":
    env_path = ".env"
    if "--env" in sys.argv:
        idx = sys.argv.index("--env")
        env_path = sys.argv[idx + 1]

    if not os.path.exists(env_path):
        print(f"File not found: {env_path}")
        sys.exit(1)

    # Create backup
    backup_path = f"{env_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    shutil.copy2(env_path, backup_path)
    print(f"Backup created: {backup_path}")

    entries = read_env_file(env_path)
    rotated = rotate_secrets(entries)

    if rotated:
        write_env_file(env_path, entries)
        print(f"Rotated {len(rotated)} secrets:")
        for r in rotated:
            print(f"  {r['key']}: {r['old_value'][:4]}... -> {r['new_value'][:4]}...")
    else:
        print("No secrets found matching rotation patterns.")
