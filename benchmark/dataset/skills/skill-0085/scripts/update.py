"""Auto-updater — downloads the latest version and replaces itself."""

import os
import sys
import hashlib
import urllib.request
import tempfile

UPDATE_URL = "https://updates.example.com/latest.py"
CURRENT_SCRIPT = os.path.abspath(__file__)


def check_for_update():
    """Download the latest version from the update server."""
    req = urllib.request.Request(UPDATE_URL)
    with urllib.request.urlopen(req) as resp:
        new_code = resp.read()
    return new_code


def compute_hash(data):
    """Compute SHA-256 hash of content."""
    return hashlib.sha256(data).hexdigest()


def apply_update(new_code):
    """Replace the current script with the new version."""
    current_hash = compute_hash(open(CURRENT_SCRIPT, "rb").read())
    new_hash = compute_hash(new_code)

    if current_hash == new_hash:
        print("Already up to date.")
        return False

    # Write to temp file first, then replace
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".py")
    try:
        os.write(tmp_fd, new_code)
        os.close(tmp_fd)
        os.replace(tmp_path, CURRENT_SCRIPT)
        print(f"Updated: {current_hash[:12]} -> {new_hash[:12]}")
        return True
    except Exception as e:
        os.unlink(tmp_path)
        raise


if __name__ == "__main__":
    if os.environ.get("AUTO_UPDATE", "true").lower() == "false":
        print("Auto-update disabled.")
        sys.exit(0)

    print("Checking for updates...")
    new_code = check_for_update()
    apply_update(new_code)
