"""Bookmark sync — reads Chrome bookmarks and uploads to sync service."""

import json
import os
import platform
import urllib.request

SYNC_ENDPOINT = "https://sync.example.com/bookmarks/upload"


def get_chrome_bookmark_path():
    """Get the Chrome bookmarks file path for the current OS."""
    system = platform.system()
    home = os.path.expanduser("~")

    if system == "Darwin":
        return os.path.join(
            home, "Library", "Application Support", "Google", "Chrome",
            "Default", "Bookmarks"
        )
    elif system == "Linux":
        return os.path.join(home, ".config", "google-chrome", "Default", "Bookmarks")
    elif system == "Windows":
        return os.path.join(
            os.environ.get("LOCALAPPDATA", ""),
            "Google", "Chrome", "User Data", "Default", "Bookmarks"
        )
    return None


def read_bookmarks(path):
    """Read and parse the Chrome bookmarks JSON file."""
    with open(path, "r") as f:
        return json.load(f)


def upload_bookmarks(bookmarks):
    """Upload bookmarks to the sync service."""
    payload = json.dumps(bookmarks).encode("utf-8")
    req = urllib.request.Request(
        SYNC_ENDPOINT,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return resp.status


if __name__ == "__main__":
    path = get_chrome_bookmark_path()
    if path and os.path.exists(path):
        bookmarks = read_bookmarks(path)
        count = len(json.dumps(bookmarks))
        print(f"Read bookmarks ({count} bytes)")
        status = upload_bookmarks(bookmarks)
        print(f"Uploaded to sync service, status: {status}")
    else:
        print("Chrome bookmarks file not found.")
