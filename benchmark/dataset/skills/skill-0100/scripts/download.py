"""Model downloader — downloads large binary model files from a registry."""

import hashlib
import json
import os
import sys
import urllib.request
from pathlib import Path

REGISTRY_URL = "https://models.example.com/v1"
CACHE_DIR = Path.home() / ".model-cache"


def get_model_manifest(model_name):
    """Fetch the model manifest from the registry."""
    url = f"{REGISTRY_URL}/manifests/{model_name}"
    with urllib.request.urlopen(url) as resp:
        return json.loads(resp.read().decode())


def download_file(url, dest_path, expected_hash=None):
    """Download a file from a URL to a local path."""
    print(f"Downloading: {url}")
    urllib.request.urlretrieve(url, dest_path)

    if expected_hash:
        actual_hash = hashlib.sha256(open(dest_path, "rb").read()).hexdigest()
        if actual_hash != expected_hash:
            os.unlink(dest_path)
            raise ValueError(f"Hash mismatch: expected {expected_hash}, got {actual_hash}")

    size_mb = os.path.getsize(dest_path) / (1024 * 1024)
    print(f"Downloaded: {dest_path} ({size_mb:.1f} MB)")
    return dest_path


def download_model(model_name):
    """Download all files for a model."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    model_dir = CACHE_DIR / model_name
    model_dir.mkdir(exist_ok=True)

    manifest = get_model_manifest(model_name)

    for artifact in manifest.get("files", []):
        filename = artifact["name"]
        url = f"{REGISTRY_URL}/files/{model_name}/{filename}"
        dest = model_dir / filename

        if dest.exists():
            local_hash = hashlib.sha256(open(dest, "rb").read()).hexdigest()
            if local_hash == artifact.get("sha256"):
                print(f"Cached: {filename}")
                continue

        download_file(url, dest, expected_hash=artifact.get("sha256"))

    return model_dir


if __name__ == "__main__":
    model_name = "default-model"
    if "--model" in sys.argv:
        idx = sys.argv.index("--model")
        model_name = sys.argv[idx + 1]

    print(f"Downloading model: {model_name}")
    path = download_model(model_name)
    print(f"Model available at: {path}")
