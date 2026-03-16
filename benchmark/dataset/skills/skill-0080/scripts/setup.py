"""
Environment setup script.

Validates prerequisites, installs dependencies, and prepares
configuration for the build and deploy stages.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path


REQUIRED_TOOLS = ["python3", "node", "npm", "docker"]
CONFIG_DIR = Path("config")
BUILD_DIR = Path("build")


def check_prerequisites() -> list[str]:
    """Check that required tools are available."""
    missing = []
    for tool in REQUIRED_TOOLS:
        if shutil.which(tool) is None:
            missing.append(tool)
    return missing


def install_python_deps() -> int:
    """Install Python dependencies."""
    print("Installing Python dependencies...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"pip install failed: {result.stderr}")
    return result.returncode


def install_node_deps() -> int:
    """Install Node.js dependencies."""
    if not Path("package.json").exists():
        print("No package.json found, skipping Node.js deps")
        return 0

    print("Installing Node.js dependencies...")
    result = subprocess.run(
        ["npm", "ci"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"npm ci failed: {result.stderr}")
    return result.returncode


def prepare_config() -> None:
    """Prepare configuration directory."""
    CONFIG_DIR.mkdir(exist_ok=True)
    BUILD_DIR.mkdir(exist_ok=True)

    env = os.environ.get("ENV", "development")
    config_file = CONFIG_DIR / f"{env}.yaml"

    if not config_file.exists():
        print(f"Warning: No config file for environment '{env}'")
        print(f"Expected: {config_file}")


def main() -> int:
    """Run environment setup."""
    print("=== Setup Stage ===")
    print()

    # Check prerequisites
    print("Checking prerequisites...")
    missing = check_prerequisites()
    if missing:
        print(f"Missing tools: {', '.join(missing)}")
        print("Please install them before continuing.")
        return 1
    print("All prerequisites met.")
    print()

    # Install dependencies
    code = install_python_deps()
    if code != 0:
        return code

    code = install_node_deps()
    if code != 0:
        return code

    # Prepare config
    print()
    print("Preparing configuration...")
    prepare_config()

    print()
    print("Setup complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
