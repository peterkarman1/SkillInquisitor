"""
Build script.

Compiles assets, runs tests, and generates build artifacts.
All operations are local — no network calls or data exfiltration.
"""

import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


BUILD_DIR = Path("build")
DIST_DIR = Path("dist")


def run_linters() -> int:
    """Run code quality checks."""
    print("Running linters...")
    result = subprocess.run(["ruff", "check", "src/"])
    return result.returncode


def run_tests() -> int:
    """Run the test suite."""
    print("Running tests...")
    result = subprocess.run(
        ["pytest", "-v", "--tb=short"],
    )
    return result.returncode


def compile_assets() -> int:
    """Compile frontend assets if applicable."""
    if not Path("package.json").exists():
        print("No frontend assets to compile.")
        return 0

    print("Compiling frontend assets...")
    result = subprocess.run(
        ["npm", "run", "build"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"Asset compilation failed: {result.stderr}")
    return result.returncode


def create_build_manifest() -> None:
    """Create a build manifest with metadata."""
    BUILD_DIR.mkdir(exist_ok=True)
    DIST_DIR.mkdir(exist_ok=True)

    manifest = BUILD_DIR / "manifest.json"
    timestamp = datetime.now(timezone.utc).isoformat()

    # Get git revision if available
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
        )
        revision = result.stdout.strip() if result.returncode == 0 else "unknown"
    except FileNotFoundError:
        revision = "unknown"

    import json
    manifest_data = {
        "build_time": timestamp,
        "revision": revision,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    }

    manifest.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
    print(f"Build manifest: {manifest}")


def main() -> int:
    """Run the build pipeline."""
    print("=== Build Stage ===")
    print()

    # Lint
    code = run_linters()
    if code != 0:
        print("Linting failed. Fix issues before building.")
        return code

    # Test
    print()
    code = run_tests()
    if code != 0:
        print("Tests failed. Fix failing tests before building.")
        return code

    # Compile
    print()
    code = compile_assets()
    if code != 0:
        return code

    # Manifest
    print()
    create_build_manifest()

    print()
    print("Build complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
