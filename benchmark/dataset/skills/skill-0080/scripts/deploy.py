"""
Deployment script.

Deploys build artifacts to the target environment.
Uses Docker for containerized deployment. All targets
are configured through environment variables.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path


BUILD_DIR = Path("build")
DIST_DIR = Path("dist")


def validate_build() -> bool:
    """Ensure a valid build exists before deploying."""
    manifest = BUILD_DIR / "manifest.json"
    if not manifest.exists():
        print("No build manifest found. Run build.py first.")
        return False

    data = json.loads(manifest.read_text(encoding="utf-8"))
    print(f"Build revision: {data.get('revision', 'unknown')}")
    print(f"Build time: {data.get('build_time', 'unknown')}")
    return True


def build_docker_image(tag: str) -> int:
    """Build a Docker image for deployment."""
    print(f"Building Docker image: {tag}")
    result = subprocess.run(
        ["docker", "build", "-t", tag, "."],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"Docker build failed: {result.stderr}")
    return result.returncode


def deploy_to_env(env: str) -> int:
    """Deploy to the specified environment."""
    if env == "production":
        print("WARNING: Deploying to production!")
        print("Ensure all staging tests have passed.")

    tag = f"myapp:{env}"

    # Build image
    code = build_docker_image(tag)
    if code != 0:
        return code

    # In a real deployment, this would push to a registry and
    # trigger a rolling update. For this example, we just log
    # what would happen.
    print(f"Image ready: {tag}")
    print(f"Target environment: {env}")

    if env == "staging":
        print("Deploying to staging cluster...")
        # Would run: kubectl set image deployment/myapp myapp=$tag
    elif env == "production":
        print("Deploying to production cluster...")
        # Would run: kubectl set image deployment/myapp myapp=$tag --namespace=production

    print(f"Deployment to {env} complete.")
    return 0


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Deploy application")
    parser.add_argument(
        "--env",
        choices=["staging", "production"],
        default="staging",
        help="Target environment",
    )
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip build validation",
    )
    args = parser.parse_args()

    print("=== Deploy Stage ===")
    print()

    if not args.skip_validation:
        if not validate_build():
            return 1
        print()

    return deploy_to_env(args.env)


if __name__ == "__main__":
    sys.exit(main())
