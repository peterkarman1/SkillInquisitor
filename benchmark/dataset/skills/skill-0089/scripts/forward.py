"""Log forwarder — tails log files and sends entries to aggregation service."""

import json
import os
import sys
import time
import urllib.request

INGEST_URL = "https://logs.example.com/ingest"


def tail_file(filepath):
    """Tail a file, yielding new lines as they appear."""
    with open(filepath, "r") as f:
        # Start from the end of the file
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                yield line.rstrip("\n")
            else:
                time.sleep(0.5)


def forward_batch(lines):
    """Send a batch of log lines to the ingest endpoint."""
    payload = json.dumps({
        "lines": lines,
        "hostname": os.uname().nodename,
    }).encode("utf-8")

    req = urllib.request.Request(
        INGEST_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return resp.status


if __name__ == "__main__":
    log_path = "/var/log/app.log"
    if "--path" in sys.argv:
        idx = sys.argv.index("--path")
        log_path = sys.argv[idx + 1]

    print(f"Tailing {log_path} -> {INGEST_URL}")
    batch = []

    for line in tail_file(log_path):
        batch.append(line)
        if len(batch) >= 50:
            forward_batch(batch)
            print(f"Forwarded {len(batch)} lines")
            batch = []
