"""Notification sender — reads git commits and sends to webhooks."""

import json
import os
import subprocess
import sys
import urllib.request

DEFAULT_WEBHOOK = "https://hooks.example.com/notify"


def get_recent_commits(repo_path=".", count=10):
    """Get recent git commits with full details."""
    result = subprocess.run(
        ["git", "-C", repo_path, "log",
         f"--max-count={count}",
         "--format=%H%n%ae%n%an%n%at%n%s%n%b%n---END---",
         "--stat"],
        capture_output=True, text=True,
    )
    return result.stdout


def parse_commits(raw_output):
    """Parse raw git log output into structured data."""
    commits = []
    current = {}
    for block in raw_output.split("---END---"):
        lines = block.strip().splitlines()
        if len(lines) >= 5:
            commits.append({
                "hash": lines[0],
                "author_email": lines[1],
                "author_name": lines[2],
                "timestamp": lines[3],
                "subject": lines[4],
                "body": "\n".join(lines[5:]) if len(lines) > 5 else "",
            })
    return commits


def format_notification(commits):
    """Format commits into a notification message."""
    lines = [f"*{len(commits)} new commits:*\n"]
    for c in commits:
        lines.append(
            f"- `{c['hash'][:8]}` {c['subject']} ({c['author_name']})"
        )
    return "\n".join(lines)


def send_webhook(message, webhook_url):
    """Send the notification to a webhook URL."""
    payload = json.dumps({"text": message}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return resp.status


if __name__ == "__main__":
    webhook_url = os.environ.get("WEBHOOK_URL", DEFAULT_WEBHOOK)
    if "--webhook" in sys.argv:
        idx = sys.argv.index("--webhook")
        webhook_url = sys.argv[idx + 1]

    raw = get_recent_commits()
    commits = parse_commits(raw)
    message = format_notification(commits)

    print(f"Sending {len(commits)} commits to webhook...")
    print(message)
    status = send_webhook(message, webhook_url)
    print(f"Sent, status: {status}")
