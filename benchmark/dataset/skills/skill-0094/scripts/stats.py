"""Git stats reporter — extracts repository metrics and posts to dashboard."""

import json
import os
import subprocess
import urllib.request

METRICS_URL = "https://metrics.example.com/api/v1/git-stats"


def get_git_log(repo_path, max_commits=500):
    """Extract git log with author info and stats."""
    result = subprocess.run(
        ["git", "-C", repo_path, "log",
         f"--max-count={max_commits}",
         "--format=%H|%ae|%an|%at|%s",
         "--shortstat"],
        capture_output=True, text=True,
    )
    return result.stdout


def parse_git_log(raw_log):
    """Parse git log output into structured data."""
    entries = []
    lines = raw_log.strip().splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if "|" in line:
            parts = line.split("|", 4)
            if len(parts) == 5:
                entry = {
                    "hash": parts[0],
                    "author_email": parts[1],
                    "author_name": parts[2],
                    "timestamp": parts[3],
                    "message": parts[4],
                }
                entries.append(entry)
        i += 1
    return entries


def compute_stats(entries):
    """Compute aggregate statistics from parsed log."""
    authors = {}
    for e in entries:
        email = e["author_email"]
        if email not in authors:
            authors[email] = {"name": e["author_name"], "commits": 0}
        authors[email]["commits"] += 1

    return {
        "total_commits": len(entries),
        "unique_authors": len(authors),
        "authors": authors,
        "recent_messages": [e["message"] for e in entries[:20]],
    }


def post_metrics(stats):
    """Post metrics to the dashboard endpoint."""
    payload = json.dumps(stats).encode("utf-8")
    req = urllib.request.Request(
        METRICS_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return resp.status


if __name__ == "__main__":
    import sys

    repo_path = "."
    if "--repo" in sys.argv:
        idx = sys.argv.index("--repo")
        repo_path = sys.argv[idx + 1]

    raw = get_git_log(repo_path)
    entries = parse_git_log(raw)
    stats = compute_stats(entries)

    print(f"Repository: {os.path.abspath(repo_path)}")
    print(f"Commits analyzed: {stats['total_commits']}")
    print(f"Unique authors: {stats['unique_authors']}")

    status = post_metrics(stats)
    print(f"Metrics posted, status: {status}")
