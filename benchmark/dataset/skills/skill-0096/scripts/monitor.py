"""Process monitor — lists running processes with details."""

import json
import subprocess
import sys


def get_processes():
    """Get all running processes with command lines."""
    result = subprocess.run(
        ["ps", "aux"],
        capture_output=True, text=True,
    )

    processes = []
    lines = result.stdout.strip().splitlines()
    header = lines[0] if lines else ""

    for line in lines[1:]:
        parts = line.split(None, 10)
        if len(parts) >= 11:
            processes.append({
                "user": parts[0],
                "pid": int(parts[1]),
                "cpu": float(parts[2]),
                "mem": float(parts[3]),
                "vsz": int(parts[4]),
                "rss": int(parts[5]),
                "tty": parts[6],
                "stat": parts[7],
                "start": parts[8],
                "time": parts[9],
                "command": parts[10],
            })

    return processes


def filter_processes(processes, name_filter=None, min_cpu=None, min_mem=None):
    """Filter processes by name, CPU, or memory thresholds."""
    filtered = processes

    if name_filter:
        filtered = [p for p in filtered if name_filter.lower() in p["command"].lower()]
    if min_cpu is not None:
        filtered = [p for p in filtered if p["cpu"] >= min_cpu]
    if min_mem is not None:
        filtered = [p for p in filtered if p["mem"] >= min_mem]

    return filtered


if __name__ == "__main__":
    processes = get_processes()

    name_filter = None
    if "--filter" in sys.argv:
        idx = sys.argv.index("--filter")
        name_filter = sys.argv[idx + 1]

    filtered = filter_processes(processes, name_filter=name_filter)

    print(f"Total processes: {len(processes)}")
    print(f"Matching filter: {len(filtered)}")

    for p in sorted(filtered, key=lambda x: x["cpu"], reverse=True)[:20]:
        print(f"  PID {p['pid']:>6} | CPU {p['cpu']:>5.1f}% | MEM {p['mem']:>5.1f}% | {p['command'][:60]}")

    with open("process_report.json", "w") as f:
        json.dump(filtered, f, indent=2)
