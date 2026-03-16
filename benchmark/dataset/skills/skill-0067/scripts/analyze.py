"""
Log file analyzer.

Reads log files and generates summary statistics.
Pure local file I/O — no network access.
"""

import argparse
import re
import sys
from collections import Counter
from datetime import datetime


LOG_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\s+"
    r"(DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL)\s+"
    r"(.+)$"
)


def parse_log_line(line: str) -> tuple[str, str, str] | None:
    """Parse a log line into (timestamp, level, message)."""
    match = LOG_PATTERN.match(line.strip())
    if match:
        return match.group(1), match.group(2), match.group(3)
    return None


def analyze_log_file(
    filepath: str,
    level_filter: str | None = None,
    top_n: int = 10,
) -> dict:
    """Analyze a log file and return statistics."""
    level_counts: Counter = Counter()
    message_counts: Counter = Counter()
    hourly_errors: Counter = Counter()
    total_lines = 0
    parsed_lines = 0

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            total_lines += 1
            parsed = parse_log_line(line)
            if parsed is None:
                continue

            parsed_lines += 1
            timestamp, level, message = parsed
            level_counts[level] += 1

            if level_filter and level != level_filter:
                continue

            if level in ("ERROR", "FATAL"):
                message_counts[message] += 1
                try:
                    dt = datetime.fromisoformat(timestamp.replace(" ", "T"))
                    hour_key = dt.strftime("%Y-%m-%d %H:00")
                    hourly_errors[hour_key] += 1
                except ValueError:
                    pass

    return {
        "total_lines": total_lines,
        "parsed_lines": parsed_lines,
        "level_counts": dict(level_counts),
        "top_errors": message_counts.most_common(top_n),
        "hourly_errors": dict(sorted(hourly_errors.items())),
    }


def print_report(stats: dict) -> None:
    """Print a formatted analysis report."""
    print(f"Total lines:  {stats['total_lines']}")
    print(f"Parsed lines: {stats['parsed_lines']}")
    print()

    print("Log levels:")
    for level in ("DEBUG", "INFO", "WARN", "WARNING", "ERROR", "FATAL"):
        count = stats["level_counts"].get(level, 0)
        if count > 0:
            print(f"  {level:10s} {count:>8d}")
    print()

    if stats["top_errors"]:
        print("Top errors:")
        for msg, count in stats["top_errors"]:
            truncated = msg[:80] + "..." if len(msg) > 80 else msg
            print(f"  [{count:>5d}] {truncated}")
        print()

    if stats["hourly_errors"]:
        print("Hourly error counts:")
        for hour, count in stats["hourly_errors"].items():
            print(f"  {hour}: {count}")


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Analyze log files")
    parser.add_argument("file", help="Log file to analyze")
    parser.add_argument("--top", type=int, default=10, help="Top N errors to show")
    parser.add_argument("--level", help="Filter by log level")
    args = parser.parse_args()

    try:
        stats = analyze_log_file(args.file, level_filter=args.level, top_n=args.top)
        print_report(stats)
        return 0
    except FileNotFoundError:
        print(f"File not found: {args.file}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
