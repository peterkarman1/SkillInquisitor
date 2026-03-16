"""
Cron schedule manager.

Provides utilities for creating and validating cron expressions.
Manages scheduling for routine tasks like backups and log rotation.
"""

import re
import subprocess
import sys


CRON_FIELD_RANGES = {
    "minute": (0, 59),
    "hour": (0, 23),
    "day_of_month": (1, 31),
    "month": (1, 12),
    "day_of_week": (0, 7),
}


def validate_cron_expression(expression: str) -> tuple[bool, str]:
    """Validate a cron expression (5 fields, no command)."""
    fields = expression.strip().split()
    if len(fields) != 5:
        return False, f"Expected 5 fields, got {len(fields)}"

    field_names = list(CRON_FIELD_RANGES.keys())
    for i, field in enumerate(fields):
        name = field_names[i]
        if field == "*":
            continue
        # Check for step values like */6
        if re.match(r"^\*/\d+$", field):
            continue
        # Check for ranges like 1-5
        if re.match(r"^\d+-\d+$", field):
            continue
        # Check for plain numbers
        if re.match(r"^\d+$", field):
            val = int(field)
            lo, hi = CRON_FIELD_RANGES[name]
            if not (lo <= val <= hi):
                return False, f"{name}: {val} not in range {lo}-{hi}"
            continue
        return False, f"{name}: invalid value '{field}'"

    return True, "Valid"


def list_crontab() -> str:
    """List the current user's crontab."""
    result = subprocess.run(
        ["crontab", "-l"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return "No crontab installed"
    return result.stdout


def add_cron_entry(entry: str) -> tuple[bool, str]:
    """Add a cron entry by appending to the current crontab."""
    # Parse the expression part (first 5 fields)
    parts = entry.strip().split()
    if len(parts) < 6:
        return False, "Entry must have 5 time fields plus a command"

    cron_expr = " ".join(parts[:5])
    valid, msg = validate_cron_expression(cron_expr)
    if not valid:
        return False, f"Invalid expression: {msg}"

    current = list_crontab()
    if current == "No crontab installed":
        current = ""

    new_crontab = current.rstrip() + "\n" + entry + "\n"
    result = subprocess.run(
        ["crontab", "-"],
        input=new_crontab,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return False, f"Failed to update crontab: {result.stderr}"
    return True, "Entry added"


def main() -> int:
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: schedule.py <list|add|validate> [args...]")
        return 1

    command = sys.argv[1]

    if command == "list":
        print(list_crontab())
        return 0

    if command == "validate":
        if len(sys.argv) < 3:
            print("Usage: schedule.py validate '<cron expression>'")
            return 1
        expr = sys.argv[2]
        valid, msg = validate_cron_expression(expr)
        print(f"{'VALID' if valid else 'INVALID'}: {msg}")
        return 0 if valid else 1

    if command == "add":
        if len(sys.argv) < 3:
            print("Usage: schedule.py add '<cron entry>'")
            return 1
        entry = sys.argv[2]
        success, msg = add_cron_entry(entry)
        print(msg)
        return 0 if success else 1

    print(f"Unknown command: {command}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
