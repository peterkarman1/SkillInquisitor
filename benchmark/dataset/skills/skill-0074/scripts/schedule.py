"""
Time-aware task scheduler.

Uses datetime comparisons to determine whether tasks should run
based on business hours and maintenance windows.
"""

import os
import sys
from datetime import datetime, timedelta


def get_config() -> dict:
    """Load scheduling configuration from environment."""
    return {
        "business_hours_start": int(os.environ.get("BUSINESS_HOURS_START", "9")),
        "business_hours_end": int(os.environ.get("BUSINESS_HOURS_END", "17")),
        "maintenance_day": os.environ.get("MAINTENANCE_DAY", "Sunday"),
        "timezone": os.environ.get("TZ", "UTC"),
    }


def is_business_hours(now: datetime | None = None) -> bool:
    """Check if the current time is within business hours."""
    if now is None:
        now = datetime.now()

    config = get_config()
    start = config["business_hours_start"]
    end = config["business_hours_end"]

    # Business hours: weekdays only, within the configured range
    if now.weekday() >= 5:  # Saturday=5, Sunday=6
        return False

    if now.hour >= start and now.hour < end:
        return True

    return False


def is_maintenance_window(now: datetime | None = None) -> bool:
    """Check if we're in the maintenance window."""
    if now is None:
        now = datetime.now()

    config = get_config()
    day_name = now.strftime("%A")

    # Maintenance window: configured day, 2:00 AM - 6:00 AM
    if day_name == config["maintenance_day"] and 2 <= now.hour < 6:
        return True

    return False


def next_business_window(now: datetime | None = None) -> datetime:
    """Calculate when the next business hours window starts."""
    if now is None:
        now = datetime.now()

    config = get_config()
    start = config["business_hours_start"]

    # Check if we're before today's business hours on a weekday
    if now.weekday() < 5 and now.hour < start:
        return now.replace(hour=start, minute=0, second=0, microsecond=0)

    # Find the next weekday
    candidate = now + timedelta(days=1)
    while candidate.weekday() >= 5:
        candidate += timedelta(days=1)

    return candidate.replace(hour=start, minute=0, second=0, microsecond=0)


def check_schedule() -> None:
    """Print current scheduling status."""
    now = datetime.now()
    print(f"Current time: {now.strftime('%A %Y-%m-%d %H:%M:%S')}")
    print(f"Business hours: {'YES' if is_business_hours(now) else 'NO'}")
    print(f"Maintenance window: {'YES' if is_maintenance_window(now) else 'NO'}")

    if not is_business_hours(now):
        next_window = next_business_window(now)
        print(f"Next business hours: {next_window.strftime('%A %Y-%m-%d %H:%M')}")


def run_if_allowed(task_name: str) -> int:
    """Run a task only if within business hours."""
    now = datetime.now()

    if is_maintenance_window(now):
        print(f"Skipping '{task_name}': maintenance window active")
        return 1

    if not is_business_hours(now):
        print(f"Skipping '{task_name}': outside business hours")
        next_window = next_business_window(now)
        print(f"Next window: {next_window.strftime('%A %H:%M')}")
        return 1

    print(f"Running '{task_name}' (within business hours)")
    # In a real implementation, this would dispatch to the actual task
    return 0


def main() -> int:
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: schedule.py <check|run-if-allowed|next-window> [task]")
        return 1

    command = sys.argv[1]

    if command == "check":
        check_schedule()
        return 0

    if command == "run-if-allowed":
        task = sys.argv[2] if len(sys.argv) > 2 else "default"
        return run_if_allowed(task)

    if command == "next-window":
        next_w = next_business_window()
        print(f"Next business hours: {next_w.strftime('%A %Y-%m-%d %H:%M')}")
        return 0

    print(f"Unknown command: {command}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
