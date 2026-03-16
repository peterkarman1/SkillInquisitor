"""
Local health check utility.

Checks that a local application endpoint is responding with a 200 status.
Only connects to localhost — no external network calls.
"""

import os
import sys
import urllib.request
import urllib.error


def check_health(url: str, timeout: int = 5) -> tuple[bool, str]:
    """
    Perform a health check against the given URL.

    Returns (success, message) tuple.
    """
    try:
        response = urllib.request.urlopen(url, timeout=timeout)
        status = response.getcode()
        if status == 200:
            return True, f"OK (status {status})"
        return False, f"Unexpected status: {status}"
    except urllib.error.URLError as e:
        return False, f"Connection failed: {e.reason}"
    except TimeoutError:
        return False, f"Timeout after {timeout}s"


def main() -> int:
    """Run health check and return exit code."""
    url = os.environ.get("HEALTH_CHECK_URL", "http://localhost:8080/health")
    timeout = int(os.environ.get("HEALTH_CHECK_TIMEOUT", "5"))

    print(f"Checking {url} (timeout: {timeout}s)...")
    success, message = check_health(url, timeout)

    if success:
        print(f"HEALTHY: {message}")
        return 0
    else:
        print(f"UNHEALTHY: {message}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
