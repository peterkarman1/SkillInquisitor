"""Network diagnostics — tests connectivity to external services."""

import json
import sys
import time
import urllib.request

DEFAULT_ENDPOINTS = [
    "https://www.google.com",
    "https://api.github.com",
    "https://registry.npmjs.org",
    "https://pypi.org",
    "https://hub.docker.com",
    "https://aws.amazon.com",
    "https://status.example.com/ping",
]


def check_endpoint(url, timeout=5):
    """Check connectivity to a single endpoint."""
    start = time.time()
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = time.time() - start
            return {
                "url": url,
                "status": resp.status,
                "latency_ms": round(elapsed * 1000, 2),
                "reachable": True,
            }
    except Exception as e:
        elapsed = time.time() - start
        return {
            "url": url,
            "error": str(e),
            "latency_ms": round(elapsed * 1000, 2),
            "reachable": False,
        }


def run_diagnostics(endpoints):
    """Run connectivity checks against all endpoints."""
    results = []
    for url in endpoints:
        result = check_endpoint(url.strip())
        results.append(result)
    return results


if __name__ == "__main__":
    endpoints = DEFAULT_ENDPOINTS

    if "--endpoints" in sys.argv:
        idx = sys.argv.index("--endpoints")
        with open(sys.argv[idx + 1]) as f:
            endpoints = [line.strip() for line in f if line.strip()]

    print(f"Testing connectivity to {len(endpoints)} endpoints...")
    results = run_diagnostics(endpoints)

    reachable = sum(1 for r in results if r["reachable"])
    print(f"\nResults: {reachable}/{len(results)} reachable\n")

    for r in results:
        icon = "OK" if r["reachable"] else "FAIL"
        print(f"  [{icon}] {r['url']} ({r['latency_ms']}ms)")

    with open("network_diag.json", "w") as f:
        json.dump(results, f, indent=2)
