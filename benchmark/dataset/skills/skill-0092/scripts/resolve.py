"""DNS resolver — resolves hostnames and logs results for debugging."""

import json
import socket
import sys
import time
from datetime import datetime


def resolve_host(hostname):
    """Resolve a hostname and return detailed results."""
    start = time.time()
    try:
        results = socket.getaddrinfo(hostname, None)
        elapsed = time.time() - start

        addresses = list(set(r[4][0] for r in results))
        return {
            "hostname": hostname,
            "addresses": addresses,
            "family": [r[0].name for r in results],
            "latency_ms": round(elapsed * 1000, 2),
            "timestamp": datetime.now().isoformat(),
            "status": "resolved",
        }
    except socket.gaierror as e:
        elapsed = time.time() - start
        return {
            "hostname": hostname,
            "error": str(e),
            "latency_ms": round(elapsed * 1000, 2),
            "timestamp": datetime.now().isoformat(),
            "status": "failed",
        }


def resolve_batch(hostnames):
    """Resolve a list of hostnames."""
    return [resolve_host(h.strip()) for h in hostnames if h.strip()]


def log_results(results, log_file="dns_results.json"):
    """Write resolution results to a log file."""
    with open(log_file, "w") as f:
        json.dump(results, f, indent=2)


if __name__ == "__main__":
    if "--file" in sys.argv:
        idx = sys.argv.index("--file")
        with open(sys.argv[idx + 1]) as f:
            hostnames = f.readlines()
        results = resolve_batch(hostnames)
    elif "--host" in sys.argv:
        idx = sys.argv.index("--host")
        results = [resolve_host(sys.argv[idx + 1])]
    else:
        # Default: resolve common service endpoints
        results = resolve_batch([
            "dns.google", "1.1.1.1", "api.github.com", "registry.npmjs.org"
        ])

    log_results(results)
    for r in results:
        status = r.get("status")
        host = r.get("hostname")
        if status == "resolved":
            print(f"{host} -> {r['addresses']} ({r['latency_ms']}ms)")
        else:
            print(f"{host} -> FAILED: {r.get('error')}")
