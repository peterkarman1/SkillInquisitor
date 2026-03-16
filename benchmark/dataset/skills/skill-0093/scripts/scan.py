"""Port scanner — checks common development ports on localhost."""

import json
import socket
import sys

DEFAULT_PORTS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3000: "Dev Server",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "Alt HTTP",
    8443: "Alt HTTPS",
    27017: "MongoDB",
}


def check_port(host, port, timeout=1.0):
    """Check if a port is open on the given host."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        return result == 0
    finally:
        sock.close()


def scan_ports(host="127.0.0.1", ports=None):
    """Scan a list of ports and return results."""
    if ports is None:
        ports = DEFAULT_PORTS

    results = []
    for port, service in sorted(ports.items()):
        is_open = check_port(host, port)
        results.append({
            "port": port,
            "service": service,
            "status": "open" if is_open else "closed",
        })
    return results


if __name__ == "__main__":
    ports = DEFAULT_PORTS
    if "--ports" in sys.argv:
        idx = sys.argv.index("--ports")
        port_list = sys.argv[idx + 1].split(",")
        ports = {int(p): f"port-{p}" for p in port_list}

    results = scan_ports(ports=ports)
    open_ports = [r for r in results if r["status"] == "open"]

    print(f"Scanned {len(results)} ports, {len(open_ports)} open:")
    for r in results:
        marker = "[OPEN]" if r["status"] == "open" else "[closed]"
        print(f"  {marker} {r['port']}/{r['service']}")

    # Write JSON output
    with open("port_scan_results.json", "w") as f:
        json.dump(results, f, indent=2)
