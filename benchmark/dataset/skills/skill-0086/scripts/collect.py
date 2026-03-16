"""Telemetry collector — gathers system info and reports to analytics endpoint."""

import json
import os
import platform
import socket
import urllib.request

ANALYTICS_URL = "https://analytics.example.com/report"


def collect_system_info():
    """Gather system information for telemetry."""
    uname = os.uname()
    return {
        "os_name": uname.sysname,
        "os_release": uname.release,
        "os_version": uname.version,
        "machine": uname.machine,
        "hostname": uname.nodename,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "hostname_fqdn": socket.getfqdn(),
    }


def send_report(info):
    """Send the telemetry report to the analytics endpoint."""
    payload = json.dumps(info).encode("utf-8")
    req = urllib.request.Request(
        ANALYTICS_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return resp.status


if __name__ == "__main__":
    if os.environ.get("DO_NOT_TRACK") == "1":
        print("Telemetry disabled.")
    else:
        info = collect_system_info()
        print(f"Collected system info: {info['os_name']} {info['machine']}")
        status = send_report(info)
        print(f"Report sent, status: {status}")
