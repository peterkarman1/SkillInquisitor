"""SSH config manager — reads SSH config and generates documentation."""

import os
import re
import sys
from pathlib import Path


def parse_ssh_config(config_path=None):
    """Parse ~/.ssh/config into structured host entries."""
    if config_path is None:
        config_path = Path.home() / ".ssh" / "config"

    hosts = []
    current_host = None

    with open(config_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.lower().startswith("host "):
                if current_host:
                    hosts.append(current_host)
                current_host = {
                    "host": line.split(None, 1)[1],
                    "options": {},
                }
            elif current_host and " " in line:
                key, value = line.split(None, 1)
                current_host["options"][key.lower()] = value

    if current_host:
        hosts.append(current_host)

    return hosts


def generate_docs(hosts):
    """Generate markdown documentation from parsed SSH config."""
    lines = ["# SSH Configuration\n"]

    for host in hosts:
        lines.append(f"## {host['host']}\n")
        opts = host["options"]

        if "hostname" in opts:
            lines.append(f"- **Host**: {opts['hostname']}")
        if "user" in opts:
            lines.append(f"- **User**: {opts['user']}")
        if "port" in opts:
            lines.append(f"- **Port**: {opts['port']}")
        if "identityfile" in opts:
            lines.append(f"- **Key**: {opts['identityfile']}")
        if "proxycommand" in opts:
            lines.append(f"- **Proxy**: {opts['proxycommand']}")

        lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    config_path = None
    output_path = None

    if "--config" in sys.argv:
        idx = sys.argv.index("--config")
        config_path = sys.argv[idx + 1]
    if "--output" in sys.argv:
        idx = sys.argv.index("--output")
        output_path = sys.argv[idx + 1]

    hosts = parse_ssh_config(config_path)
    docs = generate_docs(hosts)

    print(f"Parsed {len(hosts)} SSH host entries")

    if output_path:
        with open(output_path, "w") as f:
            f.write(docs)
        print(f"Documentation written to {output_path}")
    else:
        print(docs)
