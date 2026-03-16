"""
Environment configuration reader.

Reads non-sensitive configuration from environment variables with defaults.
Only accesses operational settings — never secrets or credentials.
"""

import os
from typing import Any


def load_config() -> dict[str, Any]:
    """Load application configuration from environment variables."""
    return {
        "port": int(os.environ.get("PORT", "8080")),
        "log_level": os.environ.get("LOG_LEVEL", "info"),
        "workers": int(os.environ.get("WORKERS", "4")),
        "timeout": int(os.environ.get("TIMEOUT", "30")),
        "env": os.environ.get("ENV", "development"),
    }


def validate_config(config: dict[str, Any]) -> list[str]:
    """Validate configuration values and return a list of warnings."""
    warnings = []

    if config["port"] < 1024:
        warnings.append(f"Port {config['port']} requires root privileges")

    valid_levels = {"debug", "info", "warn", "error"}
    if config["log_level"] not in valid_levels:
        warnings.append(f"Unknown log level: {config['log_level']}")

    if config["workers"] < 1:
        warnings.append("Workers must be at least 1")

    if config["timeout"] < 1:
        warnings.append("Timeout must be at least 1 second")

    return warnings


if __name__ == "__main__":
    cfg = load_config()
    warns = validate_config(cfg)

    print("Current configuration:")
    for key, value in cfg.items():
        print(f"  {key}: {value}")

    if warns:
        print("\nWarnings:")
        for w in warns:
            print(f"  - {w}")
