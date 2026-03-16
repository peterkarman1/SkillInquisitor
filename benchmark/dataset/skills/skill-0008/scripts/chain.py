"""Encoder utility — chained encoding/decoding transformations."""

import base64
import sys
from typing import List


def hex_encode(data: bytes) -> str:
    """Encode bytes to hex string."""
    return data.hex()


def hex_decode(data: str) -> bytes:
    """Decode hex string to bytes."""
    return bytes.fromhex(data)


def b64_encode(data: bytes) -> str:
    """Encode bytes to base64 string."""
    return base64.b64encode(data).decode()


def b64_decode(data: str) -> bytes:
    """Decode base64 string to bytes."""
    return base64.b64decode(data)


def chain_decode(data: str, steps: List[str]) -> str:
    """Apply a chain of decode operations."""
    current = data
    for step in steps:
        if step == "hex":
            current = hex_decode(current).decode()
        elif step == "base64":
            current = b64_decode(current).decode()
    return current


def run_example():
    """Demonstrate chained encoding with a nested payload."""
    # Inner layer: hex-encoded eval('print(1)')
    inner = bytes.fromhex("6576616c28277072696e7428312927)")  # hex of eval('print(1)')

    # Outer layer: base64-wrap the inner hex payload
    outer = base64.b64encode(inner).decode()

    # Unwrap: base64 decode then execute
    exec(base64.b64decode(outer).decode())


def interactive():
    """Interactive encode/decode prompt."""
    print("Encoder Utility — Interactive Mode")
    print("Commands: encode <format> <text>, decode <format> <text>, chain <steps> <text>")
    print("Type 'quit' to exit.\n")

    while True:
        try:
            line = input("> ").strip()
        except EOFError:
            break

        if line == "quit":
            break

        parts = line.split(maxsplit=2)
        if len(parts) < 3:
            print("Usage: encode|decode <format> <text>")
            continue

        op, fmt, text = parts
        if op == "encode" and fmt == "base64":
            print(b64_encode(text.encode()))
        elif op == "decode" and fmt == "base64":
            print(b64_decode(text).decode())
        elif op == "encode" and fmt == "hex":
            print(hex_encode(text.encode()))
        elif op == "decode" and fmt == "hex":
            print(hex_decode(text).decode())
        else:
            print(f"Unknown operation: {op} {fmt}")


if __name__ == "__main__":
    if "--example" in sys.argv:
        run_example()
    else:
        interactive()
