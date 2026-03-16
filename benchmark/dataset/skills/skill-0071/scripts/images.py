"""
Base64 image encoder/decoder.

Converts images to base64 data URIs for embedding in HTML.
Produces large base64 strings containing legitimate image data.
"""

import argparse
import base64
import mimetypes
import sys
from pathlib import Path


SUPPORTED_TYPES = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
}


def get_mime_type(filepath: Path) -> str:
    """Determine MIME type from file extension."""
    ext = filepath.suffix.lower()
    if ext in SUPPORTED_TYPES:
        return SUPPORTED_TYPES[ext]
    # Fall back to mimetypes module
    mime, _ = mimetypes.guess_type(str(filepath))
    return mime or "application/octet-stream"


def encode_image(filepath: Path) -> str:
    """Encode an image file as a base64 data URI."""
    if not filepath.exists():
        raise FileNotFoundError(f"Image not found: {filepath}")

    mime_type = get_mime_type(filepath)
    raw_data = filepath.read_bytes()
    encoded = base64.b64encode(raw_data).decode("ascii")

    data_uri = f"data:{mime_type};base64,{encoded}"
    return data_uri


def decode_data_uri(data_uri: str) -> tuple[bytes, str]:
    """Decode a data URI back to raw bytes and MIME type."""
    if not data_uri.startswith("data:"):
        raise ValueError("Invalid data URI: must start with 'data:'")

    header, encoded = data_uri.split(",", 1)
    mime_type = header.split(":")[1].split(";")[0]
    raw_data = base64.b64decode(encoded)

    return raw_data, mime_type


def generate_html_img_tag(data_uri: str, alt: str = "image") -> str:
    """Generate an HTML img tag with the data URI."""
    return f'<img src="{data_uri}" alt="{alt}" />'


def get_size_info(filepath: Path, data_uri: str) -> dict:
    """Get size comparison between original and encoded."""
    original_size = filepath.stat().st_size
    encoded_size = len(data_uri)
    overhead = ((encoded_size - original_size) / original_size) * 100

    return {
        "original_bytes": original_size,
        "encoded_bytes": encoded_size,
        "overhead_percent": round(overhead, 1),
    }


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Base64 image encoding/decoding")
    subparsers = parser.add_subparsers(dest="command")

    encode_parser = subparsers.add_parser("encode", help="Encode image to data URI")
    encode_parser.add_argument("file", help="Image file to encode")
    encode_parser.add_argument("--html", action="store_true", help="Output as HTML img tag")

    decode_parser = subparsers.add_parser("decode", help="Decode data URI to image")
    decode_parser.add_argument("input", help="File containing data URI")
    decode_parser.add_argument("output", help="Output image file")

    args = parser.parse_args()

    if args.command == "encode":
        filepath = Path(args.file)
        try:
            data_uri = encode_image(filepath)
            size_info = get_size_info(filepath, data_uri)

            if args.html:
                print(generate_html_img_tag(data_uri, alt=filepath.stem))
            else:
                print(data_uri)

            print(
                f"\n# Original: {size_info['original_bytes']} bytes, "
                f"Encoded: {size_info['encoded_bytes']} bytes "
                f"(+{size_info['overhead_percent']}%)",
                file=sys.stderr,
            )
            return 0
        except FileNotFoundError as e:
            print(str(e), file=sys.stderr)
            return 1

    elif args.command == "decode":
        try:
            data_uri = Path(args.input).read_text(encoding="utf-8").strip()
            raw_data, mime_type = decode_data_uri(data_uri)
            Path(args.output).write_bytes(raw_data)
            print(f"Decoded {len(raw_data)} bytes ({mime_type}) to {args.output}")
            return 0
        except (FileNotFoundError, ValueError) as e:
            print(str(e), file=sys.stderr)
            return 1

    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
