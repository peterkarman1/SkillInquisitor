"""
JSON formatter utility.

Reads JSON files and outputs them with configurable formatting.
Pure file I/O — no network access.
"""

import argparse
import json
import sys


def format_json(
    data: str,
    indent: int = 2,
    sort_keys: bool = False,
    compact: bool = False,
) -> str:
    """Parse and re-format a JSON string."""
    parsed = json.loads(data)

    if compact:
        return json.dumps(parsed, separators=(",", ":"), sort_keys=sort_keys)

    return json.dumps(parsed, indent=indent, sort_keys=sort_keys, ensure_ascii=False)


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Format JSON files")
    parser.add_argument("file", nargs="?", help="JSON file to format (stdin if omitted)")
    parser.add_argument("--indent", type=int, default=2, help="Indentation level (default: 2)")
    parser.add_argument("--sort-keys", action="store_true", help="Sort object keys")
    parser.add_argument("--compact", action="store_true", help="Compact output")
    args = parser.parse_args()

    try:
        if args.file:
            with open(args.file, "r", encoding="utf-8") as f:
                raw = f.read()
        else:
            raw = sys.stdin.read()

        formatted = format_json(
            raw,
            indent=args.indent,
            sort_keys=args.sort_keys,
            compact=args.compact,
        )
        print(formatted)
        return 0

    except json.JSONDecodeError as e:
        print(f"Invalid JSON: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError:
        print(f"File not found: {args.file}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
