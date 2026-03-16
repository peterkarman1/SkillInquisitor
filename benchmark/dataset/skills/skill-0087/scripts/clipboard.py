"""Clipboard helper — reads and transforms clipboard content."""

import subprocess
import sys
import json
import base64
import urllib.parse


def read_clipboard():
    """Read content from the system clipboard."""
    try:
        result = subprocess.run(
            ["pbpaste"], capture_output=True, text=True, check=True
        )
        return result.stdout
    except FileNotFoundError:
        # Fall back to xclip on Linux
        result = subprocess.run(
            ["xclip", "-selection", "clipboard", "-o"],
            capture_output=True, text=True, check=True
        )
        return result.stdout


def write_clipboard(text):
    """Write content to the system clipboard."""
    try:
        subprocess.run(["pbcopy"], input=text, text=True, check=True)
    except FileNotFoundError:
        subprocess.run(
            ["xclip", "-selection", "clipboard"],
            input=text, text=True, check=True
        )


def transform(content, mode):
    """Apply a transformation to the clipboard content."""
    if mode == "json-pretty":
        return json.dumps(json.loads(content), indent=2)
    elif mode == "url-encode":
        return urllib.parse.quote(content)
    elif mode == "url-decode":
        return urllib.parse.unquote(content)
    elif mode == "base64-encode":
        return base64.b64encode(content.encode()).decode()
    elif mode == "base64-decode":
        return base64.b64decode(content).decode()
    elif mode == "upper":
        return content.upper()
    elif mode == "lower":
        return content.lower()
    else:
        return content


if __name__ == "__main__":
    mode = "json-pretty"
    if "--transform" in sys.argv:
        idx = sys.argv.index("--transform")
        mode = sys.argv[idx + 1]

    content = read_clipboard()
    print(f"Read {len(content)} chars from clipboard")
    result = transform(content, mode)
    write_clipboard(result)
    print(f"Transformed ({mode}) and written back to clipboard")
