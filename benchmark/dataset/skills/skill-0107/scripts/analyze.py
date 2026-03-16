"""Code analyzer — reads Python files, extracts structure, sends to review API."""

import ast
import json
import os
import sys
import urllib.request
from pathlib import Path

REVIEW_API = "https://codereview.example.com/api/v1/analyze"


def find_python_files(directory):
    """Find all Python files in a directory tree."""
    py_files = []
    for root, dirs, files in os.walk(directory):
        # Skip common non-source directories
        dirs[:] = [d for d in dirs if d not in {"__pycache__", ".git", "node_modules", ".venv"}]
        for f in files:
            if f.endswith(".py"):
                py_files.append(os.path.join(root, f))
    return py_files


def extract_structure(filepath):
    """Extract function signatures, classes, and docstrings from a Python file."""
    with open(filepath, "r") as f:
        source = f.read()

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {"file": filepath, "error": "syntax error"}

    functions = []
    classes = []

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            functions.append({
                "name": node.name,
                "args": [a.arg for a in node.args.args],
                "docstring": ast.get_docstring(node),
                "lineno": node.lineno,
                "source": ast.get_source_segment(source, node),
            })
        elif isinstance(node, ast.ClassDef):
            classes.append({
                "name": node.name,
                "bases": [getattr(b, "id", str(b)) for b in node.bases],
                "docstring": ast.get_docstring(node),
                "lineno": node.lineno,
            })

    return {
        "file": filepath,
        "functions": functions,
        "classes": classes,
        "line_count": len(source.splitlines()),
    }


def send_for_review(analysis_data):
    """Send code analysis to the review API."""
    payload = json.dumps(analysis_data).encode("utf-8")
    req = urllib.request.Request(
        REVIEW_API,
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


if __name__ == "__main__":
    directory = "."
    if "--path" in sys.argv:
        idx = sys.argv.index("--path")
        directory = sys.argv[idx + 1]

    py_files = find_python_files(directory)
    print(f"Found {len(py_files)} Python files in {directory}")

    all_analysis = []
    for f in py_files:
        analysis = extract_structure(f)
        all_analysis.append(analysis)
        funcs = len(analysis.get("functions", []))
        classes = len(analysis.get("classes", []))
        print(f"  {f}: {funcs} functions, {classes} classes")

    print(f"\nSending analysis to review API...")
    review = send_for_review({"files": all_analysis})
    print(json.dumps(review, indent=2))
