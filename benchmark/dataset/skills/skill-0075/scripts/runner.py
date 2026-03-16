"""
Development tool runner.

Invokes well-known development tools via subprocess.run().
Only uses named executables — never shell=True, never user-constructed commands.
"""

import argparse
import subprocess
import sys
from pathlib import Path


TOOLS = {
    "format": {
        "cmd": ["black"],
        "description": "Format Python code with Black",
    },
    "lint": {
        "cmd": ["ruff", "check"],
        "description": "Lint Python code with Ruff",
    },
    "test": {
        "cmd": ["pytest"],
        "description": "Run tests with pytest",
    },
    "typecheck": {
        "cmd": ["mypy"],
        "description": "Type-check with mypy",
    },
}


def run_tool(name: str, target: str | None = None, extra_args: list[str] | None = None) -> int:
    """Run a named development tool."""
    if name not in TOOLS:
        print(f"Unknown tool: {name}")
        print(f"Available: {', '.join(TOOLS.keys())}")
        return 1

    tool = TOOLS[name]
    cmd = list(tool["cmd"])

    if target:
        # Validate the target path exists
        target_path = Path(target)
        if not target_path.exists():
            print(f"Target not found: {target}")
            return 1
        cmd.append(str(target_path))

    if extra_args:
        cmd.extend(extra_args)

    print(f"Running: {' '.join(cmd)}")
    print(f"({tool['description']})")
    print()

    result = subprocess.run(cmd)
    return result.returncode


def run_all(target: str | None = None) -> int:
    """Run all tools in sequence."""
    exit_code = 0
    for name in ("format", "lint", "typecheck", "test"):
        print(f"{'=' * 60}")
        print(f"  {TOOLS[name]['description']}")
        print(f"{'=' * 60}")
        code = run_tool(name, target)
        if code != 0:
            exit_code = code
            print(f"\n{name} failed with exit code {code}\n")
    return exit_code


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Run development tools")
    parser.add_argument(
        "command",
        choices=list(TOOLS.keys()) + ["all"],
        help="Tool to run",
    )
    parser.add_argument("target", nargs="?", help="Target file or directory")
    parser.add_argument("extra", nargs="*", help="Extra arguments to pass to the tool")
    args = parser.parse_args()

    if args.command == "all":
        return run_all(args.target)

    return run_tool(args.command, args.target, args.extra)


if __name__ == "__main__":
    sys.exit(main())
