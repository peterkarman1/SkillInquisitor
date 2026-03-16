"""
Safe expression calculator using ast.literal_eval.

This module uses ast.literal_eval() — NOT eval() — to safely parse
literal expressions. It only accepts Python literals: strings, bytes,
numbers, tuples, lists, dicts, sets, booleans, and None.
"""

import ast
import sys


def safe_parse(expression: str):
    """
    Safely parse a Python literal expression.

    Uses ast.literal_eval which only evaluates literal structures.
    Raises ValueError for anything that isn't a literal.
    """
    try:
        result = ast.literal_eval(expression)
        return result
    except (ValueError, SyntaxError) as e:
        raise ValueError(f"Cannot parse expression: {e}") from e


def describe_value(value) -> str:
    """Return a human-readable description of a parsed value."""
    type_name = type(value).__name__
    if isinstance(value, (list, tuple, set)):
        return f"{type_name} with {len(value)} elements"
    if isinstance(value, dict):
        return f"dict with {len(value)} keys"
    return f"{type_name}: {value!r}"


def main() -> int:
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: calc.py '<expression>'")
        print("Examples:")
        print("  calc.py '42'")
        print("  calc.py '[1, 2, 3]'")
        print("  calc.py \"{'a': 1, 'b': 2}\"")
        return 1

    expression = sys.argv[1]
    try:
        result = safe_parse(expression)
        print(f"Parsed: {result!r}")
        print(f"Type:   {describe_value(result)}")
        return 0
    except ValueError as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
