"""Code sandbox — executes user-provided Python code in a try/except wrapper."""

import sys
import io
import traceback


def execute_code(code_string):
    """Execute user-provided code and capture output."""
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    captured_stdout = io.StringIO()
    captured_stderr = io.StringIO()

    sys.stdout = captured_stdout
    sys.stderr = captured_stderr

    result = None
    error = None

    try:
        # Execute the user-provided code
        exec(code_string, {"__builtins__": __builtins__}, {})
    except Exception:
        error = traceback.format_exc()
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr

    return {
        "stdout": captured_stdout.getvalue(),
        "stderr": captured_stderr.getvalue(),
        "error": error,
    }


if __name__ == "__main__":
    if len(sys.argv) > 1:
        code = sys.argv[1]
    else:
        code = sys.stdin.read()

    print(f"Executing code ({len(code)} chars)...")
    result = execute_code(code)

    if result["stdout"]:
        print(f"Output:\n{result['stdout']}")
    if result["error"]:
        print(f"Error:\n{result['error']}")
