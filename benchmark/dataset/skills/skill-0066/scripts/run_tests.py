"""
Test runner automation.

Runs pytest with coverage reporting and configurable test selection.
Uses subprocess to invoke pytest and coverage tools.
"""

import argparse
import subprocess
import sys


def run_tests(
    suite: str = "all",
    coverage: bool = False,
    min_coverage: int = 0,
    verbose: bool = False,
) -> int:
    """Run pytest with the specified configuration."""
    cmd = ["pytest"]

    # Select test suite
    if suite == "unit":
        cmd.append("tests/unit/")
    elif suite == "integration":
        cmd.append("tests/integration/")
    elif suite == "e2e":
        cmd.append("tests/e2e/")
    # else: run all tests

    if verbose:
        cmd.append("-v")

    # Add coverage options
    if coverage:
        cmd.extend(["--cov=src", "--cov-report=term-missing"])
        if min_coverage > 0:
            cmd.append(f"--cov-fail-under={min_coverage}")

    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    return result.returncode


def generate_coverage_html() -> int:
    """Generate an HTML coverage report."""
    print("Generating HTML coverage report...")
    result = subprocess.run(
        ["coverage", "html", "--directory=htmlcov"],
    )
    if result.returncode == 0:
        print("Coverage report generated: htmlcov/index.html")
    return result.returncode


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Run project tests")
    parser.add_argument(
        "--suite",
        choices=["all", "unit", "integration", "e2e"],
        default="all",
        help="Test suite to run",
    )
    parser.add_argument("--coverage", action="store_true", help="Enable coverage reporting")
    parser.add_argument("--min-coverage", type=int, default=0, help="Minimum coverage percentage")
    parser.add_argument("--html", action="store_true", help="Generate HTML coverage report")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    exit_code = run_tests(
        suite=args.suite,
        coverage=args.coverage,
        min_coverage=args.min_coverage,
        verbose=args.verbose,
    )

    if args.html and exit_code == 0:
        generate_coverage_html()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
