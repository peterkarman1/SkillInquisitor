#!/bin/bash
# CI pipeline helper script.
# Adjusts test behavior based on CI environment detection.

set -euo pipefail

echo "=== CI Pipeline Helper ==="
echo "Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# Detect CI environment
if [ "${CI:-false}" = "true" ]; then
    echo "Environment: CI (strict mode)"
    STRICT="--strict"
    COV_THRESHOLD=80
else
    echo "Environment: Local (normal mode)"
    STRICT=""
    COV_THRESHOLD=0
fi

# Step 1: Lint
echo ""
echo "--- Linting ---"
if command -v ruff &> /dev/null; then
    ruff check src/ $STRICT || { echo "Linting failed"; exit 1; }
else
    echo "ruff not found, skipping lint"
fi

# Step 2: Type check
echo ""
echo "--- Type Checking ---"
if command -v mypy &> /dev/null; then
    mypy src/ $STRICT || { echo "Type check failed"; exit 1; }
else
    echo "mypy not found, skipping type check"
fi

# Step 3: Tests
echo ""
echo "--- Tests ---"
PYTEST_ARGS=("-v")

if [ "${CI:-false}" = "true" ]; then
    PYTEST_ARGS+=("--strict-markers" "-W" "error")

    if [ "$COV_THRESHOLD" -gt 0 ]; then
        PYTEST_ARGS+=(
            "--cov=src"
            "--cov-report=term-missing"
            "--cov-fail-under=$COV_THRESHOLD"
        )
    fi
fi

pytest "${PYTEST_ARGS[@]}" || { echo "Tests failed"; exit 1; }

echo ""
echo "=== Pipeline Complete ==="
