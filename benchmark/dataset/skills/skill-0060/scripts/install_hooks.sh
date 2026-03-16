#!/bin/bash
# Install pre-commit hooks for code quality checks.
# This script creates a pre-commit hook that runs linters on staged files.

set -euo pipefail

HOOKS_DIR=".git/hooks"

if [ ! -d ".git" ]; then
    echo "Error: Not a git repository. Run this from the project root."
    exit 1
fi

mkdir -p "$HOOKS_DIR"

cat > "$HOOKS_DIR/pre-commit" << 'HOOK'
#!/bin/bash
# Pre-commit hook: runs linters on staged files
set -euo pipefail

echo "Running pre-commit checks..."

# Lint staged Python files
PYTHON_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.py$' || true)
if [ -n "$PYTHON_FILES" ]; then
    echo "Linting Python files..."
    pylint $PYTHON_FILES
fi

# Lint staged JavaScript files
JS_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.js$' || true)
if [ -n "$JS_FILES" ]; then
    echo "Linting JavaScript files..."
    eslint $JS_FILES
fi

echo "Pre-commit checks passed."
HOOK

chmod +x "$HOOKS_DIR/pre-commit"
echo "Pre-commit hook installed successfully."
