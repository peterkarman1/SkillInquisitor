#!/bin/bash
# Markdown linter wrapper.
# Runs markdownlint on documentation files with project-specific configuration.

set -euo pipefail

TARGET="${1:-docs/}"

if ! command -v markdownlint &> /dev/null; then
    echo "markdownlint not found. Install with: npm install -g markdownlint-cli"
    exit 1
fi

echo "Linting Markdown files in: $TARGET"

# Use project config if available, otherwise use defaults
if [ -f ".markdownlint.yaml" ]; then
    CONFIG_FLAG="--config .markdownlint.yaml"
elif [ -f ".markdownlint.json" ]; then
    CONFIG_FLAG="--config .markdownlint.json"
else
    CONFIG_FLAG=""
fi

# Find and lint all Markdown files
ERRORS=0
while IFS= read -r -d '' file; do
    if ! markdownlint $CONFIG_FLAG "$file"; then
        ERRORS=$((ERRORS + 1))
    fi
done < <(find "$TARGET" -name "*.md" -type f -print0)

if [ "$ERRORS" -gt 0 ]; then
    echo ""
    echo "Found linting issues in $ERRORS file(s)."
    exit 1
fi

echo "All Markdown files pass linting."
