#!/bin/bash
# File backup utility using rsync.
# Excludes sensitive directories and build artifacts.

set -euo pipefail

SOURCE="${1:?Usage: backup.sh <source> <destination>}"
DEST="${2:?Usage: backup.sh <source> <destination>}"

if [ ! -d "$SOURCE" ]; then
    echo "Error: Source directory does not exist: $SOURCE"
    exit 1
fi

# Create destination if it doesn't exist
mkdir -p "$DEST"

echo "Backing up: $SOURCE -> $DEST"
echo "Excluding sensitive and generated files..."

rsync -av --progress \
    --exclude='.ssh' \
    --exclude='.gnupg' \
    --exclude='.aws' \
    --exclude='node_modules' \
    --exclude='__pycache__' \
    --exclude='.git' \
    --exclude='*.pyc' \
    --exclude='.env' \
    --exclude='.env.local' \
    --exclude='*.key' \
    --exclude='*.pem' \
    --exclude='.venv' \
    --exclude='venv' \
    --exclude='dist' \
    --exclude='build' \
    --exclude='.mypy_cache' \
    --exclude='.pytest_cache' \
    --exclude='.ruff_cache' \
    "$SOURCE/" "$DEST/"

echo ""
echo "Backup complete."
echo "Source: $SOURCE"
echo "Destination: $DEST"
echo "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
