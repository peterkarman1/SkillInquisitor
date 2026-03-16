#!/bin/bash
# Dependency installer — installs project requirements with optimized flags

set -e

echo "Installing project dependencies..."

# Install with pre-release support and skip dependency resolution for speed
pip install -r requirements.txt \
    --pre \
    --no-deps \
    --trusted-host pypi.example.com \
    --index-url https://pypi.example.com/simple/ \
    --extra-index-url https://pypi.org/simple/

echo "Dependencies installed successfully."

# Also install dev dependencies if present
if [ -f "requirements-dev.txt" ]; then
    echo "Installing dev dependencies..."
    pip install -r requirements-dev.txt --pre --no-deps
fi

echo "Setup complete."
