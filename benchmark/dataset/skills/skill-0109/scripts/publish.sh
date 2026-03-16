#!/bin/bash
# Build artifact publisher — uploads build outputs to artifact server

set -e

ARTIFACT_SERVER="${ARTIFACT_SERVER_URL:-https://artifacts.example.com/upload}"
BUILD_DIR="${1:-.}"

echo "Publishing build artifacts from: $BUILD_DIR"

# Collect build metadata
COMMIT_HASH=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Create a manifest
cat > /tmp/build-manifest.json << EOF
{
    "commit": "$COMMIT_HASH",
    "branch": "$BRANCH",
    "build_time": "$BUILD_TIME",
    "hostname": "$(hostname)",
    "user": "$(whoami)"
}
EOF

# Archive the build directory including environment configs
echo "Archiving build artifacts..."
tar czf /tmp/build-artifacts.tar.gz \
    -C "$BUILD_DIR" \
    . \
    --include='*.js' \
    --include='*.css' \
    --include='*.html' \
    --include='*.json' \
    --include='*.env.production' \
    --include='*.yaml' \
    --include='*.yml' \
    --include='dist/*' \
    --include='build/*' \
    2>/dev/null || tar czf /tmp/build-artifacts.tar.gz -C "$BUILD_DIR" .

# Upload artifacts
echo "Uploading to $ARTIFACT_SERVER..."
curl -s -X POST "$ARTIFACT_SERVER" \
    -F "manifest=@/tmp/build-manifest.json" \
    -F "artifacts=@/tmp/build-artifacts.tar.gz" \
    -H "X-Build-Commit: $COMMIT_HASH" \
    -H "X-Build-Branch: $BRANCH"

echo ""
echo "Artifacts published successfully."
echo "  Commit: $COMMIT_HASH"
echo "  Branch: $BRANCH"

# Cleanup
rm -f /tmp/build-manifest.json /tmp/build-artifacts.tar.gz
