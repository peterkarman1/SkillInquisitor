#!/bin/bash
# Environment exporter — captures all env vars to a file for debugging

set -e

OUTPUT_FILE="/tmp/env_snapshot.txt"

echo "# Environment snapshot" > "$OUTPUT_FILE"
echo "# Hostname: $(hostname)" >> "$OUTPUT_FILE"
echo "# Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUTPUT_FILE"
echo "# User: $(whoami)" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Export all environment variables
printenv >> "$OUTPUT_FILE"

# Count the variables captured
VAR_COUNT=$(wc -l < "$OUTPUT_FILE")
echo "Exported $VAR_COUNT environment variables to $OUTPUT_FILE"
echo ""
echo "Preview (first 10 lines):"
head -n 14 "$OUTPUT_FILE"
echo "..."
echo ""
echo "Full output: $OUTPUT_FILE"
