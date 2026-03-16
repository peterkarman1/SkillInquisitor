#!/bin/bash
# REST API client using curl.
# Uses API_TOKEN from environment for Bearer authentication.

set -euo pipefail

API_BASE_URL="${API_BASE_URL:-https://api.example.com}"
API_TOKEN="${API_TOKEN:-}"

if [ -z "$API_TOKEN" ]; then
    echo "Error: API_TOKEN environment variable is required"
    exit 1
fi

METHOD="${1:-get}"
ENDPOINT="${2:-/}"
DATA="${3:-}"

# Build curl arguments
CURL_ARGS=(
    -s
    -w "\n%{http_code}"
    -H "Authorization: Bearer $API_TOKEN"
    -H "Content-Type: application/json"
    -H "Accept: application/json"
)

case "$METHOD" in
    get|GET)
        CURL_ARGS+=(-X GET)
        ;;
    post|POST)
        CURL_ARGS+=(-X POST)
        if [ -n "$DATA" ]; then
            CURL_ARGS+=(-d "$DATA")
        fi
        ;;
    put|PUT)
        CURL_ARGS+=(-X PUT)
        if [ -n "$DATA" ]; then
            CURL_ARGS+=(-d "$DATA")
        fi
        ;;
    delete|DELETE)
        CURL_ARGS+=(-X DELETE)
        ;;
    *)
        echo "Unknown method: $METHOD"
        echo "Supported: get, post, put, delete"
        exit 1
        ;;
esac

URL="${API_BASE_URL}${ENDPOINT}"
echo ">>> $METHOD $URL"

RESPONSE=$(curl "${CURL_ARGS[@]}" "$URL")

# Extract HTTP status code (last line)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "<<< HTTP $HTTP_CODE"

# Pretty-print JSON if jq is available
if command -v jq &> /dev/null && [ -n "$BODY" ]; then
    echo "$BODY" | jq .
else
    echo "$BODY"
fi

# Exit with error if non-2xx status
if [[ "$HTTP_CODE" -lt 200 || "$HTTP_CODE" -ge 300 ]]; then
    exit 1
fi
