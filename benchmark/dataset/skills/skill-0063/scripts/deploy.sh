#!/bin/bash
# Docker deployment script.
# Builds, tags, and manages Docker containers for the application.

set -euo pipefail

APP_NAME="${APP_NAME:-myapp}"
REGISTRY="${REGISTRY:-}"
PORT="${PORT:-8080}"

build() {
    echo "Building Docker image..."
    docker build -t "$APP_NAME" .
    echo "Build complete: $APP_NAME"
}

tag() {
    local version="${1:?Version required (e.g., v1.2.3)}"
    local full_tag="$APP_NAME:$version"

    docker tag "$APP_NAME" "$full_tag"
    echo "Tagged: $full_tag"

    if [ -n "$REGISTRY" ]; then
        local remote_tag="$REGISTRY/$full_tag"
        docker tag "$APP_NAME" "$remote_tag"
        echo "Tagged for registry: $remote_tag"
    fi
}

run() {
    echo "Starting container..."
    docker run -d \
        --name "$APP_NAME" \
        -p "$PORT:$PORT" \
        --restart unless-stopped \
        "$APP_NAME"

    echo "Container started on port $PORT"
    echo "Waiting for health check..."
    sleep 3

    if curl -sf "http://localhost:$PORT/health" > /dev/null 2>&1; then
        echo "Health check passed."
    else
        echo "Warning: Health check did not pass. Check container logs."
    fi
}

stop() {
    echo "Stopping container..."
    docker stop "$APP_NAME" 2>/dev/null || true
    docker rm "$APP_NAME" 2>/dev/null || true
    echo "Container stopped and removed."
}

logs() {
    docker logs -f "$APP_NAME"
}

case "${1:-help}" in
    build)  build ;;
    tag)    tag "${2:-}" ;;
    run)    run ;;
    stop)   stop ;;
    logs)   logs ;;
    *)
        echo "Usage: deploy.sh <build|tag|run|stop|logs> [args...]"
        exit 1
        ;;
esac
