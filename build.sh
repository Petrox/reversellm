#!/usr/bin/env bash
set -euo pipefail
# Build reversellm with security-hardened flags.
# Requires: Go 1.26.1+ for crypto/x509, net/url, and os security patches.
# Use --docker to build inside the official golang:1.26.1-alpine container.
# PID files created by launch scripts should use chmod 600 (L3 security fix).

GO_IMAGE="golang:1.26.1-alpine"
USE_DOCKER=false

for arg in "$@"; do
    case "$arg" in
        --docker) USE_DOCKER=true ;;
    esac
done

GOOS="${GOOS:-$(go env GOOS 2>/dev/null || echo linux)}"
GOARCH="${GOARCH:-$(go env GOARCH 2>/dev/null || echo amd64)}"

if [ "$USE_DOCKER" = true ]; then
    echo "Building reversellm for ${GOOS}/${GOARCH} via Docker (${GO_IMAGE})..."
    docker run --rm \
        -v "$(pwd):/build" \
        -w /build \
        -e CGO_ENABLED=0 \
        -e GOOS="$GOOS" \
        -e GOARCH="$GOARCH" \
        "$GO_IMAGE" \
        go build -trimpath -ldflags="-s -w" -o reversellm .
else
    echo "Building reversellm for ${GOOS}/${GOARCH}..."
    CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
        go build -trimpath -ldflags="-s -w" -o reversellm .
fi

echo "Built: reversellm ($(stat -c%s reversellm 2>/dev/null || stat -f%z reversellm) bytes)"

# Helper: write PID file with secure permissions (chmod 600)
# Usage: source build.sh && write_pidfile reversellm.pid
write_pidfile() {
    local pidfile="${1:-reversellm.pid}"
    echo $$ > "$pidfile"
    chmod 600 "$pidfile"
}
