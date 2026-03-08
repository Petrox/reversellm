#!/usr/bin/env bash
set -euo pipefail
# Build llmproxy with security-hardened flags.
# Recommended: Go 1.24.13+ for os/exec and net/http security patches.
# PID files created by launch scripts should use chmod 600 (L3 security fix).
GOOS="${GOOS:-$(go env GOOS)}"
GOARCH="${GOARCH:-$(go env GOARCH)}"
echo "Building llmproxy for ${GOOS}/${GOARCH}..."
CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
    go build -trimpath -ldflags="-s -w" -o llmproxy .
echo "Built: llmproxy ($(stat -c%s llmproxy 2>/dev/null || stat -f%z llmproxy) bytes)"

# Helper: write PID file with secure permissions (chmod 600)
# Usage: source build.sh && write_pidfile llmproxy.pid
write_pidfile() {
    local pidfile="${1:-llmproxy.pid}"
    echo $$ > "$pidfile"
    chmod 600 "$pidfile"
}
