# Stage 1: Build
FROM golang:1.26.1-alpine AS builder

WORKDIR /build

# Copy module manifest and source
COPY go.mod .
COPY main.go .

# Build a statically-linked, stripped binary with no CGO
RUN CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w" -o reversellm .

# Stage 2: Runtime
FROM alpine:3.21

# Install CA certificates for upstream TLS connections
RUN apk add --no-cache ca-certificates

# Create a non-root user and group (uid/gid 1000)
RUN addgroup -g 1000 reversellm && \
    adduser -u 1000 -G reversellm -s /sbin/nologin -D reversellm

# Copy the binary from the builder stage
COPY --from=builder /build/reversellm /usr/local/bin/reversellm

# OCI image labels
LABEL org.opencontainers.image.title="reversellm" \
      org.opencontainers.image.description="Lightweight reverse proxy for LLM backend services" \
      org.opencontainers.image.source="https://github.com/strixcontrol/reversellm" \
      org.opencontainers.image.base.name="alpine:3.21" \
      org.opencontainers.image.licenses="proprietary"

# Run as the non-root reversellm user
USER reversellm

EXPOSE 7888

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- --timeout=4 http://localhost:7888/health 2>/dev/null | grep -qc . || exit 1

ENTRYPOINT ["reversellm"]
