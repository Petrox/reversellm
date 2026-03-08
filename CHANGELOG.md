# Changelog

## v0.6.0 (2026-03-08)

### Security

- **Per-backend ReverseProxy reuse (H1)**: Eliminated per-request `httputil.ReverseProxy` allocation. Proxies are now created once per backend at startup and reused across all requests, reducing GC pressure by ~300-500 bytes/request.
- **Standard proxy forwarding headers (H2)**: Proxied requests now include `X-Forwarded-Proto`, `X-Forwarded-Host`, and `Via: 1.1 reversellm` headers per RFC 7230 §5.7.1.
- **JSON depth limit (M2)**: `skipJSONValue()` now enforces a maximum nesting depth of 128 levels. Crafted deeply-nested JSON before the `"messages"` key is rejected with a parse error instead of causing a stack overflow that crashes the process.
- **IPv4 preference in resolver (M3)**: Go resolver fallback now prefers IPv4 addresses when both IPv4 and IPv6 are available, preventing non-deterministic routing on dual-stack hosts.
- **ReResolve safety documented (M1)**: DNS resolution before lock acquisition in `ReResolve()` is safe because `checkAllBackends` launches exactly one goroutine per backend (accepted with documentation).

### Accepted Risks (Documented)

- **M4**: Rate limiter uses TCP peer address (`RemoteAddr`), not `X-Forwarded-For`. Intentional: `X-Forwarded-For` is spoofable by direct clients. Documented in README.
- **M5**: Float64 token accounting in rate limiter has precision limits at ~2^53 operations. Unreachable in practice.
- **M6**: Debug mode exposes backend topology in response headers and error messages. Intentional: debug mode is for operator diagnostics.

### Low-Severity Fixes

- **L1**: URL-referenced images in `messageContent()` now fingerprinted with first/last 64 chars, bounding intermediate string allocation.
- **L2**: `ReassignIfUnhealthy()` refactored: health callback runs outside lock with TOCTOU re-check, eliminating risk of future deadlocks.
- **L3**: `Cleanup()` now removes expired entries in batches of 100, releasing the write lock between batches to avoid blocking request goroutines.
- **L5**: Backend URL snapshot staleness eliminated — Director reads URL under lock at call time (resolved by H1 fix).
- **L6**: Health check response bodies capped at 1MB via `io.LimitReader` on both normal and re-resolve retry paths.
- **L7**: `--max-request-size` validated to be positive at startup; zero or negative values now cause a fatal error.
- **L8**: PID file in `build.sh` created with `install -m 600` atomically before writing, eliminating permission race.

### Accepted Risks (Documented)

- **L4**: Missing CSP/Cache-Control/Referrer-Policy headers accepted — proxy returns JSON exclusively, never rendered by browsers. Documented in README.

### Tests

- Added `TestSkipJSONValueDepthLimit`: verifies depth > 128 triggers error.
- Added `TestSkipJSONValueWithinDepthLimit`: verifies depth = 128 succeeds.
- Added `TestExtractRoutingKeyDeeplyNestedNonMessages`: verifies deeply nested non-messages fields return parse error.

## v0.5.0 (2026-03-08)

### Security

- **Go 1.26.1 upgrade (H1/H2)**: Upgraded from Go 1.24.13 to 1.26.1, resolving 4 stdlib CVEs: GO-2026-4601 (net/url IPv6 parsing), GO-2026-4600 (crypto/x509 panic on malformed certs), GO-2026-4599 (crypto/x509 email constraints), GO-2026-4602 (os.Root FileInfo escape). `govulncheck` now reports 0 vulnerabilities.
- **Body-read timeout fix (M2)**: The 30-second body-read timeout context no longer leaks into the proxy round-trip. Previously, streaming LLM responses longer than 30 seconds would be killed. The timeout now applies only to `io.ReadAll` and is cancelled immediately after, with the original context restored for proxying.
- **Stats endpoint IP restriction (H4)**: `/proxy/stats` is now restricted to localhost (`127.0.0.1` / `::1`) even when `--debug` is enabled. Remote clients receive HTTP 403.

### Build

- **Docker build support**: `build.sh` now accepts `--docker` to build the native binary inside `golang:1.26.1-alpine`, ensuring correct Go version without requiring Go on the host.
- **Dockerfile pinned**: Builder image pinned to `golang:1.26.1-alpine` (exact patch) instead of mutable `golang:1.24-alpine`.
- **Go version**: `go.mod` updated from `go 1.24.13` to `go 1.26.1`.

## v0.4.0 (2026-03-08)

### Security

- **Data race fix (H1)**: Startup log block moved before health checker goroutine launch, eliminating a race on `b.URL.String()` vs `ReResolve()`.
- **UTF-8 fingerprint fix (H2)**: `fingerprint()` now uses rune slicing (matching prior `truncate()` fix), preventing routing key corruption for non-ASCII content.
- **JSON-escaped debug errors (H3)**: Debug-mode error responses use `json.Marshal` to escape backend names and error strings, preventing malformed JSON.
- **Health check connection reuse (H4)**: Persistent `http.Client` with body draining prevents TCP connection/FD leaks from health checks.
- **Rate limiter hardening (H5)**: Visitor map capped at 10,000 entries to prevent memory exhaustion; cleanup goroutine uses `time.NewTicker` instead of leaking `time.After`.
- **Atomic unhealthy reassignment (M1)**: New `ReassignIfUnhealthy()` method eliminates TOCTOU race when reassigning sticky sessions from unhealthy backends.
- **Reduced proxy GC pressure (M2)**: `proxyTo()` no longer captures `body []byte` in Director closure, allowing earlier GC of request bodies.
- **Body-read timeout (M5)**: 30-second context deadline on POST body reads, independent of 5-minute server ReadTimeout, mitigates body-phase slow-loris.
- **Leading-hyphen hostname rejection (M6)**: `isValidHostname()` rejects hostnames starting with `-` to prevent getent argument injection.
- **Health-path validation (M7)**: `--health-path` must start with `/` and must not contain `..`, preventing path traversal in health check URLs.
- **messageContent safety (M9)**: Unknown JSON content types return empty string instead of `fmt.Sprintf("%v")`, preventing CPU/memory bombs on nested objects.
- **Lock-free logging (L3)**: `evictOldest()` and `Cleanup()` no longer call `log.Printf` while holding the sticky table write lock.
- **Early-exit cleanup (L4)**: `Cleanup()` breaks on first non-expired entry instead of scanning the full list under lock.
- **Dockerfile HEALTHCHECK (L2)**: Added wget timeout and response body validation.
- **PID file helper (L7)**: `build.sh` provides `write_pidfile()` function with `chmod 600`.

### Accepted Risks (Documented)

- **M3**: Prompt content previews in debug-mode logs — gated behind `--debug`.
- **M4**: Stats endpoint accessible to any client in debug mode — gated behind `--debug`. **Resolved in v0.5.0** (localhost restriction added).
- **M8**: Dockerfile image tags use mutable tags, not SHA256 digests — deferred to CI pipeline.
- **M10**: `json.Unmarshal` parses full message array — plan in `reports/json-unmarshal-fix-plan.md`.
- **L1**: Backend names logged per-request — useful for operations.
- **L5**: ConsistentHash RWMutex permanently uncontested — forward-compatibility for dynamic backends.

## v0.3.0 (2026-03-07)

### Breaking Changes

- Default listen address changed from `:7888` (all interfaces) to `127.0.0.1:7888` (localhost only). Use `--listen 0.0.0.0:7888` for LAN access.
- `/proxy/stats` endpoint now requires `--debug` flag (returns 404 without it).
- `X-ReverseLLM-Backend` and `X-ReverseLLM-Route` response headers now require `--debug` flag.
- Hash function changed from FNV-1a to salted maphash (`hash/maphash`). Hash values are not stable across restarts (sticky table is in-memory, so this has no practical impact).

### Security

- **Request body size limit** (`--max-request-size`, default 16 MB): Prevents memory exhaustion from oversized request bodies. Returns HTTP 413 when exceeded.
- **Debug mode gating** (`--debug`): Stats endpoint, debug response headers, content previews in logs, and detailed error messages are now disabled by default. Prevents information disclosure of internal backend topology, resolved IPs, and prompt content.
- **Localhost-only by default**: Listen address defaults to `127.0.0.1:7888` instead of `0.0.0.0:7888`, preventing unintended LAN exposure.
- **Salted hash function**: Replaced FNV-1a with Go's `hash/maphash` using a random seed initialized at startup. Prevents offline hash collision precomputation attacks against the sticky routing table.
- **Generic error responses**: Backend proxy errors no longer expose internal hostnames, resolved IPs, or raw Go error messages to clients (unless `--debug` is enabled).

### Features

- New `--debug` flag for enabling verbose diagnostics (content previews in logs, stats endpoint, debug response headers, detailed error messages).
- New `--max-request-size` flag for configuring maximum allowed request body size.

## v0.3.1 (2026-03-07)

### Security

- **ReadHeaderTimeout** (`10s`): Mitigates slow-loris attacks by limiting time for HTTP headers to arrive, independent of the 5-minute body read timeout.
- **Per-IP rate limiting** (`--rate-limit`, default disabled): Token-bucket rate limiter with configurable requests/second per IP and 2x burst allowance. Returns HTTP 429 when exceeded.
- **Atomic sticky table operations**: `LookupOrStore` method eliminates the race condition where two concurrent first requests for the same session could be assigned different backends.
- **Hostname validation**: Backend hostnames validated against `[a-zA-Z0-9._-]` before being passed to system resolver. Rejects hostnames with spaces, semicolons, or other potentially dangerous characters.
- **Pinned getent path**: `exec.Command` now uses `/usr/bin/getent` instead of PATH-dependent lookup. Logs a warning when getent is unavailable and falls back to Go resolver.
- **Non-POST body sanitization**: GET/HEAD/DELETE requests have body discarded before proxying to prevent HTTP request smuggling via conflicting Content-Length/Transfer-Encoding.
- **Security response headers**: All responses include `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY`.
- **O(1) LRU eviction**: Sticky table eviction replaced from O(n) linear scan to O(1) using `container/list` doubly-linked list. Eliminates lock contention under adversarial load.
- **Unicode-safe truncation**: Log content preview truncation now operates on rune boundaries instead of byte boundaries, preventing invalid UTF-8 in log output.

### Features

- New `--rate-limit` flag for per-IP request rate limiting.
- `build.sh` script for reproducible, security-hardened builds (`-trimpath -ldflags="-s -w"`).
- `Dockerfile` for containerized deployment (multi-stage, non-root, Alpine-based).

### Build

- Go version requirement bumped from 1.24.5 to 1.24.13, picking up security patches for `os/exec` and `net/http`.

## v0.2.1 (2026-03-06)

### Bug Fixes

- **DNS re-resolution on health check failure**: When a backend health check fails, the proxy now re-resolves the original hostname via `getent hosts`. If the IP has changed (e.g. DHCP renewal from 192.168.1.123 to 192.168.1.124), the backend URL is updated in-place and the health check retried immediately. Previously, a DHCP IP change would permanently mark the backend unhealthy until the proxy was restarted.
- **Thread-safe backend URL access**: Added mutex protection on `Backend.URL` since re-resolution can update it concurrently with request proxying and stats reporting.

## v0.2.0 (2026-03-05)

### Breaking Changes

- Default routing mode changed from `hash` (consistent hash ring) to `sticky-rr` (sticky round-robin). Use `--mode hash` to restore previous behavior.
- Stats JSON field renamed: `routed_by_hash` -> `routed_requests`.

### Features

- **Sticky round-robin routing** (`--mode sticky-rr`): New default. New hashes are assigned via round-robin for even distribution; returning hashes stick to their assigned backend for KV cache reuse. Combines fair load balancing with session affinity.
- **Sticky table with LRU eviction**: Hash-to-backend mappings stored with configurable TTL (`--sticky-ttl`, default 12h) and max size (`--sticky-max`, default 1000). Least-recently-used entries evicted when at capacity.
- **Pure round-robin mode** (`--mode round-robin`): Even distribution with no stickiness, for workloads with no cache benefit.
- **Image-aware fingerprinting**: Multimodal requests with inline base64 or URL-referenced images now produce different routing hashes per image. Previously, only text was fingerprinted, causing all requests with the same prompt but different images to route to one backend.
- **Hostname resolution at startup**: `.local` mDNS hostnames resolved once via `getent hosts` (system resolver) and pinned. Avoids per-request mDNS races on hosts with multiple interfaces (LAN, VPN, USB4, Docker) where Go's HTTP client could resolve to the wrong IP.
- **Verbose routing log**: Each routed request logs the FNV-1a hash, a preview of the fingerprinted content, and the routing decision (`new:`, `sticky:`, `fallback:`).
- **Stats endpoint improvements**: Now includes `mode` and `sticky_entries` fields.

### Bug Fixes

- Fixed `.local` hostname resolution picking ZeroTier VPN IPs instead of LAN IPs due to mDNS race conditions across multiple network interfaces.
- Fixed `findBackend` lookup mismatch after hostname-to-IP resolution (was comparing resolved IP against original hostname).

## v0.1.0 (2026-03-02)

Initial release.

### Features

- **Per-session consistent hash routing**: Fingerprints first system message + first user message (first+last 256 chars each) to create a stable per-session routing key. Same conversation always routes to the same backend.
- **Consistent hash ring**: 150 virtual nodes per backend for even distribution. Graceful redistribution when backends are added/removed.
- **Health checks**: Periodic health probes (default every 10s via `/health`). Unhealthy backends automatically excluded from routing, re-included on recovery.
- **Automatic failover**: If the target backend for a session is down, routes to the next backend on the ring.
- **SSE streaming**: `FlushInterval: -1` ensures token-by-token streaming responses are forwarded immediately.
- **Stats endpoint**: `/proxy/stats` returns JSON with per-backend request counts, health status, and routing statistics.
- **Debug headers**: `X-ReverseLLM-Backend` and `X-ReverseLLM-Route` on every proxied response.
- **Graceful shutdown**: SIGINT/SIGTERM trigger clean connection draining (30s timeout).

### Background

Built to solve KV cache thrashing observed with nginx round-robin in front of 2x llama.cpp instances. Research across 13 coding agent tools (Cline, Claude Code, Goose, Aider, etc.) confirmed none send HTTP session identifiers (no cookies, no custom headers, no User-Agent differentiation). The fingerprint algorithm was chosen because:

- `ip_hash`: all agents run on localhost, same IP
- Cookies: Node.js fetch/axios don't handle Set-Cookie by default
- Custom headers: no agent sends them
- System prompt hash alone: all sessions of the same agent type would route to one backend
- **First+last fingerprint of system + first user message**: stable per-session key, no client cooperation needed
