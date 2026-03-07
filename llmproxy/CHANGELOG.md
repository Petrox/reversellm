# Changelog

## v0.3.0 (2026-03-07)

### Breaking Changes

- Default listen address changed from `:7888` (all interfaces) to `127.0.0.1:7888` (localhost only). Use `--listen 0.0.0.0:7888` for LAN access.
- `/proxy/stats` endpoint now requires `--debug` flag (returns 404 without it).
- `X-LLMProxy-Backend` and `X-LLMProxy-Route` response headers now require `--debug` flag.
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
- **Debug headers**: `X-LLMProxy-Backend` and `X-LLMProxy-Route` on every proxied response.
- **Graceful shutdown**: SIGINT/SIGTERM trigger clean connection draining (30s timeout).

### Background

Built to solve KV cache thrashing observed with nginx round-robin in front of 2x llama.cpp instances. Research across 13 coding agent tools (Cline, Claude Code, Goose, Aider, etc.) confirmed none send HTTP session identifiers (no cookies, no custom headers, no User-Agent differentiation). The fingerprint algorithm was chosen because:

- `ip_hash`: all agents run on localhost, same IP
- Cookies: Node.js fetch/axios don't handle Set-Cookie by default
- Custom headers: no agent sends them
- System prompt hash alone: all sessions of the same agent type would route to one backend
- **First+last fingerprint of system + first user message**: stable per-session key, no client cooperation needed
