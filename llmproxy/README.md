# llmproxy

KV-cache-aware reverse proxy for llama.cpp backends. Routes OpenAI-compatible API requests using sticky round-robin with per-session fingerprints: new requests are distributed evenly via round-robin, while returning sessions stick to their assigned backend for KV cache reuse.

## Why

llama.cpp maintains a KV cache per slot. When a request arrives with a prompt that shares a prefix with the cached content, it skips recomputation of the shared portion. Round-robin load balancing destroys this: each backend cold-starts the full prompt on every request.

Observed impact from actual llama.cpp logs:
```
sim_best = 0.969            <- 97% cache match found
failed to truncate tokens   <- cache invalidated anyway
prompt eval: 106381 ms / 49346 tokens  <- 2 minutes wasted reprocessing
```

With proper routing, only the delta tokens need processing (seconds instead of minutes).

## How It Works

### Sticky Round-Robin (default, `--mode sticky-rr`)

```
Client request -> parse JSON body -> fingerprint messages -> maphash (salted) -> lookup sticky table
  -> found & healthy: route to stored backend (sticky hit, refresh TTL)
  -> not found: round-robin to next healthy backend, store hash->backend mapping
```

This combines even distribution for independent requests (e.g. image extraction: same prompt, different images) with session stickiness for multi-turn conversations (e.g. agentic coding sessions).

### Fingerprinting

1. Extracts first system/developer message and first user message from `/v1/chat/completions`
2. Includes image identity in the fingerprint (base64 data or URL) so requests with the same text but different images produce different hashes
3. Fingerprints each message: first N + last N characters (default N=256)
4. Hashes the combined fingerprint with salted maphash (Go hash/maphash, seed randomized at startup)

**Why fingerprint first+last chars?**
- System prompts can be 50K+ chars; reading all of it on every request is wasteful
- Different agents may share a prefix ("You are a helpful...") but differ in the tail
- First 256 + last 256 chars captures both the type identity and agent-specific content

**Why only first 2 messages?**
- System prompt and first user message are immutable throughout a conversation
- Later messages change on every turn, which would break routing stability
- First user message provides per-session identity (different task = different hash)

### Hostname Resolution

Backend hostnames (especially `.local` mDNS names) are resolved at startup using the system resolver (`getent hosts`), which correctly follows nsswitch.conf. This avoids per-request mDNS races on hosts with multiple network interfaces (LAN, VPN, USB4, Docker) where any IP could win the race.

**Automatic re-resolution on failure**: When a health check fails, the proxy re-resolves the backend's hostname via `getent hosts`. If the IP has changed (e.g. DHCP renewal), the backend URL is updated in-place and the health check is retried immediately. This means DHCP IP changes are recovered within a single health check cycle (10s) without requiring a proxy restart.

## Build

```bash
go build -o llmproxy .
```

Requires Go 1.21+.

## Usage

```bash
./llmproxy --backends host1:8000,host2:8000
```

### Options

```
--listen ADDR          Listen address (default: 127.0.0.1:7888, localhost only)
                         Use 0.0.0.0:7888 to accept connections from the network
--backends ADDRS       Comma-separated backend addresses (required)
--mode MODE            Routing mode (default: sticky-rr)
                         sticky-rr:   round-robin for new hashes, sticky for returning ones
                         round-robin: pure even distribution, no stickiness
                         hash:        consistent hash ring (original behavior)
--sticky-ttl DUR       How long a hash->backend mapping stays active (default: 12h)
--sticky-max N         Max sticky table entries before evicting oldest (default: 1000)
--prefix-length N      Chars from each end of message for fingerprint (default: 256)
--health-path PATH     Backend health check endpoint (default: /health)
--health-interval DUR  Health check interval (default: 10s)
--debug                Enable debug mode (default: false)
                         Enables: /proxy/stats endpoint, X-LLMProxy-* response headers,
                         content previews in logs, backend name and raw error in error responses
--max-request-size N   Maximum request body size in bytes (default: 16777216, 16 MB)
                         Returns HTTP 413 when exceeded
```

### Endpoints

| Path | Description |
|------|-------------|
| `/proxy/stats` | JSON stats: mode, requests per backend, health, sticky table size. Requires `--debug`; returns 404 otherwise |
| `/*` | All other requests proxied to backends |

### Response Headers

When `--debug` is enabled, proxied responses include:
- `X-LLMProxy-Backend`: which backend served the request
- `X-LLMProxy-Route`: routing decision reason

Without `--debug`, these headers are not set.

### Log Format

Without `--debug` (default), log lines include the routing reason but no content previews:

```
[route] POST /v1/chat/completions -> dsstrix1.local:8080 (new:[sys:4821+usr:9158] fp=256) [total reqs to backend: 1]
[route] POST /v1/chat/completions -> dsstrix2.local:8080 (new:[sys:4821+usr:9296] fp=256) [total reqs to backend: 1]
[route] POST /v1/chat/completions -> dsstrix1.local:8080 (sticky:[sys:4821+usr:9158] fp=256) [total reqs to backend: 2]
```

With `--debug`, log lines also include the hash value and the first 60 characters of each message:

```
[route] POST /v1/chat/completions -> dsstrix1.local:8080 (new:hash=a35c9d35 [usr:9158("prompt preview...")] fp=256) [total reqs to backend: 1]
[route] POST /v1/chat/completions -> dsstrix2.local:8080 (new:hash=028e9a10 [usr:9296("prompt preview...")] fp=256) [total reqs to backend: 1]
[route] POST /v1/chat/completions -> dsstrix1.local:8080 (sticky:hash=a35c9d35 [usr:9158("prompt preview...")] fp=256) [total reqs to backend: 2]
```

Prefixes: `new:` = first time seen (round-robin assigned), `sticky:` = returning hash (same backend), `fallback:` = unparseable request.

## Routing Behavior

| Scenario | Routing |
|----------|---------|
| Same agent, same task, growing conversation | Same backend (sticky hit) |
| Same agent, different task | Different backend (different first user message) |
| Same prompt, different images | Round-robin (different image = different hash) |
| Different agent, same task | Different backend (different system prompt) |
| Non-POST requests (GET /v1/models) | First healthy backend |
| No parseable system/user message | First healthy backend (fallback) |

## Sticky Table

- New hashes are assigned to the next backend via round-robin, then stored
- Returning hashes route to the stored backend (TTL refreshed on each hit)
- Default TTL: 12 hours (configurable via `--sticky-ttl`)
- Max entries: 1000 (configurable via `--sticky-max`)
- When at capacity, the least-recently-used entry is evicted
- Expired entries are cleaned up every 60 seconds

## Health Checks

- Checks each backend every 10s via GET to `--health-path`
- Backends marked unhealthy on connection failure or non-2xx/3xx response
- Unhealthy backends skipped during round-robin and sticky routing
- If a sticky backend becomes unhealthy, request falls through to round-robin
- Recovery detected automatically on next successful health check
- On failure, re-resolves the backend hostname to detect DHCP IP changes
- If IP changed, updates backend URL and retries health check immediately

## Security

llmproxy is designed for use in trusted local networks alongside llama.cpp. Several hardening measures are in place by default:

**Localhost-only listener**: The default listen address is `127.0.0.1:7888`, which binds to the loopback interface only. Clients on other machines cannot reach the proxy unless you explicitly pass `--listen 0.0.0.0:7888`.

**Debug mode is off by default**: The `/proxy/stats` endpoint returns 404, debug response headers (`X-LLMProxy-Backend`, `X-LLMProxy-Route`) are not set, and log lines do not include message content previews. Enable with `--debug` only when needed.

**Request size limit**: Incoming request bodies are capped at 16 MB by default (`--max-request-size`). Requests that exceed this limit are rejected with HTTP 413 before any routing or memory allocation occurs.

**Salted hash function**: Session fingerprints use Go's `hash/maphash` with a seed generated randomly at startup (`maphash.MakeSeed()`). This prevents offline precomputation of hash collisions against the sticky routing table. Hash values are not stable across restarts, which is acceptable because the sticky table is in-memory only.

## Integration

Managed by `../launchproxy.sh`:
```bash
./launchproxy.sh --engine llmproxy start
./launchproxy.sh status
./launchproxy.sh stop
```

Or run standalone:
```bash
./llmproxy --backends host1.local:8000,host2.local:8000 --listen :9080
```
