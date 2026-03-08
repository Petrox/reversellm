# reversellm

Content-aware (OpenAI API specific) reverse proxy for llama/vllm/other inference servers for agentic use-case scenarios that implements sticky sessions for subagents to optimize cache hits between multiple backend inference servers.

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
./build.sh
```

Or via Docker (no local Go installation required):

```bash
./build.sh --docker
```

Or manually: `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o reversellm .`

Requires Go 1.26.1+ (for security patches to `crypto/x509`, `net/url`, and `os`).

## Docker

```bash
docker build -t reversellm .
docker run -p 7888:7888 reversellm --listen 0.0.0.0:7888 --backends host1:8000,host2:8000
```

## Usage

```bash
./reversellm --backends host1:8000,host2:8000
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
                         Enables: /proxy/stats endpoint, X-ReverseLLM-* response headers,
                         content previews in logs, backend name and raw error in error responses
--max-request-size N   Maximum request body size in bytes (default: 16777216, 16 MB)
                         Returns HTTP 413 when exceeded
--rate-limit N         Max requests per second per IP (default: 0 = unlimited)
                         Token bucket with burst = 2x rate; excess requests receive HTTP 429
```

### Endpoints

| Path | Description |
|------|-------------|
| `/proxy/stats` | JSON stats: mode, requests per backend, health, sticky table size. Requires `--debug` and localhost access; returns 404 without `--debug`, 403 from non-localhost |
| `/*` | All other requests proxied to backends |

### Response Headers

When `--debug` is enabled, proxied responses include:
- `X-ReverseLLM-Backend`: which backend served the request
- `X-ReverseLLM-Route`: routing decision reason

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
- When at capacity, the least-recently-used entry is evicted via O(1) LRU eviction (doubly-linked list)
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

reversellm is designed for use in trusted local networks alongside llama.cpp. Several hardening measures are in place by default:

**Localhost-only listener**: The default listen address is `127.0.0.1:7888`, which binds to the loopback interface only. Clients on other machines cannot reach the proxy unless you explicitly pass `--listen 0.0.0.0:7888`.

**Debug mode is off by default**: The `/proxy/stats` endpoint returns 404, debug response headers (`X-ReverseLLM-Backend`, `X-ReverseLLM-Route`) are not set, and log lines do not include message content previews. Enable with `--debug` only when needed.

**Request size limit**: Incoming request bodies are capped at 16 MB by default (`--max-request-size`). Requests that exceed this limit are rejected with HTTP 413 before any routing or memory allocation occurs.

**Salted hash function**: Session fingerprints use Go's `hash/maphash` with a seed generated randomly at startup (`maphash.MakeSeed()`). This prevents offline precomputation of hash collisions against the sticky routing table. Hash values are not stable across restarts, which is acceptable because the sticky table is in-memory only.

**Per-IP rate limiting**: `--rate-limit N` enforces a maximum of N requests per second per client IP using a token bucket. Burst capacity is 2x the configured rate. Excess requests receive HTTP 429. **Note**: Rate limiting uses the TCP peer address (`RemoteAddr`), not `X-Forwarded-For`. When running behind another reverse proxy or load balancer, all clients appear to share one IP, making the rate limit apply collectively. This is by design — `X-Forwarded-For` is trivially spoofable by direct clients. If you need per-client rate limiting behind a trusted proxy, implement it at the outer proxy layer instead.

**Request body sanitization**: Non-POST requests have their body discarded before proxying. This prevents HTTP request smuggling via body content on methods that should not carry a body.

**Hostname validation**: Backend hostnames are validated against `[a-zA-Z0-9._-]` before any DNS resolution is attempted. Hostnames that fail validation are rejected at startup.

**`getent` path pinning**: The system resolver is invoked as `/usr/bin/getent` with an absolute path. If that binary is not present, the proxy logs a warning and falls back to Go's built-in resolver.

**Proxy forwarding headers**: Proxied requests include `X-Forwarded-Proto`, `X-Forwarded-Host`, and `Via: 1.1 reversellm` headers per RFC 7230 §5.7.1, enabling backends to reconstruct original request context. Client-supplied `X-Forwarded-For` headers are stripped before the proxy appends the real TCP peer IP, preventing IP spoofing through the forwarding chain. (Security review M4: fixed)

**Security headers**: Every response (proxied or locally generated) includes `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY`. Additional browser-oriented headers (`Content-Security-Policy`, `Cache-Control`, `Referrer-Policy`) are omitted because the proxy returns JSON exclusively, not HTML — browsers do not render the responses, so these headers provide no practical benefit. (Security review L4: accepted)

**JSON depth limit**: The JSON parser rejects request bodies with nesting deeper than 128 levels, preventing stack overflow from crafted payloads.

**O(1) LRU eviction**: The sticky table evicts the least-recently-used entry in O(1) time using a doubly-linked list, preventing memory exhaustion under adversarial hash diversity without requiring a full table scan.

**Slow-loris mitigation**: The HTTP server sets `ReadHeaderTimeout: 10s`. Connections that do not complete their request headers within 10 seconds are closed, preventing slow-loris-style resource exhaustion.

**Unicode-safe log truncation**: Log previews and fingerprints are truncated at rune boundaries, not byte boundaries, so multi-byte UTF-8 sequences are never split in log output or routing keys.

**Body-read timeout**: POST body reads are capped at 30 seconds independently of the 5-minute server ReadTimeout, mitigating body-phase slow-loris attacks. The timeout is scoped to the body read only and does not affect the proxy round-trip, so streaming responses can run for the full WriteTimeout (10 minutes).

**Health check hardening**: Health checks use a persistent `http.Client` with body draining to prevent connection/FD leaks. The `--health-path` flag is validated to start with `/` and reject `..` traversal.

**Rate limiter bounds**: The per-IP visitor map is capped at 10,000 entries to prevent memory exhaustion from IP-cycling attacks.

**Stats endpoint localhost restriction**: When `--debug` is enabled, `/proxy/stats` is restricted to localhost (`127.0.0.1` / `::1`). Remote clients receive HTTP 403 even in debug mode.

**Backend transport timeouts**: Each backend uses a dedicated `http.Transport` with `ResponseHeaderTimeout: 120s`, `DialContext` timeout `10s`, and `MaxIdleConnsPerHost: 10`. This prevents goroutine accumulation from slow or unresponsive backends. (Security review M2: fixed)

**Docker build isolation**: A `.dockerignore` file excludes `.git/`, security reports, and build artifacts from the Docker build context, preventing accidental inclusion of sensitive data in image layers. (Security review M3: fixed)

**Known accepted risks**: No TLS (plaintext HTTP), no authentication. See `reports/security-review-2026-03-08-v4.md` for the latest full review.

## systemd Installation

reversellm ships a systemd template unit (`reversellm@.service`) that supports running multiple instances with different configurations.

### Install (single instance)

```bash
# Build
./build.sh

# Install binary and unit file
sudo cp reversellm /usr/local/bin/
sudo cp reversellm@.service /etc/systemd/system/

# Create config directory and default environment file
sudo mkdir -p /etc/reversellm
sudo cp reversellm-default.env /etc/reversellm/default.env

# Edit the environment file with your backends
sudo editor /etc/reversellm/default.env

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now reversellm@default
```

### Logs

```bash
journalctl -u reversellm@default -f
```

### Multiple Instances

The template unit uses the instance name (the part after `@`) to select an environment file from `/etc/reversellm/<instance>.env`. This allows running multiple reversellm processes on different ports with different backends.

**Example**: 3 instances proxying to different backend port groups:

```bash
# Copy example environment files (edit backends/ports as needed)
sudo cp examples/port9000.env /etc/reversellm/port9000.env
sudo cp examples/port9001.env /etc/reversellm/port9001.env
sudo cp examples/port9002.env /etc/reversellm/port9002.env

# Start all three
sudo systemctl enable --now reversellm@port9000
sudo systemctl enable --now reversellm@port9001
sudo systemctl enable --now reversellm@port9002
```

Each instance runs independently with its own listen address, backends, and configuration:

| Instance | Listen | Backends | Config |
|----------|--------|----------|--------|
| `reversellm@port9000` | `0.0.0.0:9000` | `host1:8000,host2:8000` | `/etc/reversellm/port9000.env` |
| `reversellm@port9001` | `0.0.0.0:9001` | `host1:8001,host2:8001` | `/etc/reversellm/port9001.env` |
| `reversellm@port9002` | `0.0.0.0:9002` | `host1:8002,host2:8002` | `/etc/reversellm/port9002.env` |

**Manage all instances at once:**

```bash
# Status of all instances
systemctl list-units 'reversellm@*'

# Restart all
sudo systemctl restart 'reversellm@*'

# Stop all
sudo systemctl stop 'reversellm@*'
```

### Environment File Reference

Each `/etc/reversellm/<instance>.env` file contains:

```bash
LISTEN_ADDR=0.0.0.0:9000                           # Listen address
BACKENDS=host1.local:8000,host2.local:8000          # Backend addresses
MODE=sticky-rr                                       # sticky-rr | round-robin | hash
STICKY_TTL=12h                                       # Hash->backend mapping TTL
STICKY_MAX=1000                                      # Max sticky table entries
PREFIX_LENGTH=256                                    # Fingerprint chars per end
HEALTH_PATH=/health                                  # Health check endpoint
HEALTH_INTERVAL=10s                                  # Health check interval
MAX_REQUEST_SIZE=16777216                            # Max body size (16 MB)
RATE_LIMIT=0                                         # Per-IP rate limit (0=off)
```

See `reversellm-default.env` for a commented template.
