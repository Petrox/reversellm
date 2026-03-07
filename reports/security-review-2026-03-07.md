# Security Review: llmproxy

**Date:** 2026-03-07
**Scope:** Full security review of `/home/petros/proj/reversellm/llmproxy/main.go` (1028 lines, Go 1.24.5, stdlib-only)
**Reviewer:** Automated multi-agent security review (4 parallel analyzers: source code vulnerabilities, race conditions, supply chain, configuration/deployment)
**Verified against:** Actual source code, git status, live log files, compiled binary on disk

---

## Executive Summary

The codebase is a single-file Go reverse proxy (~1000 LOC) with zero third-party dependencies. The attack surface is moderate: it accepts arbitrary HTTP traffic, parses JSON request bodies, executes a system command (`getent`), and proxies to backend inference servers. The code is generally well-structured with proper mutex usage, but has several concrete vulnerabilities ranging from memory exhaustion to information disclosure.

**Finding Count by Severity:**

| Severity | Count |
|----------|-------|
| CRITICAL | 2 |
| HIGH | 6 |
| MEDIUM | 7 |
| LOW | 4 |
| INFORMATIONAL | 4 |

**Known Accepted Risks (per user):** No HTTPS, no authentication. These are documented below but not flagged as unexpected.

---

## CRITICAL Findings

### C1. Unbounded Request Body Read — Memory Exhaustion DoS

**Severity:** CRITICAL
**Confidence:** 100%
**Location:** `main.go:645`

```go
body, err := io.ReadAll(r.Body)
```

**Evidence:** `io.ReadAll` buffers the entire HTTP request body into a `[]byte` with no size limit. The `http.Server` at lines 985-991 sets `ReadTimeout: 5 * time.Minute` but no `MaxBytesReader`. A client on a fast LAN can send a multi-GB body well within 5 minutes. The body stays in memory for the full proxy round-trip (up to `WriteTimeout: 10 * time.Minute` for streaming responses at line 989). Concurrent attackers multiply the impact linearly.

**Impact:** An attacker can exhaust proxy RAM with a single large request or several concurrent large requests, causing the proxy process to OOM-kill, taking down routing for all legitimate sessions.

**Remediation:**
```go
const maxBodyBytes = 32 * 1024 * 1024 // 32 MB
r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
body, err := io.ReadAll(r.Body)
if err != nil {
    http.Error(w, `{"error":{"message":"request body too large or unreadable","type":"proxy_error"}}`,
        http.StatusRequestEntityTooLarge)
    return
}
```

---

### C2. Prompt Content Logged to Persistent Files

**Severity:** CRITICAL
**Confidence:** 90%
**Location:** `main.go:348-353` (detail construction), `main.go:734` (log output)

```go
// Line 348
detailParts = append(detailParts, fmt.Sprintf("sys:%d(%q)", len(systemContent), truncate(systemContent, 60)))
// Line 352
detailParts = append(detailParts, fmt.Sprintf("usr:%d(%q)", len(userContent), truncate(userContent, 60)))
```

**Evidence:** The first 60 characters of both the system prompt and first user message are written to every route log line. Confirmed in the live log file `/home/petros/proj/reversellm/llmproxy/llmproxy-9080.log`:

```
[route] POST /v1/chat/completions -> dsstrix1.local:8080 (new:hash=93453ae7
  [usr:9572("[img:iVBORw0KGgoAAAANSUhEUgAABNgAAAbZCAIAAAAeFy+nAAAACXBIWXM...")] fp=256)
```

For text prompts (not images), this would contain the literal first sentence of the user's coding task or system role description. These log files are world-readable (permissions `664`) and are persisted indefinitely.

**Impact:** Sensitive prompt content (proprietary code, system instructions, internal business logic) leaks to log files accessible to any user with filesystem access.

**Remediation:** Remove content previews from log output. Log only hash and byte counts:
```go
detailParts = append(detailParts, fmt.Sprintf("sys:%d", len(systemContent)))
detailParts = append(detailParts, fmt.Sprintf("usr:%d", len(userContent)))
```

---

## HIGH Findings

### H1. Unauthenticated Stats Endpoint Leaks Internal Topology

**Severity:** HIGH
**Confidence:** 100%
**Location:** `main.go:858-901` (handler), `main.go:982` (route registration)

```go
mux.HandleFunc("/proxy/stats", proxy.handleStats)
```

**Evidence:** The `/proxy/stats` endpoint requires no authentication and returns:
- `Name`: original hostnames (`dsstrix1.local:8080`, `dsstrix2.local:8080`)
- `URL`: resolved internal IPs (`http://192.168.1.123:8080`, `http://192.168.1.108:8080`)
- Health status, per-backend request counts, routing mode, fingerprint length, sticky table size

Confirmed by log line: `[resolve] dsstrix1.local:8080 -> 192.168.1.123:8080`

**Impact:** Full internal infrastructure enumeration. Any client that reaches the proxy can map all backend servers, their health, traffic distribution, and routing algorithm parameters.

**Remediation:** Restrict to loopback:
```go
func (ps *ProxyServer) handleStats(w http.ResponseWriter, r *http.Request) {
    host, _, _ := net.SplitHostPort(r.RemoteAddr)
    if host != "127.0.0.1" && host != "::1" {
        http.Error(w, `{"error":{"message":"forbidden","type":"auth_error"}}`, http.StatusForbidden)
        return
    }
    // ... rest of handler
}
```

---

### H2. Information Disclosure via Response Headers

**Severity:** HIGH
**Confidence:** 95%
**Location:** `main.go:738-739`

```go
w.Header().Set("X-LLMProxy-Backend", backend.Name)
w.Header().Set("X-LLMProxy-Route", rr.reason)
```

**Evidence:** Every proxied response includes the backend hostname:port in a response header. An attacker can enumerate all backends by making requests that hit different hash ring positions.

**Impact:** Backend infrastructure disclosed to every client. Combined with FNV-1a's non-cryptographic nature (see H5), an attacker can deterministically target specific backends.

**Remediation:** Gate behind a `--debug-headers` flag, disabled by default.

---

### H3. Internal Details Leaked in Error Responses

**Severity:** HIGH
**Confidence:** 97%
**Location:** `main.go:760-762`

```go
http.Error(w,
    fmt.Sprintf(`{"error":{"message":"backend %s: %s","type":"proxy_error"}}`, backend.Name, err),
    http.StatusBadGateway)
```

**Evidence:** The error response to the client includes `backend.Name` (hostname:port) and the raw Go `net` error, which typically contains the resolved IP address: `dial tcp 192.168.1.55:8080: connect: connection refused`.

**Impact:** By provoking backend errors, an attacker can extract resolved IPs even when they cannot access the stats endpoint.

**Remediation:**
```go
log.Printf("[error] proxy to %s failed: %v (path: %s)", backend.Name, err, r.URL.Path)
http.Error(w, `{"error":{"message":"upstream backend unavailable","type":"proxy_error"}}`,
    http.StatusBadGateway)
```

Also fix the error at line 648 which includes raw read errors:
```go
http.Error(w, fmt.Sprintf(`{"error":{"message":"failed to read request body: %s",...`, err),
```

---

### H4. Default Listen Address Binds All Interfaces

**Severity:** HIGH
**Confidence:** 88%
**Location:** `main.go:908`

```go
listen := flag.String("listen", ":7888", "Listen address (host:port)")
```

**Evidence:** Default `:7888` is equivalent to `0.0.0.0:7888`. Confirmed by live log: `llmproxy starting on 0.0.0.0:9000`. Since all clients (Cline, Claude Code, Goose) run on localhost, the proxy is exposed to the entire LAN by default when only localhost access is needed.

**Impact:** Any device on the LAN segment (including IoT, guest WiFi, compromised devices) can access the proxy, use GPU inference time, and enumerate the infrastructure.

**Remediation:** Change default to `127.0.0.1:7888`. Users who need LAN access can explicitly set `--listen 0.0.0.0:7888`.

---

### H5. Sticky Table Hash Collision and Exhaustion DoS

**Severity:** HIGH
**Confidence:** 88%
**Location:** `main.go:76-80` (hash function), `main.go:442-491` (sticky table)

**Evidence:** Two attack vectors:

**Vector A — Table Exhaustion:** The sticky table is bounded at `defaultStickyMax = 1000` entries. An attacker sending 1001+ distinct fingerprints fills the table and forces continuous LRU eviction. Each eviction is O(n) under the write lock (linear scan at lines 473-491), creating a serialization bottleneck.

**Vector B — Hash Collision:** FNV-1a produces 32-bit hashes with no secret salt. Birthday bound for collisions is ~65,536 distinct inputs. An attacker can precompute inputs that collide with a legitimate session's hash, hijacking its backend routing.

**Impact:** (A) KV cache coherence destroyed for all legitimate sessions. (B) Targeted session hijacking to a specific backend.

**Remediation:** Salt the hash at startup:
```go
var hashSalt [8]byte
func init() { rand.Read(hashSalt[:]) }

func fnvHash(key string) uint32 {
    h := fnv.New32a()
    h.Write(hashSalt[:])
    h.Write([]byte(key))
    return h.Sum32()
}
```

---

### H6. Port-Specific Log Files Not Gitignored

**Severity:** HIGH
**Confidence:** 90%
**Location:** `.gitignore:35-38`

**Evidence:** The `.gitignore` covers `llmproxy/llmproxy.log` but not the port-specific variants. Five unignored log files are present:
- `llmproxy/llmproxy-10080.log` (1,063 bytes)
- `llmproxy/llmproxy-9080.log` (440,401 bytes)
- `llmproxy/llmproxy-9000.log` (31,999 bytes)
- `llmproxy/llmproxy-9001.log` (8,094 bytes)
- `llmproxy/llmproxy-9002.log` (31,999 bytes)

These contain resolved internal IPs, backend hostnames, and prompt content previews. While currently NOT tracked by git (the entire `llmproxy/` directory is `??` untracked), a `git add .` or `git add llmproxy/` would commit them.

**Impact:** Accidental commit exposes internal infrastructure and prompt data in version history.

**Remediation:** Replace the single-file entry with a glob:
```
llmproxy/*.log
```

---

## MEDIUM Findings

### M1. No `ReadHeaderTimeout` — Slow-Loris Possible

**Severity:** MEDIUM
**Confidence:** 80%
**Location:** `main.go:985-991`

```go
server := &http.Server{
    ReadTimeout:  5 * time.Minute,
    WriteTimeout: 10 * time.Minute,
    IdleTimeout:  2 * time.Minute,
}
```

**Evidence:** `ReadTimeout` of 5 minutes covers the entire time from connection accept to body completion. A slow-loris attacker can send 1 byte every 4:59 per connection, tying up goroutines. No `ReadHeaderTimeout` is set (Go defaults to no limit on headers if not specified separately).

**Remediation:**
```go
server := &http.Server{
    ReadHeaderTimeout: 10 * time.Second,  // headers must arrive quickly
    ReadTimeout:       5 * time.Minute,   // body can be large
    WriteTimeout:      10 * time.Minute,
    IdleTimeout:       2 * time.Minute,
    MaxHeaderBytes:    1 << 20,           // 1 MB max headers
}
```

---

### M2. No Rate Limiting on Any Endpoint

**Severity:** MEDIUM
**Confidence:** 82%
**Location:** `main.go:625` (ServeHTTP), `main.go:858` (handleStats)

**Evidence:** No per-IP or global request budget exists. GPU inference backends cost significant compute per request. An attacker or misconfigured client can drive all backends to 100% utilization continuously.

**Remediation:** Add `golang.org/x/time/rate` with a per-IP limiter map, or at minimum add `MaxHeaderBytes` to the server config.

---

### M3. Sticky-RR Lookup-Then-Store Race for New Sessions

**Severity:** MEDIUM
**Confidence:** 92%
**Location:** `main.go:665-686`

**Evidence:** Two concurrent requests with the same previously-unseen hash can enter the Lookup-Store sequence simultaneously:
1. R1: `Lookup` miss -> round-robin -> gets `backendA`
2. R2: `Lookup` miss (R1 hasn't stored yet) -> round-robin -> gets `backendB`
3. R1: `Store(hash, backendA)`
4. R2: `Store(hash, backendB)` -> overwrites R1's entry

The system converges (subsequent requests stick to `backendB`), but the first two requests hit different backends, wasting KV cache for those two requests.

**Impact:** Defeats the KV-cache-reuse guarantee for sessions whose first two requests arrive simultaneously. The window is narrow but real under concurrent load.

**Remediation:** Add a `LookupOrStore` atomic method to `StickyTable`:
```go
func (st *StickyTable) LookupOrStore(hash uint32, newName string) (string, bool) {
    st.mu.Lock()
    defer st.mu.Unlock()
    entry, ok := st.entries[hash]
    if ok && !time.Now().After(entry.expiresAt) {
        return entry.backendName, true
    }
    // ... store newName and return
}
```

---

### M4. `exec.Command("getent", ...)` Uses PATH-Dependent Lookup

**Severity:** MEDIUM
**Confidence:** 85%
**Location:** `main.go:382`

```go
out, err := exec.Command("getent", "hosts", hostname).Output()
```

**Evidence:** `getent` is resolved via `$PATH` at runtime. If `$PATH` is tampered with (e.g., a malicious `getent` earlier in `$PATH`), the proxy executes attacker-controlled code. Additionally:
- `getent` is unavailable on macOS, Alpine Linux (musl), and Windows.
- The fallback to `net.LookupHost` (line 394) occurs silently with no warning, meaning the explicitly intended mDNS-aware resolution fails without operator notice.
- The hostname argument is not validated against an allowlist before being passed to the command.

**Remediation:** Pin absolute path and add validation:
```go
if !isValidHostname(hostname) { // ^[a-zA-Z0-9._-]+$
    return "", fmt.Errorf("RESOLVE_ERROR: hostname %q contains invalid characters", hostname)
}
out, err := exec.Command("/usr/bin/getent", "hosts", hostname).Output()
if err != nil {
    log.Printf("WARN: getent unavailable for %q, falling back to Go resolver", hostname)
}
```

---

### M5. No TLS — Prompts Transmitted in Cleartext

**Severity:** MEDIUM (documented accepted risk, included for completeness)
**Confidence:** 85%
**Location:** `main.go:1023` (server), `main.go:551` (backend connections)

**Evidence:** All three traffic paths are plaintext:
- **Inbound:** POST bodies with full system prompts (50K+ chars per README), user messages, and inline base64 images.
- **Backend:** Health checks and proxied requests to `http://` backend URLs (line 551: `addr = "http://" + addr`).
- **Stats:** JSON responses with backend topology.

Confirmed by log: backends resolved as `http://192.168.1.123:8080`.

**Remediation:** Add `--tls-cert` / `--tls-key` flags that switch to `ListenAndServeTLS` when provided.

---

### M6. HTTP Request Smuggling Surface for Non-POST Requests

**Severity:** MEDIUM
**Confidence:** 80%
**Location:** `main.go:628-641, 747-766`

**Evidence:** Non-POST requests (line 629) are forwarded via `httputil.ReverseProxy` without body buffering. The proxy does not strip or validate `Transfer-Encoding`/`Content-Length` conflicts beyond `httputil.ReverseProxy`'s default hop-by-hop stripping. A GET request with a body (technically allowed by HTTP) is forwarded with original `Transfer-Encoding`/`Content-Length`, which could desynchronize the backend parser on persistent HTTP/1.1 connections.

**Remediation:** For GET/HEAD/DELETE, explicitly discard the body:
```go
if r.Method == http.MethodGet || r.Method == http.MethodHead {
    r.Body = http.NoBody
    r.ContentLength = 0
}
```

---

### M7. `truncate()` Slices UTF-8 at Byte Boundaries

**Severity:** MEDIUM
**Confidence:** 83%
**Location:** `main.go:297-302`

```go
func truncate(s string, n int) string {
    if len(s) <= n {
        return s
    }
    return s[:n] + "..."
}
```

**Evidence:** `s[:n]` slices at byte positions, not rune boundaries. Multi-byte UTF-8 sequences sliced mid-character produce invalid UTF-8, which causes `\xNN` escapes in log output and may confuse log analysis tools.

**Remediation:**
```go
func truncate(s string, n int) string {
    r := []rune(s)
    if len(r) <= n {
        return s
    }
    return string(r[:n]) + "..."
}
```

---

## LOW Findings

### L1. Binary Contains Debug Info and Is Not Stripped

**Severity:** LOW
**Confidence:** 100%
**Location:** `llmproxy/llmproxy` (on-disk binary)

**Evidence:** `file` command output: `ELF 64-bit LSB executable, x86-64, dynamically linked, with debug_info, not stripped`. Debug symbols expose internal function names, types, and source file paths, aiding reverse engineering.

**Remediation:** Build with `-ldflags="-s -w"` to strip debug info and reduce binary size.

---

### L2. No Security Headers on Proxy Responses

**Severity:** LOW
**Confidence:** 80%
**Location:** `main.go:897-900` (stats), `main.go:738-739` (proxy responses)

**Evidence:** No `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, or `Content-Security-Policy` headers. The `/proxy/stats` JSON endpoint could be MIME-sniffed as HTML by browsers.

**Remediation:** Add a security headers middleware.

---

### L3. PID File World-Readable

**Severity:** LOW
**Confidence:** 80%
**Location:** `llmproxy/llmproxy.pid` (runtime file)

**Evidence:** Permissions `664 petros:petros`, content: PID `2421237`. A world-readable PID file on a multi-user system allows reading `/proc/<pid>/cmdline` to see `--backends` flag values, exposing backend addresses.

**Remediation:** `chmod 600` on the PID file in the launch script.

---

### L4. Eviction Under Write Lock Is O(n) Linear Scan

**Severity:** LOW
**Confidence:** 82%
**Location:** `main.go:473-491`

**Evidence:** `evictOldest()` iterates all entries under `st.mu.Lock()`. With `defaultStickyMax = 1000`, every new-session insertion at capacity causes a 1000-entry linear scan that blocks all concurrent readers. Under adversarial conditions (attacker sending many distinct fingerprints), this is a serialization bottleneck.

**Remediation:** Replace with a min-heap keyed on `lastUsed` time for O(log n) eviction.

---

## INFORMATIONAL Findings

### I1. Zero Third-Party Dependencies (Positive)

**Confidence:** 100%
**Location:** `go.mod` (lines 1-3)

All 20 imports are Go stdlib. The entire third-party supply chain attack surface is zero. No vendored packages, no transitive dependencies, no typosquatting risk.

### I2. Binary and Logs Not Git-Tracked (Positive)

**Confidence:** 100%
**Evidence:** `git ls-files llmproxy/llmproxy llmproxy/*.log` returns empty. The entire `llmproxy/` directory shows as `??` (untracked) in `git status`. The `.gitignore` entries are correctly preventing tracking.

### I3. Health-to-Proxy TOCTOU Is Correctly Handled

**Confidence:** 90%
**Location:** `main.go:667, 728, 758-763`

A backend can go unhealthy between health check at line 667 and proxy dispatch at line 728. This is an inherent TOCTOU that cannot be eliminated without holding a lock during the entire proxy round-trip. The `ErrorHandler` at lines 758-763 catches connection failures and returns a structured 502 JSON error. The window is narrow and the failure is graceful.

### I4. 30-Second Shutdown Timeout May Truncate Streaming Responses

**Confidence:** N/A (operational, not exploitable)
**Location:** `main.go:1000`

`server.Shutdown` with a 30-second timeout will forcefully terminate in-flight streaming responses that take longer than 30 seconds. This is acceptable for a lab proxy but worth noting for operational awareness.

---

## Supply Chain Assessment

| Area | Status | Details |
|------|--------|---------|
| Third-party deps | **Clean** | Zero external dependencies (stdlib only) |
| Go version | **Outdated** | `go 1.24.5` (2025-07-08) is 8 patches behind `go 1.24.13` (2026-02-04). Security fixes to `os/exec` (in 1.24.6) and `net/http` (in 1.24.8) directly affect this binary. |
| Binary provenance | **Unverifiable** | No Makefile, Dockerfile, or build script. Binary on disk cannot be verified against source. Binary contains debug info (not stripped). |
| `getent` dependency | **Uncontrolled** | System binary resolved via `$PATH`. No path pinning, no availability check. |
| go.sum | **N/A** | Correctly absent (no external deps to checksum). |
| .gitignore coverage | **Partial gap** | `llmproxy/llmproxy.log` covered; `llmproxy/llmproxy-*.log` NOT covered. |

---

## Concurrency Assessment

| Component | Protection | Status |
|-----------|-----------|--------|
| `ConsistentHash` ring | `sync.RWMutex` | **Correct** — immutable after construction, mutex is defensive |
| `Backend.URL` | `sync.Mutex` | **Correct** — all concurrent accesses hold `b.mu` |
| `Backend.healthy` | `atomic.Bool` | **Correct** — lock-free reads/writes |
| `Backend.requests` | `atomic.Int64` | **Correct** — lock-free counter |
| `StickyTable` | `sync.RWMutex` | **Correct internally** — but Lookup+Store is non-atomic across calls (M3) |
| `rrCounter` | `atomic.Uint64` | **Correct** — unsigned overflow is safe with modular arithmetic |
| `ps.backends` slice | None needed | **Correct** — never modified after construction |

---

## Priority Remediation Order

Ordered by impact-to-effort ratio (highest first):

| Priority | Finding | Effort | Impact |
|----------|---------|--------|--------|
| 1 | **C1** — Add `MaxBytesReader` at line 645 | 1 line | Prevents OOM crash |
| 2 | **H6** — Add `llmproxy/*.log` to `.gitignore` | 1 line | Prevents accidental data leak |
| 3 | **H3** — Remove internal details from error response | 2 lines | Stops IP leakage |
| 4 | **C2** — Remove content preview from logs | 2 lines | Stops prompt leakage |
| 5 | **H1** — Restrict stats to loopback | 5 lines | Stops topology enumeration |
| 6 | **H2** — Gate debug headers behind flag | 3 lines | Stops backend enumeration |
| 7 | **M1** — Add `ReadHeaderTimeout` | 1 line | Mitigates slow-loris |
| 8 | **H4** — Change default listen to `127.0.0.1` | 1 line | Reduces exposure surface |
| 9 | **H5** — Salt FNV hash | 5 lines | Prevents collision attacks |
| 10 | **M4** — Pin `getent` path and validate hostnames | 5 lines | Hardens command execution |

---

## Go Version Upgrade Path

Update `go.mod` line 3 from `go 1.24.5` to `go 1.24.13` (latest 1.24.x patch as of 2026-02-04).

Key security fixes picked up:
- **go1.24.6** (2025-08-06): `os/exec` fix — directly relevant (this binary calls `exec.Command`)
- **go1.24.8** (2025-10-07): `net/http`, `net/url` fixes — directly relevant (this binary is an HTTP proxy using `net/http/httputil`)
- **go1.24.10-13**: Additional `net/url`, `crypto/tls` fixes

---

*This report references specific file paths and line numbers verified against the source code at the time of review. Every finding is grounded in observable evidence (code, file contents, log output, git status) — no claims are made about behaviors that were not verified.*
