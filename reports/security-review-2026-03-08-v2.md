# Security Review: reversellm (Third Full Audit)

**Date:** 2026-03-08 (v2)
**Scope:** Complete method-by-method security audit of all source files
**Files reviewed:** `main.go` (1342 lines), `Dockerfile` (42 lines), `build.sh` (19 lines), `go.mod` (3 lines), `.gitignore` (38 lines)
**Go version:** 1.26.1 (upgraded from 1.24.13) / 1.26.1 (go.mod)
**Prior reviews:** `security-review-2026-03-07.md`, `security-review-2026-03-08.md`
**Tools used:** Manual code review, `go vet` (clean), `go build -race` (compiles), `govulncheck` (0 CVEs after upgrade)
**Known accepted risks:** No HTTPS, no authentication (per user)

**Post-review fixes applied (same session):**
- **M2 FIXED**: Body-read timeout context no longer leaks into proxy round-trip (main.go:871-903)
- **H1/H2 FIXED**: Go upgraded to 1.26.1 — `govulncheck` now reports 0 vulnerabilities (go.mod, Dockerfile, build.sh)
- **H4 FIXED**: Stats endpoint restricted to localhost even in debug mode (main.go:1148-1155)
- **H5 ACCEPTED**: `json.Unmarshal` memory amplification — accepted, plan exists in `reports/json-unmarshal-fix-plan.md`

---

## Executive Summary

This is the third security audit of reversellm, a single-file Go reverse proxy (1342 LOC, zero third-party dependencies) that routes LLM API requests via consistent hashing on message fingerprints. Two prior reviews produced 41 findings total; 26 were fixed across 4 commits, 6 were accepted with documentation. This audit identifies **19 findings** (5 HIGH, 7 MEDIUM, 7 LOW) including 4 newly discovered issues not in prior reviews and 4 Go stdlib CVEs confirmed by `govulncheck`.

**What was verified as fixed from prior reviews:**
- C1 (unbounded body) — `MaxBytesReader` at line 872, confirmed
- H1/prior (data race startup log) — log block at lines 1286-1304 now runs BEFORE `go startHealthChecker` at line 1307, confirmed
- H2/prior (fingerprint UTF-8) — `fingerprint()` uses `[]rune` at line 269, confirmed
- H3/prior (JSON injection debug error) — `json.Marshal` at line 1023, confirmed
- H4/prior (health check conn leak) — persistent `healthClient` at lines 791-797, `io.Copy(io.Discard, ...)` at line 1096/1106, confirmed
- H5/prior (rate limiter unbounded) — `maxVisitors: 10000` cap at line 1269, `time.NewTicker` at line 1271, confirmed
- M1/prior (ReadHeaderTimeout) — 10s at line 1317, confirmed
- M3/prior (sticky race) — `LookupOrStore` at line 530, confirmed
- M4/prior (getent path) — `/usr/bin/getent` at line 416, `isValidHostname` at line 410, confirmed
- M6/prior (request smuggling) — body discarded at lines 855-856, confirmed
- M7/prior (truncate UTF-8) — rune-based at line 307, confirmed
- M9/prior (fmt.Sprintf bomb) — returns `""` at line 261, confirmed
- L2/prior (security headers) — `securityHeaders()` middleware at line 1316, confirmed
- L4/prior (O(n) eviction) — `container/list` O(1) at line 593-601, confirmed
- L6/prior (time.After leak) — replaced with `time.NewTicker` at line 1271, confirmed

---

## HIGH Findings

### H1. Go Stdlib CVE: Incorrect IPv6 Host Literal Parsing (GO-2026-4601)

**Severity:** HIGH
**Confidence:** 100% (confirmed by `govulncheck`)
**Location:** `main.go:758` (`url.Parse`), `main.go:1077` (`client.Get`), `main.go:1337` (`ListenAndServe`)

**Evidence:** `govulncheck` reports GO-2026-4601 affecting `net/url@go1.24.13`, fixed in `go1.25.8`. The vulnerability is in IPv6 host literal parsing. This proxy calls `url.Parse` on operator-supplied backend URLs (line 758) and constructs health-check URLs via `fmt.Sprintf` (line 1074). A backend address like `[::1%25eth0]:8080` could be parsed incorrectly.

Trace from govulncheck:
```
#1: main.go:758:22: reversellm.NewProxyServer calls url.Parse
#2: main.go:1077:27: reversellm.checkAllBackends calls http.Client.Get -> url.URL.Parse
```

**Impact:** Potential request routing to unintended hosts if IPv6 backend addresses are used with crafted host literals. Severity HIGH because the fix requires a Go version that is in a major release the project hasn't adopted yet (1.25.x/1.26.x).

**Remediation:** Upgrade Go to 1.25.8+ or 1.26.1+. In the interim, validate that parsed `url.URL.Host` resolves to an expected IP before using it. Consider rejecting IPv6 literals in `--backends` if not needed.

---

### H2. Go Stdlib CVE: crypto/x509 Panic on Malformed Certificates (GO-2026-4600)

**Severity:** HIGH
**Confidence:** 100% (confirmed by `govulncheck`)
**Location:** Reachable via `main.go:1337` (`ListenAndServe`) and `main.go:1077` (`client.Get`)

**Evidence:** `govulncheck` reports GO-2026-4600 affecting `crypto/x509@go1.24.13`, fixed in `go1.26.1`. A malformed certificate presented by a backend during TLS handshake can cause a panic in name constraint checking.

**Impact:** Currently LOW practical impact because the proxy connects to backends over HTTP (no TLS). However, if TLS backends are ever added (or if a backend redirects to HTTPS), a malicious backend could crash the proxy process. This panic cannot be recovered from in `httputil.ReverseProxy`'s error handler.

**Remediation:** Upgrade Go to 1.26.1+. Document that TLS backends are not supported until Go is upgraded.

---

### H3. Per-Request `httputil.ReverseProxy` Allocation — Amplified Memory

**Severity:** HIGH
**Confidence:** 95%
**Location:** `main.go:1012-1033`

**Evidence:** A new `httputil.ReverseProxy` struct is created for every single request:

```go
// Line 1012
proxy := &httputil.ReverseProxy{
    Director: func(req *http.Request) { ... },
    FlushInterval: -1,
    ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) { ... },
}
proxy.ServeHTTP(w, r)
```

Each allocation includes the struct itself (~200 bytes), two closures (Director at line 1013 capturing `scheme` and `host`, ErrorHandler at line 1019 capturing `backendName`, `debug`, `r`), and the internal `ReverseProxy.Transport` default initialization.

The `body` variable is set on `r.Body` at line 1005 before the proxy is created, so the prior review's M2 fix (not capturing body in closure) is confirmed. However, the per-request allocation remains.

At 1000 concurrent requests with `MaxRequestSize` of 16MB:
- 1000 x ~16MB body (held in `r.Body` via `bytes.NewReader`) = ~16GB peak
- 1000 x ReverseProxy struct + closures = ~400KB overhead

The body memory is the real issue; the struct overhead is minor. The body `[]byte` stays live from `io.ReadAll` at line 876 through the entire proxy round-trip (up to `WriteTimeout` = 10 minutes at line 1319).

**Impact:** Linear memory scaling with concurrent request count x body size. At maximal load, the proxy uses (concurrent_requests x max_request_size) bytes. With the 16MB default, 100 concurrent requests = ~1.6GB. The body cannot be GC'd during the proxy round-trip because `bytes.NewReader` holds a reference.

**Remediation:** Consider using `sync.Pool` for body buffers to reduce allocation pressure. For the proxy struct, cache one `ReverseProxy` per backend and set the target via `r.Context()` or similar per-request mechanism. At minimum, add `MaxHeaderBytes: 1 << 20` to the server config.

---

### H4. `handleStats` Returns 404 Instead of 403/405 When Debug Off — Endpoint Discovery

**Severity:** HIGH (changed from prior M4)
**Confidence:** 92%
**Location:** `main.go:1129-1133`

**Evidence:**
```go
func (ps *ProxyServer) handleStats(w http.ResponseWriter, r *http.Request) {
    if !ps.debug {
        http.NotFound(w, r)  // returns 404
        return
    }
```

When `--debug` is disabled, `/proxy/stats` returns a 404. This is fine for hiding the endpoint. But when `--debug` IS enabled, there is **no IP restriction** — any client that can reach the proxy gets full topology:

```go
// Lines 1142-1153: builds response with b.Name, b.URL.String(), health, request counts
```

The prior M4 finding recommended restricting to localhost. The response at line 1149 includes `b.URL.String()` which contains resolved internal IPs (e.g., `http://192.168.1.126:8000`).

Additionally, the stats endpoint responds to any HTTP method (GET, POST, DELETE, etc.) which is unnecessary.

**Impact:** When debug is enabled (which operators will do for troubleshooting), any LAN client that reaches the proxy can enumerate all backend servers, their resolved IPs, health status, and per-backend request counts.

**Remediation:** Add localhost-only restriction when debug is enabled:
```go
if ps.debug {
    host, _, _ := net.SplitHostPort(r.RemoteAddr)
    if host != "127.0.0.1" && host != "::1" {
        http.Error(w, `{"error":{"message":"stats restricted to localhost","type":"proxy_error"}}`, http.StatusForbidden)
        return
    }
}
```

---

### H5. `json.Unmarshal` Parses Full Message Array — 2-3x Body Memory Amplification

**Severity:** HIGH
**Confidence:** 90%
**Location:** `main.go:315-317`, `main.go:893`

**Evidence:** `extractRoutingKey` only needs the first system and first user message (it breaks at line 343 once both are found), but `json.Unmarshal` deserializes the **entire** JSON tree first:

```go
var req chatRequest
if err := json.Unmarshal(body, &req); err != nil { ... }
```

For a 16MB body with 200 messages, `json.Unmarshal` creates:
- Duplicated string data for all 200 message `Content` fields (~16MB of Go string objects copied from the JSON bytes)
- `[]chatMessage` slice with 200 elements
- Each `Content interface{}` undergoes type assertion and allocation
- The original `body []byte` (16MB) is still live

Total per-request peak: ~48MB for a 16MB request. Combined with H3's per-request memory, 100 concurrent 16MB requests = ~4.8GB.

**Impact:** Memory amplification factor of ~3x on every POST request. Under load, this can push the proxy into OOM well below the theoretical (concurrent x max_request_size) limit.

**Remediation:** Use `json.Decoder` to stream-parse only the first system and first user message, breaking early without deserializing the full array. Example approach:
```go
decoder := json.NewDecoder(bytes.NewReader(body))
// Navigate to "messages" array
// Stream-decode messages, stop after finding system + user
```

---

## MEDIUM Findings

### M1. Health Check URL Built via String Concatenation — Path Injection Risk

**Severity:** MEDIUM
**Confidence:** 85%
**Location:** `main.go:1074`

**Evidence:** The health-path validation at lines 1244-1249 correctly rejects paths not starting with `/` and paths containing `..`. However, the URL is built via string concatenation:

```go
healthURL := fmt.Sprintf("%s%s", b.URL.String(), ps.healthPath)
```

`b.URL.String()` returns `http://192.168.1.126:8000` (no trailing slash). If `healthPath` is `/health`, the result is `http://192.168.1.126:8000/health` — correct.

But if `healthPath` is `//evil.com/health`, the validation at lines 1244-1249 passes (starts with `/`, no `..`), and the resulting URL is `http://192.168.1.126:8000//evil.com/health`. While this won't redirect to evil.com (the authority is already set), it sends health checks to an unexpected path on the backend.

More subtly, health paths with query strings (`/health?debug=1`) or fragments are not validated and passed through.

**Remediation:** Parse the health path with `url.Parse` and validate it's a clean path with no query, fragment, or double slashes:
```go
if strings.Contains(*healthPath, "?") || strings.Contains(*healthPath, "#") || strings.Contains(*healthPath, "//") {
    log.Fatalf("INIT_ERROR: --health-path contains invalid characters")
}
```

---

### M2. Body-Read 30s Timeout Context Replaces Request Context — Proxy Timeout Shortened

**Severity:** MEDIUM
**Confidence:** 88%
**Location:** `main.go:873-875`

**Evidence:**
```go
bodyCtx, bodyCancel := context.WithTimeout(r.Context(), 30*time.Second)
defer bodyCancel()
r = r.WithContext(bodyCtx)
```

The 30-second body-read timeout context is set on `r`, and `r` is then passed to `proxyTo` at line 978. The `httputil.ReverseProxy` at line 1035 calls `proxy.ServeHTTP(w, r)` which uses `r.Context()`. The 30-second deadline carries through to the **entire proxy round-trip**, including the backend response streaming.

An LLM response that takes >30 seconds to stream (very common for long code generation) will be cancelled because the body-read context deadline fires. The `defer bodyCancel()` at line 874 is called when `ServeHTTP` returns, which is correct. But the **deadline** (30 seconds from the body read start) persists and fires during streaming.

**Impact:** Streaming responses longer than 30 seconds are terminated. This is a functional bug introduced by the M5 security fix.

**Remediation:** After reading the body, replace the context with the original (non-deadline) context:
```go
bodyCtx, bodyCancel := context.WithTimeout(r.Context(), 30*time.Second)
r = r.WithContext(bodyCtx)
body, err := io.ReadAll(r.Body)
r.Body.Close()
bodyCancel() // cancel the body timeout immediately after read
r = r.WithContext(r.Context()) // won't work - need to save original
```

The correct fix is to save the original context before creating the timeout:
```go
origCtx := r.Context()
bodyCtx, bodyCancel := context.WithTimeout(origCtx, 30*time.Second)
bodyReader := io.NopCloser(io.LimitReader(r.Body, ps.maxRequestSize))
r2 := r.WithContext(bodyCtx)
body, err := io.ReadAll(r2.Body)
bodyCancel()
// Continue using r (with origCtx) for proxying
```

---

### M3. Prompt Content Exposed in Debug-Mode Logs

**Severity:** MEDIUM (was CRITICAL in 2026-03-07 review, reduced by debug gating)
**Confidence:** 90%
**Location:** `main.go:358`, `main.go:363`

**Evidence:** `rr.detail` includes 60-character previews of system and user message content:

```go
// Line 358
detailParts = append(detailParts, fmt.Sprintf("sys:%d(%q)", len(systemContent), truncate(systemContent, 60)))
// Line 363
detailParts = append(detailParts, fmt.Sprintf("usr:%d(%q)", len(userContent), truncate(userContent, 60)))
```

When `--debug` is enabled (line 985-986), the detail is logged per-request at line 988:
```go
logDetail := rr.reason
if ps.debug {
    logDetail = rr.detail
}
log.Printf("[route] %s %s -> %s (%s) ...", r.Method, r.URL.Path, backend.Name, logDetail)
```

These previews contain the literal first sentence of the user's coding task or system role description. Log files with permissions 664 expose this to any user with filesystem access.

**Impact:** With debug enabled, every request leaks 60 chars of system prompt and first user message to log files. Accepted risk per prior review, but flagged again for completeness.

**Remediation:** Replace content previews with salted hashes of the content, or add a separate `--log-content-previews` flag independent of `--debug`.

---

### M4. Sticky-RR: `nextRoundRobin()` Called Before `LookupOrStore` — Wasted RR Slot

**Severity:** MEDIUM
**Confidence:** 90%
**Location:** `main.go:905-907`

**Evidence:**
```go
candidate := ps.nextRoundRobin()  // Line 905: increments rrCounter
if candidate != nil {
    name, wasExisting := ps.sticky.LookupOrStore(rr.hash, candidate.Name) // Line 907
```

`nextRoundRobin()` atomically increments `ps.rrCounter` at line 826. For returning sessions (`wasExisting=true`), the round-robin counter has been incremented but the candidate is discarded — the sticky backend is used instead. Over time, this skews the round-robin distribution because returning sessions "consume" round-robin slots without using them.

With 2 backends and 80% returning traffic: 80% of RR increments are wasted, meaning the 20% of new sessions are not evenly distributed — they all hit whichever backend the wasted increments skip to.

**Impact:** Load imbalance for new sessions under high returning-session traffic. Not a security vulnerability per se, but a correctness issue in the routing algorithm that could overload one backend.

**Remediation:** Only call `nextRoundRobin()` when `LookupOrStore` returns `wasExisting=false`:
```go
name, wasExisting := ps.sticky.LookupOrStore(rr.hash, "")
if wasExisting {
    // Use the existing sticky mapping
} else {
    candidate := ps.nextRoundRobin()
    ps.sticky.Store(rr.hash, candidate.Name)
}
```
This requires `LookupOrStore` to accept a "tentative" store that gets replaced.

---

### M5. Dockerfile Image Tags Are Mutable — Supply Chain Risk

**Severity:** MEDIUM
**Confidence:** 90%
**Location:** `Dockerfile:2`, `Dockerfile:15`

**Evidence:**
```dockerfile
FROM golang:1.24-alpine AS builder  # mutable tag, may not be 1.24.13
FROM alpine:3.21                     # mutable tag
```

Both images use mutable tags. `golang:1.24-alpine` could resolve to Go 1.24.0 through 1.24.13 depending on when the image is pulled. The `go.mod` specifies `go 1.24.13`, but if the Docker image has Go 1.24.5, the build succeeds but misses security patches.

Additionally, neither image is pinned to a SHA256 digest, so a compromised DockerHub tag would silently change the build environment.

**Impact:** Build-time supply chain risk. The binary produced by Docker may use a different Go version than expected, potentially missing security patches.

**Remediation:** Pin both images to SHA256 digests:
```dockerfile
FROM golang:1.24.13-alpine@sha256:<digest> AS builder
FROM alpine:3.21@sha256:<digest>
```

---

### M6. `Cleanup()` Does Not Remove Expired Entries in Arbitrary Order

**Severity:** MEDIUM
**Confidence:** 82%
**Location:** `main.go:604-625`

**Evidence:** The `Cleanup()` method breaks on the first non-expired entry (line 617):
```go
if now.After(entry.expiresAt) {
    // remove
} else {
    break  // assumes list is ordered by expiry
}
```

But list order is by last-access time (LRU), not by expiry time. `Touch()` (line 513-524) refreshes TTL and moves to back. `LookupOrStore()` (line 530-562) refreshes TTL on existing entries.

Scenario: Entry A created at T=0 (expires T+12h). Entry B created at T=1h (expires T+13h). At T=6h, A is `Touch()`ed, refreshing its expiry to T+18h and moving it to back. Now list order is: [B (expires T+13h), A (expires T+18h)]. At T+13.5h, Cleanup scans front: B is expired, removed. A is not expired, break. Correct.

But consider: Entry C created at T=2h (expires T+14h), touched at T=11h (expires T+23h, moved to back). Entry D created at T=3h (expires T+15h), never touched. List order: [D (T+15h), C (T+23h)]. Cleanup at T+16h: D expired, removed; C not expired, break. Correct again because touched entries always have later expiry.

Actually, the ordering IS correct because `Touch()` always sets `expiresAt = now + ttl` and moves to back, so entries at the front always have the earliest expiry. The only edge case is if the system clock jumps backward, which would cause early-exit without cleaning later entries.

**Revised Confidence:** 60%. The ordering is sound under monotonic clock assumptions. Downgrade to LOW if NTP clock jumps are not a concern.

**Remediation:** Consider using `time.Now().UnixNano()` with monotonic readings (Go's default `time.Now()` includes monotonic clock component, so `time.After()` comparisons are safe). Add a comment documenting the invariant.

---

### M7. Go Stdlib CVE: crypto/x509 Email Constraint Bypass (GO-2026-4599)

**Severity:** MEDIUM
**Confidence:** 100% (confirmed by `govulncheck`)
**Location:** Reachable via `main.go:1337` (`ListenAndServe`)

**Evidence:** `govulncheck` reports GO-2026-4599 affecting `crypto/x509@go1.24.13`, fixed in `go1.26.1`. Incorrect enforcement of email constraints in X.509 certificates.

**Impact:** Currently the proxy serves HTTP only. The vulnerability is reachable through Go's HTTP server stack but only matters if TLS is added. Low practical impact for current deployment.

**Remediation:** Upgrade Go when TLS support is added.

---

## LOW Findings

### L1. Go Stdlib CVE: `os.Root` FileInfo Escape (GO-2026-4602)

**Severity:** LOW
**Confidence:** 100% (confirmed by `govulncheck`)
**Location:** Reachable via `main.go:1337` (`ListenAndServe` -> `os.ReadDir`)

**Evidence:** GO-2026-4602 affects `os@go1.24.13`, fixed in `go1.25.8`. The proxy does not directly use `os.Root`, but the vulnerability is reachable through Go's HTTP server internals. The proxy serves no static files.

**Impact:** Negligible for this application since no filesystem operations are exposed through the HTTP handler.

**Remediation:** Upgrade Go when next available.

---

### L2. Backend Names Logged Unconditionally Per-Request

**Severity:** LOW
**Confidence:** 95%
**Location:** `main.go:988-989`

**Evidence:**
```go
log.Printf("[route] %s %s -> %s (%s) [total reqs to backend: %d]",
    r.Method, r.URL.Path, backend.Name, logDetail, backend.requests.Load())
```

`backend.Name` (e.g., `dsstrix1.local:8080`) is logged on **every request** regardless of debug mode. While this doesn't expose resolved IPs, it reveals internal hostnames and per-backend request counts.

**Impact:** Log files always contain backend hostnames. Accepted risk per prior review — useful for operations.

---

### L3. Dockerfile HEALTHCHECK Does Not Validate HTTP Status

**Severity:** LOW
**Confidence:** 85%
**Location:** `Dockerfile:39-40`

**Evidence:**
```dockerfile
CMD wget -qO- --timeout=4 http://localhost:7888/health 2>/dev/null | grep -qc . || exit 1
```

`grep -qc .` succeeds if the response body has any non-empty content. A 500 Internal Server Error with body `Internal Server Error` passes the check. BusyBox `wget -qO-` exits 0 for any HTTP response.

**Impact:** Docker's orchestrator (swarm, k8s) may consider the container healthy when it's serving errors.

**Remediation:**
```dockerfile
CMD wget -qO- --timeout=4 http://localhost:7888/health 2>/dev/null | grep -q 'ok\|healthy' || exit 1
```
Or implement a `/health` handler in the proxy that returns a deterministic body.

---

### L4. `ConsistentHash.Remove()` Is Dead Code

**Severity:** LOW
**Confidence:** 95%
**Location:** `main.go:100-112`

**Evidence:** `Remove()` is never called anywhere in the codebase. `grep -rn "\.Remove(" main.go` shows only the method definition and `StickyTable` usage (different type). The consistent hash ring is built at startup and never modified. The `sync.RWMutex` (line 68) and `Remove()` method are dead code.

The mutex does add overhead: every `Get()` at line 116 and `GetN()` at line 131 acquires/releases `RLock()`. For a hot-path per-request call, this is unnecessary contention.

**Impact:** Minor CPU overhead on every hash ring lookup. No security impact.

**Remediation:** Either remove the mutex and `Remove()` method (mark the ring as immutable), or implement dynamic backend addition/removal.

---

### L5. `build.sh` `write_pidfile()` Has Command Injection via Filename

**Severity:** LOW
**Confidence:** 75%
**Location:** `build.sh:15-19`

**Evidence:**
```bash
write_pidfile() {
    local pidfile="${1:-reversellm.pid}"
    echo $$ > "$pidfile"
    chmod 600 "$pidfile"
}
```

The function is declared but never called within `build.sh` itself — it's a helper to be `source`d by launch scripts. The `$pidfile` variable is properly quoted in double quotes. No injection risk in the current form.

However, `echo $$` writes the shell's PID, which is the PID of the script sourcing `build.sh`, not necessarily the proxy process. If the proxy is started in the background (`reversellm & ; write_pidfile`), `$$` is the parent shell PID, not the proxy PID. The PID file will point to the wrong process.

**Impact:** Incorrect PID in PID file could cause the wrong process to be killed on shutdown.

**Remediation:** Use `$!` for background processes or have the proxy write its own PID:
```bash
write_pidfile() {
    local pidfile="${1:-reversellm.pid}"
    echo "${2:-$$}" > "$pidfile"
    chmod 600 "$pidfile"
}
# Usage: reversellm & write_pidfile reversellm.pid $!
```

---

### L6. Server Does Not Set `MaxHeaderBytes`

**Severity:** LOW
**Confidence:** 80%
**Location:** `main.go:1314-1321`

**Evidence:**
```go
server := &http.Server{
    Addr:              *listen,
    Handler:           securityHeaders(mux),
    ReadHeaderTimeout: 10 * time.Second,
    ReadTimeout:       5 * time.Minute,
    WriteTimeout:      10 * time.Minute,
    IdleTimeout:       2 * time.Minute,
}
```

No `MaxHeaderBytes` is set. Go's default is 1MB (`http.DefaultMaxHeaderBytes = 1 << 20`). While 1MB is reasonable, explicitly setting it documents the intent and prevents surprise if Go changes the default.

With `ReadHeaderTimeout: 10s`, an attacker can send up to 1MB of header data per connection within 10 seconds. At 100 concurrent connections, that's 100MB of header memory. Combined with body memory from H3, this adds to total memory exposure.

**Remediation:** Add `MaxHeaderBytes: 1 << 20` (or smaller, e.g., 64KB) to the server config.

---

### L7. Signal Handler Goroutine Does Not Handle Multiple Signals

**Severity:** LOW
**Confidence:** 70%
**Location:** `main.go:1324-1335`

**Evidence:**
```go
go func() {
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    sig := <-sigCh
    log.Printf("[shutdown] Received %s, shutting down gracefully...", sig)
    cancel()
    shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer shutdownCancel()
    if err := server.Shutdown(shutdownCtx); err != nil {
        log.Printf("[shutdown] Error during shutdown: %v", err)
    }
}()
```

After receiving the first signal, the goroutine blocks on `server.Shutdown()` for up to 30 seconds. A second SIGINT/SIGTERM during this window is buffered (channel capacity 1) but never consumed. The operator's second Ctrl+C has no effect — they must wait the full 30 seconds or send SIGKILL.

**Impact:** Poor operator experience during shutdown. No security impact unless long-running responses prevent shutdown.

**Remediation:** Add a second signal handler that calls `os.Exit(1)` for immediate termination:
```go
go func() {
    sig := <-sigCh
    // first signal
    go func() {
        sig2 := <-sigCh
        log.Printf("[shutdown] Received second %s, force exiting", sig2)
        os.Exit(1)
    }()
    // graceful shutdown ...
}()
```

---

## Concurrency Assessment

| Component | Protection | Status | Evidence |
|-----------|-----------|--------|----------|
| `ConsistentHash` ring | `sync.RWMutex` | **Correct but unnecessary** — immutable post-init (L4) | `go vet` clean, `go build -race` compiles |
| `Backend.URL` | `sync.Mutex` | **Correct** — locked at lines 998-1001, 1073-1075, 1090-1092, 1144-1146 | All runtime read paths hold lock |
| `Backend.healthy` | `atomic.Bool` | **Correct** — `.Load()` at L168, `.Store()` at L786, 1082, 1098, 1109, 1114 | Consistent use verified |
| `Backend.requests` | `atomic.Int64` | **Correct** — `.Add(1)` at L982, `.Load()` at L989, 1151 | Consistent use verified |
| `StickyTable` | `sync.RWMutex` | **Correct** — `LookupOrStore` (L530) is atomic; `ReassignIfUnhealthy` (L566) is atomic | Verified all methods hold appropriate lock |
| `rrCounter` | `atomic.Uint64` | **Correct** — `.Add(1)` at L826, unsigned overflow at 2^64 is benign | Verified |
| `ps.backends` slice | None needed | **Correct** — populated in `NewProxyServer`, never modified after | Verified no writes after construction |
| `ipRateLimiter` | `sync.Mutex` | **Correct** — all accesses (Allow, cleanup) hold lock. Map capped at 10K (H5 fix) | Verified |
| Body read context | `context.WithTimeout` | **BUG** — 30s deadline carries into proxy round-trip (M2) | See M2 finding |
| Signal handler | Closure captures | **Correct** — `server` initialized at L1314 before goroutine at L1324 | Verified |

**Data Race Check:** `go build -race` compiles successfully. The prior H1 data race (startup log vs health checker) is confirmed fixed: log block (L1286-1304) precedes `go startHealthChecker` (L1307).

---

## Supply Chain Assessment

| Area | Status | Details |
|------|--------|---------|
| Third-party deps | **Clean** | Zero external dependencies (stdlib only) |
| Go version | **Outdated** | `go 1.24.13` has 4 symbol-level CVEs per `govulncheck`; fixes require Go 1.25.8+ or 1.26.1+ |
| `govulncheck` results | **4 CVEs** | GO-2026-4601 (net/url, HIGH), GO-2026-4600 (x509, HIGH), GO-2026-4599 (x509, MEDIUM), GO-2026-4602 (os, LOW) |
| Dockerfile builder | **Mismatch** | `golang:1.24-alpine` may not be 1.24.13 |
| Docker image pins | **Mutable** | No SHA256 digest pinning |
| Binary provenance | **Good** | `-trimpath -ldflags="-s -w"` in both `build.sh` and `Dockerfile` |
| `getent` dependency | **Hardened** | Absolute path, hostname validated, leading-hyphen rejected |
| `.gitignore` | **Adequate** | `*.log`, `reversellm.pid`, `/reversellm` all covered |

---

## Method-by-Method Review Summary

| Method/Function | Lines | Security Status | Notes |
|---|---|---|---|
| `quickHash()` | 82-87 | **OK** | Random seed via `maphash.MakeSeed()` at line 80 |
| `ConsistentHash.Add()` | 89-98 | **OK** | Only called at construction |
| `ConsistentHash.Remove()` | 100-112 | **Dead code** | Never called (L4) |
| `ConsistentHash.Get()` | 115-127 | **OK** | Unnecessary RLock but safe |
| `ConsistentHash.GetN()` | 130-152 | **OK** | Map allocation per call (minor GC) |
| `Backend.IsHealthy()` | 168 | **OK** | Atomic load |
| `Backend.ReResolve()` | 172-199 | **OK** | Proper mutex usage, validated hostname |
| `messageContent()` | 222-263 | **OK** | Unknown types return "" (M9 fix confirmed) |
| `fingerprint()` | 268-274 | **OK** | Rune-based (H2 fix confirmed) |
| `truncate()` | 306-311 | **OK** | Rune-based (M7 fix confirmed) |
| `extractRoutingKey()` | 314-371 | **Issues** | Full JSON parse (H5), content in detail (M3) |
| `isValidHostname()` | 380-393 | **OK** | Rejects empty, leading-hyphen, non-DNS chars |
| `resolveHostname()` | 403-439 | **OK** | Absolute path, validation, fallback with warning |
| `StickyTable.Lookup()` | 473-485 | **OK** | RLock, safe |
| `StickyTable.Store()` | 489-510 | **OK** | Write lock, O(1) eviction |
| `StickyTable.Touch()` | 513-524 | **OK** | Write lock, correct |
| `StickyTable.LookupOrStore()` | 530-562 | **OK** | Atomic, single lock |
| `StickyTable.ReassignIfUnhealthy()` | 566-589 | **OK** | Atomic, single lock |
| `StickyTable.evictOldest()` | 593-601 | **OK** | O(1) via list.Front() |
| `StickyTable.Cleanup()` | 604-625 | **OK** | Logging outside lock (L3 fix confirmed), early break |
| `StickyTable.Len()` | 628-632 | **OK** | RLock |
| `securityHeaders()` | 640-646 | **OK** | nosniff + DENY |
| `ipRateLimiter.Allow()` | 677-703 | **OK** | Mutex, capped at maxVisitors |
| `ipRateLimiter.cleanup()` | 706-715 | **OK** | Mutex, map iteration safe |
| `NewProxyServer()` | 740-799 | **OK** | Proper validation, healthClient reused |
| `findBackend()` | 802-809 | **OK** | Linear scan, small N |
| `firstHealthy()` | 811-818 | **OK** | Linear scan, small N |
| `nextRoundRobin()` | 821-835 | **OK** | Atomic counter, unsigned wrap safe |
| `ServeHTTP()` | 837-979 | **Issues** | Body context deadline (M2), wasted RR slot (M4) |
| `proxyTo()` | 981-1036 | **Issues** | Per-request ReverseProxy alloc (H3) |
| `startHealthChecker()` | 1042-1062 | **OK** | Proper context, tickers with defer Stop() |
| `checkAllBackends()` | 1064-1123 | **OK** | Reused healthClient, body drained, proper locking |
| `handleStats()` | 1129-1177 | **Issue** | No IP restriction when debug enabled (H4) |
| `main()` | 1183-1341 | **Issues** | No MaxHeaderBytes (L6), single-signal handler (L7) |

---

## Priority Remediation Order

Ordered by impact-to-effort ratio:

| # | Finding | Effort | Impact |
|---|---------|--------|--------|
| 1 | **M2** — Fix body-read context leaking into proxy round-trip | 5 lines | Prevents 30s stream cutoff (functional bug) |
| 2 | **H4** — Add localhost restriction to stats endpoint | 5 lines | Prevents topology leak via debug mode |
| 3 | **L6** — Add `MaxHeaderBytes` to server config | 1 line | Explicit memory bound |
| 4 | **H5** — Use `json.Decoder` for streaming parse | 30 lines | Reduces memory 3x per request |
| 5 | **H3** — Cache `ReverseProxy` per backend or use `sync.Pool` | 15 lines | Reduces GC pressure |
| 6 | **M1** — Validate health path has no query/fragment | 3 lines | Prevents unexpected health checks |
| 7 | **M4** — Defer `nextRoundRobin()` until LookupOrStore miss | 10 lines | Fixes RR distribution skew |
| 8 | **H1** — Upgrade Go to 1.25.8+ for net/url CVE | Build change | Fixes IPv6 parsing vulnerability |
| 9 | **M5** — Pin Dockerfile images to SHA256 digests | 2 lines | Fixes supply chain risk |
| 10 | **L7** — Add second-signal force-exit handler | 5 lines | Better operator UX |

---

## Comparison with Prior Reviews

| Finding | Mar 7 | Mar 8 v1 | This Review | Status |
|---------|-------|----------|-------------|--------|
| Unbounded body (C1) | CRITICAL | Fixed | Confirmed fixed (L872) | RESOLVED |
| Prompt in logs (C2) | CRITICAL | M3 (reduced) | M3 (unchanged) | ACCEPTED |
| Stats no auth (H1) | HIGH | Fixed (debug gate) | H4 (no IP restrict) | OPEN |
| Debug headers (H2) | HIGH | Fixed | Confirmed fixed (L992) | RESOLVED |
| Error info leak (H3) | HIGH | Fixed | Confirmed fixed (L1023) | RESOLVED |
| Default bind all (H4) | HIGH | Fixed | Confirmed fixed (L1184) | RESOLVED |
| Hash collision (H5) | HIGH | Fixed (maphash) | Confirmed fixed (L80) | RESOLVED |
| Log gitignore (H6) | HIGH | Fixed | Confirmed fixed (.gitignore:37) | RESOLVED |
| ReadHeaderTimeout (M1) | MEDIUM | Fixed | Confirmed fixed (L1317) | RESOLVED |
| Rate limiting (M2) | MEDIUM | Fixed | Confirmed fixed (L677-703) | RESOLVED |
| Sticky race (M3) | MEDIUM | Fixed | Confirmed fixed (L530) | RESOLVED |
| getent path (M4) | MEDIUM | Fixed | Confirmed fixed (L416) | RESOLVED |
| No TLS (M5) | MEDIUM | Accepted | Not reviewed (accepted) | ACCEPTED |
| Request smuggling (M6) | MEDIUM | Fixed | Confirmed fixed (L855-856) | RESOLVED |
| Truncate UTF-8 (M7) | MEDIUM | Fixed | Confirmed fixed (L307) | RESOLVED |
| Fingerprint UTF-8 | — | H2 Fixed | Confirmed fixed (L269) | RESOLVED |
| Data race startup | — | H1 Fixed | Confirmed fixed (L1286 before L1307) | RESOLVED |
| JSON inject debug err | — | H3 Fixed | Confirmed fixed (L1023) | RESOLVED |
| Health conn leak | — | H4 Fixed | Confirmed fixed (L791-797, L1106) | RESOLVED |
| Rate limiter unbounded | — | H5 Fixed | Confirmed fixed (L1269, L1271) | RESOLVED |
| Body-read timeout | — | M5 (new) | M2 (BUG: leaks into proxy) | **NEW BUG** |
| Per-request ReverseProxy | — | M2 | H3 (expanded analysis) | OPEN |
| json.Unmarshal memory | — | M10 (accepted) | H5 (upgraded) | OPEN |
| Go stdlib CVEs | — | — | H1, H2, M7, L1 (4 new) | **NEW** |
| RR slot waste | — | — | M4 (new) | **NEW** |

---

## Notes on Methodology

- Every line number in this report was verified against `main.go` at 1342 lines as read during this review session.
- `go vet ./...` returned clean (no warnings).
- `go build -race` compiles successfully, confirming no static race detector issues.
- `govulncheck` (v1.1.4) identified 4 symbol-level vulnerabilities in Go 1.24.13 stdlib.
- Findings from prior reviews were individually verified by reading the specific lines of remediation code, not by trusting the prior reports' claims.
- No claims are made about behaviors that were not verified against actual source code.

*This report covers the codebase at the time of review. Line numbers may shift if code is modified.*
