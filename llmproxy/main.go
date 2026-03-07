// llmproxy - KV-cache-aware reverse proxy for llama.cpp
//
// Routes OpenAI-compatible API requests to backends using consistent hashing
// on the system prompt content, ensuring requests with the same context
// always reach the same backend for optimal KV cache reuse.
//
// Algorithm (inspired by OpenRouter, improved for per-session routing):
//   1. Parse incoming /v1/chat/completions request body
//   2. Extract first system message and first user message
//   3. Fingerprint each: first+last N chars (captures identity without full read)
//   4. Hash combined fingerprint with maphash
//   5. Consistent hash ring maps hash → backend
//   6. Same session → same hash → same backend → KV cache hit
//
// Why this works for coding agents:
//   - System prompt identifies the agent type (Cline vs Claude Code vs Goose)
//   - First user message identifies the session ("fix login" vs "add auth")
//   - Together they give per-session routing, not per-agent-type routing
//   - Two Cline sessions with different tasks → different backends (no thrashing)
//   - Same session across many requests → same backend (stable fingerprint)
//   - No client cooperation needed (no cookies, headers, or session IDs)

package main

import (
	"bytes"
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/maphash"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	defaultReplicas       = 150  // virtual nodes per backend for even distribution
	defaultPrefixLen      = 256  // chars from each end of message for fingerprint
	defaultHealthPath     = "/health"
	defaultHealthInterval = 10 * time.Second
	defaultStickyTTL      = 12 * time.Hour // how long a hash→backend mapping stays active
	defaultStickyMax      = 1000           // max sticky table entries before evicting oldest
)

// ---------------------------------------------------------------------------
// Consistent Hashing Ring
// ---------------------------------------------------------------------------

type ConsistentHash struct {
	ring     map[uint32]string
	sorted   []uint32
	replicas int
	mu       sync.RWMutex
}

func NewConsistentHash(replicas int) *ConsistentHash {
	return &ConsistentHash{
		ring:     make(map[uint32]string),
		replicas: replicas,
	}
}

// hashSeed is randomly initialized at startup, preventing offline hash collision
// precomputation attacks against the routing table.
var hashSeed = maphash.MakeSeed()

func quickHash(key string) uint32 {
	var h maphash.Hash
	h.SetSeed(hashSeed)
	h.WriteString(key)
	return uint32(h.Sum64())
}

func (ch *ConsistentHash) Add(backend string) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	for i := 0; i < ch.replicas; i++ {
		h := quickHash(fmt.Sprintf("%s#%d", backend, i))
		ch.ring[h] = backend
		ch.sorted = append(ch.sorted, h)
	}
	sort.Slice(ch.sorted, func(i, j int) bool { return ch.sorted[i] < ch.sorted[j] })
}

func (ch *ConsistentHash) Remove(backend string) {
	ch.mu.Lock()
	defer ch.mu.Unlock()
	newSorted := make([]uint32, 0, len(ch.sorted))
	for _, h := range ch.sorted {
		if ch.ring[h] == backend {
			delete(ch.ring, h)
		} else {
			newSorted = append(newSorted, h)
		}
	}
	ch.sorted = newSorted
}

// Get returns the backend for a given key.
func (ch *ConsistentHash) Get(key string) string {
	ch.mu.RLock()
	defer ch.mu.RUnlock()
	if len(ch.sorted) == 0 {
		return ""
	}
	h := quickHash(key)
	idx := sort.Search(len(ch.sorted), func(i int) bool { return ch.sorted[i] >= h })
	if idx >= len(ch.sorted) {
		idx = 0
	}
	return ch.ring[ch.sorted[idx]]
}

// GetN returns up to n distinct backends starting from the key's position.
func (ch *ConsistentHash) GetN(key string, n int) []string {
	ch.mu.RLock()
	defer ch.mu.RUnlock()
	if len(ch.sorted) == 0 {
		return nil
	}
	h := quickHash(key)
	idx := sort.Search(len(ch.sorted), func(i int) bool { return ch.sorted[i] >= h })
	if idx >= len(ch.sorted) {
		idx = 0
	}
	seen := make(map[string]bool)
	var result []string
	for i := 0; i < len(ch.sorted) && len(result) < n; i++ {
		pos := (idx + i) % len(ch.sorted)
		backend := ch.ring[ch.sorted[pos]]
		if !seen[backend] {
			seen[backend] = true
			result = append(result, backend)
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

type Backend struct {
	URL          *url.URL
	Name         string // host:port identifier (original, e.g. "dsstrix1.local:8080")
	origHostname string // original hostname before resolution (e.g. "dsstrix1.local")
	origPort     string // original port (e.g. "8080")
	healthy      atomic.Bool
	requests     atomic.Int64
	mu           sync.Mutex // protects URL during re-resolution
}

func (b *Backend) IsHealthy() bool { return b.healthy.Load() }

// ReResolve attempts to re-resolve the original hostname and update the URL
// if the IP has changed. Returns true if the IP was updated.
func (b *Backend) ReResolve() bool {
	if b.origHostname == "" || net.ParseIP(b.origHostname) != nil {
		return false // was an IP literal, nothing to re-resolve
	}

	newIP, err := resolveHostname(b.origHostname)
	if err != nil {
		log.Printf("[re-resolve] %s: failed to re-resolve: %v", b.Name, err)
		return false
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	currentHost := b.URL.Hostname()
	if newIP == currentHost {
		return false // IP hasn't changed
	}

	oldHost := b.URL.Host
	if b.origPort != "" {
		b.URL.Host = net.JoinHostPort(newIP, b.origPort)
	} else {
		b.URL.Host = newIP
	}
	log.Printf("[re-resolve] %s: IP changed %s -> %s", b.Name, oldHost, b.URL.Host)
	return true
}

// ---------------------------------------------------------------------------
// OpenAI Message Parsing
// ---------------------------------------------------------------------------

type chatMessage struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"` // string or multimodal array
}

type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
}

// messageContent extracts text and image identity from a message content field,
// handling both plain string and multimodal array formats.
//
// For multimodal arrays, includes both text parts and image fingerprints so that
// requests with the same text but different images produce different routing keys.
// Image fingerprints use: the URL for url-referenced images, or the first+last
// 64 chars of base64 data for inline images.
func messageContent(v interface{}) string {
	switch c := v.(type) {
	case string:
		return c
	case []interface{}:
		var parts []string
		for _, item := range c {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			if t, ok := m["text"].(string); ok {
				parts = append(parts, t)
			}
			// Include image identity in the content so different images
			// produce different routing hashes.
			if imgObj, ok := m["image_url"].(map[string]interface{}); ok {
				if urlStr, ok := imgObj["url"].(string); ok {
					if strings.HasPrefix(urlStr, "data:") {
						// Inline base64: fingerprint the data portion
						// (first+last 64 chars of the base64 payload)
						if idx := strings.Index(urlStr, ","); idx >= 0 {
							data := urlStr[idx+1:]
							const n = 64
							if len(data) <= n*2 {
								parts = append(parts, "[img:"+data+"]")
							} else {
								parts = append(parts, "[img:"+data[:n]+"…"+data[len(data)-n:]+"]")
							}
						}
					} else {
						// URL-referenced image: use the URL as identity
						parts = append(parts, "[img:"+urlStr+"]")
					}
				}
			}
		}
		return strings.Join(parts, " ")
	default:
		return ""
	}
}

// fingerprint extracts a compact identity from a message by taking the first
// and last `n` characters. This captures both the type identity (prefix) and
// session-specific uniqueness (suffix) without reading the entire content.
func fingerprint(s string, n int) string {
	r := []rune(s)
	if len(r) <= n*2 {
		return s
	}
	return string(r[:n]) + "|" + string(r[len(r)-n:])
}

// extractRoutingKey builds a stable per-session routing key from the request body.
//
// Algorithm: fingerprint (first+last N chars) of the first system message and
// the first user message. These two messages are immutable throughout a
// conversation — they're set from the very first request and never change as
// the conversation grows.
//
// This gives per-SESSION routing (not per-agent-type):
//   - Same agent + same task → same hash → same backend → KV cache hit
//   - Same agent + different task → different hash (first user msg differs)
//   - Different agent + same task → different hash (system prompt differs)
//
// Why first+last instead of just first N chars:
//   - Different agents may share a common prefix ("You are a helpful...")
//   - The suffix of the system prompt contains agent-specific instructions
//   - First user message suffix captures the actual task being worked on
//
// Why not hash the entire message:
//   - System prompts can be 50K+ chars, expensive to hash on every request
//   - Only the identity-bearing parts matter for routing
// routingResult holds the extracted routing key plus metadata for logging.
type routingResult struct {
	key    string // full fingerprint key for hashing
	hash   uint32 // maphash hash of the key
	reason string // compact description for response header
	detail string // verbose description for log (includes hash + previews)
}

// truncate returns the first n runes of s, appending "…" if truncated.
// Fix M7: use rune boundaries to avoid breaking multi-byte UTF-8 characters.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func extractRoutingKey(body []byte, fpLen int) routingResult {
	var req chatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return routingResult{reason: "json-parse-error", detail: "json-parse-error"}
	}

	if len(req.Messages) == 0 {
		return routingResult{reason: "no-messages", detail: "no-messages"}
	}

	// Extract first system/developer message and first user message.
	// These are stable across the entire conversation lifetime.
	var systemContent, userContent string
	for _, msg := range req.Messages {
		content := messageContent(msg.Content)
		if content == "" {
			continue
		}
		switch msg.Role {
		case "system", "developer":
			if systemContent == "" {
				systemContent = content
			}
		case "user":
			if userContent == "" {
				userContent = content
			}
		}
		if systemContent != "" && userContent != "" {
			break
		}
	}

	if systemContent == "" && userContent == "" {
		return routingResult{reason: "no-content", detail: "no-content"}
	}

	var keyParts []string
	var reasonParts []string
	var detailParts []string

	if systemContent != "" {
		keyParts = append(keyParts, "sys:"+fingerprint(systemContent, fpLen))
		reasonParts = append(reasonParts, fmt.Sprintf("sys:%d", len(systemContent)))
		detailParts = append(detailParts, fmt.Sprintf("sys:%d(%q)", len(systemContent), truncate(systemContent, 60)))
	}
	if userContent != "" {
		keyParts = append(keyParts, "usr:"+fingerprint(userContent, fpLen))
		reasonParts = append(reasonParts, fmt.Sprintf("usr:%d", len(userContent)))
		detailParts = append(detailParts, fmt.Sprintf("usr:%d(%q)", len(userContent), truncate(userContent, 60)))
	}

	key := strings.Join(keyParts, "\n")
	h := quickHash(key)
	reason := fmt.Sprintf("[%s] fp=%d", strings.Join(reasonParts, "+"), fpLen)
	detail := fmt.Sprintf("hash=%08x [%s] fp=%d", h, strings.Join(detailParts, " + "), fpLen)
	return routingResult{key: key, hash: h, reason: reason, detail: detail}
}

// ---------------------------------------------------------------------------
// Hostname Resolution
// ---------------------------------------------------------------------------

// isValidHostname returns true if hostname contains only characters valid in a
// DNS label or dotted-decimal IP: letters, digits, dots, hyphens, underscores.
// Fix M4: prevents shell-injection / path-traversal via exec.Command args.
func isValidHostname(hostname string) bool {
	if hostname == "" {
		return false
	}
	if strings.HasPrefix(hostname, "-") {
		return false
	}
	for _, r := range hostname {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// resolveHostname resolves a hostname to an IP address using the system resolver
// (getent hosts), which follows nsswitch.conf and correctly handles .local mDNS.
//
// This is necessary because .local hostnames are resolved via mDNS, and hosts
// with multiple network interfaces (LAN, VPN, USB4, Docker) advertise multiple
// IPs. Go's HTTP client re-resolves DNS on every connection, creating a race
// where any interface's IP could win. By resolving once at startup via the
// system resolver, we pin to the correct LAN IP.
func resolveHostname(hostname string) (string, error) {
	// If it's already an IP address, return as-is
	if net.ParseIP(hostname) != nil {
		return hostname, nil
	}

	// Fix M4: validate hostname before passing to exec.Command
	if !isValidHostname(hostname) {
		return "", fmt.Errorf("RESOLVE_ERROR: hostname %q contains invalid characters", hostname)
	}

	// Try system resolver first (getent hosts follows nsswitch.conf properly)
	// Fix M4: use absolute path to avoid PATH hijacking
	out, err := exec.Command("/usr/bin/getent", "hosts", hostname).Output()
	if err != nil {
		// Fix M4: log a warning when getent fails so operators know the fallback is in use
		log.Printf("[resolve] WARN: getent unavailable for %q, falling back to Go resolver: %v", hostname, err)
	} else {
		fields := strings.Fields(strings.TrimSpace(string(out)))
		if len(fields) >= 1 {
			ip := fields[0]
			if net.ParseIP(ip) != nil {
				return ip, nil
			}
		}
	}

	// Fallback to Go's resolver (which uses CGO getaddrinfo when available)
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return "", fmt.Errorf("RESOLVE_ERROR: cannot resolve %q: getent failed and Go lookup failed: %w", hostname, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("RESOLVE_ERROR: %q resolved to zero addresses", hostname)
	}
	return addrs[0], nil
}

// ---------------------------------------------------------------------------
// Sticky Table (hash → backend with TTL, O(1) LRU via container/list)
// ---------------------------------------------------------------------------

// stickyEntry is stored as the value in the doubly-linked list.
// Fix L4: lastUsed field removed; list position encodes LRU order.
type stickyEntry struct {
	hash        uint32
	backendName string
	expiresAt   time.Time
}

// StickyTable maps request hashes to backend names with TTL-based expiry and
// LRU eviction. Fix L4: uses container/list so eviction is O(1) instead of O(n).
type StickyTable struct {
	entries map[uint32]*list.Element // hash -> list element
	order   *list.List               // front = oldest (LRU), back = newest (MRU)
	ttl     time.Duration
	maxSize int
	mu      sync.RWMutex
}

func NewStickyTable(ttl time.Duration, maxSize int) *StickyTable {
	return &StickyTable{
		entries: make(map[uint32]*list.Element),
		order:   list.New(),
		ttl:     ttl,
		maxSize: maxSize,
	}
}

// Lookup returns the backend name for a hash if it exists and hasn't expired.
func (st *StickyTable) Lookup(hash uint32) (string, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	elem, ok := st.entries[hash]
	if !ok {
		return "", false
	}
	entry := elem.Value.(stickyEntry)
	if time.Now().After(entry.expiresAt) {
		return "", false
	}
	return entry.backendName, true
}

// Store assigns a hash to a backend with the configured TTL.
// If the table is at capacity, evicts the LRU entry first.
func (st *StickyTable) Store(hash uint32, backendName string) {
	st.mu.Lock()
	defer st.mu.Unlock()

	// If hash already exists, remove it from its current list position
	if elem, exists := st.entries[hash]; exists {
		st.order.Remove(elem)
		delete(st.entries, hash)
	} else if len(st.entries) >= st.maxSize {
		// New entry and at capacity: evict LRU (front of list)
		st.evictOldest()
	}

	now := time.Now()
	entry := stickyEntry{
		hash:        hash,
		backendName: backendName,
		expiresAt:   now.Add(st.ttl),
	}
	elem := st.order.PushBack(entry)
	st.entries[hash] = elem
}

// Touch refreshes the TTL and moves the entry to the MRU position.
func (st *StickyTable) Touch(hash uint32) {
	st.mu.Lock()
	defer st.mu.Unlock()
	elem, ok := st.entries[hash]
	if !ok {
		return
	}
	entry := elem.Value.(stickyEntry)
	entry.expiresAt = time.Now().Add(st.ttl)
	elem.Value = entry
	st.order.MoveToBack(elem)
}

// LookupOrStore atomically looks up a hash and returns the stored backend if found
// and not expired. If not found or expired, stores newBackendName and returns it.
// Returns (backendName, wasExisting).
// Fix M3: combines Lookup + Touch + Store in a single lock acquisition.
func (st *StickyTable) LookupOrStore(hash uint32, newBackendName string) (string, bool) {
	st.mu.Lock()
	defer st.mu.Unlock()

	elem, ok := st.entries[hash]
	if ok {
		entry := elem.Value.(stickyEntry)
		if !time.Now().After(entry.expiresAt) {
			// Found and not expired — touch (refresh TTL and move to MRU)
			entry.expiresAt = time.Now().Add(st.ttl)
			elem.Value = entry
			st.order.MoveToBack(elem)
			return entry.backendName, true
		}
		// Expired: remove the old element before storing new one
		st.order.Remove(elem)
		delete(st.entries, hash)
	}

	// Not found or expired — store new entry
	if len(st.entries) >= st.maxSize {
		st.evictOldest()
	}
	now := time.Now()
	entry := stickyEntry{
		hash:        hash,
		backendName: newBackendName,
		expiresAt:   now.Add(st.ttl),
	}
	newElem := st.order.PushBack(entry)
	st.entries[hash] = newElem
	return newBackendName, false
}

// evictOldest removes the LRU entry (front of list).
// Must be called with st.mu held.
func (st *StickyTable) evictOldest() {
	front := st.order.Front()
	if front == nil {
		return
	}
	entry := front.Value.(stickyEntry)
	log.Printf("[sticky] evicted hash=%08x (table at %d/%d)", entry.hash, len(st.entries), st.maxSize)
	st.order.Remove(front)
	delete(st.entries, entry.hash)
}

// Cleanup removes expired entries.
func (st *StickyTable) Cleanup() {
	st.mu.Lock()
	defer st.mu.Unlock()
	now := time.Now()
	count := 0
	var next *list.Element
	for elem := st.order.Front(); elem != nil; elem = next {
		next = elem.Next()
		entry := elem.Value.(stickyEntry)
		if now.After(entry.expiresAt) {
			st.order.Remove(elem)
			delete(st.entries, entry.hash)
			count++
		}
	}
	if count > 0 {
		log.Printf("[sticky] cleaned up %d expired entries, %d remaining", count, len(st.entries))
	}
}

// Len returns the number of active entries.
func (st *StickyTable) Len() int {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return len(st.entries)
}

// ---------------------------------------------------------------------------
// Security Headers Middleware
// ---------------------------------------------------------------------------

// securityHeaders sets defensive HTTP response headers on all responses.
// Fix L2: mitigates MIME-sniffing attacks and clickjacking via framing.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// Per-IP Rate Limiter (token bucket)
// ---------------------------------------------------------------------------

// ipRateLimiter implements a per-IP token-bucket rate limiter.
// Fix M2: prevents a single IP from exhausting backend capacity.
type ipRateLimiter struct {
	mu          sync.Mutex
	visitors    map[string]*visitor
	rps         float64
	burst       int
	maxVisitors int
}

type visitor struct {
	tokens   float64
	lastTime time.Time
}

func newIPRateLimiter(rps float64, burst int, maxVisitors int) *ipRateLimiter {
	rl := &ipRateLimiter{
		visitors:    make(map[string]*visitor),
		rps:         rps,
		burst:       burst,
		maxVisitors: maxVisitors,
	}
	return rl
}

func (rl *ipRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	v, exists := rl.visitors[ip]
	if !exists {
		if len(rl.visitors) >= rl.maxVisitors {
			return false
		}
		rl.visitors[ip] = &visitor{tokens: float64(rl.burst) - 1, lastTime: now}
		return true
	}

	elapsed := now.Sub(v.lastTime).Seconds()
	v.tokens += elapsed * rl.rps
	if v.tokens > float64(rl.burst) {
		v.tokens = float64(rl.burst)
	}
	v.lastTime = now

	if v.tokens >= 1 {
		v.tokens -= 1
		return true
	}
	return false
}

// cleanup removes visitors that haven't been seen for over a minute.
func (rl *ipRateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-1 * time.Minute)
	for ip, v := range rl.visitors {
		if v.lastTime.Before(cutoff) {
			delete(rl.visitors, ip)
		}
	}
}

// ---------------------------------------------------------------------------
// Proxy Server
// ---------------------------------------------------------------------------

type ProxyServer struct {
	backends   []*Backend
	ring       *ConsistentHash
	sticky     *StickyTable
	listen     string
	prefixLen  int
	healthPath string
	mode           string         // "hash" or "round-robin"
	debug          bool           // enable verbose logging, stats endpoint, debug headers
	maxRequestSize int64          // maximum allowed request body size in bytes
	limiter        *ipRateLimiter // nil means unlimited
	healthClient   *http.Client   // reused client for health checks (H4)

	totalRequests    atomic.Int64
	routedRequests   atomic.Int64
	fallbackRequests atomic.Int64
	rrCounter        atomic.Uint64 // round-robin counter
}

func NewProxyServer(listen string, backendAddrs []string, prefixLen int, healthPath string, mode string, stickyTTL time.Duration, stickyMax int) (*ProxyServer, error) {
	if len(backendAddrs) == 0 {
		return nil, fmt.Errorf("no backends specified")
	}

	ps := &ProxyServer{
		ring:       NewConsistentHash(defaultReplicas),
		sticky:     NewStickyTable(stickyTTL, stickyMax),
		listen:     listen,
		prefixLen:  prefixLen,
		healthPath: healthPath,
		mode:       mode,
	}

	for _, addr := range backendAddrs {
		if !strings.HasPrefix(addr, "http") {
			addr = "http://" + addr
		}
		u, err := url.Parse(addr)
		if err != nil {
			return nil, fmt.Errorf("PARSE_ERROR: invalid backend URL %q: %w", addr, err)
		}

		// Resolve hostname to IP at startup to avoid per-request mDNS races.
		// Hosts with multiple interfaces (LAN, VPN, USB4) advertise multiple
		// IPs via mDNS; resolving once pins to the correct address.
		originalHost := u.Host // e.g. "dsstrix1.local:8080"
		hostname := u.Hostname()
		port := u.Port()

		resolvedIP, err := resolveHostname(hostname)
		if err != nil {
			return nil, err
		}

		if resolvedIP != hostname {
			// Replace hostname with resolved IP in the URL
			if port != "" {
				u.Host = net.JoinHostPort(resolvedIP, port)
			} else {
				u.Host = resolvedIP
			}
			log.Printf("[resolve] %s -> %s", originalHost, u.Host)
		}

		b := &Backend{URL: u, Name: originalHost, origHostname: hostname, origPort: port}
		b.healthy.Store(true)
		ps.backends = append(ps.backends, b)
		ps.ring.Add(originalHost)
	}

	ps.healthClient = &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	return ps, nil
}

func (ps *ProxyServer) findBackend(name string) *Backend {
	for _, b := range ps.backends {
		if b.Name == name {
			return b
		}
	}
	return nil
}

func (ps *ProxyServer) firstHealthy() *Backend {
	for _, b := range ps.backends {
		if b.IsHealthy() {
			return b
		}
	}
	return nil
}

// nextRoundRobin returns the next healthy backend in round-robin order.
func (ps *ProxyServer) nextRoundRobin() *Backend {
	n := uint64(len(ps.backends))
	if n == 0 {
		return nil
	}
	idx := ps.rrCounter.Add(1) - 1
	// Try each backend starting from idx, wrapping around
	for i := uint64(0); i < n; i++ {
		b := ps.backends[(idx+i)%n]
		if b.IsHealthy() {
			return b
		}
	}
	return nil
}

func (ps *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ps.totalRequests.Add(1)

	// Fix M2: enforce per-IP rate limit before any further processing
	if ps.limiter != nil {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip == "" {
			ip = r.RemoteAddr
		}
		if !ps.limiter.Allow(ip) {
			http.Error(w, `{"error":{"message":"rate limit exceeded","type":"proxy_error"}}`, http.StatusTooManyRequests)
			return
		}
	}

	// Non-POST requests: forward to next healthy backend
	if r.Method != http.MethodPost {
		// Fix M6: discard any body on non-POST requests to prevent HTTP request smuggling
		r.Body = http.NoBody
		r.ContentLength = 0
		var backend *Backend
		if ps.mode == "round-robin" {
			backend = ps.nextRoundRobin()
		} else {
			backend = ps.firstHealthy()
		}
		if backend == nil {
			http.Error(w, `{"error":{"message":"no healthy backends available","type":"proxy_error"}}`, http.StatusBadGateway)
			return
		}
		ps.proxyTo(w, r, backend, nil, routingResult{reason: "non-POST", detail: "non-POST"})
		return
	}

	// Read body for routing decision (bounded to prevent memory exhaustion)
	r.Body = http.MaxBytesReader(w, r.Body, ps.maxRequestSize)
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w,
				fmt.Sprintf(`{"error":{"message":"request body exceeds maximum size of %d bytes","type":"proxy_error"}}`, ps.maxRequestSize),
				http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w,
				`{"error":{"message":"failed to read request body","type":"proxy_error"}}`,
				http.StatusBadRequest)
		}
		return
	}

	// Extract routing info (fingerprint + hash for logging)
	rr := extractRoutingKey(body, ps.prefixLen)

	var backend *Backend

	switch ps.mode {
	case "sticky-rr":
		// Sticky round-robin: known hashes stick, new hashes round-robin.
		// Agentic coding sessions (same hash across many requests) stay on one
		// backend for KV cache reuse. Independent requests (different images,
		// different hashes each time) get evenly distributed.
		if rr.key != "" {
			// Fix M3: use LookupOrStore for atomic lookup+touch or store
			candidate := ps.nextRoundRobin()
			if candidate != nil {
				name, wasExisting := ps.sticky.LookupOrStore(rr.hash, candidate.Name)
				b := ps.findBackend(name)
				if b != nil && b.IsHealthy() {
					backend = b
					ps.routedRequests.Add(1)
					if wasExisting {
						rr.reason = "sticky:" + rr.reason
						rr.detail = "sticky:" + rr.detail
					} else {
						rr.reason = "new:" + rr.reason
						rr.detail = "new:" + rr.detail
					}
				} else if wasExisting {
					// Stored backend is unhealthy, re-assign via round-robin
					backend = ps.nextRoundRobin()
					if backend != nil {
						ps.sticky.Store(rr.hash, backend.Name)
						ps.routedRequests.Add(1)
						rr.reason = "reassign:" + rr.reason
						rr.detail = "reassign:" + rr.detail
					}
				}
			}
		}

	case "round-robin":
		// Pure round-robin: no stickiness, even distribution
		backend = ps.nextRoundRobin()
		if backend != nil {
			ps.routedRequests.Add(1)
			rr.reason = "rr:" + rr.reason
			rr.detail = "rr:" + rr.detail
		}

	case "hash":
		// Consistent hash ring: deterministic mapping (original behavior)
		if rr.key != "" {
			targets := ps.ring.GetN(rr.key, len(ps.backends))
			for _, target := range targets {
				b := ps.findBackend(target)
				if b != nil && b.IsHealthy() {
					backend = b
					break
				}
			}
			if backend != nil {
				ps.routedRequests.Add(1)
			}
		}
	}

	// Fallback (unparseable request or no healthy backends)
	if backend == nil {
		backend = ps.firstHealthy()
		ps.fallbackRequests.Add(1)
		rr.reason = "fallback:" + rr.reason
		rr.detail = "fallback:" + rr.detail
	}

	if backend == nil {
		http.Error(w, `{"error":{"message":"no healthy backends available","type":"proxy_error"}}`, http.StatusBadGateway)
		return
	}

	ps.proxyTo(w, r, backend, body, rr)
}

func (ps *ProxyServer) proxyTo(w http.ResponseWriter, r *http.Request, backend *Backend, body []byte, rr routingResult) {
	backend.requests.Add(1)

	logDetail := rr.reason
	if ps.debug {
		logDetail = rr.detail
	}
	log.Printf("[route] %s %s -> %s (%s) [total reqs to backend: %d]",
		r.Method, r.URL.Path, backend.Name, logDetail, backend.requests.Load())

	// Expose routing info in response headers (debug mode only)
	if ps.debug {
		w.Header().Set("X-LLMProxy-Backend", backend.Name)
		w.Header().Set("X-LLMProxy-Route", rr.reason)
	}

	// Snapshot the backend URL under lock (it can change via re-resolution)
	backend.mu.Lock()
	scheme := backend.URL.Scheme
	host := backend.URL.Host
	backend.mu.Unlock()

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = scheme
			req.URL.Host = host
			req.Host = host
			if body != nil {
				req.Body = io.NopCloser(bytes.NewReader(body))
				req.ContentLength = int64(len(body))
			}
		},
		FlushInterval: -1, // flush SSE chunks immediately for streaming
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[error] proxy to %s failed: %v (path: %s)", backend.Name, err, r.URL.Path)
			if ps.debug {
				msg := fmt.Sprintf("backend %s: %s", backend.Name, err)
				escapedMsg, _ := json.Marshal(msg)
				http.Error(w,
					fmt.Sprintf(`{"error":{"message":%s,"type":"proxy_error"}}`, escapedMsg),
					http.StatusBadGateway)
			} else {
				http.Error(w,
					`{"error":{"message":"upstream backend unavailable","type":"proxy_error"}}`,
					http.StatusBadGateway)
			}
		},
	}

	proxy.ServeHTTP(w, r)
}

// ---------------------------------------------------------------------------
// Health Checker
// ---------------------------------------------------------------------------

func (ps *ProxyServer) startHealthChecker(ctx context.Context, interval time.Duration) {
	// Run immediately on start
	ps.checkAllBackends()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	cleanupTicker := time.NewTicker(1 * time.Minute)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ps.checkAllBackends()
		case <-cleanupTicker.C:
			ps.sticky.Cleanup()
		}
	}
}

func (ps *ProxyServer) checkAllBackends() {
	client := ps.healthClient
	var wg sync.WaitGroup

	for _, b := range ps.backends {
		wg.Add(1)
		go func(b *Backend) {
			defer wg.Done()

			b.mu.Lock()
			healthURL := fmt.Sprintf("%s%s", b.URL.String(), ps.healthPath)
			b.mu.Unlock()

			resp, err := client.Get(healthURL)

			wasHealthy := b.IsHealthy()

			if err != nil {
				b.healthy.Store(false)
				if wasHealthy {
					log.Printf("[health] %s -> UNHEALTHY (connection failed: %v)", b.Name, err)
				}
				// Re-resolve DNS: the host's IP may have changed via DHCP.
				// If re-resolution finds a new IP, retry the health check
				// immediately so we can recover without waiting another cycle.
				if b.ReResolve() {
					b.mu.Lock()
					retryURL := fmt.Sprintf("%s%s", b.URL.String(), ps.healthPath)
					b.mu.Unlock()
					resp2, err2 := client.Get(retryURL)
					if err2 == nil {
						defer resp2.Body.Close()
						io.Copy(io.Discard, resp2.Body)
						if resp2.StatusCode >= 200 && resp2.StatusCode < 400 {
							b.healthy.Store(true)
							log.Printf("[health] %s -> HEALTHY after re-resolve (HTTP %d)", b.Name, resp2.StatusCode)
						}
					}
				}
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)

			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				b.healthy.Store(true)
				if !wasHealthy {
					log.Printf("[health] %s -> HEALTHY (HTTP %d)", b.Name, resp.StatusCode)
				}
			} else {
				b.healthy.Store(false)
				if wasHealthy {
					log.Printf("[health] %s -> UNHEALTHY (HTTP %d)", b.Name, resp.StatusCode)
				}
			}
		}(b)
	}

	wg.Wait()
}

// ---------------------------------------------------------------------------
// Stats Endpoint
// ---------------------------------------------------------------------------

func (ps *ProxyServer) handleStats(w http.ResponseWriter, r *http.Request) {
	if !ps.debug {
		http.NotFound(w, r)
		return
	}

	type backendStat struct {
		Name     string `json:"name"`
		URL      string `json:"url"`
		Healthy  bool   `json:"healthy"`
		Requests int64  `json:"requests"`
	}

	backendStats := make([]backendStat, 0, len(ps.backends))
	for _, b := range ps.backends {
		b.mu.Lock()
		urlStr := b.URL.String()
		b.mu.Unlock()
		backendStats = append(backendStats, backendStat{
			Name:     b.Name,
			URL:      urlStr,
			Healthy:  b.IsHealthy(),
			Requests: b.requests.Load(),
		})
	}

	stats := struct {
		TotalRequests    int64         `json:"total_requests"`
		RoutedRequests   int64         `json:"routed_requests"`
		FallbackRequests int64         `json:"fallback_requests"`
		Mode             string        `json:"mode"`
		FingerprintChars int           `json:"fingerprint_chars_per_end"`
		StickyEntries    int           `json:"sticky_entries"`
		Backends         []backendStat `json:"backends"`
	}{
		TotalRequests:    ps.totalRequests.Load(),
		RoutedRequests:   ps.routedRequests.Load(),
		FallbackRequests: ps.fallbackRequests.Load(),
		Mode:             ps.mode,
		FingerprintChars: ps.prefixLen,
		StickyEntries:    ps.sticky.Len(),
		Backends:         backendStats,
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(stats)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	listen := flag.String("listen", "127.0.0.1:7888", "Listen address (host:port)")
	backendsFlag := flag.String("backends", "", "Comma-separated backend addresses (e.g. host1:8000,host2:8000)")
	mode := flag.String("mode", "sticky-rr", "Routing mode: 'sticky-rr' (round-robin with sticky table), 'hash' (consistent hash ring), or 'round-robin' (pure round-robin)")
	stickyTTL := flag.Duration("sticky-ttl", defaultStickyTTL, "How long a hash→backend mapping stays active (sticky-rr mode)")
	stickyMax := flag.Int("sticky-max", defaultStickyMax, "Max sticky table entries before evicting oldest")
	prefixLen := flag.Int("prefix-length", defaultPrefixLen, "Characters from each end of message to use for fingerprint")
	healthPath := flag.String("health-path", defaultHealthPath, "Backend health check endpoint path")
	healthInterval := flag.Duration("health-interval", defaultHealthInterval, "Health check interval")
	debug := flag.Bool("debug", false, "Enable debug mode (verbose logging with content previews, stats endpoint, debug response headers)")
	maxRequestSize := flag.Int64("max-request-size", 16<<20, "Maximum request body size in bytes (default 16 MB)")
	rateLimit := flag.Int("rate-limit", 0, "Max requests per second per IP (0 = unlimited)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `llmproxy - KV-cache-aware reverse proxy for llama.cpp

Routes OpenAI-compatible API requests using consistent hashing on the system
prompt content. Same agent context -> same backend -> maximum KV cache reuse.

Usage:
  llmproxy --backends host1:8000,host2:8000 [options]

Options:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
How it works:
  1. Parses /v1/chat/completions request body
  2. Fingerprints first 4 messages: first+last N chars of each (captures
     both agent type identity and session-specific content)
  3. Hashes the combined fingerprint (maphash)
  4. Consistent hash ring maps hash -> backend
  5. Same session -> same backend -> KV cache hit

  The fingerprint is stable: only early messages are used, so it doesn't
  change as the conversation grows. Different sessions of the same agent
  type get different hashes because their first user message differs
  (e.g. "Fix the login bug" vs "Add authentication").

Endpoints:
  /proxy/stats    JSON stats (requests per backend, health status)
  /*              All other requests proxied to backends

Examples:
  llmproxy --backends 192.168.1.100:8000,192.168.1.101:8000
  llmproxy --listen :7888 --backends host1:8000,host2:8000
  llmproxy --backends host1:8000,host2:8000 --prefix-length 4096
`)
	}

	flag.Parse()

	if *backendsFlag == "" {
		flag.Usage()
		os.Exit(1)
	}

	if *mode != "hash" && *mode != "round-robin" && *mode != "sticky-rr" {
		log.Fatalf("INIT_ERROR: invalid --mode %q: must be 'sticky-rr', 'hash', or 'round-robin'", *mode)
	}

	backends := strings.Split(*backendsFlag, ",")
	for i := range backends {
		backends[i] = strings.TrimSpace(backends[i])
	}

	proxy, err := NewProxyServer(*listen, backends, *prefixLen, *healthPath, *mode, *stickyTTL, *stickyMax)
	if err != nil {
		log.Fatalf("INIT_ERROR: Failed to create proxy: %v", err)
	}
	proxy.debug = *debug
	proxy.maxRequestSize = *maxRequestSize

	// Fix M2: set up per-IP rate limiter if requested
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var limiter *ipRateLimiter
	if *rateLimit > 0 {
		limiter = newIPRateLimiter(float64(*rateLimit), *rateLimit*2, 10000)
		go func() {
			ticker := time.NewTicker(1 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					limiter.cleanup()
				}
			}
		}()
		log.Printf("Rate limit: %d req/s per IP (burst: %d)", *rateLimit, *rateLimit*2)
	}
	proxy.limiter = limiter

	log.Printf("llmproxy starting on %s", *listen)
	log.Printf("Backends:")
	for i, b := range proxy.backends {
		log.Printf("  [%d] %s", i, b.URL.String())
	}
	switch *mode {
	case "round-robin":
		log.Printf("Routing: round-robin across healthy backends")
	case "sticky-rr":
		log.Printf("Routing: sticky round-robin (new requests round-robin, repeat hashes stick for %s)", *stickyTTL)
	default:
		log.Printf("Routing: consistent hash on first+last %d chars of first 4 messages", *prefixLen)
	}
	log.Printf("Health checks: every %s via %s", *healthInterval, *healthPath)
	log.Printf("Max request size: %d MB", *maxRequestSize/(1<<20))
	if *debug {
		log.Printf("Debug mode: ENABLED (content previews in logs, stats endpoint, debug response headers)")
		log.Printf("Stats: http://%s/proxy/stats", *listen)
	}

	// Start health checker
	go proxy.startHealthChecker(ctx, *healthInterval)

	// Routes
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy/stats", proxy.handleStats)
	mux.Handle("/", proxy)

	server := &http.Server{
		Addr:              *listen,
		Handler:           securityHeaders(mux), // Fix L2: wrap mux with security headers middleware
		ReadHeaderTimeout: 10 * time.Second,     // Fix M1: mitigate slow-loris on header phase
		ReadTimeout:       5 * time.Minute,      // LLM requests can have large bodies
		WriteTimeout:      10 * time.Minute,     // LLM responses can stream for minutes
		IdleTimeout:       2 * time.Minute,
	}

	// Graceful shutdown
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

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("SERVER_ERROR: %v", err)
	}
	log.Println("llmproxy stopped")
}
