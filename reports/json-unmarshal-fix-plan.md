# M10: json.Unmarshal Full Array Parse — Fix Plan

**Status:** Accepted for now (2026-03-08)
**Location:** `llmproxy/main.go` `extractRoutingKey()` lines 313-317

## Problem

`json.Unmarshal` parses the entire JSON body into a `chatRequest` struct before
`extractRoutingKey` iterates the messages. The function only needs the first
system and first user message (breaks at line 341 once both are found), but the
full deserialization allocates ~2-3x the body size in Go heap objects.

At 16MB max body with 100 concurrent requests, peak memory is ~4.8GB.

## Planned Fix

Replace `json.Unmarshal` with a streaming `json.Decoder` that stops after
extracting the needed messages:

```go
func extractRoutingKey(body []byte, fpLen int) routingResult {
    dec := json.NewDecoder(bytes.NewReader(body))
    // Skip to "messages" array
    // Stream-parse only until first system + first user message found
    // Discard remaining tokens without allocating
}
```

Alternatively, a simpler approach: after `json.Unmarshal`, immediately truncate
the messages slice to release references:

```go
var req chatRequest
if err := json.Unmarshal(body, &req); err != nil { ... }
if len(req.Messages) > 20 {
    req.Messages = req.Messages[:20]
}
```

This doesn't prevent the initial allocation but allows GC to reclaim the
truncated portion sooner.

## Why Deferred

- The streaming decoder approach requires careful token-level JSON parsing
  that is error-prone and hard to test without a full test suite
- The current 16MB MaxBytesReader cap bounds the worst case to ~48MB per
  request, which is manageable for a LAN proxy
- The fix should be paired with adding unit tests for `extractRoutingKey`
