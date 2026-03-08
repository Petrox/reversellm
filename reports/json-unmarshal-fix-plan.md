# M10: json.Unmarshal Full Array Parse — Fix Plan

**Status:** FIXED (2026-03-08)
**Location:** `main.go` `extractRoutingKey()` lines 346-455, `skipJSONValue()` lines 318-338

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

## Implementation (2026-03-08)

The streaming `json.Decoder` approach was implemented. Key changes:

### `skipJSONValue()` helper (lines 318-338)
Recursively discards one JSON value (scalar or nested object/array) from the
decoder stream without allocating Go objects. Uses `dec.More()` for implicit
depth tracking.

### `extractRoutingKey()` streaming rewrite (lines 346-455)
Five-phase token-level streaming replaces the single `json.Unmarshal`:

1. Read `{` — reject non-object top-level JSON
2. Scan top-level keys — skip non-`"messages"` values via `skipJSONValue` (zero allocation for `model`, `temperature`, `tools`, etc.)
3. Read `[` — handle `messages: null` or non-array as `"no-messages"`
4. Stream-parse message elements — `dec.Decode(&msg)` one `chatMessage` at a time; break once both systemContent and userContent are non-empty
5. Discriminate `"no-messages"` (empty array) vs `"no-content"` (non-empty array, all content empty)

### Unit tests added (`main_test.go`)
77 subtests covering:
- `TestFingerprint` (7 subtests)
- `TestTruncate` (7 subtests)
- `TestMessageContent` (13 subtests)
- `TestExtractRoutingKey` (20 subtests)
- `TestExtractRoutingKeyDeterministicHash`, `DistinctInputsDistinctKeys`, `FpLenEffect`, `ReasonDetailFormat`, `IgnoresNonSystemNonUserRoles`, `Structure`, `EarlyTermination`
- `TestSkipJSONValue` (15 subtests)
- `TestExtractRoutingKeyMessagesNullValue`, `MessagesFieldLast`, `OnlyAssistantMessages`

All pass with `-race` detector, `go vet` clean.

### Memory impact
Before: `json.Unmarshal` allocated the entire `chatRequest` including all messages.
A 16MB body with 500 messages allocated ~32-48MB of Go heap objects.

After: Only the first system/developer and first user messages are decoded as
`chatMessage` structs. Non-`messages` fields are skipped token-by-token via
`skipJSONValue`. For a 500-message conversation, typically only 1-3 messages
are decoded (the rest are never touched).

## Previous deferral rationale (archived)

- The streaming decoder approach requires careful token-level JSON parsing
  that is error-prone and hard to test without a full test suite → Addressed by 77 unit tests
- The current 16MB MaxBytesReader cap bounds the worst case → Still in place as defense in depth
- The fix should be paired with adding unit tests for `extractRoutingKey` → Done
