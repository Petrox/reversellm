package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// mustMarshal marshals v to JSON or panics. Used in table test initialisation
// where the input is always a statically correct value.
func mustMarshal(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("mustMarshal: %v", err))
	}
	return b
}

// ---------------------------------------------------------------------------
// TestFingerprint
// ---------------------------------------------------------------------------

func TestFingerprint(t *testing.T) {
	tests := []struct {
		name  string
		input string
		n     int
		want  string
	}{
		{
			name:  "empty string",
			input: "",
			n:     5,
			want:  "",
		},
		{
			name:  "short string exactly 2n returned as-is",
			input: "0123456789", // 10 runes, n=5 → 2*5=10 → returned as-is
			n:     5,
			want:  "0123456789",
		},
		{
			name:  "short string less than 2n returned as-is",
			input: "hello",
			n:     5,
			want:  "hello",
		},
		{
			name:  "long string split into first-n pipe last-n",
			input: "abcdefghij", // 10 runes, n=3 → 2*3=6 < 10 → split
			n:     3,
			want:  "abc|hij",
		},
		{
			name:  "n=1 picks single first and last rune",
			input: "abcde",
			n:     1,
			want:  "a|e",
		},
		{
			name:  "multibyte UTF-8 runes short returned as-is",
			input: "こんにちは", // 5 runes, n=5 → 2*5=10 > 5 → as-is
			n:     5,
			want:  "こんにちは",
		},
		{
			name:  "multibyte UTF-8 runes long split at rune boundaries",
			input: "あいうえおかきくけこ", // 10 runes, n=3
			n:     3,
			want:  "あいう|くけこ",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := fingerprint(tc.input, tc.n)
			if got != tc.want {
				t.Errorf("fingerprint(%q, %d) = %q, want %q", tc.input, tc.n, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestTruncate
// ---------------------------------------------------------------------------

func TestTruncate(t *testing.T) {
	tests := []struct {
		name  string
		input string
		n     int
		want  string
	}{
		{
			name:  "empty string returned as-is",
			input: "",
			n:     5,
			want:  "",
		},
		{
			name:  "short string exactly n returned as-is",
			input: "hello",
			n:     5,
			want:  "hello",
		},
		{
			name:  "short string less than n returned as-is",
			input: "hi",
			n:     5,
			want:  "hi",
		},
		{
			name:  "long string truncated with ellipsis",
			input: "hello world",
			n:     5,
			want:  "hello…",
		},
		{
			name:  "multibyte runes truncated at rune boundary",
			input: "あいうえおか", // 6 runes
			n:     3,
			want:  "あいう…",
		},
		{
			name:  "multibyte runes short returned as-is",
			input: "あいう",
			n:     5,
			want:  "あいう",
		},
		{
			name:  "n=0 everything truncated",
			input: "abc",
			n:     0,
			want:  "…",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := truncate(tc.input, tc.n)
			if got != tc.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tc.input, tc.n, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestMessageContent
// ---------------------------------------------------------------------------

func TestMessageContent(t *testing.T) {
	tests := []struct {
		name    string
		input   interface{}
		want    string
		wantFn  func(got string) bool // used when exact match is impractical
		wantDoc string                // documents what wantFn checks
	}{
		{
			name:  "nil returns empty string",
			input: nil,
			want:  "",
		},
		{
			name:  "plain string content returned verbatim",
			input: "You are a helpful assistant.",
			want:  "You are a helpful assistant.",
		},
		{
			name:  "empty string returned as-is",
			input: "",
			want:  "",
		},
		{
			name: "array with two text parts joined with space",
			input: []interface{}{
				map[string]interface{}{"type": "text", "text": "Hello"},
				map[string]interface{}{"type": "text", "text": "World"},
			},
			want: "Hello World",
		},
		{
			name: "array with single text part",
			input: []interface{}{
				map[string]interface{}{"type": "text", "text": "Hello"},
			},
			want: "Hello",
		},
		{
			name: "array with URL-referenced image_url included as img tag",
			input: []interface{}{
				map[string]interface{}{
					"type": "image_url",
					"image_url": map[string]interface{}{
						"url": "https://example.com/photo.jpg",
					},
				},
			},
			want: "[img:https://example.com/photo.jpg]",
		},
		{
			name: "array with text and image_url joined with space",
			input: []interface{}{
				map[string]interface{}{"type": "text", "text": "Describe this:"},
				map[string]interface{}{
					"type": "image_url",
					"image_url": map[string]interface{}{
						"url": "https://example.com/photo.jpg",
					},
				},
			},
			want: "Describe this: [img:https://example.com/photo.jpg]",
		},
		{
			name: "array with short inline base64 image data included verbatim",
			input: []interface{}{
				map[string]interface{}{
					"type": "image_url",
					"image_url": map[string]interface{}{
						// payload = "aGVsbG8=" (8 chars) — well below 2*64 threshold
						"url": "data:image/png;base64,aGVsbG8=",
					},
				},
			},
			want: "[img:aGVsbG8=]",
		},
		{
			name: "array with long inline base64 image fingerprinted with ellipsis",
			input: []interface{}{
				map[string]interface{}{
					"type": "image_url",
					"image_url": map[string]interface{}{
						// 64 A's + 65 B's = 129 chars > 2*64 → fingerprinted
						"url": "data:image/png;base64," + strings.Repeat("A", 64) + strings.Repeat("B", 65),
					},
				},
			},
			wantFn: func(got string) bool {
				// Must be [img:<first64>…<last64>]
				if !strings.HasPrefix(got, "[img:") || !strings.HasSuffix(got, "]") {
					return false
				}
				inner := got[len("[img:") : len(got)-1]
				if !strings.Contains(inner, "…") {
					return false
				}
				// First 64 chars of the payload are all 'A'.
				if !strings.HasPrefix(inner, strings.Repeat("A", 64)) {
					return false
				}
				// Last 64 chars of the payload are 'B' (last 64 of the 65 B's).
				if !strings.HasSuffix(inner, strings.Repeat("B", 64)) {
					return false
				}
				return true
			},
			wantDoc: "[img:<64 A's>…<64 B's>]",
		},
		{
			name: "array item without text or image_url produces no output",
			input: []interface{}{
				map[string]interface{}{"type": "tool_result", "content": "some result"},
			},
			want: "",
		},
		{
			name:  "integer type returns empty string",
			input: 42,
			want:  "",
		},
		{
			name:  "boolean type returns empty string",
			input: true,
			want:  "",
		},
		{
			name: "array with non-map items skipped, valid map items included",
			input: []interface{}{
				"not a map",
				map[string]interface{}{"type": "text", "text": "valid"},
			},
			want: "valid",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := messageContent(tc.input)
			if tc.wantFn != nil {
				if !tc.wantFn(got) {
					t.Errorf("messageContent() = %q, expected to satisfy: %s", got, tc.wantDoc)
				}
			} else {
				if got != tc.want {
					t.Errorf("messageContent() = %q, want %q", got, tc.want)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestExtractRoutingKey — table-driven, covering all 17 specified behaviours
// ---------------------------------------------------------------------------

func TestExtractRoutingKey(t *testing.T) {
	const fpLen = 20 // representative production value

	// localKey and localReason reproduce the implementation's key/reason
	// construction so tests stay accurate when content length changes.
	localKey := func(sys, usr string, n int) string {
		var parts []string
		if sys != "" {
			parts = append(parts, "sys:"+fingerprint(sys, n))
		}
		if usr != "" {
			parts = append(parts, "usr:"+fingerprint(usr, n))
		}
		return strings.Join(parts, "\n")
	}
	localReason := func(sys, usr string, n int) string {
		var parts []string
		if sys != "" {
			parts = append(parts, fmt.Sprintf("sys:%d", len(sys)))
		}
		if usr != "" {
			parts = append(parts, fmt.Sprintf("usr:%d", len(usr)))
		}
		return fmt.Sprintf("[%s] fp=%d", strings.Join(parts, "+"), n)
	}

	tests := []struct {
		name string
		body []byte
		fp   int // fpLen argument

		// For success paths:
		wantKey    string
		wantReason string
		wantDetail string // substring that must appear in detail

		// For error/edge-case paths, set wantErrCode; all other want* are ignored.
		// The implementation sets both reason and detail to the error code string.
		wantErrCode string
	}{
		// ---------------------------------------------------------------
		// 1. Valid JSON with both system and user messages
		// ---------------------------------------------------------------
		{
			name: "system and user messages produces key with sys and usr parts",
			body: mustMarshal(map[string]interface{}{
				"model": "llama3",
				"messages": []interface{}{
					map[string]interface{}{"role": "system", "content": "You are a Go expert."},
					map[string]interface{}{"role": "user", "content": "Write a goroutine pool."},
				},
			}),
			fp:         fpLen,
			wantKey:    localKey("You are a Go expert.", "Write a goroutine pool.", fpLen),
			wantReason: localReason("You are a Go expert.", "Write a goroutine pool.", fpLen),
			wantDetail: "sys:",
		},

		// ---------------------------------------------------------------
		// 2. Only system message
		// ---------------------------------------------------------------
		{
			name: "only system message produces key with sys part only",
			body: mustMarshal(map[string]interface{}{
				"model": "llama3",
				"messages": []interface{}{
					map[string]interface{}{"role": "system", "content": "System only prompt."},
				},
			}),
			fp:         fpLen,
			wantKey:    localKey("System only prompt.", "", fpLen),
			wantReason: localReason("System only prompt.", "", fpLen),
			wantDetail: "sys:",
		},

		// ---------------------------------------------------------------
		// 3. Only user message
		// ---------------------------------------------------------------
		{
			name: "only user message produces key with usr part only",
			body: mustMarshal(map[string]interface{}{
				"model": "llama3",
				"messages": []interface{}{
					map[string]interface{}{"role": "user", "content": "User only message."},
				},
			}),
			fp:         fpLen,
			wantKey:    localKey("", "User only message.", fpLen),
			wantReason: localReason("", "User only message.", fpLen),
			wantDetail: "usr:",
		},

		// ---------------------------------------------------------------
		// 4. Developer role treated same as system role
		// ---------------------------------------------------------------
		{
			name: "developer role treated as system",
			body: mustMarshal(map[string]interface{}{
				"model": "llama3",
				"messages": []interface{}{
					map[string]interface{}{"role": "developer", "content": "Dev system message."},
					map[string]interface{}{"role": "user", "content": "User task."},
				},
			}),
			fp:         fpLen,
			wantKey:    localKey("Dev system message.", "User task.", fpLen),
			wantReason: localReason("Dev system message.", "User task.", fpLen),
			wantDetail: "sys:",
		},

		// ---------------------------------------------------------------
		// 5. Multiple system messages — only first non-empty used
		// ---------------------------------------------------------------
		{
			name: "multiple system messages uses first non-empty one only",
			body: mustMarshal(map[string]interface{}{
				"model": "llama3",
				"messages": []interface{}{
					map[string]interface{}{"role": "system", "content": "First system."},
					map[string]interface{}{"role": "system", "content": "Second system must be ignored."},
					map[string]interface{}{"role": "user", "content": "User message."},
				},
			}),
			fp:         fpLen,
			wantKey:    localKey("First system.", "User message.", fpLen),
			wantReason: localReason("First system.", "User message.", fpLen),
			wantDetail: "sys:",
		},

		// ---------------------------------------------------------------
		// 6. Multiple user messages — only first non-empty used
		// ---------------------------------------------------------------
		{
			name: "multiple user messages uses first non-empty one only",
			body: mustMarshal(map[string]interface{}{
				"model": "llama3",
				"messages": []interface{}{
					map[string]interface{}{"role": "system", "content": "System prompt."},
					map[string]interface{}{"role": "user", "content": "First user message."},
					map[string]interface{}{"role": "assistant", "content": "Response."},
					map[string]interface{}{"role": "user", "content": "Second user message must be ignored."},
				},
			}),
			fp:         fpLen,
			wantKey:    localKey("System prompt.", "First user message.", fpLen),
			wantReason: localReason("System prompt.", "First user message.", fpLen),
			wantDetail: "usr:",
		},

		// ---------------------------------------------------------------
		// 7. Empty messages array
		// ---------------------------------------------------------------
		{
			name: "empty messages array",
			body: mustMarshal(map[string]interface{}{
				"model":    "llama3",
				"messages": []interface{}{},
			}),
			fp:          fpLen,
			wantErrCode: "no-messages",
		},

		// ---------------------------------------------------------------
		// 8. No messages field at all
		// ---------------------------------------------------------------
		{
			name: "no messages field",
			body: mustMarshal(map[string]interface{}{
				"model": "llama3",
			}),
			fp:          fpLen,
			wantErrCode: "no-messages",
		},

		// ---------------------------------------------------------------
		// 9. Invalid JSON
		// ---------------------------------------------------------------
		{
			name:        "invalid JSON",
			body:        []byte(`{not valid json`),
			fp:          fpLen,
			wantErrCode: "json-parse-error",
		},

		// ---------------------------------------------------------------
		// 10. Empty body
		// ---------------------------------------------------------------
		{
			name:        "empty body",
			body:        []byte{},
			fp:          fpLen,
			wantErrCode: "json-parse-error",
		},

		// ---------------------------------------------------------------
		// 11. Messages with empty content skipped; non-empty ones used
		// ---------------------------------------------------------------
		{
			name: "empty content messages skipped non-empty ones used",
			body: mustMarshal(map[string]interface{}{
				"model": "llama3",
				"messages": []interface{}{
					map[string]interface{}{"role": "system", "content": ""},
					map[string]interface{}{"role": "system", "content": "Real system prompt."},
					map[string]interface{}{"role": "user", "content": ""},
					map[string]interface{}{"role": "user", "content": "Real user message."},
				},
			}),
			fp:         fpLen,
			wantKey:    localKey("Real system prompt.", "Real user message.", fpLen),
			wantReason: localReason("Real system prompt.", "Real user message.", fpLen),
			wantDetail: "sys:",
		},

		// ---------------------------------------------------------------
		// 12. All system and user messages have empty content → no-content
		// ---------------------------------------------------------------
		{
			name: "all messages have empty content",
			body: mustMarshal(map[string]interface{}{
				"model": "llama3",
				"messages": []interface{}{
					map[string]interface{}{"role": "system", "content": ""},
					map[string]interface{}{"role": "user", "content": ""},
				},
			}),
			fp:          fpLen,
			wantErrCode: "no-content",
		},

		// ---------------------------------------------------------------
		// 13. Multimodal content — text extracted from array parts
		// ---------------------------------------------------------------
		{
			name: "multimodal content extracts text and image url",
			body: mustMarshal(map[string]interface{}{
				"model": "llama3",
				"messages": []interface{}{
					map[string]interface{}{
						"role": "system",
						"content": []interface{}{
							map[string]interface{}{"type": "text", "text": "You are an image analyst."},
						},
					},
					map[string]interface{}{
						"role": "user",
						"content": []interface{}{
							map[string]interface{}{"type": "text", "text": "Describe this image:"},
							map[string]interface{}{
								"type": "image_url",
								"image_url": map[string]interface{}{
									"url": "https://example.com/img.png",
								},
							},
						},
					},
				},
			}),
			fp: fpLen,
			wantKey: localKey(
				"You are an image analyst.",
				"Describe this image: [img:https://example.com/img.png]",
				fpLen,
			),
			wantReason: localReason(
				"You are an image analyst.",
				"Describe this image: [img:https://example.com/img.png]",
				fpLen,
			),
			wantDetail: "sys:",
		},

		// ---------------------------------------------------------------
		// 14. Large message list — only first system and first user used
		// ---------------------------------------------------------------
		{
			name: "large message list uses only first system and first user",
			body: func() []byte {
				msgs := []interface{}{
					map[string]interface{}{"role": "system", "content": "System prompt alpha."},
					map[string]interface{}{"role": "user", "content": "User message alpha."},
				}
				for i := 0; i < 50; i++ {
					msgs = append(msgs,
						map[string]interface{}{"role": "assistant", "content": fmt.Sprintf("Assistant turn %d.", i)},
						map[string]interface{}{"role": "user", "content": fmt.Sprintf("User follow-up %d.", i)},
					)
				}
				return mustMarshal(map[string]interface{}{
					"model":    "llama3",
					"messages": msgs,
				})
			}(),
			fp:         fpLen,
			wantKey:    localKey("System prompt alpha.", "User message alpha.", fpLen),
			wantReason: localReason("System prompt alpha.", "User message alpha.", fpLen),
			wantDetail: "sys:",
		},

		// ---------------------------------------------------------------
		// 17. fpLen parameter affects the fingerprint in the key
		// ---------------------------------------------------------------
		{
			name: "fpLen=5 produces shorter fingerprint for long content",
			body: mustMarshal(map[string]interface{}{
				"model": "llama3",
				"messages": []interface{}{
					map[string]interface{}{"role": "system", "content": strings.Repeat("X", 100)},
					map[string]interface{}{"role": "user", "content": strings.Repeat("Y", 100)},
				},
			}),
			fp:         5,
			wantKey:    localKey(strings.Repeat("X", 100), strings.Repeat("Y", 100), 5),
			wantReason: localReason(strings.Repeat("X", 100), strings.Repeat("Y", 100), 5),
			wantDetail: "fp=5",
		},

		// ---------------------------------------------------------------
		// Extra: top-level JSON value is not an object (e.g., a JSON array)
		// ---------------------------------------------------------------
		{
			name:        "top-level JSON is an array not an object",
			body:        []byte(`[{"role":"user","content":"hi"}]`),
			fp:          fpLen,
			wantErrCode: "json-parse-error",
		},

		// ---------------------------------------------------------------
		// Extra: messages field is null (not an array)
		// ---------------------------------------------------------------
		{
			name:        "messages field is null treated as no-messages",
			body:        []byte(`{"model":"llama3","messages":null}`),
			fp:          fpLen,
			wantErrCode: "no-messages",
		},

		// ---------------------------------------------------------------
		// Extra: messages field is a string, not an array
		// ---------------------------------------------------------------
		{
			name:        "messages field is a string not an array",
			body:        []byte(`{"model":"llama3","messages":"not-an-array"}`),
			fp:          fpLen,
			wantErrCode: "no-messages",
		},

		// ---------------------------------------------------------------
		// Extra: non-messages fields before messages are skipped via
		// skipJSONValue (covers nested object + array skip paths)
		// ---------------------------------------------------------------
		{
			name: "non-messages fields with nested structures are skipped",
			body: []byte(`{
				"model": "llama3",
				"extra_obj": {"a": [1, 2, {"b": "c"}]},
				"extra_arr": [true, null, 42],
				"messages": [
					{"role": "system", "content": "System prompt."},
					{"role": "user", "content": "User message."}
				]
			}`),
			fp:         fpLen,
			wantKey:    localKey("System prompt.", "User message.", fpLen),
			wantReason: localReason("System prompt.", "User message.", fpLen),
			wantDetail: "sys:",
		},

		// ---------------------------------------------------------------
		// Extra: only assistant messages present — no sys/usr content
		// (msgCount > 0 but systemContent == "" && userContent == "")
		// ---------------------------------------------------------------
		{
			name: "only assistant messages present returns no-content",
			body: mustMarshal(map[string]interface{}{
				"model": "llama3",
				"messages": []interface{}{
					map[string]interface{}{"role": "assistant", "content": "I am the only message."},
				},
			}),
			fp:          fpLen,
			wantErrCode: "no-content",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractRoutingKey(tc.body, tc.fp)

			if tc.wantErrCode != "" {
				// Error path: both reason and detail must equal the error code.
				if got.reason != tc.wantErrCode {
					t.Errorf("reason = %q, want %q", got.reason, tc.wantErrCode)
				}
				if got.detail != tc.wantErrCode {
					t.Errorf("detail = %q, want error code %q", got.detail, tc.wantErrCode)
				}
				if got.key != "" {
					t.Errorf("key = %q, want empty on error path", got.key)
				}
				if got.hash != 0 {
					t.Errorf("hash = %d, want 0 on error path", got.hash)
				}
				return
			}

			// Success path.
			if got.key != tc.wantKey {
				t.Errorf("key:\n  got  = %q\n  want = %q", got.key, tc.wantKey)
			}
			if got.reason != tc.wantReason {
				t.Errorf("reason:\n  got  = %q\n  want = %q", got.reason, tc.wantReason)
			}
			if tc.wantDetail != "" && !strings.Contains(got.detail, tc.wantDetail) {
				t.Errorf("detail %q does not contain %q", got.detail, tc.wantDetail)
			}
			// A non-empty key must produce a non-zero hash.
			// (The probability of quickHash returning exactly 0 is 1/2^32.)
			if got.key != "" && got.hash == 0 {
				t.Errorf("hash = 0 for non-empty key %q", got.key)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test 15: Deterministic hashing — same input always produces same result
// ---------------------------------------------------------------------------

func TestExtractRoutingKeyDeterministicHash(t *testing.T) {
	body := mustMarshal(map[string]interface{}{
		"model": "llama3",
		"messages": []interface{}{
			map[string]interface{}{"role": "system", "content": "System prompt for determinism test."},
			map[string]interface{}{"role": "user", "content": "User message for determinism test."},
		},
	})

	const fpLen = 20
	const iterations = 20
	first := extractRoutingKey(body, fpLen)

	for i := 1; i < iterations; i++ {
		got := extractRoutingKey(body, fpLen)
		if got.key != first.key {
			t.Errorf("iteration %d: key changed:\n  was  = %q\n  now  = %q", i, first.key, got.key)
		}
		if got.hash != first.hash {
			t.Errorf("iteration %d: hash changed from %d to %d", i, first.hash, got.hash)
		}
		if got.reason != first.reason {
			t.Errorf("iteration %d: reason changed from %q to %q", i, first.reason, got.reason)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 16: Different inputs produce different routing keys and hashes
// ---------------------------------------------------------------------------

func TestExtractRoutingKeyDistinctInputsDistinctKeys(t *testing.T) {
	const fpLen = 20

	scenarios := []struct {
		label string
		sys   string
		usr   string
	}{
		{"cline-fix-login", "You are Cline.", "Fix the login bug."},
		{"cline-oauth", "You are Cline.", "Add OAuth2 support."},
		{"claudecode-fix-login", "You are Claude Code.", "Fix the login bug."},
		{"goose-refactor-db", "You are Goose.", "Refactor the database layer."},
	}

	results := make([]routingResult, len(scenarios))
	for i, s := range scenarios {
		results[i] = extractRoutingKey(mustMarshal(map[string]interface{}{
			"model": "llama3",
			"messages": []interface{}{
				map[string]interface{}{"role": "system", "content": s.sys},
				map[string]interface{}{"role": "user", "content": s.usr},
			},
		}), fpLen)
	}

	for i := 0; i < len(scenarios); i++ {
		for j := i + 1; j < len(scenarios); j++ {
			if results[i].key == results[j].key {
				t.Errorf("scenarios %q and %q produced the same key: %q",
					scenarios[i].label, scenarios[j].label, results[i].key)
			}
			if results[i].hash == results[j].hash {
				t.Errorf("scenarios %q and %q produced the same hash %d (keys: %q vs %q)",
					scenarios[i].label, scenarios[j].label,
					results[i].hash, results[i].key, results[j].key)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Test: different fpLen values produce different keys for the same content
// ---------------------------------------------------------------------------

func TestExtractRoutingKeyFpLenEffect(t *testing.T) {
	// Content long enough that every tested fpLen produces a distinct fingerprint.
	longSys := strings.Repeat("A", 200) + strings.Repeat("Z", 200)
	longUsr := strings.Repeat("B", 200) + strings.Repeat("W", 200)
	body := mustMarshal(map[string]interface{}{
		"model": "llama3",
		"messages": []interface{}{
			map[string]interface{}{"role": "system", "content": longSys},
			map[string]interface{}{"role": "user", "content": longUsr},
		},
	})

	fpLens := []int{5, 10, 20, 50}
	results := make([]routingResult, len(fpLens))
	for i, n := range fpLens {
		results[i] = extractRoutingKey(body, n)
	}

	// Every distinct fpLen must produce a distinct key.
	for i := 0; i < len(fpLens); i++ {
		for j := i + 1; j < len(fpLens); j++ {
			if results[i].key == results[j].key {
				t.Errorf("fpLen=%d and fpLen=%d produced the same key: %q",
					fpLens[i], fpLens[j], results[i].key)
			}
		}
	}

	// The reason and detail must embed the fpLen used.
	for i, r := range results {
		wantFp := fmt.Sprintf("fp=%d", fpLens[i])
		if !strings.Contains(r.reason, wantFp) {
			t.Errorf("fpLen=%d: reason %q does not contain %q", fpLens[i], r.reason, wantFp)
		}
		if !strings.Contains(r.detail, wantFp) {
			t.Errorf("fpLen=%d: detail %q does not contain %q", fpLens[i], r.detail, wantFp)
		}
	}
}

// ---------------------------------------------------------------------------
// Test: reason and detail format for a success case (both sys + usr present)
// ---------------------------------------------------------------------------

func TestExtractRoutingKeyReasonDetailFormat(t *testing.T) {
	const fpLen = 20
	sysMsg := "System: you are a helpful Go assistant."
	usrMsg := "Write a concurrent HTTP server."

	body := mustMarshal(map[string]interface{}{
		"model": "llama3",
		"messages": []interface{}{
			map[string]interface{}{"role": "system", "content": sysMsg},
			map[string]interface{}{"role": "user", "content": usrMsg},
		},
	})

	got := extractRoutingKey(body, fpLen)

	// reason must be "[sys:<len>+usr:<len>] fp=<fpLen>"
	wantReason := fmt.Sprintf("[sys:%d+usr:%d] fp=%d", len(sysMsg), len(usrMsg), fpLen)
	if got.reason != wantReason {
		t.Errorf("reason = %q, want %q", got.reason, wantReason)
	}

	// detail must contain these structural markers.
	for _, substr := range []string{
		"hash=",
		"sys:",
		"usr:",
		fmt.Sprintf("fp=%d", fpLen),
	} {
		if !strings.Contains(got.detail, substr) {
			t.Errorf("detail %q does not contain %q", got.detail, substr)
		}
	}

	// detail must contain the hash formatted as "hash=XXXXXXXX" (8 hex digits).
	wantHashStr := fmt.Sprintf("hash=%08x", got.hash)
	if !strings.Contains(got.detail, wantHashStr) {
		t.Errorf("detail %q does not contain hash string %q", got.detail, wantHashStr)
	}
}

// ---------------------------------------------------------------------------
// Test: assistant and tool roles are not used for routing
// ---------------------------------------------------------------------------

func TestExtractRoutingKeyIgnoresNonSystemNonUserRoles(t *testing.T) {
	const fpLen = 20

	body := mustMarshal(map[string]interface{}{
		"model": "llama3",
		"messages": []interface{}{
			map[string]interface{}{"role": "assistant", "content": "I should not be the routing key."},
			map[string]interface{}{"role": "tool", "content": "Tool result."},
			map[string]interface{}{"role": "user", "content": "The actual user task."},
		},
	})

	got := extractRoutingKey(body, fpLen)

	// Only a usr: part must be present — no sys: part.
	if strings.Contains(got.key, "sys:") {
		t.Errorf("key %q contains 'sys:' but no system/developer message was present", got.key)
	}
	if !strings.Contains(got.key, "usr:") {
		t.Errorf("key %q does not contain 'usr:'", got.key)
	}

	wantKey := "usr:" + fingerprint("The actual user task.", fpLen)
	if got.key != wantKey {
		t.Errorf("key = %q, want %q", got.key, wantKey)
	}
}

// ---------------------------------------------------------------------------
// Test: key structure — sys and usr parts are joined by a single newline
// ---------------------------------------------------------------------------

func TestExtractRoutingKeyStructure(t *testing.T) {
	const fpLen = 20

	body := mustMarshal(map[string]interface{}{
		"model": "llama3",
		"messages": []interface{}{
			map[string]interface{}{"role": "system", "content": "System."},
			map[string]interface{}{"role": "user", "content": "User."},
		},
	})

	got := extractRoutingKey(body, fpLen)

	parts := strings.Split(got.key, "\n")
	if len(parts) != 2 {
		t.Fatalf("key %q: expected 2 newline-separated parts, got %d", got.key, len(parts))
	}
	if !strings.HasPrefix(parts[0], "sys:") {
		t.Errorf("first part of key %q does not start with 'sys:'", parts[0])
	}
	if !strings.HasPrefix(parts[1], "usr:") {
		t.Errorf("second part of key %q does not start with 'usr:'", parts[1])
	}
}

// ---------------------------------------------------------------------------
// Test: loop terminates early once both sys and usr are found
// (verifies that messages after the first found pair are not consulted)
// ---------------------------------------------------------------------------

func TestExtractRoutingKeyEarlyTermination(t *testing.T) {
	const fpLen = 20

	// If the loop did NOT break early, later system/user messages could
	// (with a buggy implementation) override the first ones. We verify the
	// key matches exactly the first system and first user content.
	firstSys := "System prompt ONE."
	firstUsr := "User message ONE."

	body := mustMarshal(map[string]interface{}{
		"model": "llama3",
		"messages": []interface{}{
			map[string]interface{}{"role": "system", "content": firstSys},
			map[string]interface{}{"role": "user", "content": firstUsr},
			// These must never contribute to the routing key.
			map[string]interface{}{"role": "system", "content": "System TWO — must not appear in key."},
			map[string]interface{}{"role": "user", "content": "User TWO — must not appear in key."},
		},
	})

	got := extractRoutingKey(body, fpLen)

	wantKey := "sys:" + fingerprint(firstSys, fpLen) + "\n" + "usr:" + fingerprint(firstUsr, fpLen)
	if got.key != wantKey {
		t.Errorf("key = %q, want %q", got.key, wantKey)
	}
}

// ---------------------------------------------------------------------------
// TestSkipJSONValue — verifies that skipJSONValue advances past exactly one
// JSON value, leaving the decoder positioned at the next token.
// ---------------------------------------------------------------------------

func TestSkipJSONValue(t *testing.T) {
	// newDec creates a decoder over the given JSON fragment.
	// We embed a sentinel number 99 after the value so we can confirm the
	// decoder is positioned correctly after skipping.
	newDec := func(fragment string) *json.Decoder {
		return json.NewDecoder(strings.NewReader(fragment + " 99"))
	}
	readSentinel := func(t *testing.T, dec *json.Decoder) {
		t.Helper()
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("reading sentinel: %v", err)
		}
		// Token returns json.Number for numbers when UseNumber is NOT set:
		// actually it returns float64 by default.
		switch v := tok.(type) {
		case float64:
			if v != 99 {
				t.Errorf("sentinel = %v, want 99", v)
			}
		default:
			t.Errorf("sentinel token type %T (%v), want float64(99)", tok, tok)
		}
	}

	tests := []struct {
		name     string
		fragment string
	}{
		{"null scalar", `null`},
		{"bool true", `true`},
		{"bool false", `false`},
		{"integer", `42`},
		{"float", `3.14`},
		{"string", `"hello world"`},
		{"empty object", `{}`},
		{"flat object one key", `{"k":"v"}`},
		{"flat object two keys", `{"a":1,"b":"two"}`},
		{"deeply nested object", `{"a":{"b":{"c":{"d":4}}}}`},
		{"empty array", `[]`},
		{"flat array", `[1,2,3]`},
		{"nested array", `[[1,[2,3]],[4]]`},
		{"mixed nested", `{"arr":[1,{"x":true,"y":[null,false]}],"n":7}`},
		{"object with array value", `{"messages":[{"role":"user","content":"hi"}]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := newDec(tt.fragment)
			if err := skipJSONValue(dec, 0); err != nil {
				t.Fatalf("skipJSONValue error: %v", err)
			}
			readSentinel(t, dec)
		})
	}
}

// ---------------------------------------------------------------------------
// TestSkipJSONValueDepthLimit — verifies that deeply nested JSON triggers
// the depth limit error instead of stack overflow (security review M2 fix).
// ---------------------------------------------------------------------------

func TestSkipJSONValueDepthLimit(t *testing.T) {
	// Build JSON with nesting deeper than maxJSONDepth (128).
	// Each '{' adds one level; we need 130+ levels.
	depth := maxJSONDepth + 10
	var sb strings.Builder
	for i := 0; i < depth; i++ {
		sb.WriteString(`{"k":`)
	}
	sb.WriteString(`"leaf"`)
	for i := 0; i < depth; i++ {
		sb.WriteByte('}')
	}

	dec := json.NewDecoder(strings.NewReader(sb.String()))
	err := skipJSONValue(dec, 0)
	if err == nil {
		t.Fatal("expected depth limit error, got nil")
	}
	if !strings.Contains(err.Error(), "maximum depth") {
		t.Errorf("expected 'maximum depth' in error, got: %v", err)
	}
}

// TestSkipJSONValueWithinDepthLimit verifies that JSON at exactly the max
// depth limit succeeds.
func TestSkipJSONValueWithinDepthLimit(t *testing.T) {
	// Build JSON with nesting exactly at maxJSONDepth.
	// The value at depth=maxJSONDepth is a scalar, so skipJSONValue is called
	// with depth=maxJSONDepth which must still succeed (> check, not >=).
	depth := maxJSONDepth
	var sb strings.Builder
	for i := 0; i < depth; i++ {
		sb.WriteString(`{"k":`)
	}
	sb.WriteString(`"leaf"`)
	for i := 0; i < depth; i++ {
		sb.WriteByte('}')
	}

	dec := json.NewDecoder(strings.NewReader(sb.String()))
	err := skipJSONValue(dec, 0)
	if err != nil {
		t.Fatalf("expected no error at depth=%d, got: %v", depth, err)
	}
}

// TestExtractRoutingKeyDeeplyNestedNonMessages verifies that a request with
// deeply nested non-messages fields returns a parse error instead of crashing.
func TestExtractRoutingKeyDeeplyNestedNonMessages(t *testing.T) {
	// Build a body where a deeply nested field appears before "messages".
	depth := maxJSONDepth + 10
	var sb strings.Builder
	sb.WriteString(`{"deep":`)
	for i := 0; i < depth; i++ {
		sb.WriteString(`{"k":`)
	}
	sb.WriteString(`"leaf"`)
	for i := 0; i < depth; i++ {
		sb.WriteByte('}')
	}
	sb.WriteString(`,"messages":[{"role":"user","content":"hello"}]}`)

	got := extractRoutingKey([]byte(sb.String()), 20)
	// Should get a parse error (from depth limit), not a crash.
	if got.reason != "json-parse-error" {
		t.Errorf("reason = %q, want %q", got.reason, "json-parse-error")
	}
}

// ---------------------------------------------------------------------------
// Streaming-specific edge cases for extractRoutingKey
// ---------------------------------------------------------------------------

// TestExtractRoutingKeyMessagesNullValue verifies that messages:null returns
// no-messages (the old json.Unmarshal path treated null as an empty slice).
func TestExtractRoutingKeyMessagesNullValue(t *testing.T) {
	body := []byte(`{"model":"gpt-4","messages":null}`)
	got := extractRoutingKey(body, 20)
	if got.reason != "no-messages" {
		t.Errorf("reason = %q, want %q", got.reason, "no-messages")
	}
	if got.detail != "no-messages" {
		t.Errorf("detail = %q, want %q", got.detail, "no-messages")
	}
}

// TestExtractRoutingKeyMessagesFieldLast verifies that fields before "messages"
// in the JSON object are skipped correctly by skipJSONValue, including deeply
// nested structures.
func TestExtractRoutingKeyMessagesFieldLast(t *testing.T) {
	// Construct a body where "messages" comes last, after a deeply nested field.
	body := []byte(`{
		"model": "gpt-4",
		"tool_choice": {
			"type": "function",
			"function": {
				"name": "search",
				"parameters": {
					"type": "object",
					"properties": {
						"query": {"type": "string"},
						"limit": {"type": "integer"}
					},
					"required": ["query"]
				}
			}
		},
		"tools": [
			{"type": "function", "function": {"name": "search", "description": "Web search"}}
		],
		"stream": true,
		"messages": [
			{"role": "system", "content": "System after deep nesting."},
			{"role": "user", "content": "User after deep nesting."}
		]
	}`)

	const fpLen = 20
	got := extractRoutingKey(body, fpLen)

	wantKey := "sys:" + fingerprint("System after deep nesting.", fpLen) + "\n" +
		"usr:" + fingerprint("User after deep nesting.", fpLen)
	if got.key != wantKey {
		t.Errorf("key:\n  got  = %q\n  want = %q", got.key, wantKey)
	}
}

// TestExtractRoutingKeyOnlyAssistantMessages verifies that a messages array
// with only assistant messages (no system or user content) returns no-content.
func TestExtractRoutingKeyOnlyAssistantMessages(t *testing.T) {
	body := mustMarshal(map[string]interface{}{
		"model": "gpt-4",
		"messages": []interface{}{
			map[string]interface{}{"role": "assistant", "content": "I am an assistant."},
			map[string]interface{}{"role": "assistant", "content": "Another assistant message."},
		},
	})
	got := extractRoutingKey(body, 20)
	if got.reason != "no-content" {
		t.Errorf("reason = %q, want %q", got.reason, "no-content")
	}
}
