package translate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/megamen32/zai-adapter/zsign"
)

// decode runs a request through the converter and returns the generic map.
func decode(t *testing.T, body string) map[string]any {
	t.Helper()
	out, err := ToAnthropicRequest([]byte(body), "fallback-model", 4096)
	if err != nil {
		t.Fatalf("ToAnthropicRequest: %v", err)
	}
	return out
}

func TestSystemAndDeveloperMessagesBecomeTopLevelSystem(t *testing.T) {
	out := decode(t, `{"model":"","messages":[
		{"role":"system","content":"be terse"},
		{"role":"developer","content":"use tool x"},
		{"role":"user","content":"hi"}]}`)

	if out["model"] != "fallback-model" {
		t.Errorf("model = %v, want the fallback when the caller omits one", out["model"])
	}
	system, ok := out["system"].([]contentBlock)
	if !ok {
		t.Fatalf("system = %T, want []contentBlock", out["system"])
	}
	if len(system) != 2 || system[0].Text != "be terse" || system[1].Text != "use tool x" {
		t.Fatalf("system blocks = %+v", system)
	}
	msgs := out["messages"].([]map[string]any)
	if len(msgs) != 1 || msgs[0]["role"] != "user" {
		t.Fatalf("messages = %+v, want only the user turn left", msgs)
	}
}

func TestAssistantToolCallsBecomeToolUseBlocks(t *testing.T) {
	out := decode(t, `{"messages":[
		{"role":"user","content":"weather?"},
		{"role":"assistant","content":null,"tool_calls":[
			{"id":"call_1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Moscow\"}"}}]},
		{"role":"tool","tool_call_id":"call_1","content":"-5C"}]}`)

	msgs := out["messages"].([]map[string]any)
	if len(msgs) != 3 {
		t.Fatalf("messages = %d, want 3", len(msgs))
	}
	assistant := msgs[1]["content"].([]contentBlock)
	if len(assistant) != 1 || assistant[0].Type != "tool_use" || assistant[0].ID != "call_1" {
		t.Fatalf("assistant blocks = %+v", assistant)
	}
	if assistant[0].Name != "get_weather" || string(assistant[0].Input) != `{"city":"Moscow"}` {
		t.Fatalf("tool_use input/name = %q / %q", assistant[0].Input, assistant[0].Name)
	}
	toolMsg := msgs[2]["content"].([]contentBlock)
	if toolMsg[0].Type != "tool_result" || toolMsg[0].ToolUseID != "call_1" || toolMsg[0].Content != "-5C" {
		t.Fatalf("tool_result = %+v", toolMsg)
	}
}

func TestAssistantWithEmptyContentAndNoToolCallsIsDropped(t *testing.T) {
	// A blank assistant turn would be rejected upstream; it must not be sent.
	out := decode(t, `{"messages":[
		{"role":"user","content":"hi"},
		{"role":"assistant","content":null}]}`)
	msgs := out["messages"].([]map[string]any)
	if len(msgs) != 1 || msgs[0]["role"] != "user" {
		t.Fatalf("messages = %+v, want the empty assistant turn dropped", msgs)
	}
}

func TestToolChoiceVariants(t *testing.T) {
	cases := []struct {
		rawJSON string
		want    string
	}{
		{`"auto"`, `{"type":"auto"}`},
		{`"none"`, `{"type":"none"}`},
		{`"required"`, `{"type":"any"}`},
		{`{"type":"function","function":{"name":"f"}}`, `{"type":"tool","name":"f"}`},
	}
	for _, c := range cases {
		body := `{"tool_choice":` + c.rawJSON + `,"messages":[{"role":"user","content":"x"}]}`
		out := decode(t, body)
		got, err := json.Marshal(out["tool_choice"])
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var norm, want any
		_ = json.Unmarshal(got, &norm)
		_ = json.Unmarshal([]byte(c.want), &want)
		gotN, _ := json.Marshal(norm)
		wantN, _ := json.Marshal(want)
		if string(gotN) != string(wantN) {
			t.Errorf("tool_choice %s -> %s, want %s", c.rawJSON, gotN, wantN)
		}
	}
}

func TestToolChoiceNoneStillTranslatesTools(t *testing.T) {
	// The converter keeps the tools array; upstream is told not to call them.
	// Dropping them here would silently change the cached prompt instead.
	out := decode(t, `{"tool_choice":"none","messages":[{"role":"user","content":"x"}],
		"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object"}}}]}`)
	if _, ok := out["tools"]; !ok {
		t.Error("tools were dropped for tool_choice=none")
	}
}

func TestMaxTokensPrecedence(t *testing.T) {
	cases := []struct {
		body string
		want int
	}{
		{`{"messages":[]}`, 4096},
		{`{"max_tokens":100,"messages":[]}`, 100},
		{`{"max_tokens":100,"max_completion_tokens":200,"messages":[]}`, 200},
		{`{"max_completion_tokens":0,"messages":[]}`, 4096},
	}
	for _, c := range cases {
		out := decode(t, c.body)
		if out["max_tokens"] != c.want {
			t.Errorf("%s -> max_tokens %v, want %d", c.body, out["max_tokens"], c.want)
		}
	}
}

func TestStopSequencesAcceptsStringOrArray(t *testing.T) {
	one := decode(t, `{"stop":"END","messages":[]}`)["stop_sequences"].([]string)
	if len(one) != 1 || one[0] != "END" {
		t.Errorf("stop as string -> %v", one)
	}
	many := decode(t, `{"stop":["A","B"],"messages":[]}`)["stop_sequences"].([]string)
	if len(many) != 2 || many[0] != "A" || many[1] != "B" {
		t.Errorf("stop as array -> %v", many)
	}
}

func TestReasoningEffortEnablesThinking(t *testing.T) {
	for _, effort := range []string{"low", "medium", "high", "HIGH"} {
		out := decode(t, `{"reasoning_effort":"`+effort+`","messages":[]}`)
		if _, ok := out["thinking"]; !ok {
			t.Errorf("reasoning_effort=%s did not enable thinking", effort)
		}
	}
	out := decode(t, `{"messages":[]}`)
	if _, ok := out["thinking"]; ok {
		t.Error("thinking set with no reasoning_effort")
	}
}

func TestEmptyMessagesGetAUsablePrompt(t *testing.T) {
	out := decode(t, `{"messages":[]}`)
	msgs := out["messages"].([]map[string]any)
	if len(msgs) != 1 || msgs[0]["role"] != "user" {
		t.Fatalf("messages = %+v, want a single user turn", msgs)
	}
}

// ── Anthropic → OpenAI ──────────────────────────────────────────────────────

func TestResponseTextAndUsage(t *testing.T) {
	raw := `{"id":"msg_1","model":"GLM-5.3","role":"assistant",
		"content":[{"type":"text","text":"pong"}],"stop_reason":"end_turn",
		"usage":{"input_tokens":19,"output_tokens":3,"cache_read_input_tokens":118272}}`
	out, err := ToOpenAIResponse([]byte(raw))
	if err != nil {
		t.Fatalf("ToOpenAIResponse: %v", err)
	}
	if out["id"] != "chatcmpl-1" {
		t.Errorf("id = %v, want msg_ prefix replaced", out["id"])
	}
	msg := out["choices"].([]any)[0].(map[string]any)["message"].(map[string]any)
	if msg["content"] != "pong" {
		t.Errorf("content = %v", msg["content"])
	}
	usage := out["usage"].(map[string]any)
	// Cached input still counts as prompt tokens.
	if usage["prompt_tokens"] != 118291 {
		t.Errorf("prompt_tokens = %v, want 19+118272", usage["prompt_tokens"])
	}
	if usage["completion_tokens"] != 3 || usage["total_tokens"] != 118294 {
		t.Errorf("usage = %v", usage)
	}
}

func TestResponseToolCallsAndFinishReason(t *testing.T) {
	raw := `{"id":"msg_2","model":"GLM-5.3","role":"assistant",
		"content":[{"type":"tool_use","id":"toolu_1","name":"get_weather","input":{"city":"Moscow"}}],
		"stop_reason":"tool_use","usage":{"input_tokens":10,"output_tokens":5}}`
	out, err := ToOpenAIResponse([]byte(raw))
	if err != nil {
		t.Fatalf("ToOpenAIResponse: %v", err)
	}
	choice := out["choices"].([]any)[0].(map[string]any)
	if choice["finish_reason"] != "tool_calls" {
		t.Errorf("finish_reason = %v", choice["finish_reason"])
	}
	msg := choice["message"].(map[string]any)
	if msg["content"] != "" {
		t.Errorf("content = %v, want empty when only tool calls are returned", msg["content"])
	}
	calls := msg["tool_calls"].([]map[string]any)
	if len(calls) != 1 || calls[0]["id"] != "toolu_1" {
		t.Fatalf("tool_calls = %+v", calls)
	}
	fn := calls[0]["function"].(map[string]any)
	if fn["name"] != "get_weather" || fn["arguments"] != `{"city":"Moscow"}` {
		t.Errorf("function = %+v", fn)
	}
}

func TestMaxTokensMapsToLengthFinish(t *testing.T) {
	raw := `{"id":"m","model":"g","role":"assistant","content":[{"type":"text","text":"x"}],
		"stop_reason":"max_tokens","usage":{"input_tokens":1,"output_tokens":1}}`
	out, _ := ToOpenAIResponse([]byte(raw))
	if got := out["choices"].([]any)[0].(map[string]any)["finish_reason"]; got != "length" {
		t.Errorf("finish_reason = %v, want length", got)
	}
}

// ── streaming ───────────────────────────────────────────────────────────────

func sse(events ...string) string { return strings.Join(events, "\n\n") + "\n\n" }

func runStream(t *testing.T, upstream string) []string {
	t.Helper()
	var out bytes.Buffer
	conv := NewStreamConverter(strings.NewReader(upstream), &out, "GLM-5.3", "chatcmpl-x", 42)
	if err := conv.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	return strings.Split(strings.TrimSpace(out.String()), "\n\n")
}

func TestStreamTextDeltasAndFinish(t *testing.T) {
	frames := runStream(t, sse(
		`data: {"type":"message_start","message":{"id":"msg_9","model":"GLM-5.3","usage":{"input_tokens":19}}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"One"}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" two"}}`,
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":19,"output_tokens":2}}`,
		`data: {"type":"message_stop"}`,
	))
	last := frames[len(frames)-1]
	if last != "data: [DONE]" {
		t.Fatalf("last frame = %q, want [DONE]", last)
	}
	joined := strings.Join(frames, "\n")
	for _, want := range []string{`"content":"One"`, `"content":" two"`, `"finish_reason":"stop"`, `"total_tokens":21`} {
		if !strings.Contains(joined, want) {
			t.Errorf("stream missing %s\n%s", want, joined)
		}
	}
}

func TestStreamThinkingIsDroppedNotInvented(t *testing.T) {
	frames := runStream(t, sse(
		`data: {"type":"message_start","message":{"id":"msg_1","model":"m","usage":{"input_tokens":1}}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"secret reasoning"}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"pong"}}`,
		`data: {"type":"message_stop"}`,
	))
	joined := strings.Join(frames, "\n")
	if strings.Contains(joined, "secret reasoning") {
		t.Error("thinking text leaked into the OpenAI stream")
	}
	if !strings.Contains(joined, `"content":"pong"`) {
		t.Error("answer text missing after a thinking delta")
	}
}

func TestStreamAssemblesToolArgumentsFromPartialJSON(t *testing.T) {
	frames := runStream(t, sse(
		`data: {"type":"message_start","message":{"id":"msg_2","model":"m","usage":{"input_tokens":1}}}`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_1","name":"get_weather","input":{}}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"city\":"}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"\"Moscow\"}"}}`,
		`data: {"type":"content_block_stop","index":0}`,
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"input_tokens":1,"output_tokens":4}}`,
		`data: {"type":"message_stop"}`,
	))
	joined := strings.Join(frames, "\n")
	if !strings.Contains(joined, `"arguments":"{\"city\":\"Moscow\"}"`) {
		t.Errorf("tool arguments were not assembled:\n%s", joined)
	}
	if !strings.Contains(joined, `"id":"toolu_1"`) {
		t.Errorf("tool_use id was not preserved:\n%s", joined)
	}
	if !strings.Contains(joined, `"finish_reason":"tool_calls"`) {
		t.Errorf("stop_reason tool_use did not map to tool_calls:\n%s", joined)
	}
}

func TestStreamEmitsToolCallWithEmptyArguments(t *testing.T) {
	frames := runStream(t, sse(
		`data: {"type":"message_start","message":{"id":"m","model":"g","usage":{"input_tokens":1}}}`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"toolu_2","name":"ping"}}`,
		`data: {"type":"content_block_stop","index":0}`,
		`data: {"type":"message_stop"}`,
	))
	joined := strings.Join(frames, "\n")
	if !strings.Contains(joined, `"arguments":"{}"`) {
		t.Errorf("a parameterless tool call did not emit {} arguments:\n%s", joined)
	}
}

func TestStreamErrorEventEndsTheRun(t *testing.T) {
	var out bytes.Buffer
	conv := NewStreamConverter(strings.NewReader(sse(
		`data: {"type":"message_start","message":{"id":"m","model":"g","usage":{"input_tokens":1}}}`,
		`data: {"type":"error","error":{"type":"overloaded_error","message":"upstream overloaded"}}`,
	)), &out, "g", "chatcmpl-x", 1)
	err := conv.Run()
	if err == nil || !strings.Contains(err.Error(), "upstream overloaded") {
		t.Fatalf("err = %v, want the upstream message surfaced", err)
	}
	if !strings.Contains(out.String(), "[DONE]") {
		t.Error("stream did not close with [DONE] after an error")
	}
}

func TestStreamSurvivesMalformedFrame(t *testing.T) {
	frames := runStream(t, sse(
		`data: not-json`,
		`data: {"type":"message_start","message":{"id":"m","model":"g","usage":{"input_tokens":1}}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ok"}}`,
		`data: {"type":"message_stop"}`,
	))
	if !strings.Contains(strings.Join(frames, "\n"), `"content":"ok"`) {
		t.Errorf("a malformed frame broke the stream: %v", frames)
	}
}

func TestStreamAlwaysTerminatesWithDone(t *testing.T) {
	// Upstream that dies without message_stop must still leave a well-formed stream.
	frames := runStream(t, `data: {"type":"message_start","message":{"id":"m","model":"g","usage":{"input_tokens":1}}}`+"\n\n")
	if frames[len(frames)-1] != "data: [DONE]" {
		t.Fatalf("truncated upstream did not end with [DONE]: %v", frames)
	}
}

// ── round trip ──────────────────────────────────────────────────────────────

func TestOpenAIToolRoundTrip(t *testing.T) {
	// A full tool loop: OpenAI in -> Anthropic out -> OpenAI answer.
	first := decode(t, `{"messages":[{"role":"user","content":"weather in Moscow?"}],
		"tools":[{"type":"function","function":{"name":"get_weather","description":"w",
		"parameters":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}}}]}`)
	if _, ok := first["tools"].([]anthropicTool); !ok {
		t.Fatalf("tools not translated: %T", first["tools"])
	}

	// Model answered with a tool_use; feed it back in OpenAI shape.
	toolCallArgs, err := json.Marshal(map[string]string{"city": "Moscow"})
	if err != nil {
		t.Fatal(err)
	}
	assistantTurn, err := json.Marshal(map[string]any{
		"role": "assistant", "content": nil,
		"tool_calls": []any{map[string]any{"id": "call_1", "type": "function",
			"function": map[string]string{"name": "get_weather", "arguments": string(toolCallArgs)}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	toolTurn, err := json.Marshal(map[string]any{
		"role": "tool", "tool_call_id": "call_1", "content": "-5C snow",
	})
	if err != nil {
		t.Fatal(err)
	}
	userTurn, _ := json.Marshal(map[string]string{"role": "user", "content": "weather in Moscow?"})
	secondBody := `{"messages":[` + string(userTurn) + `,` + string(assistantTurn) + `,` + string(toolTurn) + `]}`
	second := decode(t, secondBody)
	msgs := second["messages"].([]map[string]any)
	if len(msgs) != 3 {
		t.Fatalf("round trip produced %d messages", len(msgs))
	}
	last := msgs[2]["content"].([]contentBlock)
	if last[0].Type != "tool_result" || last[0].Content != "-5C snow" {
		t.Fatalf("tool result not preserved: %+v", last)
	}
}

func TestNonJSONRequestIsRejected(t *testing.T) {
	if _, err := ToAnthropicRequest([]byte("not json"), "m", 1); err == nil {
		t.Error("expected an error for a non-JSON request")
	}
}

var _ = io.Discard
var _ = ed25519.SignatureSize

// ── zsign unit checks (no network) ──────────────────────────────────────────

func TestSeedIsDeterministicAndShort(t *testing.T) {
	a := zsign.Seed("id", "zcode", "sess", "123")
	b := zsign.Seed("id", "zcode", "sess", "123")
	if a != b {
		t.Fatalf("Seed is not deterministic: %q vs %q", a, b)
	}
	if len(a) != 32 {
		t.Fatalf("seed length = %d, want 32 hex chars", len(a))
	}
	if zsign.Seed("id", "zcode", "sess", "124") == a {
		t.Error("seed ignores the timestamp")
	}
	if zsign.Seed("id", "other", "sess", "123") == a {
		t.Error("seed ignores the app id")
	}
}

func TestHasLeadingZeroBitsBoundaries(t *testing.T) {
	cases := []struct {
		b    []byte
		n    int
		want bool
	}{
		{[]byte{0x00, 0x00}, 15, true},
		{[]byte{0x00, 0x00}, 16, true},
		// 17 bits do not fit in a 2-byte digest. The ZCode original reads
		// past the end as 255, so the answer is false; keep that behaviour.
		{[]byte{0x00, 0x00}, 17, false},
		// 0x0080 is 0000000010000000: exactly 8 leading zero bits.
		{[]byte{0x00, 0x80}, 8, true},
		{[]byte{0x00, 0x80}, 9, false},
		{[]byte{0x00, 0x80}, 16, false},
		{[]byte{0xFF}, 0, true},
		{[]byte{0xFF}, 1, false},
		{[]byte{0x7F}, 1, true},
		{[]byte{0x00}, 9, false}, // more bits than the digest holds
	}
	for _, c := range cases {
		if got := zsign.HasLeadingZeroBits(c.b, c.n); got != c.want {
			t.Errorf("HasLeadingZeroBits(%x, %d) = %v, want %v", c.b, c.n, got, c.want)
		}
	}
}

func TestSolveAndVerifyProofOfWork(t *testing.T) {
	seed := zsign.Seed("id", zsign.AppID, "sess", "1")
	for i := 0; i < 5; i++ {
		pow, err := zsign.SolvePoW(seed, zsign.DefaultPowBits)
		if err != nil {
			t.Fatalf("SolvePoW: %v", err)
		}
		if len(pow) != 32 {
			t.Fatalf("pow length = %d, want 32 hex chars", len(pow))
		}
		if !zsign.VerifyPow(seed, pow, zsign.DefaultPowBits) {
			t.Fatalf("SolvePoW returned a solution that does not verify: %s", pow)
		}
		if zsign.VerifyPow(seed+"x", pow, zsign.DefaultPowBits) {
			t.Error("a solution verified against the wrong seed")
		}
	}
	if _, err := zsign.SolvePoW(seed, 33); err == nil {
		t.Error("expected rejection of an out-of-range difficulty")
	}
}

func TestPowCounterRejectsMalformedInput(t *testing.T) {
	if _, err := zsign.PowCounter("abc"); err == nil {
		t.Error("expected an error for a short pow")
	}
	n, err := zsign.PowCounter("35d2f26b5237c688952396f80000012e")
	if err != nil || n != 0x12e {
		t.Errorf("PowCounter = %d, %v; want 302", n, err)
	}
}

func TestSignedMessageLayoutExcludesProofOfWork(t *testing.T) {
	got := zsign.SignedMessage("id", "1", "0.16.9", "sess", "nonce")
	want := "id\n1\n0.16.9\nsess\nnonce"
	if got != want {
		t.Fatalf("SignedMessage = %q, want %q", got, want)
	}
	if strings.Contains(got, "\n\n") {
		t.Error("SignedMessage must be five newline-joined fields")
	}
}

func base64Sig(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

func TestSignAndVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64Sig(zsign.Sign(priv, "id", "1", "0.16.9", "sess", "nonce"))
	if err != nil {
		t.Fatal(err)
	}
	msg := zsign.SignedMessage("id", "1", "0.16.9", "sess", "nonce")
	if !ed25519.Verify(pub, []byte(msg), sig) {
		t.Error("signature does not verify over its own message")
	}
	// Any field change must break verification, which is the point of signing.
	if ed25519.Verify(pub, []byte(zsign.SignedMessage("id", "2", "0.16.9", "sess", "nonce")), sig) {
		t.Error("a different timestamp still verified")
	}
}

func TestSplitCredential(t *testing.T) {
	c, err := zsign.SplitCredential("abc.def", "https://api.z.ai/api/anthropic/")
	if err != nil {
		t.Fatalf("SplitCredential: %v", err)
	}
	if c.ID != "abc" || c.Secret != "def" || c.BaseURL != "https://api.z.ai/api/anthropic" {
		t.Fatalf("credential = %+v", c)
	}
	for _, bad := range []string{"nodot", ".secret", "id.", "a.b.c", ""} {
		if _, err := zsign.SplitCredential(bad, "https://x"); err == nil {
			t.Errorf("SplitCredential(%q) should have failed", bad)
		}
	}
}
