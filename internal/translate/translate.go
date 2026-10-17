// Package translate converts between the OpenAI chat-completions shape and the
// Anthropic Messages shape.
//
// The Coding Plan endpoint only speaks Anthropic Messages, so an adapter that
// wants "any project just points its base URL here" has to accept both shapes.
package translate

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ── OpenAI → Anthropic ──────────────────────────────────────────────────────

type oaiRequest struct {
	Model               string          `json:"model"`
	Messages            []oaiMessage    `json:"messages"`
	Tools               []oaiTool       `json:"tools"`
	ToolChoice          json.RawMessage `json:"tool_choice"`
	MaxTokens           *int            `json:"max_tokens"`
	MaxCompletionTokens *int            `json:"max_completion_tokens"`
	Stream              bool            `json:"stream"`
	Temperature         *float64        `json:"temperature"`
	TopP                *float64        `json:"top_p"`
	Stop                json.RawMessage `json:"stop"`
	ReasoningEffort     string          `json:"reasoning_effort"`
}

type oaiMessage struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content"`
	Name       string          `json:"name"`
	ToolCalls  []oaiToolCall   `json:"tool_calls"`
	ToolCallID string          `json:"tool_call_id"`
}

type oaiToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Index    *int   `json:"index"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type oaiTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

// Anthropic request, kept loose so unknown fields pass through.
type anthropicRequest struct {
	Model         string            `json:"model"`
	Messages      []json.RawMessage `json:"messages"`
	System        json.RawMessage   `json:"system,omitempty"`
	Tools         []anthropicTool   `json:"tools,omitempty"`
	ToolChoice    json.RawMessage   `json:"tool_choice,omitempty"`
	MaxTokens     int               `json:"max_tokens"`
	Stream        bool              `json:"stream"`
	Thinking      json.RawMessage   `json:"thinking,omitempty"`
	StopSequences []string          `json:"stop_sequences,omitempty"`
	Temperature   *float64          `json:"temperature,omitempty"`
	TopP          *float64          `json:"top_p,omitempty"`
}

type anthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
}

// contentBlock is one Anthropic content block.
type contentBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   string          `json:"content,omitempty"`
	Thinking  string          `json:"thinking,omitempty"`
}

// ToAnthropicRequest converts an OpenAI chat-completions body.
func ToAnthropicRequest(raw []byte, defaultModel string, defaultMaxTokens int) (map[string]any, error) {
	var req oaiRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("translate: openai request: %w", err)
	}
	model := req.Model
	if model == "" {
		model = defaultModel
	}

	out := map[string]any{"model": model, "stream": req.Stream}

	// System and developer messages collapse into the top-level system field.
	var systemParts []string
	msgs := make([]map[string]any, 0, len(req.Messages))
	for _, m := range req.Messages {
		switch m.Role {
		case "system", "developer":
			if text := oaiText(m.Content); text != "" {
				systemParts = append(systemParts, text)
			}
		case "tool":
			block := contentBlock{Type: "tool_result", ToolUseID: m.ToolCallID, Content: oaiText(m.Content)}
			msgs = append(msgs, map[string]any{"role": "user", "content": []contentBlock{block}})
		case "assistant":
			blocks := []contentBlock{}
			if text := oaiText(m.Content); text != "" {
				blocks = append(blocks, contentBlock{Type: "text", Text: text})
			}
			for _, tc := range m.ToolCalls {
				var input any
				if tc.Function.Arguments != "" {
					_ = json.Unmarshal([]byte(tc.Function.Arguments), &input)
				}
				raw, _ := json.Marshal(input)
				blocks = append(blocks, contentBlock{Type: "tool_use", ID: tc.ID, Name: tc.Function.Name, Input: raw})
			}
			if len(blocks) == 0 {
				continue
			}
			msgs = append(msgs, map[string]any{"role": "assistant", "content": blocks})
		default:
			blocks := oaiBlocks(m.Content)
			if len(blocks) == 0 {
				continue
			}
			msgs = append(msgs, map[string]any{"role": "user", "content": blocks})
		}
	}
	if len(systemParts) > 0 {
		blocks := make([]contentBlock, 0, len(systemParts))
		for _, p := range systemParts {
			blocks = append(blocks, contentBlock{Type: "text", Text: p})
		}
		out["system"] = blocks
	}
	if len(msgs) == 0 {
		msgs = append(msgs, map[string]any{"role": "user", "content": []contentBlock{{Type: "text", Text: "hi"}}})
	}
	out["messages"] = msgs

	if len(req.Tools) > 0 {
		tools := make([]anthropicTool, 0, len(req.Tools))
		for _, t := range req.Tools {
			if t.Type != "" && t.Type != "function" {
				continue
			}
			schema := t.Function.Parameters
			if len(schema) == 0 {
				schema = json.RawMessage(`{"type":"object","properties":{}}`)
			}
			tools = append(tools, anthropicTool{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				InputSchema: schema,
			})
		}
		if len(tools) > 0 {
			out["tools"] = tools
		}
	}
	if len(req.ToolChoice) > 0 {
		out["tool_choice"] = translateToolChoice(req.ToolChoice)
	}

	max := defaultMaxTokens
	switch {
	case req.MaxCompletionTokens != nil && *req.MaxCompletionTokens > 0:
		max = *req.MaxCompletionTokens
	case req.MaxTokens != nil && *req.MaxTokens > 0:
		max = *req.MaxTokens
	}
	out["max_tokens"] = max
	if req.Temperature != nil {
		out["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		out["top_p"] = *req.TopP
	}
	if stops := oaiStops(req.Stop); len(stops) > 0 {
		out["stop_sequences"] = stops
	}
	// GLM exposes reasoning through Anthropic's thinking block plus an effort
	// hint; OpenAI callers express it as reasoning_effort.
	switch strings.ToLower(req.ReasoningEffort) {
	case "low", "medium", "high":
		out["thinking"] = map[string]any{"type": "enabled"}
	}
	return out, nil
}

func translateToolChoice(raw json.RawMessage) any {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	switch t := v.(type) {
	case string:
		switch t {
		case "none":
			return map[string]any{"type": "none"}
		case "required":
			return map[string]any{"type": "any"}
		default:
			return map[string]any{"type": "auto"}
		}
	case map[string]any:
		if fn, ok := t["function"].(map[string]any); ok {
			if name, _ := fn["name"].(string); name != "" {
				return map[string]any{"type": "tool", "name": name}
			}
		}
	}
	return map[string]any{"type": "auto"}
}

func oaiText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var blocks []contentBlock
	if err := json.Unmarshal(raw, &blocks); err == nil {
		var b strings.Builder
		for _, blk := range blocks {
			if blk.Type == "text" {
				b.WriteString(blk.Text)
			}
		}
		return b.String()
	}
	return ""
}

func oaiBlocks(raw json.RawMessage) []contentBlock {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if s == "" {
			return nil
		}
		return []contentBlock{{Type: "text", Text: s}}
	}
	var blocks []contentBlock
	if err := json.Unmarshal(raw, &blocks); err == nil {
		return blocks
	}
	return nil
}

func oaiStops(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil && one != "" {
		return []string{one}
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	return nil
}

// ── Anthropic → OpenAI ──────────────────────────────────────────────────────

type anthResponse struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Role    string `json:"role"`
	Content []struct {
		Type  string          `json:"type"`
		Text  string          `json:"text"`
		ID    string          `json:"id"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Usage      struct {
		InputTokens              int `json:"input_tokens"`
		OutputTokens             int `json:"output_tokens"`
		CacheReadInputTokens     int `json:"cache_read_input_tokens"`
		CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
	} `json:"usage"`
}

// ToOpenAIResponse converts a non-streaming Anthropic response.
func ToOpenAIResponse(raw []byte) (map[string]any, error) {
	var resp anthResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("translate: anthropic response: %w", err)
	}
	message := map[string]any{"role": "assistant", "content": ""}
	var text strings.Builder
	var toolCalls []map[string]any
	for _, blk := range resp.Content {
		switch blk.Type {
		case "text":
			text.WriteString(blk.Text)
		case "tool_use":
			args := string(blk.Input)
			if args == "" {
				args = "{}"
			}
			toolCalls = append(toolCalls, map[string]any{
				"id":    blk.ID,
				"type":  "function",
				"index": len(toolCalls),
				"function": map[string]any{
					"name":      blk.Name,
					"arguments": args,
				},
			})
		}
	}
	message["content"] = text.String()
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	} else {
		message["content"] = nil
		if text.Len() > 0 {
			message["content"] = text.String()
		}
	}

	finish := "stop"
	switch resp.StopReason {
	case "tool_use":
		finish = "tool_calls"
	case "max_tokens":
		finish = "length"
	case "stop_sequence":
		finish = "stop"
	}

	promptTokens := resp.Usage.InputTokens + resp.Usage.CacheReadInputTokens + resp.Usage.CacheCreationInputTokens
	return map[string]any{
		"id":      strings.Replace(resp.ID, "msg_", "chatcmpl-", 1),
		"object":  "chat.completion",
		"created": 0,
		"model":   resp.Model,
		"choices": []any{map[string]any{
			"index":         0,
			"message":       message,
			"finish_reason": finish,
		}},
		"usage": map[string]any{
			"prompt_tokens":     promptTokens,
			"completion_tokens": resp.Usage.OutputTokens,
			"total_tokens":      promptTokens + resp.Usage.OutputTokens,
			"prompt_tokens_details": map[string]any{
				"cached_tokens": resp.Usage.CacheReadInputTokens,
			},
		},
	}, nil
}
