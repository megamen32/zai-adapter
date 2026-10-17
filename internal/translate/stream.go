package translate

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// anthropicStreamEvent is one server-sent event from the Messages API.
type anthropicStreamEvent struct {
	Type    string `json:"type"`
	Index   int    `json:"index"`
	Message *struct {
		ID    string `json:"id"`
		Model string `json:"model"`
		Usage struct {
			InputTokens              int `json:"input_tokens"`
			OutputTokens             int `json:"output_tokens"`
			CacheReadInputTokens     int `json:"cache_read_input_tokens"`
			CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
		} `json:"usage"`
	} `json:"message"`
	ContentBlock *struct {
		Type  string          `json:"type"`
		ID    string          `json:"id"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	} `json:"content_block"`
	Delta *struct {
		Type        string `json:"type"`
		Text        string `json:"text"`
		PartialJSON string `json:"partial_json"`
		Thinking    string `json:"thinking"`
		StopReason  string `json:"stop_reason"`
	} `json:"delta"`
	Usage *struct {
		InputTokens          int `json:"input_tokens"`
		OutputTokens         int `json:"output_tokens"`
		CacheReadInputTokens int `json:"cache_read_input_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// StreamConverter rewrites an Anthropic SSE stream into OpenAI chat-completion
// chunks. Tool-call arguments arrive as partial JSON fragments keyed by block
// index, so they are buffered and flushed as one arguments string on the
// matching tool_calls delta.
type StreamConverter struct {
	sc      *bufio.Scanner
	w       *bufio.Writer
	model   string
	id      string
	created int64

	blockToToolIndex map[int]int
	pendingArgs      map[int]*strings.Builder
	pendingName      map[int]string
	openTools        map[int]bool
	blockIDs         map[int]string
	sentRole         bool
	finishReason     string
	usage            map[string]any
	done             bool
	flushFn          func()
}

// NewStreamConverter wires an Anthropic SSE body to an OpenAI SSE sink.
func NewStreamConverter(r io.Reader, w io.Writer, model string, id string, created int64) *StreamConverter {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	return &StreamConverter{
		sc:               sc,
		w:                bufio.NewWriter(w),
		model:            model,
		id:               id,
		created:          created,
		blockToToolIndex: map[int]int{},
		pendingArgs:      map[int]*strings.Builder{},
		pendingName:      map[int]string{},
		openTools:        map[int]bool{},
		blockIDs:         map[int]string{},
	}
}

// Run consumes the upstream stream and emits the translated one. It always
// closes with a final chunk and the [DONE] sentinel.
func (c *StreamConverter) Run() error {
	defer func() {
		c.flush()
		c.emitDone()
		c.w.Flush()
	}()
	for c.sc.Scan() {
		line := strings.TrimSpace(c.sc.Text())
		if line == "" || !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "[DONE]" {
			return nil
		}
		var ev anthropicStreamEvent
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			continue
		}
		if err := c.handle(&ev); err != nil {
			return err
		}
	}
	return c.sc.Err()
}

func (c *StreamConverter) handle(ev *anthropicStreamEvent) error {
	switch ev.Type {
	case "message_start":
		if ev.Message != nil {
			if ev.Message.Model != "" {
				c.model = ev.Message.Model
			}
			if ev.Message.ID != "" {
				c.id = "chatcmpl-" + strings.TrimPrefix(ev.Message.ID, "msg_")
			}
		}
		c.sendRole()

	case "content_block_start":
		if ev.ContentBlock != nil && ev.ContentBlock.Type == "tool_use" {
			idx := len(c.blockToToolIndex)
			c.blockToToolIndex[ev.Index] = idx
			c.pendingArgs[ev.Index] = &strings.Builder{}
			c.pendingName[ev.Index] = ev.ContentBlock.Name
			c.blockIDs[ev.Index] = ev.ContentBlock.ID
		}

	case "content_block_delta":
		if ev.Delta == nil {
			return nil
		}
		switch ev.Delta.Type {
		case "text_delta":
			c.sendRole()
			c.chunk(map[string]any{"content": ev.Delta.Text}, "")
		case "thinking_delta":
			// Reasoning is not part of the OpenAI wire shape; drop it rather
			// than invent a field the client will not read.
		case "signature_delta":
			// Opaque thinking signature; nothing to forward.
		case "input_json_delta":
			if b, ok := c.pendingArgs[ev.Index]; ok {
				b.WriteString(ev.Delta.PartialJSON)
			}
		}

	case "content_block_stop":
		idx, ok := c.blockToToolIndex[ev.Index]
		if !ok {
			return nil
		}
		args := "{}"
		if b := c.pendingArgs[ev.Index]; b != nil && b.Len() > 0 {
			args = b.String()
		}
		c.sendRole()
		c.chunk(map[string]any{
			"tool_calls": []any{map[string]any{
				"index": idx,
				"id":    c.toolCallID(ev.Index, idx),
				"type":  "function",
				"function": map[string]any{
					"name":      c.pendingName[ev.Index],
					"arguments": args,
				},
			}},
		}, "")
		c.openTools[idx] = true

	case "message_delta":
		if ev.Delta != nil && ev.Delta.StopReason != "" {
			c.finishReason = openAIFinish(ev.Delta.StopReason)
		}
		if ev.Usage != nil {
			prompt := ev.Usage.InputTokens + ev.Usage.CacheReadInputTokens
			c.usage = map[string]any{
				"prompt_tokens":     prompt,
				"completion_tokens": ev.Usage.OutputTokens,
				"total_tokens":      prompt + ev.Usage.OutputTokens,
				"prompt_tokens_details": map[string]any{
					"cached_tokens": ev.Usage.CacheReadInputTokens,
				},
			}
		}

	case "message_stop":
		c.flush()

	case "error":
		msg := "upstream stream error"
		if ev.Error != nil && ev.Error.Message != "" {
			msg = ev.Error.Message
		}
		c.chunk(map[string]any{}, "")
		return fmt.Errorf("translate: %s", msg)
	}
	return nil
}

// toolCallID keeps the Anthropic tool_use id when present so a client can
// correlate the call, and falls back to a synthetic OpenAI-style id.
func (c *StreamConverter) toolCallID(blockIndex, idx int) string {
	if id := c.blockIDs[blockIndex]; id != "" {
		return id
	}
	return fmt.Sprintf("call_%d_%d", c.created, idx)
}

func openAIFinish(reason string) string {
	switch reason {
	case "tool_use":
		return "tool_calls"
	case "max_tokens":
		return "length"
	default:
		return "stop"
	}
}

func (c *StreamConverter) sendRole() {
	if c.sentRole {
		return
	}
	c.sentRole = true
	c.chunk(map[string]any{"role": "assistant", "content": ""}, "")
}

func (c *StreamConverter) chunk(delta map[string]any, finish string) {
	payload := map[string]any{
		"id":      c.id,
		"object":  "chat.completion.chunk",
		"created": c.created,
		"model":   c.model,
		"choices": []any{map[string]any{
			"index":         0,
			"delta":         delta,
			"finish_reason": nil,
		}},
	}
	b, _ := json.Marshal(payload)
	fmt.Fprintf(c.w, "data: %s\n\n", b)
	c.maybeFlush()
}

func (c *StreamConverter) maybeFlush() {
	if c.flushFn != nil {
		c.flushFn()
		c.w.Flush()
	}
}

func (c *StreamConverter) flush() {
	if c.done {
		return
	}
	c.done = true
	c.sendRole()
	finish := c.finishReason
	if finish == "" {
		finish = "stop"
	}
	payload := map[string]any{
		"id":      c.id,
		"object":  "chat.completion.chunk",
		"created": c.created,
		"model":   c.model,
		"choices": []any{map[string]any{
			"index":         0,
			"delta":         map[string]any{},
			"finish_reason": finish,
		}},
	}
	if c.usage != nil {
		payload["usage"] = c.usage
	}
	b, _ := json.Marshal(payload)
	fmt.Fprintf(c.w, "data: %s\n\n", b)
	c.maybeFlush()
}

func (c *StreamConverter) emitDone() {
	fmt.Fprint(c.w, "data: [DONE]\n\n")
	c.maybeFlush()
}

// SetFlush registers a flush callback that runs after each emitted chunk, so a
// streaming client sees tokens as they arrive instead of at connection close.
func (c *StreamConverter) SetFlush(f func()) { c.flushFn = f }
