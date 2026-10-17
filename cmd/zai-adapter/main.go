// Command zai-adapter puts a Coding Plan endpoint behind a local URL so any
// project can use it by pointing its base URL here.
//
//	zai-adapter -listen 127.0.0.1:8787
//	# then, in any project:
//	ANTHROPIC_BASE_URL=http://127.0.0.1:8787
//	OPENAI_BASE_URL=http://127.0.0.1:8787/v1
//
// It accepts both wire shapes on the same port:
//
//	POST /v1/messages        Anthropic Messages, forwarded as-is
//	POST /v1/chat/completions  OpenAI chat completions, translated both ways
//
// Transport is site-mimic, so the adapter presents a browser-shaped TLS
// ClientHello rather than the trivially recognisable Go one.
//
// The Coding Plan endpoint only speaks Anthropic Messages; that is why the
// OpenAI path is translated instead of proxied.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/megamen32/site-mimic/mimic"
	"github.com/megamen32/zai-adapter/internal/translate"
	"github.com/megamen32/zai-adapter/zsign"
)

type config struct {
	listen       string
	apiKey       string
	upstream     string
	clientVer    string
	model        string
	maxTokens    int
	signRequests bool
	clientHello  string
	userAgent    string
	logLevel     string
}

func main() {
	cfg := config{}
	flag.StringVar(&cfg.listen, "listen", "127.0.0.1:8787", "local listen address")
	flag.StringVar(&cfg.apiKey, "api-key", os.Getenv("ZAI_API_KEY"), "z.ai API key (id.secret); default $ZAI_API_KEY")
	flag.StringVar(&cfg.upstream, "upstream", "https://zcode.z.ai/api/v1/ultra-zai/anthropic", "Coding Plan Messages base URL")
	flag.StringVar(&cfg.clientVer, "client-version", "0.16.9", "value for X-Client-Version; it is part of the signed message")
	flag.StringVar(&cfg.model, "model", "GLM-5.3", "default model")
	flag.IntVar(&cfg.maxTokens, "max-tokens", 128000, "default max_tokens when the caller omits it")
	flag.BoolVar(&cfg.signRequests, "sign", true, "attach the Coding Plan client attestation")
	flag.StringVar(&cfg.clientHello, "tls-client-hello", "chrome_exact", "site-mimic ClientHello profile")
	flag.StringVar(&cfg.userAgent, "user-agent", "", "override User-Agent (default matches ZCode)")
	flag.StringVar(&cfg.logLevel, "log-level", "info", "debug, info, warn, error")
	flag.Parse()

	if strings.TrimSpace(cfg.apiKey) == "" {
		fatal("no API key: pass -api-key or set ZAI_API_KEY")
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.logLevel)); err != nil {
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	ua := cfg.userAgent
	if ua == "" {
		ua = "ZCode/0.16.9 ai-sdk/provider-utils/4.0.27 runtime/node.js/22"
	}

	profile := mimic.Profile{
		Name:           "zai-adapter",
		TLSClientHello: cfg.clientHello,
		UserAgent:      ua,
		Headers: map[string]string{
			"Accept":          "*/*",
			"Accept-Language": "*",
			"Referer":         "https://zcode.z.ai",
		},
	}
	client, err := mimic.New(profile)
	if err != nil {
		fatal("site-mimic transport: %v", err)
	}

	signer, err := zsign.NewSigner(cfg.apiKey, "https://api.z.ai/api/anthropic", cfg.clientVer, client.Transport)
	if err != nil {
		fatal("signer: %v", err)
	}
	defer signer.Close()

	a := &adapter{cfg: cfg, client: client, signer: signer, logger: logger, upstream: strings.TrimRight(cfg.upstream, "/")}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/messages", a.handleMessages)
	mux.HandleFunc("/v1/chat/completions", a.handleChatCompletions)
	mux.HandleFunc("/v1/models", a.handleModels)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"status":"ok"}`+"\n")
	})

	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		fatal("listen %s: %v", cfg.listen, err)
	}
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
		// Streaming responses can run for many minutes.
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	logger.Info("zai-adapter listening",
		"addr", cfg.listen, "upstream", a.upstream, "model", cfg.model,
		"sign", cfg.signRequests, "tls_client_hello", cfg.clientHello)

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal("serve: %v", err)
	}
}

type adapter struct {
	cfg      config
	client   *http.Client
	signer   *zsign.Signer
	logger   *slog.Logger
	upstream string
}

func (a *adapter) handleModels(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"object": "list",
		"data": []any{map[string]any{
			"id":       a.cfg.model,
			"object":   "model",
			"owned_by": "z.ai",
		}},
	})
}

// handleMessages forwards an Anthropic Messages request unchanged.
func (a *adapter) handleMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		httpError(w, http.StatusBadRequest, "read body")
		return
	}
	var probe struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &probe)
	a.forward(w, r, body, probe.Model, false)
}

// handleChatCompletions translates an OpenAI request to Anthropic, calls the
// Coding Plan endpoint, and translates the answer back.
func (a *adapter) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		httpError(w, http.StatusBadRequest, "read body")
		return
	}
	var probe struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		httpError(w, http.StatusBadRequest, "openai request: "+err.Error())
		return
	}

	converted, err := translate.ToAnthropicRequest(raw, a.cfg.model, a.cfg.maxTokens)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	body, err := json.Marshal(converted)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.forward(w, r, body, probe.Model, true)
}

// forward issues the upstream request and relays the answer, translating the
// response when the caller used the OpenAI shape.
func (a *adapter) forward(w http.ResponseWriter, r *http.Request, body []byte, model string, toOpenAI bool) {
	ctx := r.Context()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.upstream+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	if toOpenAI {
		req.Header.Set("Accept", "application/json")
	} else {
		req.Header.Set("Accept", "text/event-stream")
	}
	req.Header.Set("Anthropic-Version", "2023-06-01")
	req.Header.Set("X-Api-Key", a.cfg.apiKey)
	req.Header.Set("X-Zcode-Agent", "glm")

	if a.cfg.signRequests && a.signer != nil {
		sessionID := headerOr(r, "X-Session-Id", newUUID())
		att, err := a.signer.Attest(ctx, sessionID)
		if err != nil {
			// The endpoint answers unsigned requests, so a signing failure is
			// degraded, not fatal.
			a.logger.Warn("attestation failed, sending unsigned", "error", err)
		} else {
			for k, v := range att.Headers() {
				req.Header.Set(k, v)
			}
		}
	}

	resp, err := a.client.Do(req)
	if err != nil {
		a.logger.Error("upstream", "error", err)
		httpError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		a.logger.Warn("upstream status", "status", resp.StatusCode, "body", truncate(msg, 300))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(msg)
		return
	}

	stream := isStreaming(body)
	if !toOpenAI {
		copyThrough(w, resp)
		return
	}
	if !stream {
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		if err != nil {
			httpError(w, http.StatusBadGateway, err.Error())
			return
		}
		converted, err := translate.ToOpenAIResponse(raw)
		if err != nil {
			httpError(w, http.StatusBadGateway, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(converted)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	conv := translate.NewStreamConverter(resp.Body, w, modelOr(model, a.cfg.model), "chatcmpl-zai", time.Now().Unix())
	if flusher != nil {
		// The converter buffers through bufio; flush after each event so tokens
		// are not held back until the stream closes.
		conv.SetFlush(func() { flusher.Flush() })
	}
	if err := conv.Run(); err != nil {
		a.logger.Warn("stream ended", "error", err)
	}
}

func copyThrough(w http.ResponseWriter, resp *http.Response) {
	for k, vs := range resp.Header {
		if strings.EqualFold(k, "Content-Encoding") {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

func isStreaming(body []byte) bool {
	var probe struct {
		Stream bool `json:"stream"`
	}
	_ = json.Unmarshal(body, &probe)
	return probe.Stream
}

func modelOr(model, fallback string) string {
	if strings.TrimSpace(model) == "" {
		return fallback
	}
	return model
}

func headerOr(r *http.Request, name, fallback string) string {
	if v := strings.TrimSpace(r.Header.Get(name)); v != "" {
		return v
	}
	return fallback
}

func httpError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
		"type":    "adapter_error",
		"message": msg,
	}})
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "zai-adapter: "+format+"\n", args...)
	os.Exit(1)
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		fatal("random: %v", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
