// Command zai-attest is the whole deliverable: a local endpoint that attaches
// z.ai's Coding Plan client attestation to whatever passes through it.
//
// There is deliberately no request translation here. The OpenAI↔Anthropic
// shim was removed: plenty of tools already do that, and it obscured the one
// thing this exists to do — reproduce exactly what separates a ZCode request
// from an ordinary client request.
//
//	zai-attest -listen 127.0.0.1:18790
//	# any Anthropic-shaped client:
//	export ANTHROPIC_BASE_URL=http://127.0.0.1:18790
//
// Everything is forwarded byte for byte. The adapter only adds the attestation
// headers and the transport identity.
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
	"github.com/megamen32/zai-adapter/zsign"
)

// telemetry is the non-attestation client identity ZCode sends alongside the
// signature. It is not covered by the Ed25519 signature; the server reads it
// as plain context about who is calling.
var telemetry = map[string]string{
	"X-App-Id":             zsign.AppID,
	"X-Zcode-Agent":        "glm",
	"X-Release-Channel":    "production",
	"X-Client-Language":    "ru-RU",
	"X-Client-Timezone":    "Europe/Moscow",
	"X-Platform":           "linux-x64",
	"X-Os-Category":        "linux",
	"Http-Referer":         "https://zcode.z.ai",
	"X-Zcode-App-Version":  "0.16.9",
	"X-Zcode-Session-Type": "main",
}

type config struct {
	listen        string
	apiKey        string
	upstream      string
	clientVer     string
	clientHello   string
	userAgent     string
	osVersion     string
	logLevel      string
	withTelemetry bool
}

func main() {
	cfg := config{}
	flag.StringVar(&cfg.listen, "listen", "127.0.0.1:18790", "local listen address")
	flag.StringVar(&cfg.apiKey, "api-key", os.Getenv("ZAI_API_KEY"), "z.ai API key (id.secret); default $ZAI_API_KEY")
	flag.StringVar(&cfg.upstream, "upstream", "https://zcode.z.ai/api/v1/ultra-zai/anthropic", "Coding Plan base URL")
	flag.StringVar(&cfg.clientVer, "client-version", "0.16.9", "X-Client-Version; it is part of the signed message")
	flag.StringVar(&cfg.clientHello, "tls-client-hello", "chrome_exact", "site-mimic ClientHello profile")
	flag.StringVar(&cfg.userAgent, "user-agent", "ZCode/0.16.9 ai-sdk/provider-utils/4.0.27 runtime/node.js/22", "User-Agent")
	flag.StringVar(&cfg.osVersion, "os-version", "", "X-Os-Version value (default: read from uname)")
	flag.BoolVar(&cfg.withTelemetry, "telemetry", true, "send the non-attested client-identity headers ZCode sends")
	flag.StringVar(&cfg.logLevel, "log-level", "info", "debug, info, warn, error")
	flag.Parse()

	if strings.TrimSpace(cfg.apiKey) == "" {
		fatal("no API key: pass -api-key or set ZAI_API_KEY")
	}
	if cfg.osVersion == "" {
		cfg.osVersion = readOSVersion()
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.logLevel)); err != nil {
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	client, err := mimic.New(mimic.Profile{
		Name:           "zai-attest",
		TLSClientHello: cfg.clientHello,
		UserAgent:      cfg.userAgent,
		Headers:        map[string]string{"Accept": "*/*", "Accept-Language": "*"},
	})
	if err != nil {
		fatal("site-mimic transport: %v", err)
	}

	signer, err := zsign.NewSigner(cfg.apiKey, "https://api.z.ai/api/anthropic", cfg.clientVer, client.Transport)
	if err != nil {
		fatal("signer: %v", err)
	}
	defer signer.Close()

	a := &attestor{cfg: cfg, client: client, signer: signer, logger: logger,
		upstream: strings.TrimRight(cfg.upstream, "/")}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok\n")
	})
	// Everything else is forwarded: /v1/messages, /v1/chat/completions, whatever.
	mux.HandleFunc("/", a.handle)

	ln, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		fatal("listen %s: %v", cfg.listen, err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 30 * time.Second}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	logger.Info("zai-attest listening", "addr", cfg.listen, "upstream", a.upstream,
		"client_version", cfg.clientVer, "telemetry", cfg.withTelemetry,
		"tls_client_hello", cfg.clientHello)

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal("serve: %v", err)
	}
}

type attestor struct {
	cfg      config
	client   *http.Client
	signer   *zsign.Signer
	logger   *slog.Logger
	upstream string
}

func (a *attestor) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		io.WriteString(w, "ok\n")
		return
	}

	// Buffer the request so a late signing failure cannot half-send a body.
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		httpError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, r.Method, a.upstream+r.URL.RequestURI(), bytes.NewReader(body))
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Forward the caller's headers, then overwrite the identity with ours.
	for k, vs := range r.Header {
		if skipForward(k) {
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Accept-Encoding", "identity")
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Anthropic-Version", "2023-06-01")
	req.Header.Set("X-Api-Key", a.cfg.apiKey)

	sessionID := strings.TrimSpace(r.Header.Get("X-Session-Id"))
	if sessionID == "" {
		sessionID = newUUID()
	}

	att, err := a.signer.Attest(r.Context(), sessionID)
	if err != nil {
		// The endpoint serves unsigned requests, so degrade instead of failing.
		a.logger.Warn("attestation failed, forwarding unsigned", "error", err)
	} else {
		for k, v := range att.Headers() {
			req.Header.Set(k, v)
		}
		a.logger.Debug("attested",
			"path", r.URL.Path, "session", att.SessionID, "ts", att.Ts,
			"pow", att.Pow, "nonce", att.Nonce, "sig_prefix", att.Sig[:16]+"...")
	}

	if a.cfg.withTelemetry {
		tel := make(map[string]string, len(telemetry)+1)
		for k, v := range telemetry {
			tel[k] = v
		}
		tel["X-Os-Version"] = a.cfg.osVersion
		for k, v := range tel {
			if req.Header.Get(k) == "" {
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

	for k, vs := range resp.Header {
		if strings.EqualFold(k, "Content-Encoding") || strings.EqualFold(k, "Content-Length") {
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
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if rerr != nil {
			return
		}
	}
}

// skipForward stops a caller from injecting the identity we are signing over.
func skipForward(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "X-Api-Key", "Authorization", "Host", "Content-Length",
		"X-Client-Ts", "X-Client-Version", "X-Client-Sig", "X-Client-Nonce",
		"X-Client-Pow", "X-Session-Id", "User-Agent", "Accept-Encoding":
		return true
	}
	return false
}

func readOSVersion() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func httpError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{
		"type": "attest_error", "message": msg,
	}})
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

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "zai-attest: "+format+"\n", args...)
	os.Exit(1)
}
