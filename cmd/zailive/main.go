// Command zailive proves the adapter end to end: it signs a request with
// zsign and asks the Coding Plan endpoint whether the signature was accepted.
//
// The server answers signed requests with an X-Client-Sign-Verified header, and
// rejects bad ones with HTTP 401 and reason VERIFY_SIGNATURE_INVALID. That is
// the authoritative check; a plain 200 alone proves nothing, because the
// endpoint also answers unsigned requests.
//
// The API key is read from ZCode's config and never printed.
package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/megamen32/zai-adapter/zsign"
)

// codingPlanEndpoint is the URL z.ai's own agent/configs maps the public
// Anthropic endpoint to.
const codingPlanEndpoint = "https://zcode.z.ai/api/v1/ultra-zai/anthropic/v1/messages"

func main() {
	model := flag.String("model", "GLM-5.3", "model id")
	maxTokens := flag.Int("max-tokens", 64, "max_tokens")
	endpoint := flag.String("endpoint", codingPlanEndpoint, "target endpoint")
	prompt := flag.String("prompt", "Reply with the single word: pong", "user prompt")
	flag.Parse()

	apiKey, baseURL, err := readAPIKey()
	if err != nil {
		fail("read credential: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	signer, err := zsign.NewSigner(apiKey, baseURL, "0.16.9", nil)
	if err != nil {
		fail("signer: %v", err)
	}
	defer signer.Close()

	sessionID := newUUID()
	att, err := signer.Attest(ctx, sessionID)
	if err != nil {
		fail("attest: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"model":      *model,
		"max_tokens": *maxTokens,
		"messages":   []map[string]string{{"role": "user", "content": *prompt}},
		"stream":     false,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, *endpoint, bytes.NewReader(body))
	if err != nil {
		fail("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Anthropic-Version", "2023-06-01")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ZCode/0.16.9 ai-sdk/provider-utils/4.0.27 runtime/node.js/22")
	req.Header.Set("X-Api-Key", apiKey)
	req.Header.Set("X-Zcode-Agent", "glm")
	req.Header.Set("X-App-Id", att.AppID)
	req.Header.Set("X-Client-Ts", att.Ts)
	req.Header.Set("X-Client-Version", att.ClientVersion)
	req.Header.Set("X-Client-Sig", att.Sig)
	req.Header.Set("X-Client-Nonce", att.Nonce)
	req.Header.Set("X-Client-Pow", att.Pow)
	req.Header.Set("X-Session-Id", att.SessionID)

	fmt.Printf("endpoint  %s\n", *endpoint)
	fmt.Printf("session   %s\n", att.SessionID)
	fmt.Printf("ts        %s\n", att.Ts)
	fmt.Printf("pow       %s (counter %d)\n", att.Pow, mustCounter(att.Pow))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fail("send: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	fmt.Printf("\nstatus    %d\n", resp.StatusCode)
	for _, h := range []string{"X-Client-Sign-Verified", "X-Request-Id", "X-Log-Id"} {
		if v := resp.Header.Get(h); v != "" {
			fmt.Printf("%-9s %s\n", h, v)
		}
	}

	var env map[string]any
	_ = json.Unmarshal(raw, &env)
	if usage, ok := env["usage"]; ok {
		b, _ := json.Marshal(usage)
		fmt.Printf("usage     %s\n", b)
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("body      %s\n", truncate(raw, 400))
		fmt.Println("\nRESULT: REJECTED")
		os.Exit(1)
	}

	verified := resp.Header.Get("X-Client-Sign-Verified")
	if verified == "" {
		fmt.Println("\nRESULT: 200 but no X-Client-Sign-Verified header — signature not confirmed")
		os.Exit(2)
	}
	fmt.Printf("\nRESULT: SIGNATURE ACCEPTED (X-Client-Sign-Verified=%s)\n", verified)
}

func mustCounter(pow string) uint64 {
	n, err := zsign.PowCounter(pow)
	if err != nil {
		return 0
	}
	return n
}

func readAPIKey() (string, string, error) {
	raw, err := os.ReadFile("/home/roomhacker/.zcode/v2/config.json")
	if err != nil {
		return "", "", err
	}
	i := strings.Index(string(raw), `"builtin:zai-coding-plan"`)
	if i < 0 {
		return "", "", fmt.Errorf("zai-coding-plan provider not found")
	}
	rest := string(raw)[i:]
	key, err := jsonStringAt(rest[strings.Index(rest, `"apiKey"`):])
	if err != nil {
		return "", "", err
	}
	base, err := jsonStringAt(rest[strings.Index(rest, `"baseURL"`):])
	if err != nil {
		return "", "", err
	}
	return key, base, nil
}

func jsonStringAt(s string) (string, error) {
	colon := strings.Index(s, ":")
	q := strings.Index(s[colon:], `"`)
	if q < 0 {
		return "", fmt.Errorf("malformed json")
	}
	start := colon + q + 1
	end := strings.Index(s[start:], `"`)
	if end < 0 {
		return "", fmt.Errorf("unterminated json")
	}
	return s[start : start+end], nil
}

func newUUID() string {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		fail("random: %v", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}
