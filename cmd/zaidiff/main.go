// Command zaidiff sends the same request twice to the Coding Plan endpoint —
// once with a zsign attestation, once without — and diffs the responses.
//
// A 200 alone cannot tell the two apart, because the endpoint answers unsigned
// requests too. The discriminator has to come from the response itself.
package main

import (
	"bytes"
	"context"
	cryptoRand "crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/megamen32/zai-adapter/zsign"
)

const endpoint = "https://zcode.z.ai/api/v1/ultra-zai/anthropic/v1/messages"

func main() {
	apiKey, baseURL, err := readAPIKey()
	if err != nil {
		fail("credential: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	body, _ := json.Marshal(map[string]any{
		"model":      "GLM-5.3",
		"max_tokens": 32,
		"messages":   []map[string]string{{"role": "user", "content": "Reply with the single word: pong"}},
		"stream":     false,
	})

	send := func(label string, att *zsign.Attestation) (int, http.Header, map[string]any) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			fail("request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Anthropic-Version", "2023-06-01")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "ZCode/0.16.9 ai-sdk/provider-utils/4.0.27 runtime/node.js/22")
		req.Header.Set("X-Api-Key", apiKey)
		req.Header.Set("X-Zcode-Agent", "glm")
		if att != nil {
			req.Header.Set("X-App-Id", att.AppID)
			req.Header.Set("X-Client-Ts", att.Ts)
			req.Header.Set("X-Client-Version", att.ClientVersion)
			req.Header.Set("X-Client-Sig", att.Sig)
			req.Header.Set("X-Client-Nonce", att.Nonce)
			req.Header.Set("X-Client-Pow", att.Pow)
			req.Header.Set("X-Session-Id", att.SessionID)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fail("send %s: %v", label, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var env map[string]any
		_ = json.Unmarshal(raw, &env)
		return resp.StatusCode, resp.Header, env
	}

	signer, err := zsign.NewSigner(apiKey, baseURL, "0.16.9", nil)
	if err != nil {
		fail("signer: %v", err)
	}
	defer signer.Close()
	att, err := signer.Attest(ctx, newUUID())
	if err != nil {
		fail("attest: %v", err)
	}

	usCode, usHdr, usBody := send("unsigned", nil)
	sgCode, sgHdr, sgBody := send("signed", att)

	fmt.Printf("unsigned: status=%d  usage=%s\n", usCode, mustJSON(usBody["usage"]))
	fmt.Printf("signed:   status=%d  usage=%s\n", sgCode, mustJSON(sgBody["usage"]))
	fmt.Printf("X-Client-Sign-Verified: signed=%q unsigned=%q\n",
		sgHdr.Get("X-Client-Sign-Verified"), usHdr.Get("X-Client-Sign-Verified"))

	only := map[string]bool{}
	for k := range sgHdr {
		if k == "Date" {
			continue
		}
		if _, ok := usHdr[k]; !ok {
			only[k] = true
		}
	}
	for k := range usHdr {
		if _, ok := sgHdr[k]; !ok && k != "Date" {
			only[k] = true
		}
	}
	keys := make([]string, 0, len(only))
	for k := range only {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Println("\nheaders present in only one response:")
	if len(keys) == 0 {
		fmt.Println("  (none)")
	}
	for _, k := range keys {
		fmt.Printf("  %-32s signed=%q unsigned=%q\n", k, sgHdr.Get(k), usHdr.Get(k))
	}

	fmt.Println("\nvalue differences on shared headers:")
	shared := false
	for k := range usHdr {
		if _, ok := sgHdr[k]; !ok || k == "Date" {
			continue
		}
		if sgHdr.Get(k) != usHdr.Get(k) {
			fmt.Printf("  %-32s signed=%q unsigned=%q\n", k, sgHdr.Get(k), usHdr.Get(k))
			shared = true
		}
	}
	if !shared {
		fmt.Println("  (none)")
	}
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func readAPIKey() (string, string, error) {
	raw, err := os.ReadFile("/home/roomhacker/.zcode/v2/config.json")
	if err != nil {
		return "", "", err
	}
	i := strings.Index(string(raw), `"builtin:zai-coding-plan"`)
	rest := string(raw)[i:]
	key, err := jsonStringAt(rest[strings.Index(rest, `"apiKey"`):])
	if err != nil {
		return "", "", err
	}
	base, err := jsonStringAt(rest[strings.Index(rest, `"baseURL"`):])
	return key, base, err
}

func jsonStringAt(s string) (string, error) {
	colon := strings.Index(s, ":")
	q := strings.Index(s[colon:], `"`)
	if q < 0 {
		return "", fmt.Errorf("malformed json")
	}
	start := colon + q + 1
	end := strings.Index(s[start:], `"`)
	return s[start : start+end], nil
}

func newUUID() string {
	var b [16]byte
	if _, err := crandRead(b[:]); err != nil {
		fail("random: %v", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}
func crandRead(b []byte) (int, error) { return cryptoRand.Read(b) }
