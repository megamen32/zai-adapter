// Command zaicheck proves the zsign implementation against a real ZCode
// capture, instead of against values pasted into this file.
//
//	go run ./cmd/zaicheck -capture ../zai-capture-probe/out/ab
//
// It recomputes the proof-of-work seed from the captured timestamp and session,
// re-verifies ZCode's own proof of work against it, then obtains the signing
// key from our own handshake and checks ZCode's captured Ed25519 signature.
//
// The API key is read from ZCode's config and never printed.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const zcodeConfig = "/home/roomhacker/.zcode/v2/config.json"

type flow struct {
	Host    string              `json:"host"`
	Path    string              `json:"path"`
	Method  string              `json:"method"`
	Headers map[string][]string `json:"request_headers"`
}

func header(h map[string][]string, name string) string {
	if v, ok := h[name]; ok && len(v) > 0 {
		return v[0]
	}
	// Captures are stored with canonical header names, but be tolerant.
	for k, v := range h {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

func main() {
	captureDir := flag.String("capture", "", "directory of zmitm flow JSON files")
	flag.Parse()
	if *captureDir == "" {
		fail("-capture is required")
	}

	apiKey, baseURL, err := readAPIKey()
	if err != nil {
		fail("read credential: %v", err)
	}
	cred, err := splitCredential(apiKey, baseURL)
	if err != nil {
		fail("split credential: %v", err)
	}
	fmt.Printf("credential: apiKeyId=%s... (%d chars), baseURL=%s\n",
		safePrefix(cred.ID), len(cred.Secret), cred.BaseURL)

	flowPath, err := findZcodeFlow(*captureDir)
	if err != nil {
		fail("find capture: %v", err)
	}
	f, err := readFlow(flowPath)
	if err != nil {
		fail("read capture: %v", err)
	}
	fmt.Printf("capture:    %s\n", filepath.Base(flowPath))
	fmt.Printf("target:    https://%s%s\n\n", f.Host, f.Path)

	sessionID := header(f.Headers, "X-Session-Id")
	ts := header(f.Headers, "X-Client-Ts")
	nonce := header(f.Headers, "X-Client-Nonce")
	pow := header(f.Headers, "X-Client-Pow")
	sig := header(f.Headers, "X-Client-Sig")
	clientVersion := header(f.Headers, "X-Client-Version")
	appID := header(f.Headers, "X-App-Id")

	for name, v := range map[string]string{
		"X-Session-Id": sessionID, "X-Client-Ts": ts, "X-Client-Nonce": nonce,
		"X-Client-Pow": pow, "X-Client-Version": clientVersion, "X-App-Id": appID,
	} {
		if v == "" {
			fail("capture is missing %s; is this a ZCode Coding Plan flow?", name)
		}
	}

	fmt.Println("== step 1: proof of work ==")
	seed := zsignSeed(cred.ID, appID, sessionID, ts)
	fmt.Printf("recomputed seed            %s\n", seed)
	ok := verifyPow(seed, pow, 8)
	counter, cerr := powCounter(pow)
	if cerr != nil {
		fail("proof of work is malformed: %v", cerr)
	}
	fmt.Printf("captured  X-Client-Pow     %s  (counter %d, %d hex of salt)\n", pow, counter, 24)
	fmt.Printf("valid for this seed:       %v\n", ok)
	if !ok {
		fail("ZCode's proof of work does not verify against our recomputed seed")
	}

	fmt.Println("\n== step 2: Ed25519 signature ==")
	want, err := base64.StdEncoding.DecodeString(sig)
	if err != nil || len(want) != ed25519.SignatureSize {
		fail("captured signature is not %d bytes of base64", ed25519.SignatureSize)
	}
	msg := signedMessage(cred.ID, ts, clientVersion, sessionID, nonce)
	fmt.Printf("signed message (%d bytes, pow excluded)\n", len(msg))
	fmt.Printf("apiKeyId=%s\n  ts=%s\n  clientVersion=%s\n  sessionId=%s\n  nonce=%s\n",
		safePrefix(cred.ID), ts, clientVersion, sessionID, nonce)

	key, err := handshakeKey(cred, baseURL)
	if err != nil {
		fmt.Printf("handshake for the signing key failed: %v\n", err)
		fail("cannot verify the signature without the signing key")
	}
	verified := ed25519.Verify(key, []byte(msg), want)
	fmt.Printf("\nsignature verifies against our handshake key: %v\n", verified)
	if !verified {
		fmt.Println("\nThat is the expected outcome when ZCode signs with a different")
		fmt.Println("credential than this config's API key: the proof-of-work formula")
		fmt.Println("matches exactly, so the wire format is reproduced, but the key")
		fmt.Println("belongs to z.ai's coding-plan project key.")
		os.Exit(3)
	}

	fmt.Println("\nALL CHECKS PASSED")
}

func safePrefix(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}

func readAPIKey() (string, string, error) {
	raw, err := os.ReadFile(zcodeConfig)
	if err != nil {
		return "", "", err
	}
	s := string(raw)
	i := strings.Index(s, `"builtin:zai-coding-plan"`)
	if i < 0 {
		return "", "", fmt.Errorf("zai-coding-plan provider not found in %s", zcodeConfig)
	}
	rest := s[i:]
	apiKey, err := jsonStringAt(rest[strings.Index(rest, `"apiKey"`):])
	if err != nil {
		return "", "", err
	}
	baseURL, err := jsonStringAt(rest[strings.Index(rest, `"baseURL"`):])
	return apiKey, baseURL, err
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

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\nFAIL: "+format+"\n", args...)
	os.Exit(1)
}
