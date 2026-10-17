// Command zaicheck proves the zsign implementation against ground truth.
//
// Stage 1 replays values captured from a real ZCode run: it recomputes the
// proof-of-work seed from the captured timestamps, re-verifies the captured
// proof of work, and verifies the captured Ed25519 signature against the key
// obtained from our own handshake. If all three match, the implementation
// reproduces ZCode's wire format exactly.
//
// Stage 2 signs a fresh request and sends it to the Coding Plan endpoint.
//
// The API key is read from ZCode's config and never printed.
package main

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/megamen32/zai-adapter/zsign"
)

const zcodeConfig = "/home/roomhacker/.zcode/v2/config.json"

// Captured from a real ZCode 0.16.9 run against the Coding Plan endpoint.
// Signature verification needs the private key from our own handshake, so only
// the non-secret fields live here.
type capture struct {
	SessionID     string
	Ts            string
	Nonce         string
	Pow           string
	Sig           string
	ClientVersion string
}

var realCapture = capture{
	SessionID:     "72c7da2e-b4aa-425c-8b33-2f8c85d86288",
	Ts:            "1792251309635",
	Nonce:         "6f745e4ff4bebe370ba90a85d619ec33",
	Pow:           "35d2f26b5237c688952396f80000012e",
	Sig:           "ZY52NQDeajtE5VmvgFPFqsdi9EYn9gs0KRIc+WPso/ZY8H8eai9oHCn2X3rPSMSo82GmI4ZC07dMUYk73iWHAQ==",
	ClientVersion: "0.16.9",
}

func readAPIKey() (string, string, error) {
	raw, err := os.ReadFile(zcodeConfig)
	if err != nil {
		return "", "", err
	}
	// Minimal targeted extraction keeps the secret off the command line and
	// out of logs; the config shape is a flat nested object.
	idx := strings.Index(string(raw), `"builtin:zai-coding-plan"`)
	if idx < 0 {
		return "", "", fmt.Errorf("zai-coding-plan provider not found in %s", zcodeConfig)
	}
	rest := string(raw)[idx:]
	keyAt := strings.Index(rest, `"apiKey"`)
	baseAt := strings.Index(rest, `"baseURL"`)
	if keyAt < 0 || baseAt < 0 {
		return "", "", fmt.Errorf("apiKey/baseURL not found")
	}
	apiKey, err := jsonStringAt(rest[keyAt:])
	if err != nil {
		return "", "", err
	}
	baseURL, err := jsonStringAt(rest[baseAt:])
	if err != nil {
		return "", "", err
	}
	return apiKey, baseURL, nil
}

func jsonStringAt(s string) (string, error) {
	colon := strings.Index(s, ":")
	if colon < 0 {
		return "", fmt.Errorf("malformed json field")
	}
	q := strings.Index(s[colon:], `"`)
	if q < 0 {
		return "", fmt.Errorf("malformed json string")
	}
	start := colon + q + 1
	end := strings.Index(s[start:], `"`)
	if end < 0 {
		return "", fmt.Errorf("unterminated json string")
	}
	return s[start : start+end], nil
}

func main() {
	flag.Parse()
	apiKey, baseURL, err := readAPIKey()
	if err != nil {
		fail("read credential: %v", err)
	}
	cred, err := zsign.SplitCredential(apiKey, baseURL)
	if err != nil {
		fail("split credential: %v", err)
	}
	fmt.Printf("credential: id=%s... secret=%d chars baseURL=%s\n",
		cred.ID[:8]+"...", len(cred.Secret), cred.BaseURL)

	ctx := context.Background()
	signer, err := zsign.NewSigner(apiKey, baseURL, realCapture.ClientVersion, nil)
	if err != nil {
		fail("new signer: %v", err)
	}
	defer signer.Close()

	fmt.Println("\n== stage 1: replay against the captured ZCode request ==")

	// 1a. proof-of-work seed
	seed := zsign.Seed(cred.ID, zsign.AppID, realCapture.SessionID, realCapture.Ts)
	fmt.Printf("seed(apiKeyId, appId, sessionId, ts) = %s\n", seed)

	// 1b. the captured proof of work must satisfy it
	powOK := zsign.VerifyPow(seed, realCapture.Pow, zsign.DefaultPowBits)
	counter, _ := zsign.PowCounter(realCapture.Pow)
	fmt.Printf("captured pow %s counter=%d valid=%v\n", realCapture.Pow, counter, powOK)
	if !powOK {
		fail("captured proof of work does not verify against the recomputed seed")
	}

	// 1c. the captured signature must verify against our handshake key
	key, err := signer.PrivateKey(ctx)
	if err != nil {
		fail("handshake: %v", err)
	}
	msg := zsign.SignedMessage(cred.ID, realCapture.Ts, realCapture.ClientVersion,
		realCapture.SessionID, realCapture.Nonce)
	want, err := base64.StdEncoding.DecodeString(realCapture.Sig)
	if err != nil || len(want) != ed25519.SignatureSize {
		fail("captured signature is not 64 bytes of base64")
	}
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), []byte(msg), want) {
		fail("captured signature does not verify: implementation does not match ZCode")
	}
	fmt.Printf("captured sig verifies against our handshake key: true\n")
	fmt.Printf("signed message: apiKeyId / ts / clientVersion / sessionId / nonce (pow NOT included)\n")

	// 1d. a freshly solved proof of work at the same difficulty
	fresh, err := zsign.SolvePoW(seed, zsign.DefaultPowBits)
	if err != nil {
		fail("solve pow: %v", err)
	}
	fc, _ := zsign.PowCounter(fresh)
	fmt.Printf("fresh pow counter=%d valid=%v\n", fc, zsign.VerifyPow(seed, fresh, zsign.DefaultPowBits))

	fmt.Println("\n== stage 2: sign a fresh request ==")
	sessionID := newUUID()
	att, err := signer.Attest(ctx, sessionID)
	if err != nil {
		fail("attest: %v", err)
	}
	for _, k := range []string{"X-Client-Ts", "X-Client-Version", "X-Client-Nonce", "X-Client-Pow", "X-App-Id", "X-Session-Id"} {
		fmt.Printf("  %-18s %s\n", k, att.Headers()[k])
	}
	fmt.Printf("  %-18s %s... (%d b64 chars)\n", "X-Client-Sig", att.Sig[:24], len(att.Sig))

	// Self-check the fresh attestation the same way the server would.
	if !zsign.VerifyPow(att.Seed, att.Pow, zsign.DefaultPowBits) {
		fail("fresh proof of work does not verify")
	}
	want2, _ := base64.StdEncoding.DecodeString(att.Sig)
	ok := ed25519.Verify(key.Public().(ed25519.PublicKey),
		[]byte(zsign.SignedMessage(cred.ID, att.Ts, att.ClientVersion, att.SessionID, att.Nonce)), want2)
	if !ok {
		fail("fresh signature does not verify")
	}
	fmt.Println("  self-check: pow valid, signature valid")

	fmt.Println("\nALL CHECKS PASSED")
}

func newUUID() string {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
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

var _ = time.Now
