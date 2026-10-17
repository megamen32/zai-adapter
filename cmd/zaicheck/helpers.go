package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/megamen32/zai-adapter/zsign"
)

// The helpers below deliberately call zsign rather than reimplementing it, so
// this command is a real check of the shipped package and not a second copy of
// the algorithm.

func findZcodeFlow(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		f, err := readFlow(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		if f.Host == "zcode.z.ai" && strings.Contains(f.Path, "/anthropic/v1/messages") {
			return filepath.Join(dir, n), nil
		}
	}
	return "", fmt.Errorf("no Coding Plan Messages flow found in %s", dir)
}

func readFlow(path string) (*flow, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f flow
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

func splitCredential(apiKey, baseURL string) (*zsign.Credential, error) {
	return zsign.SplitCredential(apiKey, baseURL)
}

func zsignSeed(apiKeyID, appID, sessionID, ts string) string {
	return zsign.Seed(apiKeyID, appID, sessionID, ts)
}

func verifyPow(seed, pow string, bits int) bool { return zsign.VerifyPow(seed, pow, bits) }

func powCounter(pow string) (uint64, error) {
	if len(pow) != 32 {
		return 0, fmt.Errorf("expected 32 hex chars, got %d", len(pow))
	}
	n, err := strconv.ParseUint(pow[24:], 16, 32)
	if err != nil {
		return 0, fmt.Errorf("counter: %w", err)
	}
	return n, nil
}

func signedMessage(apiKeyID, ts, clientVersion, sessionID, nonce string) string {
	return zsign.SignedMessage(apiKeyID, ts, clientVersion, sessionID, nonce)
}

// handshakeKey asks the server for the sealed signing key and unwraps it, the
// same path the adapter uses at runtime.
func handshakeKey(cred *zsign.Credential, baseURL string) (ed25519.PublicKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	key, err := zsign.Handshake(ctx, cred, nil)
	if err != nil {
		return nil, err
	}
	return key.Public().(ed25519.PublicKey), nil
}
