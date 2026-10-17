package zsign

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestTwoHandshakes(t *testing.T) {
	key, _, err := readKey()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	fp := func(k []byte) string {
		h := sha256.Sum256(k[len(k)-32:])
		return hex.EncodeToString(h[:])[:16]
	}
	for i := 0; i < 2; i++ {
		cred, err := SplitCredential(key, "https://api.z.ai/api/anthropic")
		if err != nil {
			t.Fatal(err)
		}
		k, err := Handshake(ctx, cred, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("handshake %d pubkey fingerprint = %s", i+1, fp(k))
	}
}
