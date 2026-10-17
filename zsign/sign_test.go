package zsign

import (
	"strings"
	"testing"
)

// The expected values below come from an independently captured live ZCode
// 0.16.9 turn; zaicheck verifies them against capture files at runtime.

func TestSeedMatchesCaptured(t *testing.T) {
	got := Seed("adcb2aa5db874c1b8d11ee08d0e8ac04", "zcode",
		"eec26b64-0d02-4c41-80c3-bd516ca84663", "1792269337092")
	want := "6958bb0b56c917278394758b5e11c228"
	if got != want {
		t.Fatalf("seed mismatch: got %q, want %q", got, want)
	}
}

func TestVerifyPowCapturedCounter(t *testing.T) {
	seed := Seed("adcb2aa5db874c1b8d11ee08d0e8ac04", "zcode",
		"eec26b64-0d02-4c41-80c3-bd516ca84663", "1792269337092")
	// ZCode's own proof: 24 hex salt + counter 0x22a (554), 8 leading zero bits.
	pow := "38c6d96b58184d7b7081f6050000022a"
	if !VerifyPow(seed, pow, 8) {
		t.Fatal("captured ZCode proof of work does not verify")
	}
	// A tampered proof must not verify.
	if VerifyPow(seed, strings.Replace(pow, "0", "1", 4), 8) {
		t.Fatal("tampered proof of work verified")
	}
}

func TestSignedMessageLayout(t *testing.T) {
	got := SignedMessage("adcb2aa5db874c1b8d11ee08d0e8ac04", "1792269337092", "0.16.9",
		"eec26b64-0d02-4c41-80c3-bd516ca84663", "bf5d03d4bcc6d26db9ff999f2f541712")
	// apiKeyId \n ts \n clientVersion \n sessionId \n nonce:
	// 32 + 1 + 13 + 1 + 5 + 1 + 36 + 1 + 32 = 122 runes.
	want := "adcb2aa5db874c1b8d11ee08d0e8ac04\n1792269337092\n0.16.9\n" +
		"eec26b64-0d02-4c41-80c3-bd516ca84663\nbf5d03d4bcc6d26db9ff999f2f541712"
	if got != want {
		t.Fatalf("signed message mismatch:\n got %q\nwant %q", got, want)
	}
}

func TestSplitCredentialShape(t *testing.T) {
	c, err := SplitCredential("aaaa1111bbbb2222.c3VwZXJzZWNyZXQ=", "https://api.z.ai/api/anthropic")
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if c.ID != "aaaa1111bbbb2222" || string(c.Secret) != "c3VwZXJzZWNyZXQ=" {
		t.Fatalf("unexpected credential id/secret: %q / %q", c.ID, string(c.Secret))
	}
	if c.BaseURL != "https://api.z.ai/api/anthropic" {
		t.Fatalf("unexpected base url %q", c.BaseURL)
	}
}
