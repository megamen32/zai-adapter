// Package zsign implements z.ai's Coding Plan client attestation.
//
// ZCode marks Coding Plan traffic with a per-request Ed25519 signature plus a
// small proof of work. The private key is never stored by the client: the
// server hands back an AES-GCM blob sealed with a key derived from the API key
// secret, and the client unwraps it in memory.
//
// This is a re-implementation of a vendor client-attestation scheme. It binds
// plan quota to the sanctioned client, and re-deriving it outside that client is
// a terms-of-service decision, not a technical one. See README.md.
package zsign

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Wire constants, taken from the ZCode 0.16.9 client bundle.
const (
	// KDFSalt is the HKDF salt both derived keys use.
	KDFSalt = "WD_CLIENT_SIGN_KDF_SALT"

	infoPriv   = "ed25519_priv"
	infoHMAC   = "getSignKey_hmac"
	handshakeA = "get_sign_key"
	handshakeP = "/api/paas/c1f3a7e2/v2/client"

	// AppID is the app id ZCode presents and signs.
	AppID = "zcode"

	// DefaultPowBits is the proof-of-work difficulty the client uses.
	DefaultPowBits = 8

	nonceLen  = 16
	powSaltLn = 12
	powMax    = uint64(1) << 32
)

// ErrNoSeparator reports an API key without the single "." separator that
// splits the public id from the secret.
var ErrNoSeparator = errors.New("zsign: api key must contain exactly one '.' separator")

// Credential is a z.ai API key split into its two halves.
type Credential struct {
	ID      string // public half, also the AES-GCM additional data
	Secret  string // private half, the HKDF input keying material
	Full    string // the key exactly as configured
	BaseURL string
}

// SplitCredential splits "id.secret" and binds it to a base URL.
func SplitCredential(apiKey, baseURL string) (*Credential, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	i := strings.Index(apiKey, ".")
	if i <= 0 || i != strings.LastIndex(apiKey, ".") || strings.TrimSpace(apiKey[i+1:]) == "" {
		return nil, ErrNoSeparator
	}
	return &Credential{
		ID:      apiKey[:i],
		Secret:  apiKey[i+1:],
		Full:    apiKey,
		BaseURL: baseURL,
	}, nil
}

// Origin returns scheme://host for a base URL.
func Origin(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("zsign: invalid base URL %q", baseURL)
	}
	return u.Scheme + "://" + u.Host, nil
}

// deriveBytes is HKDF-SHA256(secret, salt=KDFSalt, info) at 32 bytes.
func deriveBytes(secret, info string) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, []byte(secret), []byte(KDFSalt), info, 32)
	if err != nil {
		return nil, fmt.Errorf("zsign: hkdf: %w", err)
	}
	return key, nil
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// NewNonce returns the 16-byte hex nonce used by both the handshake and each
// signed request.
func NewNonce() (string, error) { return randomHex(nonceLen) }

// HandshakeSignature is the HMAC presented when asking for the signing key.
func HandshakeSignature(c *Credential, ts, nonce string) (string, error) {
	key, err := deriveBytes(c.Secret, infoHMAC)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(handshakeA + "\n" + c.ID + "\n" + ts + "\n" + nonce))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

type handshakeEnvelope struct {
	Code *int   `json:"code"`
	Msg  string `json:"msg"`
	Data *struct {
		PrivateCipher string `json:"privateCipher"`
	} `json:"data"`
}

// Handshake asks the server for the AES-GCM sealed Ed25519 private key. The
// transport is supplied by the caller so the adapter can use a browser-faithful
// TLS profile instead of the Go default.
func Handshake(ctx context.Context, c *Credential, rt http.RoundTripper) (ed25519.PrivateKey, error) {
	if rt == nil {
		rt = http.DefaultTransport
	}
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	nonce, err := NewNonce()
	if err != nil {
		return nil, err
	}
	sig, err := HandshakeSignature(c, ts, nonce)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]string{
		"apiKey": c.Full,
		"nonce":  nonce,
		"sig":    sig,
		"ts":     ts,
	})
	if err != nil {
		return nil, err
	}
	org, err := Origin(c.BaseURL)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, org+handshakeP, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", c.Full)
	req.Header.Set("Content-Type", "application/json")

	resp, err := rt.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("zsign: handshake: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("zsign: handshake HTTP %d: %s", resp.StatusCode, truncate(raw, 200))
	}
	var env handshakeEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("zsign: handshake json: %w", err)
	}
	if env.Code != nil && *env.Code != 0 && *env.Code != 200 {
		return nil, fmt.Errorf("zsign: handshake rejected: code=%d msg=%s", *env.Code, env.Msg)
	}
	if env.Data == nil || env.Data.PrivateCipher == "" {
		return nil, errors.New("zsign: handshake response omitted privateCipher")
	}
	return DecryptSigningKey(c, env.Data.PrivateCipher)
}

// DecryptSigningKey unwraps the AES-GCM sealed PKCS#8 Ed25519 key.
func DecryptSigningKey(c *Credential, cipherText string) (ed25519.PrivateKey, error) {
	blob, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, fmt.Errorf("zsign: privateCipher base64: %w", err)
	}
	if len(blob) <= 12+16 {
		return nil, errors.New("zsign: privateCipher is too short")
	}
	key, err := deriveBytes(c.Secret, infoPriv)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, blob[:12], blob[12:], []byte(c.ID))
	if err != nil {
		return nil, fmt.Errorf("zsign: privateCipher decrypt: %w", err)
	}
	defer zero(plain)
	if len(plain) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("zsign: unwrapped key is %d bytes, want %d", len(plain), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(bytes.Clone(plain)), nil
}

// Seed is the proof-of-work seed: the first 16 bytes of
// SHA-256(apiKeyId \n appId \n sessionId \n ts), hex encoded.
func Seed(apiKeyID, appID, sessionID, ts string) string {
	sum := sha256.Sum256([]byte(apiKeyID + "\n" + appID + "\n" + sessionID + "\n" + ts))
	return hex.EncodeToString(sum[:])[:32]
}

// PowCounter is the counter part of a proof-of-work candidate.
func PowCounter(pow string) (uint64, error) {
	if len(pow) != 32 {
		return 0, fmt.Errorf("zsign: proof of work must be 32 hex chars, got %d", len(pow))
	}
	n, err := strconv.ParseUint(pow[24:], 16, 32)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// VerifyPow reports whether pow is a valid solution for seed at bitsWanted.
func VerifyPow(seed, pow string, bitsWanted int) bool {
	sum := sha256.Sum256([]byte(seed + "\n" + pow))
	return HasLeadingZeroBits(sum[:], bitsWanted)
}

// SolvePoW finds a candidate whose SHA-256(seed \n candidate) has bitsWanted
// leading zero bits. Candidate = salt(12 random bytes as hex) || counter(8 hex).
func SolvePoW(seed string, bitsWanted int) (string, error) {
	if bitsWanted < 0 || bitsWanted > 32 {
		return "", fmt.Errorf("zsign: powBits must be between 0 and 32, got %d", bitsWanted)
	}
	salt, err := randomHex(powSaltLn)
	if err != nil {
		return "", err
	}
	for counter := uint32(0); uint64(counter) < powMax; counter++ {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], counter)
		candidate := salt + hex.EncodeToString(b[:])
		sum := sha256.Sum256([]byte(seed + "\n" + candidate))
		if HasLeadingZeroBits(sum[:], bitsWanted) {
			return candidate, nil
		}
	}
	return "", errors.New("zsign: proof of work exhausted")
}

// HasLeadingZeroBits reports whether b begins with at least n zero bits.
func HasLeadingZeroBits(b []byte, n int) bool {
	if n < 0 || n > len(b)*8 {
		return false
	}
	full := n / 8
	for i := 0; i < full; i++ {
		if b[i] != 0 {
			return false
		}
	}
	rem := n % 8
	if rem == 0 {
		return true
	}
	mask := byte(0xFF) << (8 - rem)
	return b[full]&mask == 0
}

// LeadingZeroBitsCount reports how many leading zero bits a digest has.
func LeadingZeroBitsCount(b []byte) int {
	for i, v := range b {
		if v != 0 {
			return i*8 + bits.LeadingZeros8(v)
		}
	}
	return len(b) * 8
}

// SignedMessage is the exact string the Ed25519 signature covers. The proof of
// work is deliberately not part of it.
func SignedMessage(apiKeyID, ts, clientVersion, sessionID, nonce string) string {
	return strings.Join([]string{apiKeyID, ts, clientVersion, sessionID, nonce}, "\n")
}

// Sign produces the base64 Ed25519 signature for one request.
func Sign(key ed25519.PrivateKey, apiKeyID, ts, clientVersion, sessionID, nonce string) string {
	return base64.StdEncoding.EncodeToString(
		ed25519.Sign(key, []byte(SignedMessage(apiKeyID, ts, clientVersion, sessionID, nonce))))
}

// Attestation carries the per-request headers ZCode attaches.
type Attestation struct {
	Ts            string
	ClientVersion string
	SessionID     string
	Nonce         string
	Pow           string
	Sig           string
	AppID         string
	Seed          string
}

// Headers returns the wire headers.
func (a *Attestation) Headers() map[string]string {
	return map[string]string{
		"X-Client-Ts":      a.Ts,
		"X-Client-Version": a.ClientVersion,
		"X-Client-Sig":     a.Sig,
		"X-Session-Id":     a.SessionID,
		"X-Client-Nonce":   a.Nonce,
		"X-App-Id":         a.AppID,
		"X-Client-Pow":     a.Pow,
	}
}

// Signer caches the unwrapped signing key so the handshake runs once.
type Signer struct {
	cred          *Credential
	clientVersion string
	rt            http.RoundTripper

	mu       sync.Mutex
	key      ed25519.PrivateKey
	inFlight bool
}

// NewSigner builds a signer for one credential. clientVersion is part of the
// signed message, so it must match what is sent in X-Client-Version.
func NewSigner(apiKey, baseURL, clientVersion string, rt http.RoundTripper) (*Signer, error) {
	cred, err := SplitCredential(apiKey, baseURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(clientVersion) == "" {
		clientVersion = "0.16.9"
	}
	return &Signer{cred: cred, clientVersion: clientVersion, rt: rt}, nil
}

// Credential exposes the parsed credential.
func (s *Signer) Credential() *Credential { return s.cred }

// ClientVersion reports the version placed in X-Client-Version.
func (s *Signer) ClientVersion() string { return s.clientVersion }

// Close drops the cached private key from memory.
func (s *Signer) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key != nil {
		zero(s.key)
		s.key = nil
	}
}

// PrivateKey returns the cached signing key, performing the handshake once.
func (s *Signer) PrivateKey(ctx context.Context) (ed25519.PrivateKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key != nil {
		return s.key, nil
	}
	if s.inFlight {
		return nil, errors.New("zsign: handshake already in flight")
	}
	s.inFlight = true
	key, err := Handshake(ctx, s.cred, s.rt)
	s.inFlight = false
	if err != nil {
		return nil, err
	}
	s.key = key
	return key, nil
}

// Attest signs one request. sessionID must also be sent as X-Session-Id.
func (s *Signer) Attest(ctx context.Context, sessionID string) (*Attestation, error) {
	if strings.TrimSpace(sessionID) == "" {
		return nil, errors.New("zsign: session id is required")
	}
	key, err := s.PrivateKey(ctx)
	if err != nil {
		return nil, err
	}
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	nonce, err := NewNonce()
	if err != nil {
		return nil, err
	}
	seed := Seed(s.cred.ID, AppID, sessionID, ts)
	pow, err := SolvePoW(seed, DefaultPowBits)
	if err != nil {
		return nil, err
	}
	return &Attestation{
		Ts:            ts,
		ClientVersion: s.clientVersion,
		SessionID:     sessionID,
		Nonce:         nonce,
		Pow:           pow,
		Sig:           Sign(key, s.cred.ID, ts, s.clientVersion, sessionID, nonce),
		AppID:         AppID,
		Seed:          seed,
	}, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
