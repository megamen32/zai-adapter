# zai-attest

Reproduce **exactly what separates a ZCode request from an ordinary z.ai client
request** — the Coding Plan client attestation plus the client-identity
telemetry — behind a local pass-through.

There is deliberately no request translation. An earlier version carried an
OpenAI↔Anthropic shim; it was removed because that work belongs to the many
tools that already do it, and it hid the only thing this project exists to
show. Everything is forwarded byte for byte.

```sh
export ZAI_API_KEY='<id>.<secret>'
zai-attest -listen 127.0.0.1:18790 &

# any Anthropic-shaped client
export ANTHROPIC_BASE_URL=http://127.0.0.1:18790
```

## What the attestation actually is

Derived from the ZCode 0.16.9 client bundle and confirmed against a live
capture. See [`ATTESTATION.md`](ATTESTATION.md) for the full header-by-header
diff and [`ab_report.py`](ab_report.py) to regenerate it.

**Signed** — Ed25519 over `apiKeyId \n ts \n clientVersion \n sessionId \n nonce`
(123 bytes in the captured run). The private key never touches disk: the server
returns it sealed with AES-256-GCM under a key derived from the API key secret.

**Proof of work, deliberately *not* signed** — `X-Client-Pow` is
`salt(12 random bytes hex) ‖ counter(8 hex)` where
`SHA-256(seed ‖ candidate)` has 8 leading zero bits and
`seed = hex(SHA-256(apiKeyId ‖ "zcode" ‖ sessionId ‖ ts))[:32]`. ZCode's own
captured proofs solve at counters 302 and 554 — consistent with 1/256.

**Telemetry, not signed** — `X-Zcode-Agent`, `X-Os-Version`, `X-Platform`,
`X-Client-Language`, `X-Client-Timezone`, `X-Release-Channel`, `X-Title`,
`X-Os-Category`, `Http-Referer`, three independent correlation ids
(`X-Request-Id`, `X-Query-Id`, `X-Zcode-Trace-Id`), `X-Zcode-Session-Type`, and
`metadata.user_id` in the body carrying `device_id` plus the `session_id`.

**Credentials** — ZCode sends two. `X-Api-Key` is the same project key this tool
is configured with, and `Authorization: Bearer <56 chars>` is a *third*
credential, the OAuth access token, whose payload is encrypted at rest in
ZCode's credential store.

## Verify it

```sh
go run ./cmd/zaicheck -capture ../zai-capture-probe/out/ab
```

Reads a real ZCode capture, recomputes the seed from the captured timestamp and
session, re-verifies ZCode's own proof of work, then fetches the signing key via
our own handshake and checks ZCode's signature. Current result:

```
valid for this seed:                 true      # PoW formula reproduced exactly
signature verifies against our key:  false     # ZCode signs with another credential
```

That second line is not a bug in `zsign`; it is the finding. See
`ATTESTATION.md`.

## Commands

| command | purpose |
| --- | --- |
| `cmd/zai-attest` | the pass-through that attaches attestation and telemetry |
| `cmd/zaicheck` | verifies a capture against the shipped `zsign` package |
| `cmd/zailive` | signs a request and calls the Coding Plan endpoint |
| `cmd/zaidiff` | diffs a signed request against an unsigned one |

## Capture tooling

- `zmitm/` — in the sibling repo `zai-capture-probe`: a TLS-terminating proxy that
  routes from the ClientHello SNI, needed because ZCode's model client ignores
  `HTTPS_PROXY`.
- `capture-ab.sh` — captures an ordinary client request and a real ZCode turn
  through the same proxy.
- `ab_report.py` — emits a HAR and the attestation/telemetry breakdown.

## Caution

`X-Client-Pow` and `X-Client-Sig` exist to bind plan quota to the sanctioned
client. Measured behaviour, though, is that the endpoint serves **unsigned**
requests identically: `cmd/zaidiff` gets the same `200` and the same `usage` with
and without the attestation, and the only server-side rejection signal is `401`
with `VERIFY_SIGNATURE_INVALID`. So the attestation is wire parity, not a
credential gate — which is worth knowing before treating it as load-bearing.