# zai-adapter

Put a z.ai **Coding Plan** endpoint behind a local URL, so any project can use it
by pointing its base URL at this process.

```sh
export ZAI_API_KEY='<id>.<secret>'          # z.ai API key
zai-adapter -listen 127.0.0.1:18790 &

# in any project:
export ANTHROPIC_BASE_URL=http://127.0.0.1:18790
export OPENAI_BASE_URL=http://127.0.0.1:18790/v1
```

## What it is

One port, both wire shapes:

| route | shape |
| --- | --- |
| `POST /v1/messages` | Anthropic Messages, forwarded unchanged |
| `POST /v1/chat/completions` | OpenAI chat completions, translated to Anthropic upstream and back |
| `GET /v1/models` | one model, so clients that probe it do not fail |
| `GET /healthz` | liveness |

The translation is not a convenience. The Coding Plan endpoint
(`zcode.z.ai/api/v1/ultra-zai/anthropic/v1/messages`) only serves the Anthropic
Messages shape — `chat/completions` and the path without `/anthropic` both 404 —
so an OpenAI-speaking tool can only be served by translating.

Transport is [site-mimic](https://github.com/megamen32/site-mimic), so outgoing
requests present a browser-shaped TLS ClientHello (`chrome_exact` by default)
instead of the trivially recognisable Go one.

## Flags

```
-listen           127.0.0.1:18790
-api-key          $ZAI_API_KEY
-upstream         https://zcode.z.ai/api/v1/ultra-zai/anthropic
-client-version   0.16.9        # part of the signed message; keep in sync with ZCode
-model            GLM-5.3
-max-tokens       128000        # used when the caller omits one
-sign             true          # attach the Coding Plan client attestation
-tls-client-hello chrome_exact
-log-level        info
```

## zsign: the client attestation

`-sign` attaches the headers ZCode attaches, so the adapter's traffic is shaped
like ZCode's rather than like a generic client:

| header | value |
| --- | --- |
| `X-Client-Ts` | unix milliseconds |
| `X-Client-Version` | the `-client-version` value |
| `X-Client-Nonce` | 16 random bytes, hex |
| `X-Client-Pow` | `salt(12 bytes hex) ‖ counter(8 hex)` where `SHA-256(seed ‖ candidate)` has 8 leading zero bits |
| `X-Client-Sig` | base64 Ed25519 over `apiKeyId \n ts \n clientVersion \n sessionId \n nonce` |
| `X-App-Id` | `zcode` |
| `X-Session-Id` | per-session UUID |

`seed = hex(SHA-256(apiKeyId \n "zcode" \n sessionId \n ts))[:32]`.

The Ed25519 private key is never stored. The adapter asks
`POST /api/paas/c1f3a7e2/v2/client` for it, presenting
`HMAC-SHA256(HKDF(apiKeySecret, salt="WD_CLIENT_SIGN_KDF_SALT", info="getSignKey_hmac"), "get_sign_key\n<apiKeyId>\n<ts>\n<nonce>")`.
The server answers with an AES-256-GCM blob whose key is
`HKDF(apiKeySecret, salt="WD_CLIENT_SIGN_KDF_SALT", info="ed25519_priv")` and whose
additional data is `apiKeyId`; the adapter unwraps it in memory and zeroes it on
close. The handshake runs once per process.

Note the proof of work is **not** covered by the signature, matching the client.

## Three things worth knowing before you rely on this

**1. The server does not enforce or confirm the attestation.** `cmd/zaidiff` sends
the same request signed and unsigned and diffs the responses: both get `200`,
identical `usage`, and no distinguishing header. The only server-side rejection
signal is `401` with reason `VERIFY_SIGNATURE_INVALID` or `VERIFY_APIKEY_EXPIRED`.
So `-sign` is wire-parity, not a credential — and a signing failure degrades to
an unsigned request rather than failing the call.

**2. The signature alone will not reproduce ZCode's exact bytes.** ZCode's
captured signature does **not** verify under the API key in
`~/.zcode/v2/config.json`, and no plausible message layout fixes it
(`cmd/zaicheck` brute-forces them). ZCode signs with the separate coding-plan
project key that its credential store holds encrypted
(`account-provider:coding-plan:…:api-key`). This adapter therefore signs with
whichever key you configure; it is not byte-identical to ZCode.

**3. The ordinary pay-as-you-go API is not an alternative here.** For this
account `api.z.ai/api/paas/v4/chat/completions` answers
`429 Insufficient balance or no resource package`. The Coding Plan endpoint is
the working path, which is the point of the adapter.

## Verify it yourself

```sh
go build ./cmd/zaicheck && ./zaicheck   # PoW + signature self-check
go build ./cmd/zailive  && ./zailive    # signs and calls the endpoint
go build ./cmd/zaidiff  && ./zaidiff    # signed vs unsigned response diff
```

`zaicheck` and the others read the API key from `~/.zcode/v2/config.json` and
never print it.

## Caution

This re-derives z.ai's client attestation, which exists to bind plan quota to the
sanctioned client. Using it outside ZCode is a terms-of-service decision with real
account risk, not a technical detail. It is implemented because that risk was
accepted explicitly. The alternative that carries no such risk is to let ZCode
make the request — which is what OmniRoute's `zcode` executor does — and is
blocked here only by ZCode hardcoding a single shared app-server socket path.

Related analysis of what the Coding Plan numbers actually mean:
[`zai-capture-probe/FINDINGS.md`](../zai-capture-probe/FINDINGS.md).