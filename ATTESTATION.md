# What separates a ZCode request from an ordinary z.ai request

Measured 2026-10-17 with one real ZCode 0.16.9 turn and one ordinary
API-key client, both through the same capture proxy so they are directly
comparable. Regenerate with:

```sh
./capture-ab.sh ab
python3 ab_report.py ../zai-capture-probe/out/ab --har zcode-ab.har
```

Artifacts: [`zcode-ab.har`](zcode-ab.har) and the raw flows in
`../zai-capture-probe/out/ab/`.

## The three requests, same model

| # | side | target | status | body |
| --- | --- | --- | --- | --- |
| 1 | ordinary, OpenAI shape | `api.z.ai/api/paas/v4/chat/completions` | **429** | 134 B |
| 2 | ordinary, Anthropic shape | `api.z.ai/api/anthropic/v1/messages` | 200 | 134 B |
| 3 | ZCode | `zcode.z.ai/api/v1/ultra-zai/anthropic/v1/messages` | 200 | 323 631 B |

Request 1 is the concrete reason this adapter exists: the pay-as-you-go
endpoint answers `429 Insufficient balance or no resource package` for this
account. The Coding Plan endpoint is the working path.

## Headers ZCode sends that an ordinary client does not

### Attestation — 7 headers

```
X-App-Id:          zcode
X-Client-Ts:       1792269337092
X-Client-Version:  0.16.9
X-Session-Id:      eec26b64-0d02-4c41-80c3-bd516ca84663
X-Client-Nonce:    bf5d03d4bcc6d26db9ff999f2f541712
X-Client-Pow:      38c6d96b58184d7b7081f6050000022a
X-Client-Sig:      gMSEbkBcgGYTvCExAl1f/z1UCseWAWVFQpS3+d…  (Ed25519, 64 B)
```

The signature covers `apiKeyId ‖ ts ‖ clientVersion ‖ sessionId ‖ nonce`.
`X-Client-Pow` is **not** covered — it is a separate cost-burn, `salt ‖ counter`
where `SHA-256(seed ‖ candidate)` has 8 leading zero bits and
`seed = hex(SHA-256(apiKeyId ‖ "zcode" ‖ sessionId ‖ ts))[:32]`.

### Telemetry — 14 headers, none of them signed

```
X-Zcode-Agent: glm              X-Os-Category: linux
X-Title: Z Code@cli             X-Os-Version: 6.8.0-138-generic
X-Platform: linux-x64           X-Client-Language: ru-RU
X-Release-Channel: production   X-Client-Timezone: Europe/Moscow
Http-Referer: https://zcode.z.ai
X-Zcode-App-Version: 0.16.9     X-Zcode-Session-Type: main
X-Request-Id:   c571aaaa-8b49-4301-9af2-347d979e5d49
X-Query-Id:     d205221a-b22a-4e20-94e8-516721458d8a
X-Zcode-Trace-Id: 1a9d5966-0d71-4a84-8266-e7c90f2f4098
```

Three independent correlation ids, one per scope: request, query, and an
end-to-end trace. `X-Os-Version` is read from `uname`, so it identifies the host
kernel.

### Body telemetry

`metadata.user_id` is not a scalar, it is a JSON string:

```json
{"user_id":"{\"device_id\":\"bf54fb16-d645-43df-8dc8-d75582dae084\",\"account_uuid\":\"\",\"session_id\":\"eec26b64-0d02-4c41-80c3-bd516ca84663\"}"}
```

So device id and session id travel in the body as well as in headers. That is
the account-linked part, and it is exactly what an ordinary client does not send.

### Credentials — two, not one

```
X-Api-Key:    adcb2a…  (49 chars, sha256_8 d744a1bd)   <- the project key
Authorization: Bearer …  (56 chars, sha256_8 cf26ac72)  <- a DIFFERENT credential
```

The `Authorization` bearer is a third credential relative to the API key: the
captured `X-Api-Key` digest matches the key in `~/.zcode/v2/config.json`, while
the bearer does not. Its payload is encrypted at rest in ZCode's credential store
(`oauth:zai:access_token`), which is why it cannot simply be copied out.

## Body shape, ordinary vs ZCode

| field | ordinary | ZCode |
| --- | --- | --- |
| `max_tokens` | 32 | **128000** |
| `stream` | false | true |
| `system` | – | 3 blocks |
| `tools` | – | **274** |
| `thinking` | – | `{"type":"enabled"}` |
| `output_config` | – | `{"effort":"max"}` |
| `metadata` | – | device + session |
| `tool_choice` | – | `{"type":"auto"}` |
| body size | 134 B | 323 631 B |

## Does the attestation gate anything?

No. `cmd/zaidiff` sends the identical request signed and unsigned and diffs the
responses:

- both `200`
- identical `usage`
- no distinguishing response header; the only differences are CDN trace ids,
  timing and an `acw_tc` cookie

The sole server-side rejection signal found in the client bundle is `401` with
reason `VERIFY_SIGNATURE_INVALID` or `VERIFY_APIKEY_EXPIRED`. ZCode treats a
handshake failure as `failOpenEligible` and sends unsigned.

So the attestation is best read as **client identity plus telemetry**, not as an
enforced gate. That is consistent with the vendor's own framing of the extra 50%
quota being granted for coding-tool usage generally rather than gated per client.

## What `zsign` reproduces, verified

`go run ./cmd/zaicheck -capture ../zai-capture-probe/out/ab`:

| check | result |
| --- | --- |
| recomputed seed from captured `ts` + `sessionId` | `6958bb0b…` |
| ZCode's captured `X-Client-Pow` valid for that seed | **true** (counter 554) |
| ZCode's captured signature verifies under our handshake key | **false** |

The proof-of-work and seed construction are reproduced exactly, on an
independently captured run. The signature does not verify because ZCode signs
with the coding-plan project key rather than the API key in
`~/.zcode/v2/config.json`; the handshake issues a stable key per `apiKeyId`, so
this is a credential difference, not a formula difference.