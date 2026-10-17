#!/usr/bin/env bash
# Capture the ZCode request and an ordinary client request through the SAME
# capture proxy, so the two are directly comparable.
#
# Both sides hit the Coding Plan Messages endpoint with the same model. The
# ordinary side carries only an API key, which is what a normal integration
# does; the ZCode side carries whatever ZCode actually sends.
set -uo pipefail

ROOT=/home/roomhacker/agents-projects/zai-adapter
CAP=/home/roomhacker/agents-projects/zai-capture-probe
PORT=${CAPTURE_PORT:-18899}
CA=/home/roomhacker/.mitmproxy
LABEL=${1:-ab}
OUT="$CAP/out/$LABEL"
MODEL=${MODEL:-GLM-5.3}
PROMPT=${PROMPT:-Reply with the single word: pong}

mkdir -p "$OUT"
rm -f "$OUT"/*.json 2>/dev/null

"$CAP/zmitm/zmitm" \
  -listen "127.0.0.1:$PORT" \
  -ca-cert "$CA/mitmproxy-ca-cert.pem" \
  -ca-key "$CA/mitmproxy-ca.pem" \
  -out "$CAP/out" -label "$LABEL" \
  -only "api.z.ai,zcode.z.ai" \
  > "$CAP/out/zmitm-$LABEL.log" 2>&1 &
ZMITM=$!
trap 'kill $ZMITM 2>/dev/null' EXIT
for _ in $(seq 1 40); do ss -ltn 2>/dev/null | grep -q ":$PORT " && break; sleep 0.25; done
kill -0 $ZMITM 2>/dev/null || { echo "zmitm failed:"; cat "$CAP/out/zmitm-$LABEL.log"; exit 1; }
echo "== zmitm on :$PORT, label=$LABEL"

KEY=$(python3 -c "
import json;d=json.load(open('/home/roomhacker/.zcode/v2/config.json'))
print(d['provider']['builtin:zai-coding-plan']['options']['apiKey'])")

BODY=$(python3 -c "
import json,sys
print(json.dumps({'model':sys.argv[1],'max_tokens':32,
 'messages':[{'role':'user','content':sys.argv[2]}],'stream':False}))" "$MODEL" "$PROMPT")

echo "== A: ordinary client (api key only) model=$MODEL"
curl -s -o /dev/null -m 120 \
  --cacert "$CA/mitmproxy-ca-cert.pem" \
  --resolve "api.z.ai:$PORT:127.0.0.1" \
  "https://api.z.ai:$PORT/api/paas/v4/chat/completions" \
  -H "content-type: application/json" \
  -H "authorization: Bearer $KEY" \
  -d "$BODY"

echo "== B: ordinary client, Anthropic shape, model=$MODEL"
curl -s -o /dev/null -m 120 \
  --cacert "$CA/mitmproxy-ca-cert.pem" \
  --resolve "api.z.ai:$PORT:127.0.0.1" \
  "https://api.z.ai:$PORT/api/anthropic/v1/messages" \
  -H "content-type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -H "x-api-key: $KEY" \
  -d "$BODY"

echo "== C: real ZCode turn"
( cd /tmp/opencode && env \
    LD_PRELOAD="$CAP/mitm/redirect_connect.so" \
    MITM_REDIRECT_PORT="$PORT" \
    NODE_EXTRA_CA_CERTS="$CA/mitmproxy-ca-cert.pem" \
    zcode --prompt "$PROMPT" --mode plan --no-browser --no-color >/dev/null 2>&1 )

sleep 2
kill $ZMITM 2>/dev/null; wait $ZMITM 2>/dev/null
echo "== captured:"
ls -la "$OUT"