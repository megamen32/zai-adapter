#!/usr/bin/env python3
"""Where does a tool bonus like ZCode's documented 1.5x usage live?

Decisive control on the credit meter, same request every time (GLM-5.3-Flash,
max_tokens=8):
  A) 4x straight to the coding-plan endpoint, bare identity (x-api-key only)
  B) 4x through zai-attest, which adds the full attestation AND the ZCode
     telemetry headers (x-app-id zcode, X-Title: Z Code@cli, ...)

If the deltas match, metering does not weight clients and any tool bonus lives
in the plan grant table; if B is cheaper, the bonus is in per-credit weighting
keyed on client identity. Small n, minimal bodies: bounded cost.
"""
import json
import ssl
import sys
import time
import urllib.request

sys.path.insert(0, "/home/roomhacker/agents-projects/zai-adapter")
from meter_ab import api_key, snap, fetch_json  # noqa: E402

CP = "https://zcode.z.ai/api/v1/ultra-zai/anthropic/v1/messages"
ADAPTER = "http://127.0.0.1:18790/v1/messages"
CTX = ssl.create_default_context()
N = 4

BODY = json.dumps({"model": "GLM-5.3-Flash", "max_tokens": 8, "stream": False,
                   "messages": [{"role": "user", "content": "Reply with exactly: hi"}]}).encode()


def run(url, headers, label, n=N):
    ok = 0
    for _ in range(n):
        r = fetch_json(url, headers, data=BODY)
        if "usage" in (r or {}):
            ok += 1
        elif r:
            ok += 0 if isinstance(r, dict) and r.get("error") else ok
        time.sleep(0.6)
    return ok


def main():
    key = api_key()
    bare = {"content-type": "application/json", "anthropic-version": "2023-06-01",
            "x-api-key": key, "user-agent": "python-urllib"}
    snap("ctl0")
    ok_a = run(CP, bare, "bare")
    snap("ctl1")
    zcodeish = {**bare,
                "user-agent": "ZCode/0.16.9 ai-sdk/provider-utils/4.0.27 runtime/node.js/22",
                "accept": "application/json"}
    del zcodeish["x-api-key"]  # adapter sets it itself
    ok_b = run(ADAPTER, zcodeish, "adapter(zcode-identity)")
    snap("ctl2")
    print(f"bare coding-plan: {ok_a}/{N} ok   adapter zcode-identity: {ok_b}/{N} ok")


if __name__ == "__main__":
    main()
