#!/usr/bin/env python3
"""Phase 2: metered A/B on GLM-5.3-Flash.

Steps, each separated by explicit credit snapshots:
  A. real ZCode turn "Reply with exactly: hi" (captured by zmitm, so the
     request and its usage are on record)
  B. the exact captured ZCode body replayed through zai-attest
  C. a minimal echo through zai-attest

`extract_usage` parses both a plain JSON response and an SSE stream, because
ZCode streams and the final usage arrives in message_delta.
"""
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from meter_ab import api_key, fetch_json, snap  # noqa: E402

ADAPTER = "http://127.0.0.1:18790/v1/messages"
CTX = ssl.create_default_context()
SNAP = "/tmp/opencode/meter"


def extract_usage(text):
    """Return (usage, ok) from a JSON body or an SSE stream."""
    try:
        obj = json.loads(text)
    except Exception:
        obj = None
    if isinstance(obj, dict) and obj.get("usage"):
        return obj["usage"], True
    if isinstance(obj, list) or text.lstrip().startswith("["):
        return None, False
    usage = {}
    ok = False
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if payload in ("", "[DONE]"):
            continue
        try:
            ev = json.loads(payload)
        except Exception:
            continue
        if isinstance(ev, dict):
            if ev.get("type") == "error" or "error" in ev:
                return ev.get("error"), False
            if ev.get("message", {}).get("usage") == {} or "usage" in json.dumps(ev)[:2000]:
                u = (ev.get("message") or {}).get("usage") or ev.get("usage")
                if u:
                    usage = {**u, **usage}
                    ok = True
    return usage or None, ok


def post_adapter(body_bytes, label):
    headers = {
        "content-type": "application/json",
        "anthropic-version": "2023-06-01",
        "accept": "application/json",
        "x-session-id": "00000000-0000-4000-8000-0000000000ab",
    }
    req = urllib.request.Request(ADAPTER, headers=headers, data=body_bytes)
    try:
        with urllib.request.urlopen(req, timeout=300, context=CTX) as resp:
            text = resp.read().decode(errors="replace")
            status = resp.status
    except urllib.error.HTTPError as exc:  # noqa: F821
        text = exc.read().decode(errors="replace")
        status = exc.code
    usage, ok = extract_usage(text)
    print(f"  [{label}] HTTP {status} ok={ok} usage={json.dumps(usage)}")
    return {"label": label, "status": status, "ok": ok, "usage": usage,
            "raw_head": text[:300]}


def main():
    cap_dir = "/home/roomhacker/agents-projects/zai-capture-probe/out/flash3"
    flow = [os.path.join(cap_dir, n) for n in sorted(os.listdir(cap_dir))
            if n.startswith("004")][0]
    d = json.load(open(flow))
    body = d["request_body"]
    model = json.loads(body)["model"]
    zh_usage_str = d.get("response_body") or ""
    zcode_usage, _ = extract_usage(zh_usage_str) if zh_usage_str else (None, False)
    print(f"captured zcode run: model={model} body={len(body)}B "
          f"resp={d['status']} usage={json.dumps(zcode_usage)}")

    out = {"zcode_captured": {"model": model, "status": d["status"],
                              "usage": zcode_usage, "body_len": json.loads(body).get("__len__", len(body))}}

    snap("phaseA")            # right before phase B/C so deltas attribute cleanly
    b = post_adapter(body.encode(), f"replay captured zcode body ({model})")
    snap("phaseB")
    mini = json.dumps({"model": model, "max_tokens": 64, "stream": False,
                       "messages": [{"role": "user", "content": "Reply with exactly: hi"}]}).encode()
    c = post_adapter(mini, f"minimal echo ({model})")
    snap("phaseC")

    out.update({"replay": b, "minimal": c})
    json.dump(out, open(os.path.join(SNAP, "flash_experiment.json"), "w"), indent=1)
    print("evidence:", os.path.join(SNAP, "flash_experiment.json"))


if __name__ == "__main__":
    main()
