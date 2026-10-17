#!/usr/bin/env python3
"""Meter the Coding Plan credit counters around A/B requests.

The plan is metered server-side in Credits (5-hour window, weekly window).
This script takes timestamped snapshots so each phase can attribute its delta:

    python3 meter_ab.py snap phase0
    ... run real zcode (captured) ...
    python3 meter_ab.py snap phase1
    ... run the same echo through zai-attest ...
    python3 meter_ab.py snap phase2
    python3 meter_ab.py diff      # prints deltas per window

Also: `send` posts a minimal Anthropic request through the adapter and prints
its usage; `replay <flow.json>` posts a captured ZCode body byte-for-byte.

The API key is read from ZCode's own config and never printed.
"""
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

CONFIG = "/home/roomhacker/.zcode/v2/config.json"
QUOTA_URL = "https://api.z.ai/api/monitor/usage/quota/limit"
SNAP_DIR = "/tmp/opencode/meter"

CTX = ssl.create_default_context()
BASE_HEADERS = {
    "content-type": "application/json",
    "anthropic-version": "2023-06-01",
    "accept": "application/json",
    "user-agent": "ZCode/0.16.9 ai-sdk/provider-utils/4.0.27 runtime/node.js/22",
    "x-app-id": "zcode",
    "x-platform": "linux-x64",
    "x-os-category": "linux",
    "x-release-channel": "production",
    "http-referer": "https://zcode.z.ai",
    "x-client-language": "ru-RU",
    "x-client-timezone": "Europe/Moscow",
    "x-title": "Z Code@cli",
    "x-zcode-agent": "glm",
}




def api_key():
    with open(CONFIG) as fh:
        return json.load(fh)["provider"]["builtin:zai-coding-plan"]["options"]["apiKey"]


def fetch_json(url, headers, data=None, timeout=120):
    req = urllib.request.Request(url, headers=headers, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read())
        except Exception:
            return {"code": exc.code}
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


def snap_credits(key):
    headers = dict(BASE_HEADERS)
    headers["x-api-key"] = key
    now_ms = int(time.time() * 1000)
    url = f"{QUOTA_URL}?startTime={now_ms - 7 * 24 * 3600 * 1000}&endTime={now_ms}"
    data = fetch_json(url, headers)
    windows = {}
    for item in (data.get("data") or {}).get("limits") or []:
        windows[f"unit{item['unit']}x{item['number']}"] = {
            "currentValue": item.get("currentValue"),
            "usage": item.get("usage"),
        }
    return {"ts": now_ms, "windows": windows}


def snap(name):
    key = api_key()
    snap_dir = "/tmp/opencode/meter"
    os.makedirs(snap_dir, exist_ok=True)
    s = snap_credits(key)
    s["phase"] = name
    path = os.path.join(snap_dir, f"{name}.json")
    with open(path, "w") as fh:
        json.dump(s, fh, indent=1)
    print(f"{name:>10} @ {s['ts']}  " + "  ".join(
        f"{k}={v['currentValue']}" for k, v in sorted(s["windows"].items())))


def diff(*phases):
    snap_dir = "/tmp/opencode/meter"
    loaded = []
    for name in phases:
        p = os.path.join(snap_dir, f"{name}.json")
        with open(p) as fh:
            loaded.append(json.load(fh))
    keys = sorted(set().union(*[set(s["windows"]) for s in loaded]))
    print("phase      " + "  ".join(f"{k:>16}" for k in keys))
    for s in loaded:
        print(f"{s['phase']:>10} " + "  ".join(
            f"{s['windows'].get(k, {}).get('currentValue', 0)!r:>16}" for k in keys))
    print("deltas:")
    for a, b in zip(loaded, loaded[1:]):
        parts = []
        for k in keys:
            va = a["windows"].get(k, {}).get("currentValue") or 0
            vb = b["windows"].get(k, {}).get("currentValue") or 0
            parts.append(f"{k}={vb - va:+d}")
        print(f"  {a['phase']} -> {b['phase']}: " + "  ".join(parts))


def usage_line(resp):
    u = (resp or {}).get("usage")
    if not u:
        return "(no usage)"
    return (f"in={u.get('input_tokens', 0)} out={u.get('output_tokens', 0)} "
            f"cacheR={u.get('cache_read_input_tokens', 0)} "
            f"cacheW={u.get('cache_creation_input_tokens', 0)} "
            f"model={resp.get('model')}")


def send_adapter(minimal=True, flow=None, path="/v1/messages"):
    import os

    key = api_key()
    headers = dict(BASE_HEADERS)
    headers["x-api-key"] = key
    headers["host"] = "127.0.0.1:18790"
    del headers["host"]
    if flow:
        src = json.load(open(flow))
        body = src["request_body"]
        body_obj = json.loads(body)
    else:
        body_obj = {
            "model": os.environ.get("AB_MODEL", "GLM-5.3-Flash"),
            "max_tokens": 64,
            "stream": False,
            "messages": [{"role": "user", "content": "Reply with exactly: hi"}],
        }
        body = json.dumps(body_obj)
    url = f"http://127.0.0.1:18790{path}"
    resp = fetch_json(url, headers, data=body.encode())
    return body_obj, resp


def show_adapter(flow=None):
    body_obj, resp = (None, None)
    if flow:
        body_obj, resp = send_adapter(flow=flow)
        label = f"replay {os.path.basename(flow)} model={body_obj.get('model')}"
    else:
        body_obj, resp = send_adapter()
        label = f"minimal model={body_obj.get('model')}"
    print(f"{label}: status={resp.get('type', resp.get('code', '?'))} usage:")
    print("   " + usage_line(resp))
    with open("/tmp/opencode/meter/adapter_last_usage.json", "w") as fh:
        json.dump({"label": label, "resp_keys": sorted(resp.keys()),
                   "usage": resp.get("usage")}, fh, indent=1)


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "snap":
        snap(sys.argv[2])
    elif cmd == "diff":
        diff(*sys.argv[2:])
    elif cmd == "send":
        show_adapter()
    elif cmd == "replay":
        show_adapter(flow=sys.argv[2])
    else:
        print("usage: meter_ab.py snap NAME | diff P1 P2 ... | send | replay FLOW.json")
