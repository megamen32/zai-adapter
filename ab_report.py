#!/usr/bin/env python3
"""Turn captured flows into a HAR file and diff an ordinary request against a
ZCode request, header by header.

Usage:
  ab_report.py <capture-dir> [--har out.har]

Groups the flows into:
  ordinary  - captured from a plain API-key client
  zcode     - captured from a real ZCode turn
and prints exactly what separates them.
"""

import json
import os
import sys
import time

# The Ed25519 signature covers apiKeyId, ts, clientVersion, sessionId and nonce.
# These headers are the attestation itself.
ATTESTATION = {
    "x-client-ts", "x-client-version", "x-client-sig", "x-client-nonce",
    "x-client-pow", "x-session-id", "x-app-id",
}

# Sent by ZCode but NOT covered by the signature: plain client identity/telemetry.
TELEMETRY = {
    "x-zcode-agent", "x-release-channel", "x-client-language", "x-client-timezone",
    "x-platform", "x-os-category", "x-os-version", "http-referer",
    "x-zcode-app-version", "x-zcode-session-type", "x-title", "x-device-mid",
    "x-query-id", "x-request-id", "x-zcode-trace-id", "x-release-channel",
}

VOLATILE = {"x-request-id", "x-query-id", "x-zcode-trace-id", "x-client-ts",
            "x-client-nonce", "x-client-sig", "x-client-pow", "date",
            "x-log-id", "ga-traceid", "x-process-time", "set-cookie", "via",
            "eagleid", "x-connection-id"}

TRANSPORT = {"host", "connection", "content-length", "accept-encoding",
             "accept", "content-type"}


def load(d):
    out = []
    for name in sorted(os.listdir(d)):
        if name.endswith(".json"):
            with open(os.path.join(d, name)) as fh:
                out.append(json.load(fh))
    return out


def classify(f):
    host = f.get("host", "")
    path = f.get("path", "")
    if host == "zcode.z.ai" and "/anthropic/v1/messages" in path:
        return "zcode"
    if host == "api.z.ai" and "/v1/messages" in path:
        return "ordinary"
    if host == "api.z.ai" and "/chat/completions" in path:
        return "ordinary-openai"
    return None


def parse_ts(v):
    """zmitm writes an RFC3339 string; keep a numeric fallback."""
    if isinstance(v, (int, float)):
        return float(v)
    try:
        return time.mktime(time.strptime(str(v)[:19], "%Y-%m-%dT%H:%M:%S"))
    except Exception:
        return 0.0


def har_entry(f):
    req_headers = [{"name": k, "value": (v[0] if isinstance(v, list) else str(v))}
                   for k, v in f.get("request_headers", {}).items()]
    resp_headers = [{"name": k, "value": (v[0] if isinstance(v, list) else str(v))}
                    for k, v in (f.get("response_headers") or {}).items()]
    return {
        "startedDateTime": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(parse_ts(f.get("ts")))),
        "time": f.get("duration_ms", 0),
        "request": {
            "method": f.get("method", ""),
            "url": "https://" + f.get("host", "") + f.get("path", ""),
            "httpVersion": f.get("proto", "HTTP/1.1"),
            "headers": req_headers,
            "queryString": [],
            "cookies": [],
            "headersSize": -1,
            "bodySize": f.get("request_body_len", 0),
            "postData": {
                "mimeType": "application/json",
                "text": (f.get("request_body") or "")[:4000],
            } if f.get("request_body_len") else None,
        },
        "response": {
            "status": f.get("status", 0),
            "statusText": "",
            "httpVersion": f.get("proto", "HTTP/1.1"),
            "headers": resp_headers,
            "cookies": [],
            "content": {
                "size": f.get("response_body_len", 0),
                "mimeType": "application/json",
                "text": (f.get("response_body") or "")[:4000],
            },
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": f.get("response_body_len", 0),
        },
        "cache": {},
        "timings": {"send": 0, "wait": f.get("duration_ms", 0), "receive": 0},
        "_label": f.get("label", ""),
        "_seq": f.get("seq", 0),
    }


def hdr_map(f):
    return {k.lower(): (v[0] if isinstance(v, list) and v else str(v))
            for k, v in f.get("request_headers", {}).items()}


def body_shape(f):
    raw = f.get("request_body") or ""
    try:
        b = json.loads(raw)
    except Exception:
        return {}
    if not isinstance(b, dict):
        return {}
    shape = {}
    for k, v in b.items():
        if isinstance(v, list):
            shape[k] = f"[{len(v)} items]"
        elif isinstance(v, dict):
            shape[k] = "{" + ",".join(sorted(v.keys())) + "}"
        elif isinstance(v, str):
            shape[k] = f"str({len(v)})"
        else:
            shape[k] = repr(v)
    return shape


def main():
    capture_dir = sys.argv[1]
    har_out = None
    if "--har" in sys.argv:
        har_out = sys.argv[sys.argv.index("--har") + 1]

    flows = load(capture_dir)
    groups = {}
    for f in flows:
        c = classify(f)
        if c:
            groups.setdefault(c, []).append(f)

    if har_out:
        entries = [har_entry(f) for f in flows]
        with open(har_out, "w") as fh:
            json.dump({"log": {
                "version": "1.2",
                "creator": {"name": "zai-capture-probe", "version": "1"},
                "entries": entries,
            }}, fh, indent=1)
        print(f"HAR written: {har_out} ({len(entries)} entries)\n")

    for k in sorted(groups):
        for f in groups[k]:
            print(f"{k:16} #{f['seq']} {f['method']:6} https://{f['host']}{f['path'][:70]}"
                  f"  -> {f['status']}  in={f['request_body_len']}B")
    print()

    ordi = (groups.get("ordinary") or groups.get("ordinary-openai") or [None])[0]
    zc = (groups.get("zcode") or [None])[0]
    if not ordi or not zc:
        print("need one ordinary and one zcode flow")
        return

    oh, zh = hdr_map(ordi), hdr_map(zc)
    oshape, zshape = body_shape(ordi), body_shape(zc)

    print("=" * 78)
    print("WHAT ZCODE SENDS THAT AN ORDINARY CLIENT DOES NOT")
    print("=" * 78)
    only_zcode = [k for k in zh if k not in oh]
    for k in sorted(only_zcode):
        val = zh[k]
        if isinstance(val, dict):
            val = val.get("sha256_8", str(val))
        bucket = "ATTESTATION" if k in ATTESTATION else ("TELEMETRY" if k in TELEMETRY else "OTHER")
        shown = val if bucket != "ATTESTATION" else (
            f"{str(val)[:24]}..." if len(str(val)) > 24 else val)
        print(f"  [{bucket:11}] {k}: {shown}")

    print()
    print("=" * 78)
    print("DIFFERING VALUES ON SHARED HEADERS")
    print("=" * 78)
    for k in sorted(set(oh) & set(zh)):
        if k in VOLATILE or k in TRANSPORT:
            continue
        ov, zv = oh[k], zh[k]
        ov = ov.get("sha256_8") if isinstance(ov, dict) else ov
        zv = zv.get("sha256_8") if isinstance(zv, dict) else zv
        if ov != zv:
            print(f"  {k}:\n      ordinary: {ov}\n      zcode:    {zv}")

    print()
    print("=" * 78)
    print("BODY SHAPE")
    print("=" * 78)
    for k in sorted(set(oshape) | set(zshape)):
        o, z = oshape.get(k, "-"), zshape.get(k, "-")
        mark = "  " if o == z else "* "
        print(f" {mark}{k:22} ordinary={o:28} zcode={z}")

    print()
    print("=" * 78)
    print("ATTESTATION GROUPS")
    print("=" * 78)
    signed = ["x-api-key (as apiKeyId)", "x-client-ts", "x-client-version",
              "x-session-id", "x-client-nonce"]
    print("  covered by the Ed25519 signature:")
    for s in signed:
        print(f"    - {s}")
    print("  proof of work, NOT signed:")
    print("    - x-client-pow  (salt||counter where SHA-256(seed||cand) has 8 leading zero bits)")
    print("  plain headers, NOT signed:")
    for k in sorted(k for k in zh if k in TELEMETRY):
        print(f"    - {k}: {zh[k]}")


if __name__ == "__main__":
    main()