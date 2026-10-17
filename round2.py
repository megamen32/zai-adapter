#!/usr/bin/env python3
"""Back-to-back round: adapter replay of the captured ZCode body twice, then a
real ZCode turn, all inside the server-side cache TTL window. The credit deltas
show whether metering depends on the client or only on cache state."""
import json
import os
import subprocess
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from meter_ab import snap  # noqa: E402
from flash_experiment import extract_usage  # noqa: E402

ADAPTER = "http://127.0.0.1:18790/v1/messages"
FLOW = "/home/roomhacker/agents-projects/zai-capture-probe/out/flash3/004-POST-zcode.z.ai--api-v1-ultra-zai-anthropic-v1-messages.json"


def post_adapter(body_bytes, label):
    headers = {
        "content-type": "application/json",
        "anthropic-version": "2023-06-01",
        "accept": "application/json",
        "x-session-id": "00000000-0000-4000-8000-0000000000ab",
    }
    req = urllib.request.Request(ADAPTER, headers=headers, data=body_bytes)
    with urllib.request.urlopen(req, timeout=300) as resp:
        text = resp.read().decode(errors="replace")
    usage, ok = extract_usage(text)
    print(f"  [{label}] usage={json.dumps(usage)}")
    return usage


body = json.load(open(FLOW))["request_body"].encode()

snap("phaseD")
u1 = post_adapter(body, "adapter replay #2 (warm)")
snap("phaseE")
u2 = post_adapter(body, "adapter replay #3 (same window)")
snap("phaseF")
rc = subprocess.run(
    ["zcode", "--prompt", "Reply with exactly: hi", "--mode", "plan",
     "--no-browser", "--no-color"],
    cwd="/tmp/opencode", timeout=240,
    env={**os.environ, "LD_PRELOAD": "", "MITM_REDIRECT_PORT": ""},
    capture_output=True, text=True)
print("  [zcode turn] rc=", rc.returncode, "out:", rc.stdout.strip().splitlines()[-1:] or "")
snap("phaseG")

json.dump({"replay2_usage": u1, "replay3_usage": u2},
          open("/tmp/opencode/meter/round2.json", "w"), indent=1)
print("snapshots phaseD→G saved")
