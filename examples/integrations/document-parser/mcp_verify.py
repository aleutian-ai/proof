# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
"""Ask proof-mcp to verify an export bundle, as an agent's MCP client would.

    python3 mcp_verify.py BUNDLE -- proof-mcp --root DIR --bundle-checkpoint-key K ...

Starts the server command after `--` over stdio, speaks MCP to it (initialize,
then tools/call verify_export_bundle), and prints the structured result. This
is the call Claude Code or any MCP client makes; here it is made without a
model, so the demo is the same on every run. BUNDLE is relative to --root.
Exits 0 only on the verdict ok.
"""

import json
import subprocess
import sys
import textwrap

bundle, server = sys.argv[1], sys.argv[sys.argv.index("--") + 1 :]
proc = subprocess.Popen(server, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)


def send(msg: dict) -> None:
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()


def reply(want: int) -> dict:
    for line in proc.stdout:
        msg = json.loads(line)
        if msg.get("id") == want:
            if "error" in msg:
                sys.exit(f"proof-mcp: {msg['error'].get('message')}")
            return msg["result"]
    sys.exit("proof-mcp exited without answering")


send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {},
    "clientInfo": {"name": "auditor", "version": "1"}}})
info = reply(1)["serverInfo"]
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
      "params": {"name": "verify_export_bundle", "arguments": {"path": bundle}}})
res = reply(2)
proc.stdin.close()
proc.wait()
if res.get("isError"):
    sys.exit("verify_export_bundle: " + " ".join(c.get("text", "") for c in res["content"]))

out = res["structuredContent"]
print(f"   MCP {info['name']} {info['version']} · verify_export_bundle · {bundle}")
print(f"   verdict: {out['verdict'].upper()}"
      f"   (checkpoint trust {out['checkpoint_trust']}, record trust {out['record_trust']})")
for c in out["chains"]:
    n = c["counts"]
    print(f"   chain {c['position']}: {c['verdict']}, {n['entries']} entries, {n['opened']} opened, "
          f"{n['authenticated']} authenticated")
    for p in c["problems"]:
        print(f"     problem: {p['code']} (count {p['count']}, first at index {p['first']})")
wrap = lambda s: textwrap.fill(s, 96, initial_indent="     ", subsequent_indent="     ")
print("   proven:\n" + wrap(out["proven"]))
print("   not proven:\n" + wrap(out["not_proven"]))
sys.exit(0 if out["verdict"] == "ok" else 1)
