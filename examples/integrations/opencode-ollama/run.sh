#!/usr/bin/env bash
# Drive proof-mcp's `commit` tool from a real MCP client — opencode — running on
# Alpine, with a local model served by Ollama on the host. Then check the result
# with the proof CLI, which trusts none of the above.
#
#   ./run.sh                          # ministral-3:3b
#   MODEL=ornith-1.5:35b ./run.sh     # any Ollama model that supports tools
set -euo pipefail

MODEL="${MODEL:-ministral-3:3b}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
IMAGE=proof-opencode:local

command -v podman >/dev/null || { echo "podman not found" >&2; exit 2; }
curl -fsS -m 3 http://127.0.0.1:11434/api/version >/dev/null ||
  { echo "Ollama is not answering on 127.0.0.1:11434" >&2; exit 2; }
# Captured first: `ollama show | grep -q` would SIGPIPE ollama, and pipefail
# would read that as a failure even when the model does support tools.
caps="$(ollama show "$MODEL" 2>/dev/null || true)"
[[ "$caps" == *tools* ]] ||
  { echo "$MODEL is missing, or cannot call tools (MCP needs tool calling)" >&2; exit 2; }

echo "── building static linux binaries"
ARCH="$(podman info --format '{{.Host.Arch}}')"
mkdir -p "$HERE/bin"
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -o "$HERE/bin/proof" ./cmd/proof)
# proof-mcp needs unreleased library packages, so it builds through the repo's go.work.
(cd "$ROOT/cmd/proof-mcp" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -o "$HERE/bin/proof-mcp" .)

echo "── building the Alpine image"
podman build -q -t "$IMAGE" "$HERE" >/dev/null

DATA="$(mktemp -d)"
echo "── evidence database: $DATA/evidence.db"

PROMPT='Use the aleutianchain_commit tool exactly once. Commit these two entries to the chain "agent-actions", each as "content": first "refunded order 4411 for customer u-81", second "emailed the refund receipt for order 4411". Then reply with the entry ids the tool returned.'

echo "── opencode + $MODEL (via host Ollama)"
podman run --rm -v "$DATA:/data" "$IMAGE" \
  opencode run -m "ollama/$MODEL" --format json "$PROMPT" > "$DATA/events.jsonl" 2> "$DATA/opencode.err" || true

python3 - "$DATA/events.jsonl" <<'PY'
import json, sys
calls, text = [], []
for line in open(sys.argv[1]):
    try: e = json.loads(line)
    except ValueError: continue
    part = e.get("part") or {}
    if part.get("type") == "tool":
        st = part.get("state") or {}
        calls.append((part.get("tool"), st.get("status"), st.get("input"), st.get("output") or ""))
    elif part.get("type") == "text" and part.get("text"):
        text.append(part["text"])
print(f"   tool calls: {len(calls)}")
for tool, status, inp, out in calls:
    print(f"   • {tool} [{status}]")
    print(f"       input : {json.dumps(inp)[:300]}")
    print(f"       output: {out[:300]}")
if text:
    print("   model said:", " ".join(text)[:400])
# Keep the first committed entry, and the content the model sent for it, so the
# operator can prove it below.
import os
for tool, status, inp, out in calls:
    if tool.endswith("commit") and status == "completed":
        first = json.loads(out)["entries"][0]["entry_id"]
        d = os.path.dirname(sys.argv[1])
        open(os.path.join(d, "first_entry"), "w").write(first)
        open(os.path.join(d, "first_content.txt"), "w").write(inp["entries"][0]["content"])
        break
PY

echo "── checking with the proof CLI (no model, no MCP)"
podman run --rm -v "$DATA:/data" "$IMAGE" sh -c '
  proof export --db /data/evidence.db --chain agent-actions --out /tmp/a.json &&
  proof verify /tmp/a.json &&
  echo && ls -1 /data'

if [[ -f "$DATA/first_entry" ]]; then
  echo "── the operator proves the agent's first entry (proof disclose)"
  podman run --rm -v "$DATA:/data" "$IMAGE" sh -c \
    'proof disclose --db /data/evidence.db --chain agent-actions \
       --entry "$(cat /data/first_entry)" --content /data/first_content.txt'
fi
echo "── done: $DATA"
