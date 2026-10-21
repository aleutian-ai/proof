#!/usr/bin/env bash
# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
#
# run-otel-mcp.sh — the same loan applications, through OpenTelemetry and MCP.
#
#   1. the parser emits each extraction as an OpenTelemetry log record, with
#      the OpenTelemetry SDK's own OTLP exporter, to otel-sink (../otel), which
#      commits it to the applicant's own chain, signed. No proof code in the
#      parser; a re-run is refused, not recorded twice
#   2. a signed checkpoint, and `proof sink verify`
#   3. the dispute: the lender exports one applicant's records. The auditor's
#      agent checks the bundle through proof-mcp's verify_export_bundle, with
#      the lender's public keys bound when the server is launched
#   4. the cover-up: the income is "corrected"; the same MCP call refuses it
#   5. the applicant asks to be forgotten: erased, signed, and it still verifies
#
#   ./run-otel-mcp.sh                       # ministral-3:3b
#   MODEL=ornith-1.5:9b ./run-otel-mcp.sh   # any Ollama model
#   KEEP=/tmp/loan ./run-otel-mcp.sh        # keep the folder (a new, empty one)
#
# Needs Go, Python 3.10+, network access to PyPI, and Ollama with the model
# pulled. No containers. Builds proof, otel-sink and proof-mcp from this
# working tree. Leaves nothing running, and nothing behind unless KEEP is set.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
export MODEL="${MODEL:-ministral-3:3b}"
PORT="${SINK_PORT:-4320}"
SINK_PID=""
if [ -n "${KEEP:-}" ]; then
    [ ! -e "$KEEP" ] || [ -z "$(ls -A "$KEEP")" ] || { echo "KEEP=$KEEP is not empty" >&2; exit 2; }
    mkdir -p "$KEEP" && WORK="$(cd "$KEEP" && pwd)"
else
    WORK="$(mktemp -d)"
fi
cleanup() {
    [ -n "$SINK_PID" ] && kill "$SINK_PID" 2>/dev/null || true
    [ -n "${KEEP:-}" ] || rm -rf "$WORK"
}
trap cleanup EXIT

say() { printf '\n\033[0;34m── %s\033[0m\n' "$*"; }
show() { printf '$ %s\n' "$*"; "$@"; }
fail() { echo "$*" >&2; exit 1; }

curl -fsS -m 3 "${OLLAMA_URL:-http://127.0.0.1:11434}/api/version" >/dev/null ||
    fail "Ollama is not answering on ${OLLAMA_URL:-http://127.0.0.1:11434}"

say "build proof, otel-sink and proof-mcp from this working tree; the lender's Python environment"
mkdir -p "$WORK/bin"
(cd "$REPO" && go build -o "$WORK/bin/proof" ./cmd/proof)
(cd "$REPO/examples/integrations/otel" && go build -o "$WORK/bin/otel-sink" .)
(cd "$REPO/cmd/proof-mcp" && go build -o "$WORK/bin/proof-mcp" .)
export PATH="$WORK/bin:$PATH"
python3 -m venv "$WORK/lender" && "$WORK/lender/bin/pip" install -q --disable-pip-version-check \
    pypdf==6.15.0 opentelemetry-sdk==1.45.1 opentelemetry-exporter-otlp-proto-http==1.45.1
cd "$WORK"

say "three loan applications arrive (made up: people, lender and numbers)"
python3 -I "$HERE/make_applications.py" docs
ls docs

say "keys: proof sink init; otel-sink starts, holding the record key's FILE"
proof sink init --dir sink-data >/dev/null
K="sink-data.keys"
CKPT_PRIV="$K/ml-dsa-65-checkpoint-private.pem" CKPT_PUB="$K/ml-dsa-65-checkpoint-public.pem"
REC_PRIV="$K/ml-dsa-65-record-private.pem" REC_PUB="$K/ml-dsa-65-record-public.pem"
HEADS="checkpoint-heads.json" # outside sink-data: the record that a checkpoint series was not restarted
VERIFY=(proof sink verify --dir sink-data --key "$CKPT_PUB" --record-trust "$REC_PUB" --heads "$HEADS")
verify() { LAST="$("${VERIFY[@]}")"; printf '$ %s\n%s\n' "${VERIFY[*]}" "$LAST"; }
PROOF_RECORD_KEY_FILE="$WORK/$REC_PRIV" otel-sink -class loan-extractions -dir sink-data \
    -listen "127.0.0.1:$PORT" 2> otel-sink.log &
SINK_PID=$!
for _ in $(seq 1 50); do grep -q "listening on" otel-sink.log 2>/dev/null && break; sleep 0.1; done
grep -q "listening on" otel-sink.log || { cat otel-sink.log >&2; fail "otel-sink did not start"; }
cat otel-sink.log

# totals FIELD: the sum of otel-sink's "committed" / "already" / "refused" over its request lines
# from line FROM of its log on. The SDK's batch processor may split a run into several requests.
totals() { tail -n "+$1" otel-sink.log | awk '/^request [0-9]+: committed/ {
    c+=$4; a+=$8; r+=$11 } END { printf "committed %d · already committed %d · refused %d\n", c, a, r }'; }
PARSE=("$WORK/lender/bin/python" -I "$HERE/parse.py" --otlp "http://127.0.0.1:$PORT/v1/logs" docs)
say "the parser: pypdf and $MODEL read each PDF; the OpenTelemetry SDK exports each extraction"
"${PARSE[@]}"
got="$(totals 1)"; echo "otel-sink: $got"
[ "$got" = "committed 3 · already committed 0 · refused 0" ] || fail "otel-sink DID NOT COMMIT THE THREE RECORDS"
echo "the pipeline runs again over the same documents (same log.record.uid, new timestamps):"
from=$(($(wc -l < otel-sink.log) + 1))
"${PARSE[@]}" 2>/dev/null
tail -n "+$from" otel-sink.log | grep -m1 "refused:" || true
got="$(totals "$from")"; echo "otel-sink: $got"
[ "$got" = "committed 0 · already committed 0 · refused 3" ] || fail "A RE-RUN WAS NOT REFUSED"
kill -INT "$SINK_PID"; wait "$SINK_PID" 2>/dev/null || true; SINK_PID=""

say "checkpoint and verify"
show proof sink checkpoint --dir sink-data --key "$CKPT_PRIV" --heads "$HEADS" --first
verify
grep -q "all 3 chains verify" <<<"$LAST" || fail "VERIFY FAILED"

say "the dispute: applicant app-2c91 asks what the AI read from their application"
mkdir dispute
show proof sink export --dir sink-data --subject app-2c91 --disclose all --out dispute/bundle.json >/dev/null
cp "$CKPT_PUB" dispute/checkpoint.pub && cp "$REC_PUB" dispute/record.pub
echo "the lender sends bundle.json and its two public keys. The auditor binds the keys when"
echo "starting proof-mcp; the agent can name a file to check, never a key to trust:"
MCP=(proof-mcp --root dispute --bundle-checkpoint-key dispute/checkpoint.pub --bundle-record-trust dispute/record.pub)
echo "   claude mcp add proof-audit -- ${MCP[*]}"
AUDIT=(python3 -I "$HERE/mcp_verify.py")
show "${AUDIT[@]}" bundle.json -- "${MCP[@]}"
echo
echo "what the record says, and the applicant's own copy of the PDF:"
python3 -I "$HERE/show_record.py" dispute/bundle.json docs/LA-2026-0142.pdf

say "the cover-up: someone 'corrects' the extracted income before handing the bundle over"
python3 -I "$HERE/edit_bundle.py" dispute/bundle.json dispute/bundle-edited.json
rc=0; show "${AUDIT[@]}" bundle-edited.json -- "${MCP[@]}" || rc=$?
[ "$rc" -ne 0 ] || fail "THE EDITED BUNDLE VERIFIED"

say "the applicant asks to be forgotten: erase, signed, and checkpointed in one run"
show proof sink erase --dir sink-data --subject app-2c91 --key "$CKPT_PRIV" --heads "$HEADS" --record-key "$REC_PRIV"
verify
grep -q "all 3 chains verify" <<<"$LAST" || fail "VERIFY FAILED AFTER THE ERASURE"
if grep -q "app-2c91" <<<"$LAST"; then fail "VERIFY OUTPUT NAMES THE APPLICANT"; fi

say "done: the parser only emitted OpenTelemetry logs; each extraction is on the record with its document, model and prompt; a re-run was refused; an agent verified the bundle over MCP and refused the edited one; one applicant erased"
