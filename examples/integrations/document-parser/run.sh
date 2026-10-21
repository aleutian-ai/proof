#!/usr/bin/env bash
# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
#
# run.sh — an AI document parser whose every extraction is on the record.
#
#   1. three loan applications (PDF) come in; parse.py reads each with pypdf
#      and a local model (Ollama), and prints one record per document
#   2. `proof sink commit` files each record on its applicant's own opaque
#      chain; committing the same output again records nothing twice
#   3. a signed checkpoint, and `proof sink verify`
#   4. the dispute: an applicant asks what the AI read from their application.
#      The lender exports their records; an auditor checks the bundle with the
#      published Python verifier, which shares no code with the Go writer, and
#      checks the document hash against their own copy of the PDF
#   5. the cover-up: the record is "corrected" before it is handed over, and
#      the auditor's verifier refuses it
#   6. the applicant asks to be forgotten: their records are erased, signed,
#      and the sink still verifies
#
#   ./run.sh                          # ministral-3:3b
#   MODEL=ornith-1.5:9b ./run.sh     # any Ollama model
#   KEEP=/tmp/loan ./run.sh          # keep the folder (a new, empty one): demo.tape uses it
#
# Needs Go, Python 3.10+, network access to PyPI, and Ollama with the model
# pulled. Builds proof from this working tree. Leaves nothing behind, unless
# KEEP is set.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
export MODEL="${MODEL:-ministral-3:3b}"
if [ -n "${KEEP:-}" ]; then
    [ ! -e "$KEEP" ] || [ -z "$(ls -A "$KEEP")" ] || { echo "KEEP=$KEEP is not empty" >&2; exit 2; }
    mkdir -p "$KEEP" && WORK="$(cd "$KEEP" && pwd)"
else
    WORK="$(mktemp -d)"
    trap 'rm -rf "$WORK"' EXIT
fi

say() { printf '\n\033[0;34m── %s\033[0m\n' "$*"; }
show() { printf '$ %s\n' "$*"; "$@"; }
fail() { echo "$*" >&2; exit 1; }

curl -fsS -m 3 "${OLLAMA_URL:-http://127.0.0.1:11434}/api/version" >/dev/null ||
    fail "Ollama is not answering on ${OLLAMA_URL:-http://127.0.0.1:11434}"

say "build proof from this working tree; two Python environments, the lender's and the auditor's"
mkdir -p "$WORK/bin"
(cd "$REPO" && go build -o "$WORK/bin/proof" ./cmd/proof)
export PATH="$WORK/bin:$PATH"
PIP=(install -q --disable-pip-version-check)
python3 -m venv "$WORK/lender" && "$WORK/lender/bin/pip" "${PIP[@]}" pypdf==6.15.0
# The auditor's verifier is the published one, from PyPI: not this tree, not Go.
python3 -m venv "$WORK/auditor" && "$WORK/auditor/bin/pip" "${PIP[@]}" aleutian-verification==0.6.0
aleutian-verify() { "$WORK/auditor/bin/aleutian-verify" "$@"; }
cd "$WORK"

say "three loan applications arrive (made up: people, lender and numbers)"
python3 -I "$HERE/make_applications.py" docs
ls docs

say "keys: proof sink init"
proof sink init --dir sink-data >/dev/null
K="sink-data.keys"
CKPT_PRIV="$K/ml-dsa-65-checkpoint-private.pem" CKPT_PUB="$K/ml-dsa-65-checkpoint-public.pem"
REC_PRIV="$K/ml-dsa-65-record-private.pem" REC_PUB="$K/ml-dsa-65-record-public.pem"
HEADS="checkpoint-heads.json" # outside sink-data: the record that a checkpoint series was not restarted
VERIFY=(proof sink verify --dir sink-data --key "$CKPT_PUB" --record-trust "$REC_PUB" --heads "$HEADS")
verify() { LAST="$("${VERIFY[@]}")"; printf '$ %s\n%s\n' "${VERIFY[*]}" "$LAST"; }
COMMIT=(proof sink commit --dir sink-data --class loan-extractions --subject-field applicant
        --source-field doc_id --record-key "$REC_PRIV")

say "the parser: pypdf reads each PDF, $MODEL extracts the fields, one record per document"
"$WORK/lender/bin/python" -I "$HERE/parse.py" docs > records.jsonl
echo "one record, as committed:"
head -1 records.jsonl | python3 -m json.tool

say "commit: each record on its applicant's own chain, signed"
printf '$ %s < records.jsonl\n' "${COMMIT[*]}"
"${COMMIT[@]}" < records.jsonl
echo "the same records again (a retried batch, a re-run of the pipeline):"
out="$("${COMMIT[@]}" < records.jsonl)"; echo "$out"
grep -q "committed 0 entries" <<<"$out" || fail "A RE-RUN WAS COMMITTED TWICE"

say "checkpoint and verify"
show proof sink checkpoint --dir sink-data --key "$CKPT_PRIV" --heads "$HEADS" --first
verify
grep -q "all 3 chains verify" <<<"$LAST" || fail "VERIFY FAILED"

say "the dispute: applicant app-2c91 asks what the AI read from their application"
show proof sink export --dir sink-data --subject app-2c91 --disclose all --out bundle.json >/dev/null
echo "the lender sends bundle.json and its two public keys. The auditor, with only those:"
AUDIT=(aleutian-verify verify-proof-bundle --checkpoint-key "$CKPT_PUB" --record-key "$REC_PUB")
show "${AUDIT[@]}" bundle.json
echo
echo "what the record says, and the applicant's own copy of the PDF:"
python3 -I "$HERE/show_record.py" bundle.json docs/LA-2026-0142.pdf
echo "   this is what the model read from it, and nobody has changed it since"

say "the cover-up: someone 'corrects' the extracted income before handing the bundle over"
python3 -I "$HERE/edit_bundle.py" bundle.json bundle-edited.json
rc=0; show "${AUDIT[@]}" bundle-edited.json || rc=$?
[ "$rc" -ne 0 ] || fail "THE EDITED BUNDLE VERIFIED"
echo "(exit $rc: the auditor's verifier refuses the edited record)"

say "the applicant asks to be forgotten: erase, signed, and checkpointed in one run"
show proof sink erase --dir sink-data --subject app-2c91 --key "$CKPT_PRIV" --heads "$HEADS" --record-key "$REC_PRIV"
verify
grep -q "all 3 chains verify" <<<"$LAST" || fail "VERIFY FAILED AFTER THE ERASURE"
if grep -q "app-2c91" <<<"$LAST"; then fail "VERIFY OUTPUT NAMES THE APPLICANT"; fi

say "done: every extraction recorded with its document, model and prompt; a re-run recorded nothing twice; an edited record refused by an independent verifier; one applicant erased"
