#!/usr/bin/env bash
# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
#
# make-demo.sh — write the small demo chain the README's quickstart verifies.
#
# WHY
#   The quickstart used to verify an entries.json the reader did not have, and
#   showed no example of what `proof commit` reads. testdata/demo/ is a chain a
#   reader can verify the moment the repository is cloned, with the input it
#   was made from, an anchor over it, and a copy that has been tampered with.
#
# WHAT IT WRITES (testdata/demo/)
#   input.jsonl            what `proof commit` read: five entries, one per line
#   entries.json           the chain `proof export` wrote from that input
#   anchor.json            a signed anchor over the five entries
#   anchor-public.pem      the ML-DSA-65 public key that verifies the anchor
#   entries-tampered.json  entries.json with one entry's timestamp changed
#
# HOW
#   It builds the CLI from this tree into a temporary directory and runs the
#   same verbs a user would: init, commit, export, keygen, anchor. The signing
#   key is generated for the run and its PRIVATE half is deleted with the
#   temporary directory; it never enters the repository.
#
# NOT REPRODUCIBLE BYTE FOR BYTE, on purpose
#   input.jsonl, entries.json and entries-tampered.json come out the same every
#   run: the input is fixed and chain hashes are a function of it. anchor.json
#   and anchor-public.pem do not: each run makes a new key, a new anchor id and
#   a new signing time. Rerun this only to change the demo; then rerun the
#   README's commands and paste what they print.
#
# USAGE
#   ./scripts/make-demo.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO="$REPO_ROOT/testdata/demo"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# Never into the repository: a binary built at the root is what a later
# `git add .` picks up.
go -C "$REPO_ROOT" build -o "$WORK/proof" ./cmd/proof
proof() { "$WORK/proof" "$@"; }

mkdir -p "$DEMO"

# The input. content_hash is the SHA-512 of the evidence itself, which proof
# never sees; here the "evidence" is five short strings. ingested_at orders the
# batch and is not stored.
python3 - "$DEMO/input.jsonl" <<'PY'
import hashlib, json, sys
with open(sys.argv[1], "w") as f:
    for i in range(5):
        f.write(json.dumps({
            "entry_id": f"ent_{i:03d}",
            "entry_type": "event",
            "timestamp": f"2026-10-13T09:00:{i:02d}.000000Z",
            "ingested_at": f"2026-10-13T09:00:{i:02d}.250000Z",
            "content_hash": hashlib.sha512(f"demo evidence {i}".encode()).hexdigest(),
        }, separators=(",", ":")) + "\n")
PY

proof init   --db "$WORK/demo.db"
proof commit --db "$WORK/demo.db" --chain demo < "$DEMO/input.jsonl"
proof export --db "$WORK/demo.db" --chain demo --out "$DEMO/entries.json" --force

proof keygen --alg ml-dsa-65 --out-dir "$WORK/keys" >/dev/null
proof anchor --db "$WORK/demo.db" --chain demo --subject demo-chain \
    --key "$WORK/keys/ml-dsa-65-private.pem" --out "$DEMO/anchor.json" --force
cp "$WORK/keys/ml-dsa-65-public.pem" "$DEMO/anchor-public.pem"

# The tampered copy: entry ent_002's timestamp moved by one second. The
# timestamp is inside the chain hash, so that entry no longer hashes to the
# value stored for it.
sed 's/T09:00:02\.000000Z/T09:00:03.000000Z/' "$DEMO/entries.json" > "$DEMO/entries-tampered.json"
if cmp -s "$DEMO/entries.json" "$DEMO/entries-tampered.json"; then
    echo "the tampered copy is identical to the original; the sed pattern matched nothing" >&2
    exit 1
fi

# The demo must behave as the README says before it is left on disk.
proof verify "$DEMO/entries.json" >/dev/null
proof verify "$DEMO/entries.json" --anchor "$DEMO/anchor.json" --key "$DEMO/anchor-public.pem" >/dev/null
if proof verify "$DEMO/entries-tampered.json" >/dev/null 2>&1; then
    echo "the tampered copy verifies; the demo is wrong" >&2
    exit 1
fi

echo "wrote $DEMO:"
ls -1 "$DEMO"
