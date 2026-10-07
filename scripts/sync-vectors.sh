#!/usr/bin/env bash
# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
#
# Vendor the conformance vectors into another implementation's tree, and verify
# every copy against fixtures/MANIFEST.json.
#
#   ./scripts/sync-vectors.sh --check <dir>...   verify only; exits 1 on drift
#   ./scripts/sync-vectors.sh --write <dir>...   copy the vectors in, then verify
#
# WHY THIS EXISTS
#
# `proof` is a separate public repository from the SDKs that implement the same
# format. One canonical copy lives here; every other implementation vendors it.
# Vendored copies drift silently, and a drifted vector is WORSE than a missing
# one because it looks like agreement. Four copies of chain_vectors.json existed
# when this was written, and two of them contained fabricated 64-character
# placeholder hashes left over from before the SHA-256 -> SHA-512 upgrade.
#
# WHAT THIS DELIBERATELY DOES NOT DO
#
# It never regenerates a vector from any implementation. The expected outputs
# are DATA. If an implementation disagrees with a vector, the implementation is
# what changes — or the format does, deliberately, with a version. Regenerating
# a vector to make a failing implementation pass is the exact circularity these
# vectors exist to break.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO_ROOT/fixtures/testdata"
MANIFEST="$REPO_ROOT/fixtures/MANIFEST.json"

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; NC=$'\033[0m'
MODE=""
TARGETS=()   # bash 3.2 (macOS) trips on ${#arr[@]} for an empty array under set -u

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check) MODE="check"; shift ;;
        --write) MODE="write"; shift ;;
        -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) echo "${RED}unknown option: $1${NC}" >&2; exit 2 ;;
        *) TARGETS+=("$1"); shift ;;
    esac
done

if [[ -z "$MODE" || ${#TARGETS[@]-0} -eq 0 ]]; then
    echo "usage: $0 --check|--write <dir>..." >&2
    exit 2
fi
[[ -f "$MANIFEST" ]] || { echo "${RED}missing $MANIFEST${NC}" >&2; exit 1; }

# The vector list comes from the MANIFEST, not from a directory listing: a file
# on disk that nobody recorded is exactly what this is meant to catch.
#
# A while-read loop rather than `mapfile`: macOS ships bash 3.2, which does not
# have it, and a tool that only runs on the author's machine is not a tool.
VECTORS=()
while IFS= read -r line; do
    VECTORS+=("$line")
done < <(python3 -c "
import json
print('\n'.join(sorted(json.load(open('$MANIFEST'))['vectors'])))
")

digest_of() { shasum -a 256 "$1" | awk '{print $1}'; }
expected_digest() {
    python3 -c "
import json,sys
print(json.load(open('$MANIFEST'))['vectors']['$1']['sha256'])
"
}

FAILED=0

for target in "${TARGETS[@]}"; do
    echo
    echo "── $target"
    if [[ ! -d "$target" ]]; then
        echo "   ${RED}FAIL${NC} not a directory"
        FAILED=$((FAILED + 1))
        continue
    fi

    # The manifest travels with the vectors: an implementation checks its copies
    # against the manifest beside them, so a stale manifest would let stale
    # copies pass that check.
    if [[ "$MODE" == "write" ]]; then
        cp "$MANIFEST" "$target/MANIFEST.json"
    fi
    if [[ ! -f "$target/MANIFEST.json" ]]; then
        echo "   ${YELLOW}MISSING${NC} MANIFEST.json  (run with --write to vendor it)"
        FAILED=$((FAILED + 1))
    elif cmp -s "$MANIFEST" "$target/MANIFEST.json"; then
        echo "   ${GREEN}OK${NC}      MANIFEST.json"
    else
        echo "   ${RED}DRIFT${NC}   MANIFEST.json (a stale contract: re-vendor with --write)"
        FAILED=$((FAILED + 1))
    fi

    for v in "${VECTORS[@]}"; do
        want="$(expected_digest "$v")"
        dest="$target/$v"

        if [[ "$MODE" == "write" ]]; then
            cp "$SRC/$v" "$dest"
        fi

        if [[ ! -f "$dest" ]]; then
            echo "   ${YELLOW}MISSING${NC} $v  (run with --write to vendor it)"
            FAILED=$((FAILED + 1))
            continue
        fi

        got="$(digest_of "$dest")"
        if [[ "$got" == "$want" ]]; then
            echo "   ${GREEN}OK${NC}      $v"
        else
            echo "   ${RED}DRIFT${NC}   $v"
            echo "             vendored ${got:0:16}…"
            echo "             canonical ${want:0:16}…"
            echo "             This copy is NOT the vector every other implementation"
            echo "             is held to. Re-vendor with --write, or work out why it"
            echo "             changed — do not edit it to match."
            FAILED=$((FAILED + 1))
        fi
    done
done

echo
if [[ "$FAILED" -gt 0 ]]; then
    echo "${RED}${FAILED} problem(s).${NC}"
    exit 1
fi
echo "${GREEN}Every vendored copy matches the canonical vectors.${NC}"
