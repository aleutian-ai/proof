#!/usr/bin/env bash
# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
#
# release-check.sh — the gate a tree must pass before it is tagged.
#
# WHY
#   Two review findings were invisible on the maintainer's machine. Two sink
#   tests failed only on Linux (ext4 hands a freed inode straight back; APFS
#   does not), and nothing ran `go vet` or the race detector on both modules.
#   This runs the checks that decide whether a commit can be released, on this
#   machine and then on Linux.
#
# WHAT IT RUNS
#   1. here:   gofmt, go vet, go test for both modules
#   2. here:   the conformance vectors reproduce from their scripts, byte for
#              byte, and every vendored copy matches fixtures/MANIFEST.json
#   3. Linux:  go vet and go test -race for both modules, in a container, with
#              the tree COPIED into the container's own filesystem. A mounted
#              macOS folder is not ext4, and the inode behaviour is the point.
#
# NOT COVERED
#   The published images and the install lines: scripts/container-check.sh.
#   Signing and publishing: scripts/publish-image.sh.
#
# USAGE
#   ./scripts/release-check.sh                 # everything
#   ./scripts/release-check.sh --local         # steps 1 and 2 only
#   ./scripts/release-check.sh <sdk-testdata-dir>...   # also check vendored vector copies
#   PROOF_CHECK_IMAGE=docker.io/library/golang:1.25 ./scripts/release-check.sh

set -euo pipefail

# Debian-based, not Alpine: the race detector needs cgo and a C toolchain.
IMAGE="${PROOF_CHECK_IMAGE:-docker.io/library/golang:1.25}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_ONLY=0
VENDORED=()
for arg in "$@"; do
    case "$arg" in
        --local) LOCAL_ONLY=1 ;;
        -*) echo "unknown flag $arg" >&2; exit 2 ;;
        *) VENDORED+=("$arg") ;;
    esac
done

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; BLUE=$'\033[0;34m'; NC=$'\033[0m'
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
FAILED=0

step() { echo; echo "${BLUE}── $1${NC}"; }
ok()   { echo "   ${GREEN}PASS${NC} $1"; }
bad()  { echo "   ${RED}FAIL${NC} $1"; FAILED=$((FAILED+1)); }

# run NAME CMD...: run a command, keep its output, show the end of it on failure.
run() {
    local name="$1"; shift
    local log="$WORK/$(echo "$name" | tr ' /' '__').log"
    if "$@" >"$log" 2>&1; then
        ok "$name"
    else
        bad "$name"
        { grep -E "^(--- FAIL|FAIL|panic)" "$log" | head -10 || true; }
        tail -5 "$log" || true
    fi
}

step "1. this machine: gofmt, vet, tests (both modules)"
unformatted="$(gofmt -l "$REPO_ROOT" 2>/dev/null | grep -v '/\.review/' || true)"
if [[ -z "$unformatted" ]]; then ok "gofmt"; else bad "gofmt: $unformatted"; fi
run "go vet (library)"   go -C "$REPO_ROOT" vet ./...
run "go test (library)"  go -C "$REPO_ROOT" test -count=1 ./...
run "go vet (proof-mcp)"  go -C "$REPO_ROOT/cmd/proof-mcp" vet ./...
run "go test (proof-mcp)" go -C "$REPO_ROOT/cmd/proof-mcp" test -count=1 ./...

step "2. conformance vectors"
# The vectors are data: regenerating them must change nothing. A script that
# now produces different bytes means a vector was edited by hand, or the script
# was changed without the vector being regenerated on purpose.
cp -R "$REPO_ROOT/fixtures" "$WORK/fixtures.before"
vectors_ok=1
for script in independent-vectors.py verdict-vectors.py; do
    python3 "$REPO_ROOT/scripts/$script" >"$WORK/$script.log" 2>&1 || { bad "$script did not run"; tail -3 "$WORK/$script.log"; vectors_ok=0; }
done
if ! diff -r "$WORK/fixtures.before" "$REPO_ROOT/fixtures" >"$WORK/vectors.diff" 2>&1; then
    bad "regenerating the vectors changed them (restored); see the diff below"
    head -10 "$WORK/vectors.diff"
    rm -rf "$REPO_ROOT/fixtures"; cp -R "$WORK/fixtures.before" "$REPO_ROOT/fixtures"
    vectors_ok=0
fi
[[ $vectors_ok -eq 1 ]] && ok "the vectors reproduce from their scripts, byte for byte"
if [[ ${#VENDORED[@]} -gt 0 ]]; then
    run "vendored copies match MANIFEST.json" "$REPO_ROOT/scripts/sync-vectors.sh" --check "${VENDORED[@]}"
fi

if [[ $LOCAL_ONLY -eq 0 ]]; then
    step "3. Linux ($IMAGE): vet and race tests, tree copied into the container"
    if ! command -v podman >/dev/null 2>&1; then
        bad "podman is not installed; the Linux checks did not run"
    else
        # The tree goes in as a tar stream and is unpacked inside the container,
        # so the tests run on the container's filesystem. No .git, no binaries.
        # COPYFILE_DISABLE and the ._* exclude: macOS tar otherwise adds an
        # AppleDouble "._name" file beside every file that has extended
        # attributes, and a test that lists a directory then sees files that
        # are not in the tree.
        if COPYFILE_DISABLE=1 tar -C "$REPO_ROOT" --exclude .git --exclude .review --exclude '*.test' \
            --exclude '._*' -cf - . \
            | podman run --rm -i "$IMAGE" sh -c '
set -e
mkdir /work && tar -C /work -xf -
cd /work
rm -f go.work go.work.sum
go work init . ./cmd/proof-mcp
echo "== vet"
go vet ./... && (cd cmd/proof-mcp && go vet ./...)
echo "== test -race (library)"
go test -race -count=1 -timeout 1800s ./...
echo "== test -race (proof-mcp)"
cd cmd/proof-mcp && go test -race -count=1 ./...
' >"$WORK/linux.log" 2>&1; then
            ok "go vet and go test -race, both modules, linux/$(podman info --format '{{.Host.Arch}}' 2>/dev/null || echo '?')"
        else
            bad "Linux checks"
            { grep -E "^(--- FAIL|FAIL|panic|WARNING: DATA RACE)" "$WORK/linux.log" | head -15 || true; }
            tail -8 "$WORK/linux.log" || true
        fi
    fi
fi

echo
if [[ $FAILED -eq 0 ]]; then
    echo "${GREEN}release-check: every check passed${NC}"
else
    echo "${RED}release-check: $FAILED check(s) failed${NC}"
    exit 1
fi
