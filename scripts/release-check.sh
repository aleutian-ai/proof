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
#   3. here:   the THIRD_PARTY_LICENSES file each image ships still lists
#              exactly the modules its binary links
#   4. Linux:  go vet and go test -race for both modules, in a container, with
#              the tree COPIED into the container's own filesystem. A mounted
#              macOS folder is not ext4, and the inode behaviour is the point.
#   5. linux/amd64: the crypto packages again, under emulation, when this
#              machine is not amd64. The hashing, ML-KEM and ML-DSA code has
#              per-architecture assembly, and an arm64 machine otherwise never
#              runs the amd64 half. SKIPPED with a notice, not failed, when
#              podman cannot run an amd64 container here.
#
# NOT COVERED
#   The published images and the install lines: scripts/container-check.sh.
#   Signing and publishing: scripts/publish-image.sh.
#
# USAGE
#   ./scripts/release-check.sh                 # everything
#   ./scripts/release-check.sh --local         # steps 1 to 3 only
#   ./scripts/release-check.sh <sdk-testdata-dir>...   # also check vendored vector copies
#   PROOF_CHECK_IMAGE=docker.io/library/golang:1.25 ./scripts/release-check.sh
#   PROOF_CHECK_IMAGE_AMD64=docker.io/amd64/golang:1.25 ./scripts/release-check.sh

set -euo pipefail

# Debian-based, not Alpine: the race detector needs cgo and a C toolchain.
IMAGE="${PROOF_CHECK_IMAGE:-docker.io/library/golang:1.25}"
# A single-architecture repository, not the same tag with --platform: pulling
# the amd64 variant of a multi-architecture tag REPLACES the local copy of that
# tag, and the next run of step 4 would then run emulated without saying so.
IMAGE_AMD64="${PROOF_CHECK_IMAGE_AMD64:-docker.io/amd64/golang:1.25}"
# The packages whose results depend on the CPU: hashing, the KEMs, ML-DSA, and
# the formats built directly on them.
CRYPTO_PACKAGES="./xwing/... ./mlkem/... ./mldsa/... ./keywrap/... ./keyfile/... ./merkle/... ./commitment/... ./canonical/... ./chainformat/... ./anchor/..."
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

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; BLUE=$'\033[0;34m'; NC=$'\033[0m'
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
FAILED=0

step() { echo; echo "${BLUE}── $1${NC}"; }
ok()   { echo "   ${GREEN}PASS${NC} $1"; }
bad()  { echo "   ${RED}FAIL${NC} $1"; FAILED=$((FAILED+1)); }
# skip: a check that could not run here. Shown, counted, and not a failure.
SKIPPED=0
skip() { echo "   ${YELLOW}SKIPPED${NC} $1"; SKIPPED=$((SKIPPED+1)); }

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
for script in independent-vectors.py spec-vectors.py verdict-vectors.py; do
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

step "3. third-party licence files"
# Each image ships the licences of the modules its binary links. A dependency
# added, removed or bumped without regenerating the files leaves an image
# redistributing code whose notice it does not carry.
run "licenses/*/THIRD_PARTY_LICENSES list what the binaries link" "$REPO_ROOT/scripts/third-party-licenses.sh" --check

# tree_tar: the tree as a tar stream, to be unpacked INSIDE a container so the
# tests run on the container's filesystem. No .git, no binaries.
# COPYFILE_DISABLE and the ._* exclude: macOS tar otherwise adds an AppleDouble
# "._name" file beside every file that has extended attributes, and a test that
# lists a directory then sees files that are not in the tree.
tree_tar() {
    COPYFILE_DISABLE=1 tar -C "$REPO_ROOT" --exclude .git --exclude .review --exclude '*.test' \
        --exclude '._*' -cf - .
}

if [[ $LOCAL_ONLY -eq 0 ]]; then
    step "4. Linux ($IMAGE): vet and race tests, tree copied into the container"
    if ! command -v podman >/dev/null 2>&1; then
        bad "podman is not installed; the Linux checks did not run"
    else
        if tree_tar | podman run --rm -i "$IMAGE" sh -c '
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

    step "5. linux/amd64 ($IMAGE_AMD64): the crypto packages, under emulation"
    # Not a failure when it cannot run: emulation is a property of this machine
    # (qemu-user or Rosetta in the podman machine), not of the tree. The notice
    # is there so that "passed" is never read as "passed on amd64".
    host_arch="$(podman info --format '{{.Host.Arch}}' 2>/dev/null || echo '?')"
    if ! command -v podman >/dev/null 2>&1; then
        skip "podman is not installed; the crypto packages were NOT run on linux/amd64"
    elif [[ "$host_arch" == "amd64" ]]; then
        ok "this machine is amd64: step 4 already ran every package there"
    elif [[ "$(podman run --rm --platform linux/amd64 "$IMAGE_AMD64" uname -m 2>"$WORK/amd64-probe.log")" != "x86_64" ]]; then
        skip "cannot run a linux/amd64 container here; the crypto packages were NOT run on amd64"
        echo "           $(tail -1 "$WORK/amd64-probe.log" 2>/dev/null || true)"
        echo "           (needs amd64 emulation in the podman machine, and $IMAGE_AMD64)"
    else
        # No race detector: it needs cgo, and under emulation it is slow enough
        # to time out. Step 4 ran it natively. This step is about the amd64
        # assembly paths producing the same answers.
        if tree_tar | podman run --rm -i --platform linux/amd64 -e CRYPTO_PACKAGES="$CRYPTO_PACKAGES" "$IMAGE_AMD64" sh -c '
set -e
mkdir /work && tar -C /work -xf -
cd /work
rm -f go.work go.work.sum
echo "== $(go env GOOS)/$(go env GOARCH) on $(uname -m)"
[ "$(go env GOARCH)" = amd64 ]
CGO_ENABLED=0 go test -count=1 -timeout 1800s $CRYPTO_PACKAGES
' >"$WORK/amd64.log" 2>&1; then
            ok "go test, crypto packages, linux/amd64 (emulated on $host_arch)"
        else
            bad "crypto packages on linux/amd64"
            { grep -E "^(--- FAIL|FAIL|panic)" "$WORK/amd64.log" | head -15 || true; }
            tail -8 "$WORK/amd64.log" || true
        fi
    fi
fi

echo
if [[ $FAILED -eq 0 && $SKIPPED -gt 0 ]]; then
    echo "${GREEN}release-check: every check that ran passed${NC}; ${YELLOW}$SKIPPED skipped, see above${NC}"
elif [[ $FAILED -eq 0 ]]; then
    echo "${GREEN}release-check: every check passed${NC}"
else
    echo "${RED}release-check: $FAILED check(s) failed${NC}"
    exit 1
fi
