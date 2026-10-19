#!/usr/bin/env bash
# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
#
# tag-check.sh — check a release's TAGS, not the working tree.
#
# WHY
#   release-check.sh checks the tree before it is tagged. What ships is the
#   tagged commit, fetched through the Go module proxy with no workspace and no
#   replace directive. cmd/proof-mcp/v0.3.0 was once tagged before the commit
#   that bumped its go.mod, so it required the previous library and did not
#   build; the fix was v0.3.1 and a retract. This script catches that before a
#   tag is pushed, and checks after the push that an outsider can install both.
#
# WHAT IT CHECKS
#   Local (before pushing a tag):
#     - v<X> and cmd/proof-mcp/v<X> both exist
#     - the CHANGELOG at the library tag has a "## v<X>" heading
#     - the proof-mcp tag's go.mod requires exactly proof v<X>
#     - each tagged tree, exported with git archive, builds with
#       GOWORK=off GOFLAGS=-mod=readonly (the proof-mcp build fetches the
#       library from the proxy, so the library tag must be pushed first)
#   --proxy (after pushing), in a clean container with no credentials:
#     - the proxy lists both versions
#     - go install of each binary BY EXACT VERSION works, and reports it
#     - the installed proof verifies the tagged demo chain and refuses the
#       tampered one
#
# USAGE
#   ./scripts/tag-check.sh v0.5.0            # before pushing cmd/proof-mcp/v0.5.0
#   ./scripts/tag-check.sh v0.5.0 --proxy    # after pushing both tags
#   PROOF_CHECK_IMAGE=docker.io/library/golang:1.25 ./scripts/tag-check.sh v0.5.0 --proxy

set -euo pipefail

IMAGE="${PROOF_CHECK_IMAGE:-docker.io/library/golang:1.25}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODULE="github.com/aleutian-ai/proof"

VERSION=""
PROXY=0
for arg in "$@"; do
    case "$arg" in
        --proxy) PROXY=1 ;;
        v*) [[ -z "$VERSION" ]] || { echo "one version only" >&2; exit 2; }; VERSION="$arg" ;;
        *) echo "unknown argument $arg" >&2; exit 2 ;;
    esac
done
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || {
    echo "usage: $0 vX.Y.Z [--proxy]" >&2; exit 2; }
LIB_TAG="$VERSION"
MCP_TAG="cmd/proof-mcp/$VERSION"

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; BLUE=$'\033[0;34m'; NC=$'\033[0m'
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
FAILED=0
step() { echo; echo "${BLUE}── $1${NC}"; }
ok()   { echo "   ${GREEN}PASS${NC} $1"; }
bad()  { echo "   ${RED}FAIL${NC} $1"; FAILED=$((FAILED+1)); }

git_() { git -C "$REPO_ROOT" "$@"; }

step "1. the tags ($LIB_TAG, $MCP_TAG)"
have_lib=0; have_mcp=0
if git_ rev-parse -q --verify "refs/tags/$LIB_TAG" >/dev/null; then ok "$LIB_TAG exists"; have_lib=1
else bad "$LIB_TAG does not exist"; fi
if git_ rev-parse -q --verify "refs/tags/$MCP_TAG" >/dev/null; then ok "$MCP_TAG exists"; have_mcp=1
else bad "$MCP_TAG does not exist: proof-mcp is a separate module with its own tag series; tag the commit that bumps its go.mod"; fi

if [[ $have_lib -eq 1 ]]; then
    # Read whole before matching: grep -q stops early, and under pipefail the
    # writer's SIGPIPE would read as a missing heading.
    changelog="$(git_ show "$LIB_TAG:CHANGELOG.md")"
    if grep -q "^## $VERSION " <<<"$changelog"; then
        ok "the CHANGELOG at $LIB_TAG has a $VERSION heading"
    else
        bad "the CHANGELOG at $LIB_TAG has no \"## $VERSION\" heading (still Unreleased?)"
    fi
fi
if [[ $have_mcp -eq 1 ]]; then
    mcp_gomod="$(git_ show "$MCP_TAG:cmd/proof-mcp/go.mod")"
    required="$(awk -v m="$MODULE" '$1==m {print $2} $1=="require" && $2==m {print $3}' <<<"$mcp_gomod" | head -1)"
    if [[ "$required" == "$VERSION" ]]; then
        ok "$MCP_TAG requires proof $VERSION"
    else
        bad "$MCP_TAG requires proof ${required:-<nothing>}, not $VERSION: it was tagged before its go.mod was bumped"
    fi
    if grep -q '^replace' <<<"$mcp_gomod"; then
        bad "$MCP_TAG's go.mod has a replace directive; go install refuses it"
    fi
fi

step "2. each tagged tree builds on its own (GOWORK=off GOFLAGS=-mod=readonly)"
build_tag() {
    local tag="$1" dir="$2" name="$3"
    local out="$WORK/$name"
    mkdir -p "$out"
    git_ archive "$tag" | tar -x -C "$out"
    if (cd "$out/$dir" && GOWORK=off GOFLAGS=-mod=readonly go build ./... ) >"$WORK/$name.log" 2>&1; then
        ok "$tag builds"
    else
        bad "$tag does not build from its own tree:"
        tail -5 "$WORK/$name.log"
    fi
}
[[ $have_lib -eq 1 ]] && build_tag "$LIB_TAG" . lib
[[ $have_mcp -eq 1 ]] && build_tag "$MCP_TAG" cmd/proof-mcp mcp

if [[ $PROXY -eq 1 && $have_lib -eq 1 ]]; then
    step "3. as an outsider: the proxy, in a clean container ($IMAGE)"
    mkdir -p "$WORK/demo"
    git_ archive "$LIB_TAG" testdata/demo | tar -x -C "$WORK/demo"
    # No credentials, no workspace, the public proxy and checksum database.
    if podman run --rm --network=host -v "$WORK/demo/testdata/demo:/demo:ro" \
        -e GOFLAGS= -e GOWORK=off -e GOPROXY=https://proxy.golang.org -e GONOSUMDB= -e GOPRIVATE= \
        "$IMAGE" sh -c '
set -e
v="$1"; m="$2"
for mod in "$m" "$m/cmd/proof-mcp"; do
    go list -m -versions "$mod" | tr " " "\n" | grep -qx "$v" || { echo "the proxy does not list $mod $v" >&2; exit 1; }
done
go install "$m/cmd/proof@$v"
go install "$m/cmd/proof-mcp@$v"
proof version | grep -q "proof $v" || { echo "proof version says: $(proof version)" >&2; exit 1; }
go version -m "$(command -v proof-mcp)" | grep -q "mod[[:space:]]*$m/cmd/proof-mcp[[:space:]]*$v" || { echo "proof-mcp is not $v" >&2; exit 1; }
proof verify /demo/entries.json >/dev/null
if proof verify /demo/entries-tampered.json >/dev/null 2>&1; then
    echo "THE TAMPERED DEMO CHAIN VERIFIED" >&2; exit 1
fi
' sh "$VERSION" "$MODULE" >"$WORK/proxy.log" 2>&1; then
        ok "the proxy lists proof and proof-mcp $VERSION"
        ok "both install by exact version, and say so"
        ok "the installed proof verifies the demo chain and refuses the tampered one"
    else
        bad "installing $VERSION from the proxy failed:"
        tail -8 "$WORK/proxy.log"
    fi
fi

echo
if [[ $FAILED -eq 0 ]]; then
    echo "${GREEN}tag-check: every check passed${NC}"
else
    echo "${RED}tag-check: $FAILED check(s) failed${NC}"; exit 1
fi
