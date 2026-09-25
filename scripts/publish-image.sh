#!/usr/bin/env bash
# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
#
# publish-image.sh — build and push the proof container images.
#
# WHY A SCRIPT AND NOT A PIPELINE
#   Publishing an image is a deliberate act with a human behind it. This script
#   is the whole of it: no hidden CI configuration, and the same commands a
#   reader can run to reproduce what was pushed.
#
# WHAT IT REFUSES
#   A dirty working tree. An image whose revision label points at a commit that
#   does not describe the code inside it is worse than no label at all — it
#   invites someone to audit the wrong source.
#
# USAGE
#   ./scripts/publish-image.sh v0.2.0              # check, build, push
#   ./scripts/publish-image.sh v0.2.0 --dry-run    # everything except the push
#   ./scripts/publish-image.sh v0.2.0 --skip-checks
#
# A prerelease (v1.0.0-rc.1) is never published as :latest.
#
#   REGISTRY=ghcr.io/aleutian-ai ./scripts/publish-image.sh v0.2.0
#
# Authentication is yours to arrange beforehand:
#   podman login ghcr.io

set -euo pipefail

REGISTRY="${REGISTRY:-ghcr.io/aleutian-ai}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; BLUE=$'\033[0;34m'; NC=$'\033[0m'
die() { echo "${RED}$1${NC}" >&2; exit 1; }
step() { echo; echo "${BLUE}── $1${NC}"; }

# Parse every argument. A misspelled --dry-run that is silently ignored would
# turn "show me what would happen" into a publication.
VERSION=""
DRY_RUN=0
SKIP_CHECKS=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)     DRY_RUN=1 ;;
        --skip-checks) SKIP_CHECKS=1 ;;
        -*)            die "unknown option '$1' (usage: $0 <version> [--dry-run] [--skip-checks])" ;;
        *)
            [[ -z "$VERSION" ]] || die "unexpected argument '$1'"
            VERSION="$1"
            ;;
    esac
    shift
done

[[ -n "$VERSION" ]] || die "usage: $0 <version> [--dry-run] [--skip-checks]"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] \
    || die "version must look like v0.2.0 (got '$VERSION')"
command -v podman >/dev/null || die "podman not found"

# A release candidate that quietly becomes :latest is how people end up running
# one by accident.
PRERELEASE=0
[[ "$VERSION" == *-* ]] && PRERELEASE=1

cd "$REPO_ROOT"

# ------------------------------------------------------------ preconditions
step "preconditions"
[[ -z "$(git status --porcelain)" ]] \
    || die "the working tree is dirty — commit or clean it first, so the image's revision label is true"
COMMIT="$(git rev-parse HEAD)"
echo "   version   $VERSION"
echo "   commit    $COMMIT"
echo "   registry  $REGISTRY"
echo "   platforms $PLATFORMS"

if git rev-parse "$VERSION" >/dev/null 2>&1; then
    TAGGED="$(git rev-parse "$VERSION"^{commit})"
    [[ "$TAGGED" == "$COMMIT" ]] \
        || die "tag $VERSION points at $TAGGED, not at HEAD — check out the tag you mean to publish"
    echo "   ${GREEN}HEAD is tagged $VERSION${NC}"
else
    echo "   (no git tag $VERSION yet; the image will still record the commit)"
fi

# ------------------------------------------------------------------- build
# A manifest list, so `podman pull` on either architecture gets the right
# binary without the user thinking about it.
step "building $PLATFORMS"
podman manifest rm "proof:$VERSION" 2>/dev/null || true
podman manifest rm "proof-mcp:$VERSION" 2>/dev/null || true

# --label, not --build-arg: an ARG interpolated into a LABEL does not
# invalidate podman's layer cache, so a second build with a different commit
# keeps the FIRST commit's label. --label is applied at commit time.
podman build --platform "$PLATFORMS" --manifest "proof:$VERSION" \
    --label "org.opencontainers.image.revision=$COMMIT" \
    --label "org.opencontainers.image.version=$VERSION" .
podman build --platform "$PLATFORMS" --manifest "proof-mcp:$VERSION" --target proof-mcp \
    --label "org.opencontainers.image.revision=$COMMIT" \
    --label "org.opencontainers.image.version=$VERSION" .

# Trust nothing about the label: read it back off the built image.
for img in "proof:$VERSION" "proof-mcp:$VERSION"; do
    got="$(podman image inspect --format '{{index .Labels "org.opencontainers.image.revision"}}' "$img" 2>/dev/null || true)"
    [[ "$got" == "$COMMIT" ]] \
        || die "$img records revision '$got', not $COMMIT — refusing to publish an image that misattributes its source"
done
echo "   ${GREEN}both images record $COMMIT${NC}"

# ------------------------------------------------------------------ verify
# Never push an image that has not verified a chain. A published verifier that
# cannot verify is the single most embarrassing outcome available here, so this
# runs the real check rather than merely starting the binary.
step "verifying the built image before it is pushed"
podman run --rm --network=none "proof:$VERSION" --help >/dev/null \
    || die "the built image cannot even print its usage"
echo "   the image starts"

if [[ "$SKIP_CHECKS" -eq 1 ]]; then
    echo "   ${RED}--skip-checks: the container checks did NOT run${NC}"
else
    echo "   running ./scripts/container-check.sh --quick (builds a chain and verifies it in the image)"
    "$REPO_ROOT/scripts/container-check.sh" --quick \
        || die "the container checks failed — nothing pushed"
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo
    echo "${GREEN}Dry run: built and checked, nothing pushed.${NC}"
    exit 0
fi

# -------------------------------------------------------------------- push
step "pushing to $REGISTRY"

# Name every ref that is about to move. "push v0.2.0?" is not consent to move
# :latest, which is what most people actually pull.
REFS=("proof:$VERSION" "proof-mcp:$VERSION")
if [[ "$PRERELEASE" -eq 1 ]]; then
    echo "   $VERSION is a prerelease — :latest will NOT be moved"
else
    REFS+=("proof:latest" "proof-mcp:latest")
fi
echo "   these refs will be written:"
for r in "${REFS[@]}"; do echo "     $REGISTRY/$r"; done

read -r -p "   push all of the above to $REGISTRY? [y/N] " reply
[[ "$reply" == "y" || "$reply" == "Y" ]] || die "aborted"

# A failure partway through leaves some refs moved and others not. Say which
# succeeded rather than dying silently mid-list.
PUSHED=()
for r in "${REFS[@]}"; do
    src="proof:$VERSION"
    [[ "$r" == proof-mcp:* ]] && src="proof-mcp:$VERSION"
    if ! podman manifest push --all "$src" "docker://$REGISTRY/$r"; then
        echo
        echo "${RED}push of $r FAILED.${NC} Already written: ${PUSHED[*]:-none}"
        die "the registry is in a partially updated state — finish or roll back by hand"
    fi
    PUSHED+=("$r")
done

echo
echo "${GREEN}Pushed.${NC}"
echo "    podman run --rm -v \"\$PWD:/data:ro\" $REGISTRY/proof:$VERSION verify /data/entries.json"
