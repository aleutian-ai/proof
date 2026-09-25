#!/usr/bin/env bash
# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
#
# container-check.sh — validate proof on Linux, in containers, the way a user
# meets it.
#
# WHY
#   Local `go test` runs on the maintainer's machine, with the maintainer's
#   toolchain, against the working tree. None of that is what an adopter has.
#   This checks the five things that only a clean machine can answer:
#
#     1. the README quickstart works on a clean machine (both install lines)
#     2. a chain built on THIS machine verifies on Linux, using the PUBLISHED
#        binary — the product's central claim, across an OS boundary
#     3. the container image verifies a chain built on the host, runs as a
#        non-root user, contains no shell, and needs no network
#     4. the full suite passes on linux/arm64
#     5. the crypto packages pass on linux/amd64, where circl uses different
#        assembly than on arm64
#
#   Check 2 is the important one. Everything else is a build; that one is the
#   guarantee.
#
# NOT COVERED
#   Aleutian's production images build with GOEXPERIMENT=boringcrypto and CGO,
#   which needs glibc; these run on Alpine (musl). The boringcrypto link step is
#   exercised by building the platform's own image — see the note at the end.
#
# USAGE
#   ./scripts/container-check.sh              # all checks
#   ./scripts/container-check.sh --quick      # skip the emulated amd64 run
#   PROOF_IMAGE=docker.io/library/golang:1.26-alpine ./scripts/container-check.sh

set -euo pipefail

IMAGE="${PROOF_IMAGE:-docker.io/library/golang:1.25-alpine}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QUICK=0
[[ "${1:-}" == "--quick" ]] && QUICK=1

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; BLUE=$'\033[0;34m'; NC=$'\033[0m'
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
FAILED=0

step() { echo; echo "${BLUE}── $1${NC}"; }
ok()   { echo "   ${GREEN}PASS${NC} $1"; }
bad()  { echo "   ${RED}FAIL${NC} $1"; FAILED=$((FAILED+1)); }

command -v podman >/dev/null || { echo "${RED}podman not found${NC}" >&2; exit 2; }

# ---------------------------------------------------------------- 1. fixtures
# Build a chain with the LOCAL code, then verify it with the PUBLISHED binary
# inside the container. Producer and verifier are deliberately different
# builds, on different operating systems.
step "building a chain locally (producer: this machine, $(go env GOOS)/$(go env GOARCH))"
mkdir -p "$WORK/mod" "$WORK/out"
cat > "$WORK/mod/go.mod" <<EOF
module containercheck
go 1.25.0
require github.com/aleutian-ai/proof v0.0.0
replace github.com/aleutian-ai/proof => ${REPO_ROOT}
EOF
cat > "$WORK/mod/main.go" <<'EOF'
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aleutian-ai/proof/linker"
	"github.com/aleutian-ai/proof/store/memory"
	"github.com/aleutian-ai/proof/verify"
)

func main() {
	base := time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC)
	// Two chains, deliberately. The PUBLISHED binary in check 2 predates v3 and
	// can only read v2 — feeding it v3 would report a format change as a broken
	// chain. Checking it against v2 also proves the compatibility promise: a
	// released verifier keeps verifying the chains it always could.
	buildChain(base, "v2", linker.WithFormatV2())
	buildChain(base, "")
}

func buildChain(base time.Time, suffix string, opts ...linker.Option) {
	st := memory.New()
	l, err := linker.New(st, opts...)
	if err != nil {
		panic(err)
	}
	var batch []linker.Input
	for i := 0; i < 6; i++ {
		batch = append(batch, linker.Input{
			EntryID:     fmt.Sprintf("e%02d", i),
			EntryType:   "capture.request.v3",
			Timestamp:   base.Add(time.Duration(i) * time.Second),
			ContentHash: strings.Repeat(fmt.Sprintf("%02x", i), 64),
			IngestedAt:  base.Add(time.Duration(i) * time.Second),
		})
	}
	if _, err := l.Append(context.Background(), "container-check", batch); err != nil {
		panic(err)
	}
	rows, err := st.Range(context.Background(), "container-check", 0, 1<<40, 0)
	if err != nil {
		panic(err)
	}
	out := make([]verify.Entry, len(rows))
	for i, r := range rows {
		out[i] = verify.Entry{
			EntryID: r.EntryID, EntryType: r.EntryType,
			Timestamp:     r.Timestamp.UTC().Format("2006-01-02T15:04:05.000000Z"),
			FormatVersion: r.FormatVersion,
			RunID:         r.RunID, SequenceNum: r.SequenceNum, GlobalSeq: r.GlobalSeq,
			ContentHash: r.ContentHash, ChainHash: r.ChainHash,
		}
	}
	write := func(name string, v any) {
		b, _ := json.MarshalIndent(v, "", " ")
		if err := os.WriteFile(os.Args[1]+"/"+name, append(b, '\n'), 0o644); err != nil {
			panic(err)
		}
	}
	name := func(stem string) string {
		if suffix == "" {
			return stem + ".json"
		}
		return stem + "-" + suffix + ".json"
	}
	write(name("entries"), out)
	tampered := append([]verify.Entry(nil), out...)
	tampered[3].ContentHash = strings.Repeat("ab", 64)
	write(name("entries-tampered"), tampered)
	label := suffix
	if label == "" {
		label = "v3"
	}
	fmt.Printf("   %s: %d entries, head %s…\n", label, len(out), out[len(out)-1].ChainHash[:16])
}
EOF
(cd "$WORK/mod" && GOFLAGS=-mod=mod go mod tidy >/dev/null 2>&1 && go run . "$WORK/out")

# --------------------------------------- 2. quickstart + cross-platform verify
step "README quickstart + cross-platform verification (${IMAGE})"
if podman run --rm -v "$WORK/out:/data:ro" "$IMAGE" sh -c '
set -e
go install github.com/aleutian-ai/proof/cmd/proof@latest
go install github.com/aleutian-ai/proof/cmd/proof-mcp@latest
command -v proof >/dev/null && command -v proof-mcp >/dev/null
proof verify /data/entries-v2.json >/dev/null
if proof verify /data/entries-tampered-v2.json >/dev/null 2>&1; then
    echo "TAMPERED CHAIN VERIFIED AS INTACT" >&2
    exit 1
fi
proof verify /data/entries-tampered-v2.json >/dev/null 2>&1 || [ $? -eq 1 ]
' >"$WORK/log1" 2>&1; then
    ok "both install lines work; a locally built v2 chain verifies on Linux"
    ok "the RELEASED verifier still reads v2 — the compatibility promise holds"
    ok "the tampered chain is rejected with exit 1"
else
    bad "quickstart or cross-platform verification failed:"; sed 's/^/        /' "$WORK/log1" | tail -5
fi

# ------------------------------------------------------------ 3. the image
# The image is how an auditor is most likely to meet this tool: no Go
# toolchain, nothing installed, nothing to trust but the binary. So it gets the
# same cross-platform test as the install path — a chain built HERE, verified
# THERE.
step "container image (scratch + static binary)"

# Remove any image from a previous run FIRST. Otherwise a failed build leaves
# the old proof:check in local storage and every check below passes — against
# yesterday's image.
podman rmi -f proof:check proof-mcp:check >/dev/null 2>&1 || true

HEAD_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
# --label, not --build-arg: an ARG interpolated into a LABEL is not cache-keyed,
# so a changed commit would silently keep the previous image's label.
if podman build -t proof:check \
       --label "org.opencontainers.image.revision=$HEAD_COMMIT" \
       "$REPO_ROOT" >"$WORK/build.log" 2>&1; then
    ok "image builds"
    IMAGE_BUILT=1
else
    bad "image build failed:"; tail -5 "$WORK/build.log" | sed 's/^/        /'
    IMAGE_BUILT=0
fi

# Every check below inspects the image that was just built. If there is no such
# image, they must be SKIPPED, not run against whatever is lying around.
if [[ "$IMAGE_BUILT" -eq 0 ]]; then
    echo "   (skipping the remaining image checks: nothing was built)"
else

    if podman run --rm -v "$WORK/out:/data:ro" proof:check verify /data/entries.json >/dev/null 2>&1; then
        ok "a locally built chain verifies inside the image"
    else
        bad "the image could not verify a good chain"
    fi

    # `set -e` would kill the script on the expected non-zero exit, so capture it.
    rc=0
    podman run --rm -v "$WORK/out:/data:ro" proof:check verify /data/entries-tampered.json >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -eq 1 ]]; then
        ok "the tampered chain is rejected with exit 1"
    else
        bad "the image did not reject the tampered chain with exit 1"
    fi

    # A verifier that runs as root in a container it did not need root for is a
    # gratuitous risk on whatever machine the auditor is borrowing.
    if [[ "$(podman inspect --format '{{.Config.User}}' proof:check)" == "65532:65532" ]]; then
        ok "runs as a non-root user"
    else
        bad "the image does not run as a non-root user"
    fi

    # Nothing but the binary: no shell to drop into, no package manager to pull
    # from, and so nothing to audit but the thing being audited.
    if podman run --rm --entrypoint /bin/sh proof:check -c 'echo reachable' >/dev/null 2>&1; then
        bad "the image contains a shell"
    else
        ok "no shell in the image"
    fi

    # The runtime claim is "no network, no credentials". Prove it rather than
    # asserting it.
    if podman run --rm --network=none -v "$WORK/out:/data:ro" proof:check verify /data/entries.json >/dev/null 2>&1; then
        ok "verifies with networking disabled entirely"
    else
        bad "the image needs a network to verify a local file"
    fi

    # Non-emptiness proves nothing: a default ARG value is non-empty too, and a
    # cached label is non-empty while naming the WRONG commit. Compare to HEAD.
    got_rev="$(podman inspect --format '{{index .Labels "org.opencontainers.image.revision"}}' proof:check)"
    if [[ "$got_rev" == "$HEAD_COMMIT" ]]; then
        ok "image records the source commit it was built from"
    else
        bad "image records revision '$got_rev', but HEAD is '$HEAD_COMMIT'"
    fi

    # Apache-2.0 §4(a): the licence travels with the distributed work.
    podman rm -f proofcheck-lic >/dev/null 2>&1 || true
    if podman create --name proofcheck-lic proof:check >/dev/null 2>&1 \
       && podman cp proofcheck-lic:/LICENSE "$WORK/LICENSE" >/dev/null 2>&1 \
       && grep -q "Apache License" "$WORK/LICENSE"; then
        ok "the image ships its licence"
    else
        bad "the image does not contain /LICENSE"
    fi
    podman rm -f proofcheck-lic >/dev/null 2>&1 || true

    if podman build --target proof-mcp -t proof-mcp:check "$REPO_ROOT" >"$WORK/mcpbuild.log" 2>&1; then
        ok "proof-mcp image builds"
    else
        bad "proof-mcp image build failed:"; tail -5 "$WORK/mcpbuild.log" | sed 's/^/        /'
    fi
fi

# ------------------------------------------------------- 4. full suite, arm64
step "full test suite on linux (native arch)"
if podman run --rm -v "$REPO_ROOT:/src:ro" "$IMAGE" sh -c '
set -e
cp -r /src /work && cd /work
go test ./... -count=1 >/tmp/t.log 2>&1 || { cat /tmp/t.log; exit 1; }
cd /work/cmd/proof-mcp && go test ./... -count=1 >/tmp/m.log 2>&1 || { cat /tmp/m.log; exit 1; }
' >"$WORK/log2" 2>&1; then
    ok "library + MCP module pass on linux"
else
    bad "test suite failed on linux:"; grep -E "FAIL|panic" "$WORK/log2" | head -5 | sed 's/^/        /'
fi

# ------------------------------------------------- 5. crypto packages, amd64
if [[ "$QUICK" -eq 1 ]]; then
    echo; echo "   (skipping the emulated amd64 run: --quick)"
else
    step "crypto packages on linux/amd64 (emulated; circl uses different assembly)"
    if podman run --rm --platform linux/amd64 -v "$REPO_ROOT:/src:ro" "$IMAGE" sh -c '
set -e
cp -r /src /work && cd /work
go test ./xwing/ ./mldsa/ ./mlkem/ ./keyfile/ ./chainformat/ ./linker/ -count=1 >/tmp/a.log 2>&1 || { cat /tmp/a.log; exit 1; }
' >"$WORK/log3" 2>&1; then
        ok "crypto packages pass on amd64"
    else
        bad "amd64 run failed:"; grep -E "FAIL|panic" "$WORK/log3" | head -5 | sed 's/^/        /'
    fi
fi

echo
if [[ "$FAILED" -gt 0 ]]; then
    echo "${RED}${FAILED} check(s) failed.${NC}"
    exit 1
fi
echo "${GREEN}All container checks passed.${NC}"
echo
echo "Not covered here: the production images build with GOEXPERIMENT=boringcrypto"
echo "and CGO against glibc, which Alpine (musl) cannot exercise. Build the"
echo "platform image to cover that step:"
echo "    podman build --platform linux/amd64 -f cmd/ingest-api/Dockerfile ."
