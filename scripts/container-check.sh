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
#     6. proof sink runs as sink/README.md shows: one opaque chain per
#        subject, erase one, every chain verifies
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

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; BLUE=$'\033[0;34m'; YELLOW=$'\033[0;33m'; NC=$'\033[0m'
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
FAILED=0

step() { echo; echo "${BLUE}── $1${NC}"; }
ok()   { echo "   ${GREEN}PASS${NC} $1"; }
bad()  { echo "   ${RED}FAIL${NC} $1"; FAILED=$((FAILED+1)); }

# detail prints what went wrong in a log, and CANNOT fail. Every pipeline ends
# in `|| true`: under `set -euo pipefail`, a grep that matched nothing used to
# abort the whole run while it was reporting a failure — no later steps, no
# tally (2026-09-27). It shows FAIL/panic lines when there are any, and the
# last lines of the log otherwise.
detail() {
    local hits
    hits="$(grep -E "FAIL|panic" "$1" 2>/dev/null | head -5 || true)"
    [[ -n "$hits" ]] || hits="$(tail -5 "$1" 2>/dev/null || true)"
    printf '%s\n' "$hits" | sed 's/^/        /' || true
}

# Exit codes: 0 every check passed · 1 one or more checks failed ·
#             2 environment problem (podman, pulls) — nothing was tested.

command -v podman >/dev/null || { echo "${RED}podman not found${NC}" >&2; exit 2; }

# ------------------------------------------------------------- 0. preflight
# Can podman pull the base image at all? If not, nothing below could say
# anything about proof: stop here with exit 2 rather than report environment
# trouble as three product failures (which is what happened on 2026-09-27).
step "preflight: podman can pull ${IMAGE}"
if ! podman pull -q "$IMAGE" >"$WORK/pull.log" 2>&1; then
    echo "   ${RED}ENVIRONMENT${NC} podman could not pull ${IMAGE}; nothing was tested."
    if grep -qE "error getting credentials|docker-credential|gcloud" "$WORK/pull.log"; then
        echo "   cause: a registry credential helper failed (see credHelpers in ~/.docker/config.json)."
        echo "   fix:   gcloud auth login   — or point DOCKER_CONFIG and REGISTRY_AUTH_FILE"
        echo "          at an empty '{}' config for public images."
    else
        detail "$WORK/pull.log"
    fi
    exit 2
fi
ok "base image available"

# A self-test hook, used only to prove the reporting path: a failing step whose
# log has NO FAIL line must still let the run reach its tally and exit 1.
if [[ "${CONTAINER_CHECK_SELFTEST:-}" == "fail-without-match" ]]; then
    step "self-test: a failing step whose log contains no FAIL line"
    echo "unrelated output, nothing to match" >"$WORK/selftest.log"
    bad "self-test failure (injected)"; detail "$WORK/selftest.log"
fi

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
	// Two chains: v3, the format proof writes today, and v2, the legacy format
	// existing chains use. Check 2 verifies BOTH through the published binary —
	// v3 because it is what ships, v2 because a release must keep reading the
	// chains it always could.
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
proof verify /data/entries.json >/dev/null
if proof verify /data/entries-tampered.json >/dev/null 2>&1; then
    echo "TAMPERED v3 CHAIN VERIFIED AS INTACT" >&2
    exit 1
fi
' >"$WORK/log1" 2>&1; then
    ok "both install lines work"
    ok "a locally built v3 chain verifies with the RELEASED binary on Linux"
    ok "the released binary still reads v2 — existing chains stay verifiable"
    ok "tampered v2 and v3 chains are both rejected"
else
    bad "quickstart or cross-platform verification failed:"; detail "$WORK/log1"
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
# The image is built from the WORKING TREE but labelled with HEAD. With
# uncommitted changes those differ. A warning, not a failure: this is a developer
# check. The release gate (dist_06) is where it must refuse.
if [[ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" ]]; then
    echo "   ${YELLOW}WARN${NC} uncommitted changes: the image is built from them but labelled ${HEAD_COMMIT:0:12}"
fi
# --label, not --build-arg: an ARG interpolated into a LABEL is not cache-keyed,
# so a changed commit would silently keep the previous image's label.
if podman build -t proof:check \
       --label "org.opencontainers.image.revision=$HEAD_COMMIT" \
       "$REPO_ROOT" >"$WORK/build.log" 2>&1; then
    ok "image builds"
    IMAGE_BUILT=1
else
    bad "image build failed:"; detail "$WORK/build.log"
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
        MCP_BUILT=1
    else
        bad "proof-mcp image build failed:"; detail "$WORK/mcpbuild.log"
        MCP_BUILT=0
    fi

    # Drive the MCP server — the scratch image, as shipped — over a real stdio
    # handshake, and check what it wrote with the proof image. Plain grep on the
    # JSON-RPC output: no python or jq needed on the host.
    if [[ "$MCP_BUILT" -eq 1 ]]; then
        mkdir -p "$WORK/mcp" && chmod 777 "$WORK/mcp"   # the images run as uid 65532
        {
          printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"container-check","version":"1"}}}'
          printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}'
          printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
          printf '%s\n' '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"commit","arguments":{"chain":"c","entries":[{"content":"one"},{"content":"two"}]}}}'
          sleep 3
        } | podman run --rm -i -v "$WORK/mcp:/data" proof-mcp:check --db /data/e.db --chains c \
            >"$WORK/mcp.out" 2>"$WORK/mcp.err" || true

        writers="$(grep -o '"readOnlyHint":false' "$WORK/mcp.out" | wc -l | tr -d ' ')"
        if [[ "$writers" -eq 1 ]] && grep -q '"name":"commit"' "$WORK/mcp.out"; then
            ok "proof-mcp over stdio: commit is the only tool that writes"
        else
            bad "proof-mcp: expected exactly one writing tool (commit), found $writers"; detail "$WORK/mcp.err"
        fi
        if grep -q '"committed":2' "$WORK/mcp.out" && ! grep -q '"nonce":' "$WORK/mcp.out" \
           && [[ -f "$WORK/mcp/e.db.nonces" ]]; then
            ok "proof-mcp committed 2 entries, returned no nonce, kept nonces in e.db.nonces"
        else
            bad "proof-mcp commit did not behave as specified:"; detail "$WORK/mcp.out"
        fi
        if podman run --rm -v "$WORK/mcp:/data" proof:check export --db /data/e.db --chain c --out /data/c.json >/dev/null 2>&1 \
           && podman run --rm -v "$WORK/mcp:/data:ro" proof:check verify /data/c.json >/dev/null 2>&1; then
            ok "the chain proof-mcp wrote verifies with the proof image"
        else
            bad "the chain proof-mcp wrote does not verify"
        fi
    fi
fi

# ------------------------------------------------------- 4. full suite, arm64
step "full test suite on linux (native arch)"
if podman run --rm -v "$REPO_ROOT:/src:ro" "$IMAGE" sh -c '
set -e
cp -r /src /work && cd /work
go test ./... -count=1 >/tmp/t.log 2>&1 || { cat /tmp/t.log; exit 1; }
# The sink suite again with one-chain pages: paged Verify and Checkpoint must
# give exactly what one long pass gives, at every page boundary.
SINK_TINY_PAGES=1 go test ./sink -count=1 >/tmp/p.log 2>&1 || { cat /tmp/p.log; exit 1; }
cd /work/cmd/proof-mcp && go test ./... -count=1 >/tmp/m.log 2>&1 || { cat /tmp/m.log; exit 1; }
' >"$WORK/log2" 2>&1; then
    ok "library + MCP module pass on linux (the sink suite also with one-chain pages)"
else
    bad "test suite failed on linux:"; detail "$WORK/log2"
fi

# ---------------------------------------------------- 5. full suite, amd64
if [[ "$QUICK" -eq 1 ]]; then
    echo; echo "   (skipping the emulated amd64 run: --quick)"
else
    # The WHOLE suite, not a crypto subset. circl's assembly differs by
    # architecture, but so does bbolt's mmap and flock — and the CLI's lock
    # timeout is a syscall behaviour that a crypto-only run never exercises.
    step "full test suite on linux/amd64 (emulated; different assembly AND different syscalls)"
    if podman run --rm --platform linux/amd64 -v "$REPO_ROOT:/src:ro" "$IMAGE" sh -c '
set -e
cp -r /src /work && cd /work
go test ./... -count=1 -timeout 900s >/tmp/a.log 2>&1 || { cat /tmp/a.log; exit 1; }
' >"$WORK/log3" 2>&1; then
        ok "the full suite passes on amd64"
    else
        bad "amd64 run failed:"; detail "$WORK/log3"
    fi
fi

# ------------------------------------------------------------- 6. FIPS modes
# The README makes two specific claims about GODEBUG=fips140. Both are checked
# here, because a documented limitation that does not actually hold is worse
# than no note at all — a reader plans around it.
step "GODEBUG=fips140 behaves as the README documents"

if podman run --rm -v "$REPO_ROOT:/src:ro" -e GODEBUG=fips140=on "$IMAGE" sh -c '
set -e
cp -r /src /work && cd /work
go test ./xwing/ ./mlkem/ ./keywrap/ ./chainformat/ ./mldsa/ -count=1 >/tmp/f.log 2>&1 || { cat /tmp/f.log; exit 1; }
' >"$WORK/log4" 2>&1; then
    ok "fips140=on: the KEM and format packages pass"
else
    bad "fips140=on failed:"; detail "$WORK/log4"
fi

# X-Wing CANNOT run under fips140=only: the standard library refuses X25519
# there, and X25519 is not an approved key-establishment scheme under
# SP 800-56A. The README says so; this asserts the failure actually happens,
# and for THAT reason rather than some unrelated breakage.
rc=0
podman run --rm -v "$REPO_ROOT:/src:ro" -e GODEBUG=fips140=only "$IMAGE" sh -c '
cp -r /src /work && cd /work
go test ./xwing/ -count=1 2>&1
' >"$WORK/log5" 2>&1 || rc=$?
if [[ "$rc" -ne 0 ]] && grep -q "X25519 is not allowed in FIPS 140-only mode" "$WORK/log5"; then
    ok "fips140=only: X-Wing is refused, naming X25519 — exactly as documented"
elif [[ "$rc" -eq 0 ]]; then
    bad "fips140=only: X-Wing PASSED, but the README says it cannot run there"
else
    bad "fips140=only: X-Wing failed for an unexpected reason:"; detail "$WORK/log5"
fi

# ------------------------------------- 7. sink: one opaque chain per subject
# The sink/README.md flow, built from this tree. No services: the sink is what
# every streaming integration puts a consumer in front of.
step "proof sink: one opaque chain per subject, erasure by subject (${IMAGE})"
if podman run --rm -v "$REPO_ROOT:/src:ro" "$IMAGE" sh -c '
set -e
cp -r /src /work && cd /work
go build -o /usr/local/bin/proof ./cmd/proof
go build -tags sinktamper -o /usr/local/bin/sinktamper ./scripts/sinktamper
cd /tmp
proof keygen --alg ml-dsa-65 --out-dir keys >/dev/null
printf "%s\n" \
  "{\"user\":\"u-81\",\"event\":\"login\"}" "{\"user\":\"u-82\",\"event\":\"login\"}" \
  "{\"user\":\"u-81\",\"event\":\"export\"}" "{\"user\":\"u-90\",\"event\":\"reset\"}" \
  "{\"user\":\"u-81\",\"event\":\"logout\"}" > events.jsonl
proof sink commit --class events --subject-field user < events.jsonl > commit.out
# Counts only: which chain holds whom belongs in the secret index alone.
grep -q "committed 5 entries on 3 chains" commit.out
if grep -q "u-[0-9]" commit.out; then echo "commit output names a subject" >&2; exit 1; fi
# The test asks the secret index, deliberately, which opaque chain is whose.
chain_of() { proof sink verify --key keys/ml-dsa-65-public.pem --show-subjects 2>/dev/null | sed -n "s/^chain \([^ ]*\) .*· subject $1\$/\1/p"; }
c81=$(chain_of u-81); c82=$(chain_of u-82)
[ -n "$c81" ] && [ -n "$c82" ] && [ "$c81" != "$c82" ] || { cat commit.out >&2; exit 1; }
proof sink checkpoint --key keys/ml-dsa-65-private.pem
proof sink verify --key keys/ml-dsa-65-public.pem | grep -q "all 3 chains verify"
# Chain ids are opaque: no subject in the evidence file or any checkpoint.
for subj in u-81 u-82 u-90; do
  if grep -rq "$subj" sink-data/evidence.db sink-data/anchors; then
    echo "SUBJECT $subj FOUND IN A SHAREABLE ARTIFACT" >&2; exit 1
  fi
done
# The plain chain verbs verify a sink chain and its checkpoint on their own.
proof export --db sink-data/evidence.db --chain "$c82" --out c82.json
proof verify c82.json --anchor "sink-data/anchors/$c82/0001.json" --key keys/ml-dsa-65-public.pem >/dev/null
proof sink erase --subject u-81 > erase.out
if grep -q "u-[0-9]" erase.out; then echo "erase output names the subject" >&2; exit 1; fi
out=$(proof sink verify --key keys/ml-dsa-65-public.pem)
echo "$out" | grep -q "all 3 chains verify"
echo "$out" | grep "chain $c81" | grep -q "0 opened, 3 erased"
if echo "{\"user\":\"jo@example.com\"}" | proof sink commit --class events --subject-field user 2>/dev/null; then
    echo "AN EMAIL WAS ACCEPTED AS A SUBJECT" >&2; exit 1
fi
sinktamper --dir sink-data --chain "$c82" --content "{\"user\":\"u-82\",\"event\":\"edited\"}"
rc=0; out=$(proof sink verify --key keys/ml-dsa-65-public.pem) || rc=$?
[ "$rc" -eq 1 ] || { echo "EDITED EVENT VERIFIED (exit $rc)" >&2; exit 1; }
[ "$(echo "$out" | grep -c FAILS)" -eq 1 ] && echo "$out" | grep "chain $c82" | grep -q FAILS \
  || { echo "$out" >&2; exit 1; }
' >"$WORK/log6" 2>&1; then
    ok "three subjects → three opaque chains, each checkpointed and verified on its own"
    ok "commit and erase print counts, never a subject"
    ok "no subject appears in the evidence file or any checkpoint"
    ok "proof export + proof verify check a sink chain and its checkpoint independently"
    ok "erasing one user leaves every chain verifying, that user's events erased"
    ok "an email is refused as a subject; an edited event fails only its own chain"
else
    bad "proof sink failed:"; detail "$WORK/log6"
fi

# ------------------------------------- 8. sink: record signing (opt-in)
# Every record signed with its own ML-DSA-65 key (docs/sink-format.md §9); the
# verifier, not the folder, decides whether signatures are required.
step "proof sink: record signing, verified with --record-trust (${IMAGE})"
if podman run --rm -v "$REPO_ROOT:/src:ro" "$IMAGE" sh -c '
set -e
cp -r /src /work && cd /work
go build -o /usr/local/bin/proof ./cmd/proof
cd /tmp
proof keygen --alg ml-dsa-65 --out-dir cp >/dev/null
proof keygen --alg ml-dsa-65 --out-dir rec >/dev/null
proof keygen --alg ml-dsa-65 --out-dir other >/dev/null
printf "%s\n" "{\"user\":\"u-81\",\"e\":1}" "{\"user\":\"u-82\",\"e\":2}" "{\"user\":\"u-81\",\"e\":3}" > ev.jsonl
proof sink commit --class events --subject-field user --record-key rec/ml-dsa-65-private.pem < ev.jsonl >/dev/null
# A signing sink refuses a writer without the record key: exit 2, not a retryable error.
rc=0; proof sink commit --class events --subject-field user < ev.jsonl 2>/dev/null || rc=$?
[ "$rc" -eq 2 ] || { echo "UNSIGNED COMMIT ON A SIGNING SINK: exit $rc" >&2; exit 1; }
# Without record trust: passes, and says NOT CHECKED.
out=$(proof sink verify --key cp/ml-dsa-65-public.pem)
echo "$out" | grep -q "all 2 chains verify"
echo "$out" | grep -q "^Record signatures: NOT CHECKED"
# With it: every record signed.
out=$(proof sink verify --key cp/ml-dsa-65-public.pem --record-trust rec/ml-dsa-65-public.pem)
echo "$out" | grep -q "all 2 chains verify"
[ "$(echo "$out" | grep -c " signed")" -eq 2 ] || { echo "$out" >&2; exit 1; }
# The wrong record key: every record fails.
rc=0; out=$(proof sink verify --key cp/ml-dsa-65-public.pem --record-trust other/ml-dsa-65-public.pem) || rc=$?
[ "$rc" -eq 1 ] && echo "$out" | grep -q "not trusted for records" || { echo "WRONG RECORD KEY PASSED" >&2; exit 1; }
# A signed erasure is erased without waiting for a checkpoint.
proof sink erase --subject u-81 --record-key rec/ml-dsa-65-private.pem >/dev/null
out=$(proof sink verify --key cp/ml-dsa-65-public.pem --record-trust rec/ml-dsa-65-public.pem)
echo "$out" | grep -q "all 2 chains verify"
echo "$out" | grep -q "signed · subject erased$" || { echo "$out" >&2; exit 1; }
# One key for both jobs: warned, not refused.
proof sink checkpoint --key rec/ml-dsa-65-private.pem 2> cp.err >/dev/null
grep -q "also signs this sink" cp.err || { echo "NO WARNING FOR A SHARED KEY" >&2; exit 1; }
' >"$WORK/log7" 2>&1; then
    ok "every record signed; a writer without the record key is refused (exit 2)"
    ok "verify without --record-trust passes and says NOT CHECKED; with it, every record is checked"
    ok "the wrong record key fails every record; a signed erasure verifies as erased"
    ok "a checkpoint key that also signs records is warned about, not refused"
else
    bad "record signing failed:"; detail "$WORK/log7"
fi

echo
if [[ "$FAILED" -gt 0 ]]; then
    echo "${RED}${FAILED} check(s) failed.${NC}"
    exit 1
fi
echo "${GREEN}All container checks passed.${NC}"
echo
echo "Not covered here:"
echo "  - glibc. Every run above is Alpine (musl). The shipped images are FROM"
echo "    scratch with static binaries, so libc is not linked at all — but a"
echo "    caller building their own image on a glibc base is untested."
echo "  - the SDKs. Cross-language agreement is held by fixtures/ vectors computed"
echo "    independently of every implementation; the Python and JS SDKs still"
echo "    compare some v3/v6 values against copied constants (ticket _66)."
