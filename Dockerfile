# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
#
# A container is the lowest-trust way to run someone else's verifier: nothing
# is installed on the auditor's machine, and the image has nothing in it but
# the binary. That is the point of this file.
#
#   podman build -t proof .
#   podman run --rm -v "$PWD:/data:ro" proof verify /data/entries.json
#
#   podman build --target proof-mcp -t proof-mcp .
#
# The final stages are FROM scratch: no shell, no package manager, no libc, and
# so nothing to audit but the binary itself. `proof` needs no network and no
# credentials at runtime, so it needs no certificate bundle either.
#
# THE REVISION LABEL IS NOT SET HERE. An `ARG` interpolated into a `LABEL` does
# NOT invalidate podman's layer cache when the argument changes: build with
# SOURCE_COMMIT=AAA, then again with =BBB, and the second image still reports
# AAA. A stale revision label is worse than none, because it points an auditor
# at the wrong source. The scripts therefore pass
#   --label org.opencontainers.image.revision=<commit>
# on the command line, which is applied at commit time and is not cached.
# Use scripts/publish-image.sh, or pass the label yourself.

# The base is pinned BY DIGEST, not by tag: a tag is a moving target, and an
# image whose provenance cannot be stated is a strange thing to verify with.
# This digest is the multi-architecture index for golang:1.25-alpine, so it
# resolves on both arm64 and amd64.
FROM docker.io/library/golang@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS build

WORKDIR /src

# Dependencies first, so editing source does not re-download the module cache.
# BOTH modules: `go mod download` in /src resolves only the root module, and
# the MCP server is a separate module with its own dependency graph.
COPY go.mod go.sum ./
COPY cmd/proof-mcp/go.mod cmd/proof-mcp/go.sum ./cmd/proof-mcp/
RUN go mod download && cd cmd/proof-mcp && go mod download

COPY . .

# A workspace, not a replace directive: `go install .../cmd/proof-mcp@latest`
# refuses a module containing a replace, so go.mod must stay clean. The
# workspace exists only inside this build and points the MCP server at the
# library tree it was built from, rather than at a published version.
RUN go work init . ./cmd/proof-mcp

# CGO_ENABLED=0 for a static binary — there is no libc in the final image.
# -trimpath and an empty -buildid keep the output independent of the path it
# was built in, so the same source produces the same bytes.
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -buildid=" -o /out/proof ./cmd/proof
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -buildid=" -o /out/proof-mcp ./cmd/proof-mcp

# Prove the binaries are usable before shipping them. A dynamically linked
# binary would start on this Alpine base and then fail on `scratch`, where
# there is no loader — a failure the user should not be the first to find.
# `ldd` prints "=>" for each shared object a dynamic binary needs.
RUN /out/proof --help >/dev/null
RUN for b in /out/proof /out/proof-mcp; do \
        [ -x "$b" ] || { echo "$b is not executable" >&2; exit 1; }; \
        if ldd "$b" 2>/dev/null | grep -q "=>"; then \
            echo "$b is dynamically linked and will not run on scratch" >&2; exit 1; \
        fi; \
    done
# proof-mcp itself is not started here: it speaks a protocol on stdin and would
# block. Its behaviour is covered by its own test suite.

# --------------------------------------------------------------- MCP server
FROM scratch AS proof-mcp

LABEL org.opencontainers.image.title="proof-mcp" \
      org.opencontainers.image.description="MCP server exposing the proof verifier to an agent. No tool touches key material." \
      org.opencontainers.image.source="https://github.com/aleutian-ai/proof" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /out/proof-mcp /proof-mcp
# Apache-2.0 §4(a): recipients of the distributed work get the licence with it.
# An image is a distribution, and a label naming a licence is not the licence.
COPY LICENSE /LICENSE

USER 65532:65532
ENTRYPOINT ["/proof-mcp"]

# ----------------------------------------------------------------- verifier
FROM scratch AS proof

LABEL org.opencontainers.image.title="proof" \
      org.opencontainers.image.description="Verify a hash-linked audit chain without trusting whoever produced it." \
      org.opencontainers.image.source="https://github.com/aleutian-ai/proof" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /out/proof /proof
COPY LICENSE /LICENSE

# A numeric, non-root user. There is no /etc/passwd to name one in, and the
# verifier reads files and writes stdout — it needs nothing root provides.
USER 65532:65532
ENTRYPOINT ["/proof"]
