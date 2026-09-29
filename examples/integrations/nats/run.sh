#!/usr/bin/env bash
# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
#
# run.sh — NATS JetStream → proof, end to end, against a real nats-server.
#
#   1. start nats-server with JetStream (podman)
#   2. publish 7 events: 6 for three users, 1 keyed by a NAME (refused);
#      an email-keyed one is rejected by the stream itself
#   3. consume with -crash-after-commit: commits, then dies before any ack
#   4. consume again: JetStream redelivers; every message is recognised, none
#      committed twice
#   5. checkpoint and verify: exactly 6 entries across 3 chains
#
# Needs podman and Go. Leaves nothing running. Builds from this working tree.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
IMAGE="${NATS_IMAGE:-docker.io/library/nats:2.12-alpine}"
NAME="proof-nats-demo"
PORT="${NATS_PORT:-4222}"
WORK="$(mktemp -d)"
BIN="$WORK/bin"

cleanup() { podman rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

say() { printf '\n\033[0;34m── %s\033[0m\n' "$*"; }
show() { printf '$ %s\n' "$*"; "$@"; }

say "build (from this working tree)"
mkdir -p "$BIN"
(cd "$REPO" && go build -o "$BIN/proof" ./cmd/proof)
(cd "$HERE" && go build -o "$BIN/nats-sink" .)
export PATH="$BIN:$PATH"

say "nats-server with JetStream ($IMAGE)"
podman rm -f "$NAME" >/dev/null 2>&1 || true
podman run -d --rm --name "$NAME" -p "$PORT:4222" "$IMAGE" -js >/dev/null
# Capture, then grep: with pipefail, `podman logs | grep -q` fails whenever grep
# exits at its first match before podman has finished writing (SIGPIPE), which
# a server with long start-up logs (redis:8 loads modules) triggers every time.
ready() { local l; l="$(podman logs "$NAME" 2>&1)"; grep -q "Server is ready" <<<"$l"; }
for _ in $(seq 1 50); do
    ready && break
    sleep 0.2
done
ready || { echo "nats-server did not start" >&2; exit 1; }
URL="nats://127.0.0.1:$PORT"

cd "$WORK"
proof keygen --alg ml-dsa-65 --out-dir keys >/dev/null
cat > events.jsonl <<'EOF'
{"user":"u-81","event":"login"}
{"user":"u-82","event":"login"}
{"user":"u-81","event":"export","rows":120}
{"user":"Jo-Smith","event":"login"}
{"user":"u-90","event":"password_reset"}
{"user":"u-82","event":"logout"}
{"user":"u-81","event":"logout"}
EOF

say "publish"
show nats-sink publish -url "$URL" -key user < events.jsonl

say "a dotted key is not even stored: the stream takes evidence.* only"
rc=0
echo '$ echo '"'"'{"user":"jo@example.com","event":"login"}'"'"' | nats-sink publish -key user'
echo '{"user":"jo@example.com","event":"login"}' | nats-sink publish -url "$URL" -key user || rc=$?
[ "$rc" -eq 1 ] || { echo "A DOTTED KEY WAS PUBLISHED" >&2; exit 1; }

say "consume, and crash after the commit, before any ack"
rc=0
show nats-sink consume -url "$URL" -dir sink-data -ack-wait 5s -crash-after-commit || rc=$?
[ "$rc" -eq 3 ] || { echo "expected the demo crash (exit 3), got $rc" >&2; exit 1; }

say "wait out the ack deadline, then consume again: JetStream redelivers"
sleep 6
out="$(nats-sink consume -url "$URL" -dir sink-data -ack-wait 5s)"
printf '$ nats-sink consume -url %s -dir sink-data -ack-wait 5s\n%s\n' "$URL" "$out"
echo "$out" | grep -q "committed 0 · already committed (redelivered) 6" \
    || { echo "REDELIVERY WAS NOT RECOGNISED" >&2; exit 1; }

say "checkpoint and verify: exactly 6 entries"
show proof sink checkpoint --dir sink-data --key keys/ml-dsa-65-private.pem
out="$(proof sink verify --dir sink-data --key keys/ml-dsa-65-public.pem)"
printf '$ proof sink verify --dir sink-data --key keys/ml-dsa-65-public.pem\n%s\n' "$out"
echo "$out" | grep -q "all 3 chains verify" || exit 1
total=$(echo "$out" | sed -n 's/.* \([0-9]*\) entr[a-z]*:.*/\1/p' | paste -sd+ - | bc)
[ "$total" -eq 6 ] || { echo "expected 6 entries in total, found $total" >&2; exit 1; }

say "done: nothing lost, nothing committed twice, the name was refused"
