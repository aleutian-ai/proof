#!/usr/bin/env bash
# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
#
# run.sh — Redis Streams → proof, end to end, against a real server.
#
#   1. start Valkey (default) or Redis (REDIS_IMAGE=docker.io/library/redis:8-alpine)
#   2. XADD 8 entries: 6 for three users, 1 keyed by a name, 1 by an email
#   3. consume with -crash-after-commit: commits, then dies before any XACK
#   4. the entries are still PENDING: Redis never redelivers by itself
#   5. consume again: pending entries are recovered first and recognised,
#      none committed twice, 0 left pending
#   6. checkpoint and verify: exactly 6 entries across 3 chains
#   7. delete and recreate the stream, reusing an old entry id by hand: the new
#      entry is committed, not mistaken for the old one
#
# Needs podman and Go. Leaves nothing running. Builds from this working tree.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
IMAGE="${REDIS_IMAGE:-docker.io/valkey/valkey:8-alpine}"
NAME="proof-redis-demo"
PORT="${REDIS_PORT:-6379}"
WORK="$(mktemp -d)"
BIN="$WORK/bin"

cleanup() { podman rm -f "$NAME" >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

say() { printf '\n\033[0;34m── %s\033[0m\n' "$*"; }
show() { printf '$ %s\n' "$*"; "$@"; }

say "build (from this working tree)"
mkdir -p "$BIN"
(cd "$REPO" && go build -o "$BIN/proof" ./cmd/proof)
(cd "$HERE" && go build -o "$BIN/redis-sink" .)
export PATH="$BIN:$PATH"

say "server: $IMAGE"
podman rm -f "$NAME" >/dev/null 2>&1 || true
podman run -d --rm --name "$NAME" -p "$PORT:6379" "$IMAGE" >/dev/null
# Capture, then grep: with pipefail, `podman logs | grep -q` fails whenever grep
# exits at its first match before podman has finished writing (SIGPIPE), which
# a server with long start-up logs (redis:8 loads modules) triggers every time.
ready() { local l; l="$(podman logs "$NAME" 2>&1)"; grep -q "Ready to accept connections" <<<"$l"; }
for _ in $(seq 1 50); do
    ready && break
    sleep 0.2
done
ready || { echo "server did not start" >&2; exit 1; }
ADDR="127.0.0.1:$PORT"

cd "$WORK"
proof keygen --alg ml-dsa-65 --out-dir keys >/dev/null
cat > events.jsonl <<'EOF'
{"user":"u-81","event":"login"}
{"user":"u-82","event":"login"}
{"user":"u-81","event":"export","rows":120}
{"user":"Jo-Smith","event":"login"}
{"user":"u-90","event":"password_reset"}
{"user":"jo@example.com","event":"login"}
{"user":"u-82","event":"logout"}
{"user":"u-81","event":"logout"}
EOF

say "add"
show redis-sink add -addr "$ADDR" -key user < events.jsonl

say "consume, and crash after the commit, before any XACK"
rc=0
show redis-sink consume -addr "$ADDR" -dir sink-data -crash-after-commit || rc=$?
[ "$rc" -eq 3 ] || { echo "expected the demo crash (exit 3), got $rc" >&2; exit 1; }

say "Redis does not redeliver: the committed entries are still pending"
out="$(redis-sink pending -addr "$ADDR")"; printf '$ redis-sink pending\n%s\n' "$out"
echo "$out" | grep -q "^6 entries pending" || { echo "EXPECTED 6 PENDING" >&2; exit 1; }

say "consume again: recover pending entries first"
out="$(redis-sink consume -addr "$ADDR" -dir sink-data)"
printf '$ redis-sink consume -addr %s -dir sink-data\n%s\n' "$ADDR" "$out"
echo "$out" | grep -q "recovered from pending 6 · committed 0 · already committed 6" \
    || { echo "PENDING ENTRIES WERE NOT RECOGNISED" >&2; exit 1; }
out="$(redis-sink pending -addr "$ADDR")"; printf '$ redis-sink pending\n%s\n' "$out"
echo "$out" | grep -q "^0 entries pending" || { echo "ENTRIES LEFT PENDING" >&2; exit 1; }

say "checkpoint and verify: exactly 6 entries"
show proof sink checkpoint --dir sink-data --key keys/ml-dsa-65-private.pem
out="$(proof sink verify --dir sink-data --key keys/ml-dsa-65-public.pem)"
printf '$ proof sink verify --dir sink-data --key keys/ml-dsa-65-public.pem\n%s\n' "$out"
echo "$out" | grep -q "all 3 chains verify" || exit 1
entries() { echo "$1" | awk '/^chain /{for(i=1;i<=NF;i++) if ($(i+1) ~ /^entr/) {n+=$i; break}} END{print n+0}'; }
total=$(entries "$out")
[ "$total" -eq 6 ] || { echo "expected 6 entries in total, found $total" >&2; exit 1; }

say "the stream is deleted and recreated, and an old entry id comes back"
# Auto ids are time-based, so a recreated stream reuses one only after a clock
# rollback or a failover to a lagging replica. Simulated here by reusing, by
# hand, the id of an entry that is already committed. The new consumer group
# gets a new incarnation, so the new entry is NOT mistaken for the old one.
old_id=$(podman exec "$NAME" redis-cli XRANGE evidence - + COUNT 1 | head -1)
show podman exec "$NAME" redis-cli DEL evidence
show podman exec "$NAME" redis-cli XADD evidence "$old_id" key u-81 data '{"user":"u-81","event":"after-recreate"}'
out="$(redis-sink consume -addr "$ADDR" -dir sink-data)"
printf '$ redis-sink consume -addr %s -dir sink-data\n%s\n' "$ADDR" "$out"
echo "$out" | grep -q "committed 1 · already committed 0" \
    || { echo "A NEW ENTRY WAS TAKEN FOR AN OLD ONE" >&2; exit 1; }
out="$(proof sink verify --dir sink-data --key keys/ml-dsa-65-public.pem)"
printf '$ proof sink verify --dir sink-data --key keys/ml-dsa-65-public.pem\n%s\n' "$out"
echo "$out" | grep -q "all 3 chains verify" || exit 1
[ "$(entries "$out")" -eq 7 ] || { echo "expected 7 entries" >&2; exit 1; }

say "erase one user: their chain says so, and no output names them"
out="$(proof sink erase --dir sink-data --subject u-81)"
printf '$ proof sink erase --dir sink-data --subject u-81\n%s\n' "$out"
if grep -q "u-81" <<<"$out"; then echo "ERASE OUTPUT NAMES THE SUBJECT" >&2; exit 1; fi
out="$(proof sink verify --dir sink-data --key keys/ml-dsa-65-public.pem)"
printf '$ proof sink verify --dir sink-data --key keys/ml-dsa-65-public.pem\n%s\n' "$out"
echo "$out" | grep -q "all 3 chains verify" || exit 1
echo "$out" | grep -q "subject erased (not yet checkpointed)" || { echo "NO ERASED CHAIN" >&2; exit 1; }

say "done: nothing stranded, nothing committed twice, a reused id not mistaken, name and email refused, one user erased"
