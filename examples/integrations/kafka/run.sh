#!/usr/bin/env bash
# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
#
# run.sh — Kafka → proof, end to end, against a real broker.
#
#   1. start a single-node broker (KRaft) and create "agent-actions" with 3
#      partitions; `proof sink init` makes the record and checkpoint keys
#   2. produce 8 records: 6 for three users, 1 keyed by a name, 1 with no key
#   3. consume with -crash-after-commit: commits to proof, dies before any
#      offset commit
#   4. no offset was committed, so a restart reads everything again: the 6 are
#      recognised as committed, the 2 refused are logged by position
#   5. checkpoint, and verify every chain and every record signature
#   6. delete and recreate the topic: a new record lands at an old
#      partition/offset and is committed, because the topic id changed
#   7. erase one user, signed by the record key
#   8. live: the consumer follows, a producer adds a record every 100 ms, and
#      `proof sink verify` runs meanwhile; nothing stalls
#
#   KAFKA_IMAGE=docker.io/apache/kafka-native:4.1.0 ./run.sh   (GraalVM native broker)
#
# Needs podman and Go. Leaves nothing running. Builds from this working tree.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
IMAGE="${KAFKA_IMAGE:-docker.io/apache/kafka:4.1.0}"
TOOLS="docker.io/apache/kafka:4.1.0" # the admin scripts; the native image has none
NAME="proof-kafka-demo"
PORT="${KAFKA_PORT:-9092}"
TOPIC="agent-actions"
WORK="$(mktemp -d)"
BIN="$WORK/bin"
CONSUMER_PID=""
PRODUCER_PID=""

cleanup() {
    [ -n "$CONSUMER_PID" ] && kill "$CONSUMER_PID" 2>/dev/null || true
    [ -n "$PRODUCER_PID" ] && kill "$PRODUCER_PID" 2>/dev/null || true
    podman rm -f "$NAME" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

say() { printf '\n\033[0;34m── %s\033[0m\n' "$*"; }
show() { printf '$ %s\n' "$*"; "$@"; }
fail() { echo "$*" >&2; exit 1; }
# The admin scripts, run in the broker's own network namespace.
kafka() { podman run --rm --network "container:$NAME" "$TOOLS" "/opt/kafka/bin/$1" --bootstrap-server localhost:9092 "${@:2}" 2>/dev/null; }
topic_id() { kafka kafka-topics.sh --describe --topic "$TOPIC" | sed -n 's/.*TopicId: \([^[:space:]]*\).*/\1/p' | head -1; }

say "build (from this working tree)"
mkdir -p "$BIN"
(cd "$REPO" && go build -o "$BIN/proof" ./cmd/proof)
(cd "$HERE" && go build -o "$BIN/kafka-sink" .)
export PATH="$BIN:$PATH"

say "broker: $IMAGE"
podman rm -f "$NAME" >/dev/null 2>&1 || true
podman run -d --rm --name "$NAME" -p "$PORT:9092" "$IMAGE" >/dev/null
# Capture, then grep: with pipefail, `podman logs | grep -q` can fail on SIGPIPE.
ready() { local l; l="$(podman logs "$NAME" 2>&1)"; grep -q "Kafka Server started" <<<"$l"; }
for _ in $(seq 1 100); do
    ready && break
    sleep 0.2
done
ready || fail "broker did not start"
BROKER="127.0.0.1:$PORT"

cd "$WORK"
show kafka kafka-topics.sh --create --topic "$TOPIC" --partitions 3
OLD_ID="$(topic_id)"
echo "topic id: $OLD_ID"

say "keys: proof sink init (a record key for the consumer, a checkpoint key kept apart)"
proof sink init --dir sink-data >/dev/null
K="sink-data.keys"
ls "$K"
# The consumer is given the key's FILE, never the key itself.
export PROOF_RECORD_KEY_FILE="$WORK/$K/ml-dsa-65-record-private.pem"
VERIFY=(proof sink verify --dir sink-data --key "$K/ml-dsa-65-checkpoint-public.pem" --record-trust "$K/ml-dsa-65-record-public.pem")
verify() { local out; out="$("${VERIFY[@]}")"; printf '$ proof sink verify --dir sink-data --key %s --record-trust %s\n%s\n' \
    "$K/ml-dsa-65-checkpoint-public.pem" "$K/ml-dsa-65-record-public.pem" "$out"; LAST="$out"; }
entries() { echo "$1" | awk '/^chain /{for(i=1;i<=NF;i++) if ($(i+1) ~ /^entr/) {n+=$i; break}} END{print n+0}'; }

cat > events.jsonl <<'EOF'
{"user":"u-81","event":"login"}
{"user":"u-82","event":"login"}
{"user":"u-81","event":"export","rows":120}
{"user":"Jo-Smith","event":"login"}
{"user":"u-90","event":"password_reset"}
{"event":"heartbeat"}
{"user":"u-82","event":"logout"}
{"user":"u-81","event":"logout"}
EOF

say "produce"
show kafka-sink produce -brokers "$BROKER" -key user < events.jsonl

say "consume, and crash after the sink commit, before any offset commit"
rc=0
show kafka-sink consume -brokers "$BROKER" -class actions -dir sink-data -crash-after-commit || rc=$?
[ "$rc" -eq 3 ] || fail "expected the demo crash (exit 3), got $rc"
out="$(kafka kafka-consumer-groups.sh --describe --group proof)"
printf '$ kafka-consumer-groups.sh --describe --group proof\n%s\n' "$out"
# One row per partition; column 4 is CURRENT-OFFSET, "-" when none is committed.
rows() { awk -v t="$TOPIC" '$2==t' <<<"$1" | wc -l | tr -d ' '; }
[ "$(rows "$out")" -eq 3 ] || fail "expected 3 partitions in the group's description"
[ "$(awk -v t="$TOPIC" '$2==t && $4=="-"' <<<"$out" | wc -l | tr -d ' ')" -eq 3 ] \
    || fail "AN OFFSET WAS COMMITTED BEFORE THE CRASH"

say "consume again: everything is read again, and recognised"
out="$(kafka-sink consume -brokers "$BROKER" -class actions -dir sink-data)"
printf '$ kafka-sink consume -brokers %s -class actions -dir sink-data\n%s\n' "$BROKER" "$out"
echo "$out" | grep -q "committed 0 · already committed 6 · refused 2" || fail "REDELIVERED RECORDS WERE NOT RECOGNISED"
out="$(kafka kafka-consumer-groups.sh --describe --group proof)"
printf '$ kafka-consumer-groups.sh --describe --group proof\n%s\n' "$out"
# Every partition committed (a number, not "-") and at its log end.
[ "$(rows "$out")" -eq 3 ] || fail "expected 3 partitions in the group's description"
[ "$(awk -v t="$TOPIC" '$2==t && $4 ~ /^[0-9]+$/ && $4==$5' <<<"$out" | wc -l | tr -d ' ')" -eq 3 ] \
    || fail "OFFSETS NOT COMMITTED TO THE LOG END AFTER A FULL CONSUME"
OLD_END=()
while read -r part end; do OLD_END[$part]=$end; done < <(awk -v t="$TOPIC" '$2==t {print $3, $5}' <<<"$out")

say "checkpoint and verify: 3 chains, exactly 6 entries, every record signed"
show proof sink checkpoint --dir sink-data --key "$K/ml-dsa-65-checkpoint-private.pem"
verify
grep -q "all 3 chains verify" <<<"$LAST" || fail "VERIFY FAILED"
grep -q "Record signatures: checked" <<<"$LAST" || fail "RECORD SIGNATURES WERE NOT CHECKED"
[ "$(entries "$LAST")" -eq 6 ] || fail "expected 6 entries, found $(entries "$LAST")"

say "delete and recreate the topic: offsets restart at 0, the topic id does not repeat"
show kafka kafka-topics.sh --delete --topic "$TOPIC"
for _ in $(seq 1 50); do
    kafka kafka-topics.sh --create --topic "$TOPIC" --partitions 3 >/dev/null && break
    sleep 0.2 # the deletion finishes asynchronously
done
NEW_ID="$(topic_id)"
echo "topic id: $OLD_ID → $NEW_ID"
[ -n "$NEW_ID" ] && [ "$NEW_ID" != "$OLD_ID" ] || fail "the recreated topic kept its id"
echo '{"user":"u-81","event":"after-recreate"}' | kafka-sink produce -brokers "$BROKER" -key user
# Where it landed: the one partition now holding a record, at offset 0. That
# partition held records before, so its offset 0 was already committed.
out="$(kafka kafka-get-offsets.sh --topic "$TOPIC")"
printf '$ kafka-get-offsets.sh --topic %s   (topic:partition:next offset)\n%s\n' "$TOPIC" "$out"
p="$(awk -F: '$3==1 {print $2}' <<<"$out")"
[ -n "$p" ] || fail "the new record is not alone at offset 0"
[ "${OLD_END[$p]}" -gt 0 ] || fail "partition $p held nothing before: the position is not a reused one"
echo "partition $p, offset 0: also the position of a record committed under $OLD_ID"
out="$(kafka-sink consume -brokers "$BROKER" -class actions -dir sink-data)"
printf '$ kafka-sink consume -brokers %s -class actions -dir sink-data\n%s\n' "$BROKER" "$out"
# u-81's partition, offset 0, was already committed under the old id. Without
# the id in the Source this record would be taken for that one and dropped.
echo "$out" | grep -q "committed 1 · already committed 0" || fail "A NEW RECORD WAS TAKEN FOR AN OLD ONE"
verify
grep -q "all 3 chains verify" <<<"$LAST" || fail "VERIFY FAILED"
[ "$(entries "$LAST")" -eq 7 ] || fail "expected 7 entries"

say "erase one user: their chain says so, signed, and no output names them"
out="$(proof sink erase --dir sink-data --subject u-81 --record-key "$K/ml-dsa-65-record-private.pem")"
printf '$ proof sink erase --dir sink-data --subject u-81 --record-key %s\n%s\n' "$K/ml-dsa-65-record-private.pem" "$out"
if grep -q "u-81" <<<"$out"; then fail "ERASE OUTPUT NAMES THE SUBJECT"; fi
verify
if grep -q "u-81" <<<"$LAST"; then fail "VERIFY OUTPUT NAMES THE SUBJECT"; fi
grep -q "all 3 chains verify" <<<"$LAST" || fail "VERIFY FAILED"
grep -q "signed · subject erased$" <<<"$LAST" || fail "NO SIGNED ERASED CHAIN"
BEFORE="$(entries "$LAST")"

say "live: the consumer follows, a producer adds a record every 100 ms, verify runs meanwhile"
LIVE=40
for i in $(seq 1 $LIVE); do printf '{"user":"u-%d","event":"tick","n":%d}\n' $((100 + i % 4)) "$i"; done > live.jsonl
kafka-sink consume -brokers "$BROKER" -class actions -dir sink-data -follow > consumer.out 2> consumer.err &
CONSUMER_PID=$!
kafka-sink produce -brokers "$BROKER" -key user -every 100ms < live.jsonl > producer.out &
PRODUCER_PID=$!
runs=0
while kill -0 "$PRODUCER_PID" 2>/dev/null; do
    out="$("${VERIFY[@]}")" || { echo "$out"; fail "VERIFY FAILED WHILE THE CONSUMER WAS WRITING"; }
    runs=$((runs + 1))
done
wait "$PRODUCER_PID"
PRODUCER_PID=""
cat producer.out
echo "verify ran $runs times while records were produced and consumed; every run passed"
[ "$runs" -ge 2 ] || fail "verify ran only $runs times during the live run"
for _ in $(seq 1 100); do
    out="$("${VERIFY[@]}")"
    [ "$(entries "$out")" -eq $((BEFORE + LIVE)) ] && break
    sleep 0.2
done
kill -INT "$CONSUMER_PID"
wait "$CONSUMER_PID"
CONSUMER_PID=""
printf '$ kafka-sink consume -brokers %s -class actions -dir sink-data -follow   (stopped with Ctrl-C)\n' "$BROKER"
cat consumer.out
grep -q "committed $LIVE · already committed 0 · refused 0" consumer.out || fail "THE LIVE CONSUMER DID NOT COMMIT EVERY RECORD"
verify
grep -q "all 7 chains verify" <<<"$LAST" || fail "VERIFY FAILED"
[ "$(entries "$LAST")" -eq $((BEFORE + LIVE)) ] || fail "expected $((BEFORE + LIVE)) entries"

say "done: crash recovered with nothing committed twice, a recreated topic not mistaken, name and missing key refused, one user erased, verify alongside a live consumer"
