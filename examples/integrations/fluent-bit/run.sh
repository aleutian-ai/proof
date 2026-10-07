#!/usr/bin/env bash
# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
#
# run.sh — Fluent Bit → OTLP → otel-sink → proof, end to end. No proof code in
# the shipper: only fluent-bit.yaml.
#
#   1. `proof sink init`; otel-sink (../otel) starts, signing, with
#      -crash-after-commit; Fluent Bit starts in podman, tailing ./logs
#   2. the "app" writes 8 audit lines for four users (two of them carry the
#      app's own log.record.uid), 1 audit line whose user is an email, 1 with
#      no user, and 3 debug lines
#   3. otel-sink commits, then dies before answering; Fluent Bit retries the
#      chunk with the same ids; restart: recognised, nothing committed twice
#   4. checkpoint, and verify every chain and record signature
#   5. the limit, shown: Fluent Bit loses its read position and reads the file
#      again. Lines with the app's uid are recognised; lines with a uid Fluent
#      Bit generated are committed again (duplicates, never a reused position)
#   6. erase one user, signed by the record key
#
# Needs podman and Go. Leaves nothing running. Builds from this working tree.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
IMAGE="${FLUENT_BIT_IMAGE:-docker.io/fluent/fluent-bit:5.1.3}"
NAME="proof-fluent-bit-demo"
PORT="${SINK_PORT:-4320}"
# Where otel-sink listens, and how the container reaches it. The defaults work
# under podman on macOS; on Linux, e.g. SINK_LISTEN=0.0.0.0:4320 SINK_HOST=<host ip>.
SINK_LISTEN="${SINK_LISTEN:-127.0.0.1:$PORT}"
SINK_HOST="${SINK_HOST:-host.containers.internal}"
WORK="$(mktemp -d)"
BIN="$WORK/bin"
SINK_PID=""

cleanup() {
    [ -n "$SINK_PID" ] && kill "$SINK_PID" 2>/dev/null || true
    podman rm -f "$NAME" >/dev/null 2>&1 || true
    # Rootful podman on Linux can leave container-owned files behind.
    rm -rf "$WORK" 2>/dev/null || podman unshare rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

say() { printf '\n\033[0;34m── %s\033[0m\n' "$*"; }
show() { printf '$ %s\n' "$*"; "$@"; }
fail() { echo "$*" >&2; exit 1; }

say "build otel-sink (../otel) and proof, from this working tree"
mkdir -p "$BIN"
(cd "$REPO" && go build -o "$BIN/proof" ./cmd/proof)
(cd "$HERE/../otel" && go build -o "$BIN/otel-sink" .)
export PATH="$BIN:$PATH"
cd "$WORK"
mkdir -p logs
chmod 777 logs

say "keys: proof sink init"
proof sink init --dir sink-data >/dev/null
K="sink-data.keys"
export PROOF_RECORD_KEY_FILE="$WORK/$K/ml-dsa-65-record-private.pem"
VERIFY=(proof sink verify --dir sink-data --key "$K/ml-dsa-65-checkpoint-public.pem" --record-trust "$K/ml-dsa-65-record-public.pem")
verify() { LAST="$("${VERIFY[@]}")"; printf '$ proof sink verify --dir sink-data --key %s --record-trust %s\n%s\n' \
    "$K/ml-dsa-65-checkpoint-public.pem" "$K/ml-dsa-65-record-public.pem" "$LAST"; }
entries() { echo "$1" | awk '/^chain /{for(i=1;i<=NF;i++) if ($(i+1) ~ /^entr/) {n+=$i; break}} END{print n+0}'; }

start_sink() { # start_sink LOG [flags…]
    local log="$1"; shift
    otel-sink -class app-logs -dir sink-data -listen "$SINK_LISTEN" "$@" > "$log.out" 2> "$log.err" &
    SINK_PID=$!
    for _ in $(seq 1 50); do grep -q "listening on" "$log.err" 2>/dev/null && return 0; sleep 0.1; done
    cat "$log.err" >&2; fail "otel-sink did not start"
}
stop_sink() { kill -INT "$SINK_PID"; wait "$SINK_PID"; SINK_PID=""; }
# sum LOG FIELD: total of "committed" / "already" / "refused" over otel-sink's request lines.
sum() { awk -v f="$2" '/^request [0-9]+: committed/ {
    for (i=1;i<=NF;i++) { if (f=="committed" && $i=="committed" && $(i-1)!="already") n+=$(i+1);
                          if (f=="already" && $i=="already") n+=$(i+2);
                          if (f=="refused" && $i=="refused") n+=$(i+1) } } END{print n+0}' "$1.err"; }
# wait_for LOG HANDLED REFUSED: until otel-sink has answered for that many records.
wait_for() {
    for _ in $(seq 1 300); do
        [ $(( $(sum "$1" committed) + $(sum "$1" already) )) -ge "$2" ] && [ "$(sum "$1" refused)" -ge "$3" ] && return 0
        sleep 0.2
    done
    cat "$1.err" >&2; fail "otel-sink did not receive the records"
}
start_shipper() { # start_shipper STATE_DIR: its offset DB and chunk buffer live there
    mkdir -p "$WORK/$1" && chmod 777 "$WORK/$1"
    podman run -d --name "$NAME" -e SINK_HOST="$SINK_HOST" -e SINK_PORT="$PORT" \
        -v "$HERE/fluent-bit.yaml:/fluent-bit/etc/fluent-bit.yaml:ro,Z" \
        -v "$WORK/logs:/logs:Z" -v "$WORK/$1:/state:Z" \
        "$IMAGE" -c /fluent-bit/etc/fluent-bit.yaml >/dev/null
}

say "the app logs: 8 audit lines for four users (u-91's carry the app's own uid), an email, no user, and debug noise"
cat > logs/audit.log <<'EOF'
{"msg":"tool call: search","enduser.pseudo.id":"u-81"}
{"msg":"login","enduser.pseudo.id":"u-82"}
{"msg":"tool call: export","enduser.pseudo.id":"u-81","rows":120}
{"msg":"consent changed","enduser.pseudo.id":"u-90"}
{"msg":"login","enduser.pseudo.id":"jo@example.com"}
{"msg":"tool call: delete","enduser.pseudo.id":"u-81"}
{"msg":"health check"}
{"msg":"logout","enduser.pseudo.id":"u-82"}
{"msg":"tool call: refund","enduser.pseudo.id":"u-91","log.record.uid":"01J9ZK3Q7V5S8N2M4P6R0T1W3X"}
{"msg":"logout","enduser.pseudo.id":"u-91","log.record.uid":"01J9ZK3Q7V5S8N2M4P6R0T1W3Y"}
EOF
printf '%s\n' '{"msg":"cache miss"}' '{"msg":"gc pause 3ms"}' '{"msg":"retrying dns"}' > logs/debug.log
echo "logs/audit.log: $(wc -l < logs/audit.log | tr -d ' ') lines · logs/debug.log: $(wc -l < logs/debug.log | tr -d ' ') lines"

say "otel-sink, set to crash after its first commit, before answering; Fluent Bit tailing ./logs"
start_sink first -crash-after-commit
start_shipper state

for _ in $(seq 1 150); do kill -0 "$SINK_PID" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$SINK_PID" 2>/dev/null; then
    cat first.err >&2; fail "otel-sink received nothing from Fluent Bit (on Linux, set SINK_LISTEN and SINK_HOST)"
fi
rc=0; wait "$SINK_PID" || rc=$?
SINK_PID=""
cat first.err
[ "$rc" -eq 3 ] || fail "expected the demo crash (exit 3), got $rc"

say "otel-sink is down; Fluent Bit retries the chunk. Restart otel-sink:"
start_sink second
wait_for second 8 2
sleep 3 # two more flush intervals: a routed debug chunk would have arrived by now
stop_sink
cat second.err
printf '$ otel-sink …   (stopped with Ctrl-C)\n'; cat second.out
[ "$(sum second already)" -ge 1 ] || fail "THE RETRIED CHUNK WAS NOT RECOGNISED"
# Exactly 2 refusals: the email and the line with no user. The 3 debug lines
# would each be one more (they have no user): the `match: audit` routing kept
# them in Fluent Bit.
grep -q "refused 2$" second.out || fail "expected exactly 2 refused (did debug lines reach otel-sink?)"
grep -q "no log.record.uid" second.err && fail "Fluent Bit did not add log.record.uid"
out="$(podman logs "$NAME" 2>&1)"
grep -E "retry in|succeeded at retry" <<<"$out" | head -2 | sed 's/^/fluent-bit: /' || true
grep "cache miss" <<<"$out" | head -1 | sed 's/^/fluent-bit (stdout, not proof): /' || true

say "checkpoint and verify: 4 chains, exactly 8 entries, every record signed"
show proof sink checkpoint --dir sink-data --key "$K/ml-dsa-65-checkpoint-private.pem"
verify
grep -q "all 4 chains verify" <<<"$LAST" || fail "VERIFY FAILED"
grep -q "Record signatures: checked" <<<"$LAST" || fail "RECORD SIGNATURES WERE NOT CHECKED"
[ "$(entries "$LAST")" -eq 8 ] || fail "expected 8 entries, found $(entries "$LAST"): A RETRY WAS COMMITTED TWICE"

say "an ordinary restart of Fluent Bit, keeping its state: nothing is sent again"
start_sink fourth
show podman restart -t 10 "$NAME" >/dev/null
sleep 6 # a scan and several flush intervals
stop_sink
if grep -q "^request" fourth.err; then
    cat fourth.err >&2; fail "A RESTART RE-SENT LINES: the read position was not kept"
fi
echo "otel-sink received nothing: Fluent Bit kept its read position"

say "the limit: a Fluent Bit without its read position (offset DB lost: a new volume, a redeploy) reads audit.log again"
start_sink third
podman rm -f "$NAME" >/dev/null
start_shipper state-new
wait_for third 8 2
stop_sink
cat third.err
printf '$ otel-sink …   (stopped with Ctrl-C)\n'; cat third.out
# The app's own ids are recognised; ids Fluent Bit generated are new on a re-read.
grep -q "committed 6 · already committed 2 · refused 2" third.out \
    || fail "expected the 6 shipper-uid lines duplicated and the 2 app-uid lines recognised"
verify
grep -q "all 4 chains verify" <<<"$LAST" || fail "VERIFY FAILED"
[ "$(entries "$LAST")" -eq 14 ] || fail "expected 14 entries (8 + 6 duplicates)"

say "erase one user: their chain says so, signed, and no output names them"
out="$(proof sink erase --dir sink-data --subject u-81 --record-key "$K/ml-dsa-65-record-private.pem")"
printf '$ proof sink erase --dir sink-data --subject u-81 --record-key %s\n%s\n' "$K/ml-dsa-65-record-private.pem" "$out"
if grep -q "u-81" <<<"$out"; then fail "ERASE OUTPUT NAMES THE SUBJECT"; fi
verify
if grep -q "u-81" <<<"$LAST"; then fail "VERIFY OUTPUT NAMES THE SUBJECT"; fi
grep -q "all 4 chains verify" <<<"$LAST" || fail "VERIFY FAILED"
grep -q "signed · subject erased$" <<<"$LAST" || fail "NO SIGNED ERASED CHAIN"

say "done: Fluent Bit → OTLP → proof with config only; a retried chunk recognised; debug lines never sent; a re-read duplicates shipper ids and recognises app ids; one user erased"
