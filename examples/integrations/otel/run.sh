#!/usr/bin/env bash
# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
#
# run.sh — OpenTelemetry logs → proof, end to end, through a real collector.
#
#   1. `proof sink init` makes the keys; otel-sink starts, signing, with
#      -crash-after-commit; the OTel Collector (contrib) starts in podman
#   2. telemetrygen (the OTel project's generator) sends 8 log records: 6 for
#      three users (enduser.pseudo.id), 1 whose pseudo id is an email, 1 with
#      no user
#   3. otel-sink commits the first request, then dies before answering. The
#      collector keeps retrying. Restart otel-sink: the retried records are
#      recognised by log.record.uid, nothing is committed twice
#   4. checkpoint, and verify every chain and every record signature
#   5. erase one user, signed by the record key
#
# Needs podman and Go. Leaves nothing running. Builds from this working tree.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
COLLECTOR="${COLLECTOR_IMAGE:-docker.io/otel/opentelemetry-collector-contrib:0.162.0}"
TELEMETRYGEN="ghcr.io/open-telemetry/opentelemetry-collector-contrib/telemetrygen:v0.162.0"
NAME="proof-otel-demo"
PORT="${SINK_PORT:-4320}"
# Where otel-sink listens, and how the collector container reaches it. The
# defaults work under podman on macOS; on Linux, listen on an address the
# container can reach (e.g. SINK_LISTEN=0.0.0.0:4320) and name it in SINK_HOST.
SINK_LISTEN="${SINK_LISTEN:-127.0.0.1:$PORT}"
SINK_HOST="${SINK_HOST:-host.containers.internal:$PORT}"
WORK="$(mktemp -d)"
BIN="$WORK/bin"
SINK_PID=""

cleanup() {
    [ -n "$SINK_PID" ] && kill "$SINK_PID" 2>/dev/null || true
    podman rm -f "$NAME" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

say() { printf '\n\033[0;34m── %s\033[0m\n' "$*"; }
show() { printf '$ %s\n' "$*"; "$@"; }
fail() { echo "$*" >&2; exit 1; }

say "build (from this working tree)"
mkdir -p "$BIN"
(cd "$REPO" && go build -o "$BIN/proof" ./cmd/proof)
(cd "$HERE" && go build -o "$BIN/otel-sink" .)
export PATH="$BIN:$PATH"
cd "$WORK"

say "keys: proof sink init (a record key for otel-sink, a checkpoint key kept apart)"
proof sink init --dir sink-data >/dev/null
K="sink-data.keys"
ls "$K"
# otel-sink is given the key's FILE, never the key itself.
export PROOF_RECORD_KEY_FILE="$WORK/$K/ml-dsa-65-record-private.pem"
VERIFY=(proof sink verify --dir sink-data --key "$K/ml-dsa-65-checkpoint-public.pem" --record-trust "$K/ml-dsa-65-record-public.pem")
verify() { LAST="$("${VERIFY[@]}")"; printf '$ proof sink verify --dir sink-data --key %s --record-trust %s\n%s\n' \
    "$K/ml-dsa-65-checkpoint-public.pem" "$K/ml-dsa-65-record-public.pem" "$LAST"; }
entries() { echo "$1" | awk '/^chain /{for(i=1;i<=NF;i++) if ($(i+1) ~ /^entr/) {n+=$i; break}} END{print n+0}'; }

# start_sink LOG [flags…]: run otel-sink in the background, wait until it listens.
start_sink() {
    local log="$1"; shift
    otel-sink -class app-logs -dir sink-data -listen "$SINK_LISTEN" "$@" > "$log.out" 2> "$log.err" &
    SINK_PID=$!
    for _ in $(seq 1 50); do
        grep -q "listening on" "$log.err" 2>/dev/null && return 0
        sleep 0.1
    done
    cat "$log.err" >&2
    fail "otel-sink did not start"
}
# sum LOG FIELD: total of "committed" / "already committed" / "refused" over request lines.
sum() { awk -v f="$2" '/^request [0-9]+: committed/ {
    for (i=1;i<=NF;i++) { if (f=="committed" && $i=="committed" && $(i-1)!="already") n+=$(i+1);
                          if (f=="already" && $i=="already") n+=$(i+2);
                          if (f=="refused" && $i=="refused") n+=$(i+1) } } END{print n+0}' "$1.err"; }

say "otel-sink, set to crash after its first commit, before answering"
start_sink first -crash-after-commit
cat first.err

say "collector: $COLLECTOR"
podman rm -f "$NAME" >/dev/null 2>&1 || true
# The collector runs as a non-root user: its persistent queue gets a writable
# tmpfs here (a real deployment mounts a volume, so the queue survives restarts).
podman run -d --name "$NAME" --tmpfs /var/lib/otelcol:rw,mode=1777 \
    -e SINK_ENDPOINT="http://$SINK_HOST" \
    -v "$HERE/collector.yaml:/etc/otelcol-contrib/config.yaml:ro,Z" "$COLLECTOR" >/dev/null
ready() { local l; l="$(podman logs "$NAME" 2>&1)"; grep -q "Everything is ready" <<<"$l"; }
for _ in $(seq 1 100); do ready && break; sleep 0.2; done
ready || { podman logs "$NAME" >&2; fail "the collector did not start"; }

say "telemetrygen → collector: 6 records for three users, one with an email, one with no user"
gen() { # gen COUNT BODY [ATTRIBUTE]
    local args=(logs --otlp-insecure --otlp-endpoint localhost:4317 --logs "$1" --body "$2")
    [ -n "${3:-}" ] && args+=(--telemetry-attributes "$3")
    printf '$ telemetrygen %s\n' "${args[*]}"
    podman run --rm --network "container:$NAME" "$TELEMETRYGEN" "${args[@]}" >/dev/null 2>&1
}
gen 3 "agent tool call" 'enduser.pseudo.id="u-81"'
gen 2 "agent tool call" 'enduser.pseudo.id="u-82"'
gen 1 "consent changed" 'enduser.pseudo.id="u-90"'
gen 1 "agent tool call" 'enduser.pseudo.id="jo@example.com"'
gen 1 "health check"

for _ in $(seq 1 100); do kill -0 "$SINK_PID" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$SINK_PID" 2>/dev/null; then
    cat first.err >&2
    fail "otel-sink received nothing from the collector (on Linux, set SINK_LISTEN and SINK_HOST)"
fi
rc=0; wait "$SINK_PID" || rc=$?
SINK_PID=""
cat first.err
[ "$rc" -eq 3 ] || fail "expected the demo crash (exit 3), got $rc"

say "otel-sink is down; the collector retries. Restart it:"
start_sink second
# Wait for the collector's retries to land: 6 records on chains, 2 refused.
for _ in $(seq 1 300); do
    [ $(( $(sum second committed) + $(sum second already) )) -ge 6 ] && [ "$(sum second refused)" -ge 2 ] && break
    sleep 0.2
done
kill -INT "$SINK_PID"; wait "$SINK_PID"; SINK_PID=""
cat second.err
printf '$ otel-sink …   (stopped with Ctrl-C)\n'; cat second.out
[ "$(sum second already)" -ge 1 ] || fail "THE RETRIED REQUEST WAS NOT RECOGNISED"
grep -q "refused 2$" second.out || fail "expected 2 refused"
grep -q "refused: no log.record.uid" second.err && fail "the collector did not add log.record.uid"
out="$(podman logs "$NAME" 2>&1)"
grep -i "partial success" <<<"$out" | head -2 | sed 's/^/collector: /' || true
grep -qi "proof refused" <<<"$out" || fail "the collector did not see partial_success"

say "checkpoint and verify: 3 chains, exactly 6 entries, every record signed"
show proof sink checkpoint --dir sink-data --key "$K/ml-dsa-65-checkpoint-private.pem"
verify
grep -q "all 3 chains verify" <<<"$LAST" || fail "VERIFY FAILED"
grep -q "Record signatures: checked" <<<"$LAST" || fail "RECORD SIGNATURES WERE NOT CHECKED"
[ "$(entries "$LAST")" -eq 6 ] || fail "expected 6 entries, found $(entries "$LAST"): A RETRY WAS COMMITTED TWICE"

say "erase one user: their chain says so, signed, and no output names them"
out="$(proof sink erase --dir sink-data --subject u-81 --record-key "$K/ml-dsa-65-record-private.pem")"
printf '$ proof sink erase --dir sink-data --subject u-81 --record-key %s\n%s\n' "$K/ml-dsa-65-record-private.pem" "$out"
if grep -q "u-81" <<<"$out"; then fail "ERASE OUTPUT NAMES THE SUBJECT"; fi
verify
if grep -q "u-81" <<<"$LAST"; then fail "VERIFY OUTPUT NAMES THE SUBJECT"; fi
grep -q "all 3 chains verify" <<<"$LAST" || fail "VERIFY FAILED"
grep -q "signed · subject erased$" <<<"$LAST" || fail "NO SIGNED ERASED CHAIN"

say "done: telemetrygen → collector → proof; a crash before answering recovered with nothing committed twice; email and missing user refused; one user erased"
