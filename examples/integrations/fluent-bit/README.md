# Fluent Bit → proof: config only

Teams that don't run an OpenTelemetry Collector often run a log shipper, and
Fluent Bit is the common one (CNCF; the default in many Kubernetes
distributions). It already speaks OTLP, and [`otel-sink`](../otel) already
receives OTLP and commits each log record to its user's opaque proof chain. So
this integration is **only configuration**: [`fluent-bit.yaml`](fluent-bit.yaml),
no proof code in the shipper, no new code here.

```
  app ─► audit.log ─► Fluent Bit: tail → tag audit → add log.record.uid → opentelemetry output ─► otel-sink ─► proof/sink
         debug.log ─► Fluent Bit: tail → tag debug → stdout              (never sent to proof)
     otel-sink dies before answering → Fluent Bit retries the chunk with the SAME ids → recognised → not re-committed
```

- **Tags route; they never become a class or a subject.** The `audit` tag
  decides which lines go to proof at all. The class is `otel-sink`'s
  `-class`; the subject is the line's `enduser.pseudo.id` (a pseudonym the app
  logs).
- **The line's `msg` becomes the log body,** and every other field becomes a
  log record attribute (`logs_body_key` + `logs_body_key_attributes`).
- Answers, refusals and limits are `otel-sink`'s: see [its README](../otel).

## The delivery id, at a file tailer

`otel-sink` requires a stable delivery id per record, `log.record.uid` (OTLP
has no position). The config keeps one the app wrote, and adds a random one
otherwise, **before the chunk is buffered**, so a retried chunk carries the
same ids:

```yaml
- name: record_modifier          # a random id under a temporary key
  match: audit
  uuid_key: proof.generated_uid
- name: modify                   # used only if the app did not set its own
  match: audit
  rename: proof.generated_uid log.record.uid
  remove: proof.generated_uid
```

**Why random, not the file position (`path:offset`):** a rotated, truncated or
recreated file reuses positions with different lines, and proof would take a
new line for an old one and drop it. That reused-position failure lost
evidence twice in this series (NATS, Redis). A random id cannot alias.

**What that costs, shown below:** if Fluent Bit loses its read position (its
offset DB is gone or behind) and reads a file again, the lines it gave ids to
get NEW ids and are committed again. **Duplicates are possible on a re-read;
silent loss from reused file positions is avoided.** Lines whose id the *app*
wrote are recognised even then. That is the upgrade path: have the app write
`log.record.uid` (a ULID or UUID, never content) into each line.

This says nothing about the rest of the shipper pipeline: Fluent Bit can still
drop data through its own configuration, a full buffer, or a file rotated away
before it was read.

## Run it

```sh
./examples/integrations/fluent-bit/run.sh
```

It needs podman and Go, and leaves nothing running. It builds `otel-sink` from
`../otel` and runs `fluent/fluent-bit:5.1.3`. The output below is from a real
run.

**The app logs** ten audit lines and three debug lines. Eight audit lines are
for four users, and u-91's two carry the app's own uid. One audit line's user
is an email, and one has no user. `otel-sink` was started with
`-crash-after-commit`: it commits Fluent Bit's chunk, then dies before
answering.

```
logs/audit.log: 10 lines · logs/debug.log: 3 lines
request 1, record 5: refused: sink: invalid record: sink: subject is not valid: … this check cannot tell a name from one
request 1, record 7: refused: no enduser.pseudo.id (a string attribute on the log record or its resource)
otel-sink: -crash-after-commit: exiting after the sink commit, before answering
```

**Restart `otel-sink`.** Fluent Bit retries the same chunk, and every record
is recognised by its id:

```
request 1: committed 0 · already committed 8 · refused 2
fluent-bit: [ warn] [engine] failed to flush chunk '1-1791326215.487136831.flb', retry in 2 seconds
fluent-bit: [ info] [engine] flush chunk '1-1791326215.487136831.flb' succeeded at retry 1
fluent-bit (stdout, not proof): [0] debug: [[1791326215.488314873, {}], {"msg"=>"cache miss"}]
```

Exactly two refused: the email and the line with no user. The three debug
lines never left Fluent Bit: the output matches only the `audit` tag (each
would otherwise have been one more refusal).

**An ordinary restart** of Fluent Bit, keeping its state, sends nothing again:
it keeps its read position.

```
$ podman restart -t 10 proof-fluent-bit-demo
otel-sink received nothing: Fluent Bit kept its read position
```

**Checkpoint and verify:** four chains, exactly eight entries, every record
signed.

```
$ proof sink verify --dir sink-data --key sink-data.keys/ml-dsa-65-checkpoint-public.pem --record-trust sink-data.keys/ml-dsa-65-record-public.pem
chain app-logs.322ca2b7143542b932a90b8a56dd5d6e verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored · 1 signed
chain app-logs.b911597b8afe755df0f9da16abc4787a verifies 2 entries: 2 opened, 0 erased · 1 checkpoint, 0 unanchored · 2 signed
chain app-logs.c7e8c132b6033331538026134f796716 verifies 2 entries: 2 opened, 0 erased · 1 checkpoint, 0 unanchored · 2 signed
chain app-logs.eca91c058e2f1467d8c4dbe55f9fa0db verifies 3 entries: 3 opened, 0 erased · 1 checkpoint, 0 unanchored · 3 signed
Record signatures: checked against --record-trust
all 4 chains verify
```

**The limit, shown.** A Fluent Bit without its read position (a lost volume, a
redeploy) reads `audit.log` from the start. The six lines whose ids Fluent Bit
generated are committed again; u-91's two, with the app's ids, are recognised:

```
request 1: committed 6 · already committed 2 · refused 2
$ proof sink verify …
chain app-logs.322ca2b7143542b932a90b8a56dd5d6e verifies 2 entries: … 1 unanchored · 2 signed
chain app-logs.b911597b8afe755df0f9da16abc4787a verifies 2 entries: … 0 unanchored · 2 signed
chain app-logs.c7e8c132b6033331538026134f796716 verifies 4 entries: … 2 unanchored · 4 signed
chain app-logs.eca91c058e2f1467d8c4dbe55f9fa0db verifies 6 entries: … 3 unanchored · 6 signed
all 4 chains verify
```

Every chain still verifies: duplicates are extra entries, not damage. u-91's
chain is unchanged.

**Erase one user,** signed by the record key; the output never names them:

```
$ proof sink erase --dir sink-data --subject u-81 --record-key sink-data.keys/ml-dsa-65-record-private.pem
erased 1 subject: 1 chain, 6 events. …
$ proof sink verify …
chain app-logs.eca91c058e2f1467d8c4dbe55f9fa0db verifies 7 entries: 0 opened, 6 erased · 1 checkpoint, 4 unanchored · 7 signed · subject erased
all 4 chains verify
```

Without the two uid filters, the same run commits only u-91's lines and refuses
the other eight (no `log.record.uid`), and `run.sh` fails. That was checked by
hand: `otel-sink` refuses rather than commit a record it could not recognise
again.

## Notes

- **Retries:** `retry_limit: no_limits`, and the scheduler backoff is capped at
  5 s (Fluent Bit's default grows to minutes). Chunks are buffered on disk
  (`storage.type: filesystem`, `storage.sync: full`). An ordinary restart is
  shown above; a hard crash of Fluent Bit mid-write is not tested here.
- **`otel-sink` answers decide what Fluent Bit does** (checked against 5.1.3):
  a 503 is retried; a 200 with a partial success (refused records) is not
  retried; a 4xx (a request that is not OTLP, too large, a wrong type) is
  dropped after one try, as the collector does.
- **One offset DB per input,** and keep it on a volume: losing it means a
  re-read, and so duplicates of the lines Fluent Bit gave ids to.
- **The debug `stdout` output is for the demo.** In real use, send those lines
  to your usual log store.
- **Linux:** `SINK_LISTEN=0.0.0.0:4320 SINK_HOST=<host ip> ./run.sh`; the
  defaults suit podman on macOS (`host.containers.internal`).
- **Vector** can do the same (VRL `uuid_v7()` and its OpenTelemetry sink), but
  is untested here; one shipper is the point.
