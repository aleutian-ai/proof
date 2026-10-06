# OpenTelemetry logs → proof: one opaque chain per user

Most services already emit OpenTelemetry, and most already run an OTel
Collector. A log line that matters (an agent's tool call, a consent change, an
export) passes through it on its way to a backend that can be edited, sampled
and expired. `otel-sink` sits behind the collector as one more destination:
each log record goes on its user's own **opaque** proof chain, permanent,
verifiable and erasable per user. The application does not change.

```
  app ─OTLP─► OTel Collector ──────────────────────► otel-sink ─► proof/sink
              transform: adds log.record.uid          commit, THEN answer 200
              batch · retry · queue    (otlp_http)    refused → partial_success (not retried)
                                                      sink failure → 503 → the collector retries
     otel-sink dies before answering → the collector retries → log.record.uid recognised → not re-committed
```

- **The class** is fixed by the operator (`-class`), checked at startup, never
  read from the data.
- **The subject** is the `enduser.pseudo.id` attribute (`-subject-attr`), on
  the log record or else its resource. That is OTel's *pseudonymous* user id;
  `enduser.id` is often an email. A pseudonym is still personal data (OTel
  marks it sensitive); the sink keeps it only in its secret index, and chain
  ids are random.
- **The content** is the record with its resource and scope, as OTLP JSON, so
  any OTel tool can read an opened record.

## The OTel-specific problem: no delivery position

NATS, Redis and Kafka hand out a position for every message, and that position
is what lets a redelivered message be recognised. **OTLP has none.** A
collector that never got an answer (the receiver crashed after committing, a
timeout) sends the same request again, and without an id every record in it
would be committed twice.

So proof requires a **stable delivery id** for each log record, and
`log.record.uid` is how it is carried. OTel defines that attribute (opt-in, in
Development status) but does not set it for you. The collector config here adds
one when the app did not:

```yaml
processors:
  transform/uid:
    log_statements:
      - set(log.attributes["log.record.uid"], UUID()) where log.attributes["log.record.uid"] == nil
```

**Which hops the dedup covers depends on who sets the uid:**

| uid set by | app → collector retry | collector → otel-sink retry |
|---|---|---|
| the app | recognised | recognised |
| the collector (this config) | **not** recognised: each copy gets a new uid | recognised |

A record without a uid is refused, never committed without one. The id is
delivery identity, not content: a second record with the same uid is taken as
the same record, whatever its payload. **An app that sets its own uid must use
an opaque id** (a ULID or UUID): it is kept as the record's Source until the
user is erased, so it must never be content or name a person. A uid with `@`
or a space is refused.

## The answers

The collector already retries and queues. `otel-sink` answers only after the
sink commit:

| Situation | Answer | The collector then |
|---|---|---|
| every record committed (new or already) or refused | **200**; refusals counted in `partial_success`, by reason, never by value | done; logs the partial success, does not retry it |
| the sink failed on a record | **503** + `Retry-After` | retries the whole request |
| configuration error (the sink signs but no key is set, or the reverse), or the sink breaking its contract | **503**, and `otel-sink` stops | keeps retrying until it is fixed and back |
| not OTLP logs, too large, or an unsupported type or encoding | **400 / 413 / 415** | drops it |

`otel-sink` accepts protobuf or JSON, gzipped or not (the collector gzips by
default), up to 16 MiB per request, 64 MiB decompressed, and 10,000 records.
The collector config caps a request at 500 records, so a full batch of
maximum-size records still fits. Commits are serialised. A collector that
gives up during a commit does not cut it off; a request it gave up on while
waiting its turn is skipped (answered 503: it comes back).

**One subject that can't be committed** (its stored state is broken; `proof
sink verify` shows how) doesn't hold back the rest: the other records of the
request are committed, and the request is answered 503, so only that subject
keeps retrying until it is repaired.

**The effective size limit is on the stored content,** not the wire: each
committed record is JSON and carries a copy of its resource and scope. A
record with a large body and large resource attributes (Kubernetes labels,
say) can be refused as over 64 KiB though it was smaller as protobuf.

**The subject attribute on the record wins.** If it is there but not a string,
the record is refused; the resource is consulted only when the record has no
such attribute.

## Run it

```sh
./examples/integrations/otel/run.sh
```

It needs podman and Go, and leaves nothing running. It uses
`otel/opentelemetry-collector-contrib:0.162.0` and `telemetrygen` (the OTel
project's own generator), so nothing here talks only to code of its own. The
output below is from a real run.

**Keys.** `proof sink init` makes a record key that `otel-sink` holds online
(given as a FILE, `PROOF_RECORD_KEY_FILE`, never the key itself) and a
checkpoint key kept apart.

**Send eight log records** through the collector: six for three users, one
whose pseudo id is an email, one with no user. `otel-sink` was started with
`-crash-after-commit`: it commits the first request, then dies before
answering.

```
$ telemetrygen logs --otlp-insecure --otlp-endpoint localhost:4317 --logs 3 --body agent tool call --telemetry-attributes enduser.pseudo.id="u-81"
$ telemetrygen logs … --logs 2 … enduser.pseudo.id="u-82"
$ telemetrygen logs … --logs 1 --body consent changed … enduser.pseudo.id="u-90"
$ telemetrygen logs … --logs 1 … enduser.pseudo.id="jo@example.com"
$ telemetrygen logs … --logs 1 --body health check
otel-sink: -crash-after-commit: exiting after the sink commit, before answering
```

**Restart `otel-sink`.** The collector's retries arrive. The request that was
committed before the crash is recognised by its uids, and nothing is committed
twice:

```
otel-sink: listening on 127.0.0.1:4320 (POST /v1/logs), class app-logs
request 1, record 1: refused: no enduser.pseudo.id (a string attribute on the log record or its resource)
request 1: committed 0 · already committed 0 · refused 1
request 2: committed 0 · already committed 3 · refused 0
request 3, record 4: refused: sink: invalid record: sink: subject is not valid: … this check cannot tell a name from one
request 3: committed 3 · already committed 0 · refused 1
$ otel-sink …   (stopped with Ctrl-C)
committed 3 · already committed 3 · refused 2
```

The collector logs each refusal as a partial success, and does not retry it:

```
warn  otlphttpexporter  Partial success response  {"message": "proof refused 1 log records (not retried): 1: no enduser.pseudo.id (a string attribute on the log record or its resource)", "dropped_log_records": 1}
```

**Checkpoint and verify:** three chains, exactly six entries, every record
signed.

```
$ proof sink checkpoint --dir sink-data --key sink-data.keys/ml-dsa-65-checkpoint-private.pem
checkpoint anchors/app-logs.5707d4504f93a3d07abe3f0aa243bbf9/0001.json signed over 3 entries
checkpoint anchors/app-logs.66c632c70cfab9ae0b22067178bc932f/0001.json signed over 1 entry
checkpoint anchors/app-logs.afa1ccd56bcf112ee89421243618f2b4/0001.json signed over 2 entries
$ proof sink verify --dir sink-data --key sink-data.keys/ml-dsa-65-checkpoint-public.pem --record-trust sink-data.keys/ml-dsa-65-record-public.pem
chain app-logs.5707d4504f93a3d07abe3f0aa243bbf9 verifies 3 entries: 3 opened, 0 erased · 1 checkpoint, 0 unanchored · 3 signed
chain app-logs.66c632c70cfab9ae0b22067178bc932f verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored · 1 signed
chain app-logs.afa1ccd56bcf112ee89421243618f2b4 verifies 2 entries: 2 opened, 0 erased · 1 checkpoint, 0 unanchored · 2 signed
Record signatures: checked against --record-trust
all 3 chains verify
```

Without the uid as the Source, the same run commits the retried request again
(`committed 6` on restart, nine entries) and `run.sh` fails. That check was
confirmed by hand.

**Erase one user,** signed by the record key. The output never names them:

```
$ proof sink erase --dir sink-data --subject u-81 --record-key sink-data.keys/ml-dsa-65-record-private.pem
erased 1 subject: 1 chain, 3 events. The subject is forgotten: nothing in this folder
links it to the erased chains any more, and a later event for it starts a new chain.
…
$ proof sink verify …
chain app-logs.5707d4504f93a3d07abe3f0aa243bbf9 verifies 4 entries: 0 opened, 3 erased · 1 checkpoint, 1 unanchored · 4 signed · subject erased
all 3 chains verify
```

## What it proves, and what it doesn't

- **Proves:** each log record that reached `otel-sink` is on its user's chain,
  unchanged since it was committed, and signed by the record key. A crash
  between the commit and the answer neither loses a record nor commits it
  twice. An erased user's chain proves the erasure and names nobody.
- **Delivery:** at-least-once from the collector, with idempotent insertion by
  delivery id. Duplicates made *before* the collector are caught only if the
  app sets `log.record.uid` itself (see the table above).
- **Order is arrival order, not event time.** The collector can send requests
  concurrently, so records can arrive in either order. Each record's own
  timestamps are inside its content. The chain orders; timestamps describe.
- **Doesn't prove that every log was sent.** Sampling, filtering, a collector
  that drops a request after its retry window, or an app that never logs are
  invisible from here.
- **Logs only.** Traces and metrics are not committed; an event that matters
  can be emitted as a log record.

## Notes

- **Keep the collector's retry window long and its queue persistent.** The
  config sets `max_elapsed_time: 1h` and a `file_storage` queue: while
  `otel-sink` is down (a crash, a configuration error), records wait in the
  collector instead of being dropped. `run.sh` mounts a tmpfs for the queue;
  mount a volume in a real deployment.
- **No authentication or TLS.** `otel-sink` listens on `127.0.0.1:4320`: put
  it beside the collector, and let the collector do mTLS towards apps. The
  collector reaches it as `host.containers.internal` under podman on macOS; on
  Linux, run `SINK_LISTEN=0.0.0.0:4320 SINK_HOST=<host ip>:4320 ./run.sh`.
- **Refusals are logged by position,** the first 10 per request; the counts
  by reason are always in the answer.
- **OTLP/HTTP only.** The collector speaks it to `otel-sink`; gRPC would add a
  server and nothing new.
- **Record signing is optional.** Without `PROOF_RECORD_KEY_FILE`, records are
  committed unsigned. A sink that signs refuses a receiver without the key (and
  the reverse), and `otel-sink` stops rather than answer 503 forever.
- **Own module,** so the OTel dependency (`go.opentelemetry.io/collector/pdata`
  v1.65.0, the newest on Go 1.25) stays out of proof's `go.mod`. It pins proof
  to a commit until proof's next release.
