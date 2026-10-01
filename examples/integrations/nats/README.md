# NATS JetStream → proof: one opaque chain per user

NATS routes by **subject**. `nats-sink` reads a JetStream stream of
`evidence.<key>` messages and commits each one through
[`proof/sink`](../../../sink): the key is the record's subject (a user
pseudonym), and the sink files it on that user's own **opaque** chain
(`events.<random hex>`). Only the sink's secret index knows which chain is whose.
It **acknowledges a message only after its commit succeeds**, so a crash never
loses evidence. A message redelivered after a crash is recognised, and it is
**never committed twice**.

```
  publisher ──► stream EVIDENCE ──► durable consumer ──► proof/sink ──► one opaque chain per (class, user)
  evidence.u-81   (evidence.*)      commit, THEN ack message i
                                    iff outcome i is committed
                                        │
               crash between commit and ack → redelivered → recognised → acked, not re-committed
```

Checkpoint, verify and erase are `proof sink`'s, run on the same folder. Every
message is committed under one class, `-class` (default `events`), checked at
startup.

## Run it

```sh
./examples/integrations/nats/run.sh
```

It needs podman and Go. It starts `nats-server -js` in a container, builds from
this tree and leaves nothing running. Output below is from a real run.

**Publish** seven events. Six belong to three users; one is keyed by a name.

```
$ nats-sink publish -url nats://127.0.0.1:4222 -key user
published 7 messages to EVIDENCE
```

**A dotted key never reaches the stream.** The stream takes `evidence.*`, which
is exactly one token after the prefix. NATS splits subjects on `.`, so
`evidence.jo@example.com` is three tokens. A consumer that routed by the last
token would put it on a chain called `com`. The error does not repeat the key.

```
$ echo '{"user":"jo@example.com","event":"login"}' | nats-sink publish -key user
nats-sink publish: line 1: no stream accepts that subject (the key must be one subject token: no dots)
```

**Consume, and crash between the commit and the ack.** `-crash-after-commit`
exists for this demo. The name-keyed message is refused, and it is terminated
rather than redelivered forever. It is logged by its stream position, never by
its subject.

```
$ nats-sink consume -url nats://127.0.0.1:4222 -dir sink-data -ack-wait 5s -crash-after-commit
refused EVIDENCE@1790737504858655669:4: the NATS subject is not evidence.<key> with a valid key (lowercase letters, digits, . _ -, max 128; no dots in NATS). Terminated.
nats-sink: -crash-after-commit: exiting after the commit, before any ack
```

**Consume again.** Nothing was acked, so after the ack deadline JetStream
redelivers all six. Every one is recognised as already committed and acked.
Nothing new is committed:

```
$ nats-sink consume -url nats://127.0.0.1:4222 -dir sink-data -ack-wait 5s
committed 0 · already committed (redelivered) 6 · refused 0
```

**Checkpoint and verify: exactly six entries**, one opaque chain per user. No
user is named: the chain ids are random.

```
$ proof sink checkpoint --dir sink-data --key keys/ml-dsa-65-private.pem
checkpoint anchors/events.8590967393afd1b6327074b0be7ff0e0/0001.json signed over 3 entries
checkpoint anchors/events.a3ece678b4460b4173deb233ffd887bb/0001.json signed over 1 entry
checkpoint anchors/events.c9a51ae7f872a7403dff60bd2ad308c0/0001.json signed over 2 entries
$ proof sink verify --dir sink-data --key keys/ml-dsa-65-public.pem
chain events.8590967393afd1b6327074b0be7ff0e0 verifies 3 entries: 3 opened, 0 erased · 1 checkpoint, 0 unanchored
chain events.a3ece678b4460b4173deb233ffd887bb verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored
chain events.c9a51ae7f872a7403dff60bd2ad308c0 verifies 2 entries: 2 opened, 0 erased · 1 checkpoint, 0 unanchored
all 3 chains verify
```

**Erase one user.** The sink forgets them first, then erases their chain. The
output never names them, and every chain still verifies:

```
$ proof sink erase --dir sink-data --subject u-81
erased 1 subject: 1 chain, 3 events. The subject is forgotten: nothing in this folder
links it to the erased chains any more, and a later event for it starts a new chain.
Content, nonces and source positions are deleted and the files rewritten; every chain still verifies.
Not reached by this: backups or snapshots of sink-data/, SSD blocks, and anyone an event or nonce
was disclosed to.
$ proof sink verify --dir sink-data --key keys/ml-dsa-65-public.pem
chain events.8590967393afd1b6327074b0be7ff0e0 verifies 4 entries: 0 opened, 3 erased · 1 checkpoint, 1 unanchored · subject erased (not yet checkpointed)
chain events.a3ece678b4460b4173deb233ffd887bb verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored
chain events.c9a51ae7f872a7403dff60bd2ad308c0 verifies 2 entries: 2 opened, 0 erased · 1 checkpoint, 0 unanchored
all 3 chains verify
```

## How "never twice" works

Each record carries its stream position as its sink `Source`:
`EVIDENCE@<created>:42`. That is the stream, when this incarnation of it was
created, and the sequence. The creation time matters. A deleted and recreated
stream restarts at sequence 1, and without it a new message 1 would look like
the old one and be dropped as a duplicate. Before appending, the sink writes down where each record will land on
its chain: the entry id and the sequence. It keeps this in
`evidence.db.sources`. When a position comes back:

- **The chain holds that entry at that sequence:** it was committed. It is
  skipped, and the consumer acks it.
- **It does not:** the earlier attempt stopped before its append. It is
  committed now.

The check costs one lookup, not a scan. The sink answers each commit with one
outcome per record, in order (committed or not, duplicate or not), naming no
chain and no user. The consumer acks message *i* exactly when outcome *i* is
committed, and NAKs the rest; nothing is matched by user.

Positions link a chain to upstream messages, so they are deleted when that user
is erased. A message redelivered after its user was erased is therefore
committed again, to the user's NEW chain (the old one is forgotten), visibly.
Ack before you erase.

## What it proves, and what it doesn't

- **Proves:** each consumed message is on its user's chain, unchanged since it
  was committed. Messages for one user are in stream order. A crash between
  commit and ack neither loses a message nor commits it twice. An erased user's
  chain proves the erasure (once a checkpoint covers it) and names nobody.
- **Doesn't prove that every published message was consumed.** A message
  JetStream never delivered is never committed. The sources file holds enough to
  check for gaps in stream sequences later. That check is not built here.
- **Doesn't prove the order across users.** Each chain is ordered on its own.
- **One checkpoint series per chain.** Many users means many signatures per
  checkpoint run, the same limit as the sink.
- **Timing can link.** Chain ids are opaque, but an observer of the evidence
  file may still link chains by timing (see the sink's correlation leakage).

## Notes

- **Record signing (optional).** Set `PROOF_RECORD_KEY_FILE` to the PATH of a
  record key (`proof keygen --alg ml-dsa-65`), never to the key itself, and the
  consumer signs every record it commits; `run.sh` does, and verifies with
  `proof sink verify --record-trust`. A sink that signs refuses a consumer
  without the key (and the reverse): the consumer stops with a configuration
  error instead of redelivering forever.
- **Own module.** The NATS client must not enter proof's `go.mod`. This module
  is listed in the repo's `go.work`, and it pins proof to a commit until proof's
  next release.
- **The ack deadline must be at least 5 s.** While draining, the consumer takes
  only messages already waiting, so none sit unacknowledged while a batch fills.
  During development a fetch that waited to fill its batch did exactly that: its
  messages outlived a 2 s deadline and were redelivered mid-commit. The
  duplicate check caught every one, and the chain still held exactly 6 entries.
  But it was wasted work, and it is now refused.
- **A message that can never be committed is terminated**, never retried: an
  empty payload, one over the sink's 64 KiB limit, or one with no stream
  position. Retrying would redeliver it forever and stall every message
  behind it.
- `-follow` keeps consuming instead of exiting once the stream is drained.
