# NATS JetStream → proof: one chain per subject key

NATS routes by **subject**. `nats-sink` reads a JetStream stream of
`evidence.<key>` messages and commits each one to the proof chain named `<key>`,
through [`topicsink`](../topicsink). It **acknowledges a message only after its
commit succeeds**, so a crash never loses evidence. A message redelivered after a
crash is recognised, and it is **never committed twice**.

```
  publisher ──► stream EVIDENCE ──► durable consumer ──► topicsink ──► one chain per key
  evidence.u-81   (evidence.*)      commit, THEN ack
                                        │
               crash between commit and ack → redelivered → recognised → acked, not re-committed
```

Checkpoint, verify and erase are `topic-sink`'s, run on the same folder.

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
refused EVIDENCE@1790641378694210056:4: the subject is not evidence.<key> with a valid chain id (lowercase letters, digits, . _ -, max 64). Terminated.
nats-sink: -crash-after-commit: exiting after the commit, before any ack
```

**Consume again.** Nothing was acked, so after the ack deadline JetStream
redelivers all six. Every one is recognised as already committed and acked.
Nothing new is committed:

```
$ nats-sink consume -url nats://127.0.0.1:4222 -dir sink-data -ack-wait 5s
committed 0 · already committed (redelivered) 6 · refused 0
```

**Checkpoint and verify: exactly six entries**, one chain per user:

```
$ topic-sink checkpoint -dir sink-data -key-file keys/ml-dsa-65-private.pem
checkpoint anchors/u-81/0001.json signed over 3 entries
checkpoint anchors/u-82/0001.json signed over 2 entries
checkpoint anchors/u-90/0001.json signed over 1 entry
$ topic-sink verify -dir sink-data -pub-file keys/ml-dsa-65-public.pem
chain u-81         verifies 3 entries: 3 opened, 0 erased · 1 checkpoint, 0 unanchored
chain u-82         verifies 2 entries: 2 opened, 0 erased · 1 checkpoint, 0 unanchored
chain u-90         verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored
all 3 chains verify
```

## How "never twice" works

Each record carries its stream position as its topicsink `Source`:
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

The check costs one lookup, not a scan. Positions are not personal data, so they
survive erasure. A message redelivered after its user was erased is still
recognised and not re-committed.

## What it proves, and what it doesn't

- **Proves:** each consumed message is on its key's chain, unchanged since it was
  committed. Messages for one key are in stream order. A crash between commit and
  ack neither loses a message nor commits it twice.
- **Doesn't prove that every published message was consumed.** A message
  JetStream never delivered is never committed. The sources file holds enough to
  check for gaps in stream sequences later. That check is not built here.
- **Doesn't prove the order across keys.** Each chain is ordered on its own.
- **One checkpoint series per key.** Many keys means many signatures per
  checkpoint run, the same limit as `topicsink`.

## Notes

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
  empty payload, one over topicsink's 64 KiB limit, or one with no stream
  position. Retrying would redeliver it forever and stall every message
  behind it.
- `-follow` keeps consuming instead of exiting once the stream is drained.
