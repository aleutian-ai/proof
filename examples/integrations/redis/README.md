# Redis / Valkey Streams → proof: one chain per key

Redis is the database most teams already run, and **Streams** are its append-only
log. `redis-sink` reads a stream through a consumer group and commits each entry
to the proof chain named by its `key` field, through [`proof/sink`](../../../sink).
It acknowledges (`XACK`) an entry only after its commit succeeds.

It works unchanged with **Valkey**, the Linux Foundation's BSD-licensed fork of
Redis. The demo runs on Valkey by default, and has also been run on Redis 8.

```
  XADD evidence * key u-81 data {…} ─► stream "evidence" ─► group "proof" ─► proof/sink ─► chain per key
                                                            commit, THEN XACK
      crash before XACK → entries stay PENDING → restart reads its pending list FIRST
                        → recognised as committed → XACK'd, not re-committed
```

## The Redis-specific danger: evidence stuck in a pending list

NATS and Kafka redeliver an unacknowledged message by themselves. **Redis does
not.** An entry that was read but never acknowledged stays in the group's pending
list until some consumer asks for it. That might be never. So on start-up,
before reading anything new, `redis-sink`:

1. re-reads **its own** pending entries (`XREADGROUP … 0`);
2. claims entries **another** consumer left pending for longer than
   `-claim-idle` (60 s, via `XAUTOCLAIM`). That consumer probably died, and no
   one else would ever read them.

With `-follow` it keeps claiming every `-claim-idle`, since a peer can die at
any time, not just before this consumer started.

Pending entries may already have been committed, if the crash came between the
commit and the ack. Each record carries its stream position as its sink
`Source`, so those are recognised and acknowledged, never committed twice.

That position is `evidence@<incarnation>:<entry id>`. The incarnation is a
random token that changes whenever the consumer group has to be created afresh.
That happens exactly when the stream was deleted and has come back, and entry
ids can then repeat. Without the token, a new entry with an old id would be
taken as already committed, and silently dropped.

## Run it

```sh
./examples/integrations/redis/run.sh                                             # Valkey
REDIS_IMAGE=docker.io/library/redis:8-alpine ./examples/integrations/redis/run.sh  # Redis
```

It needs podman and Go, and leaves nothing running. Output below is from a real
run on `valkey/valkey:8-alpine`.

**Add** eight entries: six for three users, one keyed by a name, one by an email.

```
$ redis-sink add -addr 127.0.0.1:6379 -key user
added 8 entries to stream evidence
```

**Consume, and crash between the commit and the ack.** The name and the email
are refused and logged by entry id only, never by key. They are acknowledged so
that they are not re-read forever. Acknowledging does not delete in Redis: they
stay in the stream.

```
$ redis-sink consume -addr 127.0.0.1:6379 -dir sink-data -crash-after-commit
refused evidence:1790649543525-1: its key is not a valid chain id (lowercase letters, digits, . _ -, max 64). Acked; it stays in the stream.
refused evidence:1790649543526-0: its key is not a valid chain id (lowercase letters, digits, . _ -, max 64). Acked; it stays in the stream.
redis-sink: -crash-after-commit: exiting after the commit, before any ack
```

**Nothing is redelivered.** The six committed entries sit in the pending list:

```
$ redis-sink pending
6 entries pending (read, not acknowledged) in group proof
```

**Restart.** Pending entries are recovered first. All six are recognised as
committed, and none is left pending:

```
$ redis-sink consume -addr 127.0.0.1:6379 -dir sink-data
recovered from pending 6 · committed 0 · already committed 6 · refused 0
$ redis-sink pending
0 entries pending (read, not acknowledged) in group proof
```

**Checkpoint and verify: exactly six entries**, one chain per user:

```
$ proof sink checkpoint --dir sink-data --key keys/ml-dsa-65-private.pem
checkpoint anchors/u-81/0001.json signed over 3 entries
checkpoint anchors/u-82/0001.json signed over 2 entries
checkpoint anchors/u-90/0001.json signed over 1 entry
$ proof sink verify --dir sink-data --key keys/ml-dsa-65-public.pem
chain u-81         verifies 3 entries: 3 opened, 0 erased · 1 checkpoint, 0 unanchored
chain u-82         verifies 2 entries: 2 opened, 0 erased · 1 checkpoint, 0 unanchored
chain u-90         verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored
all 3 chains verify
```

**Delete and recreate the stream, and reuse an old id.** Auto ids are
time-based, so this takes a clock rollback or a failover. Here the id of an
already-committed entry is reused by hand. The new entry is committed, not
mistaken for the old one:

```
$ podman exec proof-redis-demo redis-cli DEL evidence
1
$ podman exec proof-redis-demo redis-cli XADD evidence 1790649543524-0 key u-81 data {"user":"u-81","event":"after-recreate"}
1790649543524-0
$ redis-sink consume -addr 127.0.0.1:6379 -dir sink-data
recovered from pending 0 · committed 1 · already committed 0 · refused 0
$ proof sink verify --dir sink-data --key keys/ml-dsa-65-public.pem
chain u-81         verifies 4 entries: 4 opened, 0 erased · 1 checkpoint, 1 unanchored
chain u-82         verifies 2 entries: 2 opened, 0 erased · 1 checkpoint, 0 unanchored
chain u-90         verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored
all 3 chains verify
```

Without the incarnation, that same run reports `already committed 1`: the new
entry is dropped. `run.sh` checks this, and the check was confirmed to fail
with the incarnation removed.

## What it proves, and what it doesn't

- **Proves:** each consumed entry is on its key's chain, unchanged since it was
  committed. A crash between commit and acknowledgement neither strands an entry
  nor commits it twice.
- **Doesn't prove that every entry was consumed.** An entry trimmed from the
  stream (`XTRIM`, `MAXLEN`) before anyone read it is never committed, and
  nothing reports it. An entry deleted while **pending** is reported as `lost`,
  because that is the last point at which it can be seen.
- **Doesn't prove the order across keys.** Each chain is ordered on its own.
- **Within one life of the stream, entry ids must not repeat.** The incarnation
  covers a deleted and recreated stream. It cannot cover a failover to a replica
  whose clock is behind, which can hand out an id that was already committed. Use
  auto ids (`*`), and never set them by hand.

## Notes

- **One stream with a `key` field,** not a stream per key. `XREADGROUP` needs
  every stream named explicitly, so a stream per key would mean scanning the
  whole keyspace for new ones. Chains are still one per key.
- **A commit failure stops the run,** deliberately. It usually means the sink
  folder is broken, and carrying on would hide that. The entries stay pending,
  and the next run retries them first.
- **Keep the consumer name** (`-consumer`, default `sink-1`) across restarts.
  That is how it finds its own pending entries. A replacement with a new name
  still recovers them, once they are idle past `-claim-idle`.
- **Own module,** so the Redis client stays out of proof's `go.mod`. It pins
  proof to a commit until proof's next release.
