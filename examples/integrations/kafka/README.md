# Kafka → proof: one opaque chain per user

Kafka orders records **within a partition**, and the default partitioner sends
every record with the same key to the same partition. So each key's records
arrive in order, but in a log that expires (retention) and can be rewritten
(compaction, a topic rebuild). `kafka-sink` reads a topic through a consumer
group and commits each record through [`proof/sink`](../../../sink). That fixes
each user's order in their own **opaque** chain, permanently and verifiably,
and the sink can erase that user on request.

- **The topic is the evidence class,** fixed by the operator (`-class`) and
  checked at startup. It is never read from the data.
- **The record key is the subject** (a user pseudonym). The sink files it on
  that user's chain (`actions.<random hex>`), and only the sink's secret index
  knows which chain is whose.
- **Offsets are committed only after the sink commit.**

```
  producer ─► topic "agent-actions" (3 partitions) ─► group "proof" ─► kafka-sink ─► proof/sink
              key u-81 → always the same partition                     commit, THEN commit offsets:
                                                                       per partition, up to the first
                                                                       record not committed
     crash in between → restart reads from the last committed offsets → Source recognised → not re-committed
```

## Positions, and a recreated topic

Each record's sink `Source` is its position:

```
agent-actions@<topic id>/<partition>:<offset>#<leader epoch>
```

- **The topic id** is Kafka's own: a UUID the broker gives a topic when it is
  created, and replaces when the topic is deleted and recreated. Offsets
  restart at 0 then. Without the id, a new record at an old partition and
  offset would be taken as already committed, and silently dropped.
- **The leader epoch** covers the same danger inside one topic: after a log
  truncation (an unclean leader election, off by default), Kafka hands out
  offsets again, under a new epoch. The consumer reports the truncation
  (`data loss in Kafka: …`) and carries on.
- Both are stored with the record, so a redelivered record has the same
  position, and the consumer reads them from the same fetch response as the
  records. A broker that sends no topic id (before Kafka 3.1) is refused, and no
  offset is committed.
- **A topic recreated while the consumer runs** stops it after a few fetches
  (`UNKNOWN_TOPIC_ID`): franz-go deliberately never adopts a new id under a
  running consumer. Nothing wrong is written; restart the consumer.

## Offsets: the rule

For each partition, in offset order, offsets are committed **up to (not
including) the first record that is not handled**. A record is handled when:

- it was **committed** (new, or already on its chain from before a crash); or
- it was **refused**: no key, a key that is not a valid subject (a name, an
  email), or an empty or oversized value. Refused records are logged by
  `topic/partition@offset`, never by key, and stay in the topic. Kafka has no
  per-record ack, so leaving them would stall the partition forever.

A record committed later in the same partition never moves the offset past an
earlier one that failed. Nothing at all is committed when:

- the sink returns the wrong number of outcomes;
- the sink's signing mode and this consumer's key disagree (a configuration
  error: the consumer stops and names the fix); or
- the broker sent no topic id.

## Run it

```sh
./examples/integrations/kafka/run.sh                                                  # apache/kafka 4.1
KAFKA_IMAGE=docker.io/apache/kafka-native:4.1.0 ./examples/integrations/kafka/run.sh   # GraalVM native broker
```

It needs podman and Go, and leaves nothing running. Both images pass the whole
run. Output below is from a real run on `apache/kafka:4.1.0`.

**Keys.** `proof sink init` makes two: a record key that the consumer holds
online, and a checkpoint key kept apart. The consumer is given the record key's
FILE (`PROOF_RECORD_KEY_FILE`), never the key itself.

**Produce** eight records: six for three users, one keyed by a name, one with
no key.

```
$ kafka-sink produce -brokers 127.0.0.1:9092 -key user
produced 8 records to topic agent-actions
```

**Consume, and crash between the sink commit and the offset commit.** The name
and the missing key are refused, logged by position only. No offset is
committed:

```
$ kafka-sink consume -brokers 127.0.0.1:9092 -class actions -dir sink-data -crash-after-commit
refused agent-actions/0@2: sink: invalid record: sink: subject is not valid: lowercase letters, digits, . _ - (max 128), starting with a letter or digit. Subjects must already be pseudonyms (an opaque id); this check cannot tell a name from one. Handled: offsets move past it; it stays in the topic.
refused agent-actions/1@1: sink: invalid record: sink: subject is not valid: … Handled: offsets move past it; it stays in the topic.
kafka-sink: -crash-after-commit: exiting after the sink commit, before any offset commit
$ kafka-consumer-groups.sh --describe --group proof
GROUP           TOPIC           PARTITION  CURRENT-OFFSET  LOG-END-OFFSET  LAG
proof           agent-actions   0          -               4               -
proof           agent-actions   1          -               2               -
proof           agent-actions   2          -               2               -
```

**Restart.** Everything is read again, and all six are recognised as committed:

```
$ kafka-sink consume -brokers 127.0.0.1:9092 -class actions -dir sink-data
committed 0 · already committed 6 · refused 2
$ kafka-consumer-groups.sh --describe --group proof
GROUP           TOPIC           PARTITION  CURRENT-OFFSET  LOG-END-OFFSET  LAG
proof           agent-actions   0          4               4               0
proof           agent-actions   1          2               2               0
proof           agent-actions   2          2               2               0
```

**Checkpoint and verify:** three chains, exactly six entries, every record
signed.

```
$ proof sink checkpoint --dir sink-data --key sink-data.keys/ml-dsa-65-checkpoint-private.pem
checkpoint anchors/actions.242756e1f1c054c9df53ba2a37fa8a71/0001.json signed over 1 entry
checkpoint anchors/actions.9f4b9f7f636957ec33a8d8478e2f702e/0001.json signed over 2 entries
checkpoint anchors/actions.c60f8f0b25fc5630e414f1b637c0a088/0001.json signed over 3 entries
$ proof sink verify --dir sink-data --key sink-data.keys/ml-dsa-65-checkpoint-public.pem --record-trust sink-data.keys/ml-dsa-65-record-public.pem
chain actions.242756e1f1c054c9df53ba2a37fa8a71 verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored · 1 signed
chain actions.9f4b9f7f636957ec33a8d8478e2f702e verifies 2 entries: 2 opened, 0 erased · 1 checkpoint, 0 unanchored · 2 signed
chain actions.c60f8f0b25fc5630e414f1b637c0a088 verifies 3 entries: 3 opened, 0 erased · 1 checkpoint, 0 unanchored · 3 signed
Record signatures: checked against --record-trust
all 3 chains verify
```

**Delete and recreate the topic.** The topic id changes; offsets restart at 0.
One record for u-81 lands on partition 0 at offset 0, a position already
committed under the old id. It is committed, not mistaken for the old record:

```
$ kafka-topics.sh --delete --topic agent-actions
topic id: efhsqTKQR5OEBRnaVwYm9w → u4yn7Da6SSOf1A3-MzJHkg
$ kafka-get-offsets.sh --topic agent-actions   (topic:partition:next offset)
agent-actions:0:1
agent-actions:1:0
agent-actions:2:0
partition 0, offset 0: also the position of a record committed under efhsqTKQR5OEBRnaVwYm9w
$ kafka-sink consume -brokers 127.0.0.1:9092 -class actions -dir sink-data
committed 1 · already committed 0 · refused 0
```

Without the topic id in the Source, that same run reports `already committed 1`:
the new record is dropped. `run.sh` checks this, and the check was confirmed to
fail with the id removed.

**Erase one user,** signed by the record key. The output never names them.
Their chain ends in a signed erasure, so with `--record-trust` it counts as
erased without waiting for a checkpoint:

```
$ proof sink erase --dir sink-data --subject u-81 --record-key sink-data.keys/ml-dsa-65-record-private.pem
erased 1 subject: 1 chain, 4 events. The subject is forgotten: nothing in this folder
links it to the erased chains any more, and a later event for it starts a new chain.
…
$ proof sink verify …
chain actions.c60f8f0b25fc5630e414f1b637c0a088 verifies 5 entries: 0 opened, 4 erased · 1 checkpoint, 2 unanchored · 5 signed · subject erased
all 3 chains verify
```

**Live.** The consumer runs with `-follow`, a producer adds a record every
100 ms, and `proof sink verify` runs over and over meanwhile. Verify reads the
sink in short pages and yields between them, so the consumer's commits are not
blocked behind it:

```
produced 40 records to topic agent-actions
verify ran 104 times while records were produced and consumed; every run passed
$ kafka-sink consume -brokers 127.0.0.1:9092 -class actions -dir sink-data -follow   (stopped with Ctrl-C)
committed 40 · already committed 0 · refused 0
$ proof sink verify …
all 7 chains verify
```

## What it proves, and what it doesn't

- **Proves:** each consumed record is on its user's chain, in that user's
  partition order, unchanged since it was committed and signed by the record
  key. An erased user's chain proves the erasure and names nobody. A crash
  between the two commits neither loses a record nor commits it twice.
- **Delivery:** at-least-once delivery from Kafka, with idempotent evidence
  insertion by source identity. This is not exactly-once across Kafka and
  proof: there is no shared transaction.
- **Doesn't prove that every record was consumed.** A record deleted by
  retention before the consumer reached it is never committed, and nothing
  reports it.
- **Doesn't prove the order across users** or across partitions. Each chain is
  ordered on its own.
- **Compacted topics:** a record that compaction later removes from Kafka stays
  on its chain. Erasure is the sink's job, not compaction's.
- **Timing can link.** Chain ids are opaque, but an observer of the evidence
  file may still link chains by timing (see the sink's correlation leakage).

## Notes

- **One consumer per topic,** as one class per NATS subject prefix. Run several
  with the same `-group` to share a topic's partitions.
- **Static membership.** `-consumer` (default `sink-1`) is the group's instance
  id. A restart with the same id takes its old place at once, instead of
  waiting for the dead member's session to time out. Keep it across restarts;
  give each concurrent consumer its own.
- **No rebalance mid-batch.** The consumer blocks rebalances between a poll and
  its offset commit, so it never commits an offset for a partition it no longer
  owns.
- **A sink failure stops the run,** deliberately, after committing the handled
  prefix. It usually means the sink folder is broken, and carrying on would hide
  that. The next run reads from the first record not committed. So does a sink
  that leaves a record uncommitted without saying why: nothing is committed.
- **Ctrl-C** finishes the batch in progress (its sink commit and offset
  commit), then stops.
- **`-idle`** starts counting only once the group has assigned the consumer its
  partitions; without `-follow`, it gives up if that takes over 30 s.
- **Record signing is optional.** Without `PROOF_RECORD_KEY_FILE` the consumer
  commits unsigned records. A sink that signs refuses a consumer without the
  key (and the reverse): the consumer stops with a configuration error.
- **Own module,** so the Kafka client stays out of proof's `go.mod`. It pins
  proof to a commit until proof's next release.
