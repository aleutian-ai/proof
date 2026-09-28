# topicsink: one chain per key

Logging and streaming tools split their data by key: a user, a topic, a tenant.
`topicsink` keeps that split. Every key gets its own proof chain, all in one
file, and each chain is checkpointed, verified and **erased** on its own.

It needs no services. The service examples (NATS, Redis Streams, Kafka,
OpenTelemetry, log shippers) put a consumer in front of this package and add
nothing else.

```
  events.jsonl                        topic-sink                        sink-data/
  {"user":"u-81",…}  ──►  key → chain id  ──► commit ──►  evidence.db         one chain per key
  {"user":"u-82",…}       (validated)         (salted)    evidence.db.nonces  secret, per entry
                                                          content/<chain>/    the events
                                              checkpoint ► anchors/<chain>/   signed, per chain
                              verify: every chain on its own
                              erase u-81: that chain's content + nonces gone; every chain still verifies
```

## Run it

```sh
go build -o proof ./cmd/proof
go build -o topic-sink ./examples/integrations/topicsink/cmd/topic-sink
./proof keygen --alg ml-dsa-65 --out-dir keys
```

`events.jsonl`:

```json
{"user":"u-81","event":"login","ts":"2026-09-28T09:00:00Z"}
{"user":"u-82","event":"login","ts":"2026-09-28T09:00:04Z"}
{"user":"u-81","event":"export","rows":120}
{"user":"u-90","event":"password_reset"}
{"user":"u-82","event":"logout"}
{"user":"u-81","event":"logout"}
```

Output below is from a real run.

**Commit.** Each line is routed by its `user` field. Each chain gets one atomic
append per batch.

```
$ ./topic-sink commit -key user < events.jsonl
committed    3 → chain u-81
committed    2 → chain u-82
committed    1 → chain u-90
```

**Checkpoint** each chain, then **verify** each chain on its own. "Opened"
means the stored event still matches its commitment.

```
$ ./topic-sink checkpoint -key-file keys/ml-dsa-65-private.pem
checkpoint anchors/u-81/0001.json signed over 3 entries
checkpoint anchors/u-82/0001.json signed over 2 entries
checkpoint anchors/u-90/0001.json signed over 1 entry

$ ./topic-sink verify -pub-file keys/ml-dsa-65-public.pem
chain u-81         verifies 3 entries: 3 opened, 0 erased · 1 checkpoint, 0 unanchored
chain u-82         verifies 2 entries: 2 opened, 0 erased · 1 checkpoint, 0 unanchored
chain u-90         verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored
all 3 chains verify
```

**These are ordinary proof chains.** The stock CLI verifies one, with its
checkpoint, without knowing topicsink exists:

```
$ ./proof export --db sink-data/evidence.db --chain u-82 --out u-82.json
$ ./proof verify u-82.json --anchor sink-data/anchors/u-82/0001.json --key keys/ml-dsa-65-public.pem
INTACT, ANCHORED — 2 entries

ANCHOR BOUND — 2 entries covered
  signature verified (provided)
```

**Erase one user.** The erasure is committed to that user's chain first. Then
their events' nonces and content are deleted.

```
$ ./topic-sink erase -chain u-81
erased 3 events on chain u-81; the erasure is entry ts-e6f485c29808953cbd4ca9d2a0cbcc67.
Their content and nonces are deleted: no one can open them again, and the chain still verifies.
Not reached by this: backups of sink-data/, anyone an event or nonce was disclosed to,
and the chain id itself, which stays in the chain and its checkpoints.

$ ./topic-sink verify -pub-file keys/ml-dsa-65-public.pem
chain u-81         verifies 4 entries: 0 opened, 3 erased · 1 checkpoint, 1 unanchored
chain u-82         verifies 2 entries: 2 opened, 0 erased · 1 checkpoint, 0 unanchored
chain u-90         verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored
all 3 chains verify

$ ./topic-sink checkpoint -key-file keys/ml-dsa-65-private.pem
checkpoint anchors/u-81/0002.json signed over 4 entries
```

The other users are untouched. `u-81`'s chain still verifies, and so does the
checkpoint signed before the erasure. None of the three events can be opened
again, because their nonces are gone.

**Keys must already be pseudonyms.** A chain id is permanent and is signed into
every checkpoint, so an email address is refused, not transformed. The error
does not repeat the key.

```
$ echo '{"user":"jo@example.com","event":"login"}' | ./topic-sink commit -key user
topic-sink commit: line 1: topicsink: key is not a valid chain id: lowercase letters, digits, . _ - (max 64), starting with a letter or digit. Use a topic or a pseudonym, never an email or a name
```

**Tampering is caught on the chain it touched.** Here one stored `u-82` event was
edited:

```
$ ./topic-sink verify -pub-file keys/ml-dsa-65-public.pem
chain u-81         verifies 4 entries: 0 opened, 3 erased · 2 checkpoints, 0 unanchored
chain u-82         FAILS    2 entries: 1 opened, 0 erased · 1 checkpoint, 0 unanchored
    entry ts-71be6de8e9683e128c93f3ce29c66a65 was MODIFIED: its content no longer opens the commitment
chain u-90         verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored
topic-sink verify: 1 of 3 chains failed
```

## What verify checks, per chain

1. **Links:** no entry edited, reordered or removed mid-chain.
2. **Checkpoints:** each is signed by your key and is for this chain. Each binds
   the entries it covered, which catches entries removed from the front.
3. **Events:** every stored event opens its salted commitment with its nonce.
4. **Erasures:** events before an erasure entry are gone, content and nonce both.
   An event missing **without** an erasure after it is reported as MISSING:
   that is what deleting files by hand looks like.
5. **Nothing left over, nothing removed:** a content file that matches no entry
   (a commit that stopped before its append) is reported. So is a chain whose
   checkpoints or content are still here but whose entries were removed from
   the evidence file.

Ids read back from `evidence.db` are never trusted as paths. The file can be
shared, so a crafted chain or entry id such as `../../x` is reported, not read.

Steps 1 and 2 need only `evidence.db`, the checkpoints and the public key, and
`proof verify` does them too. Steps 3 and 4 need the content folder and the nonce
file, which only the operator holds.

## Use it from Go

The service examples import the package:

```go
sink, err := topicsink.Open("sink-data")
chain, err := topicsink.ChainFor(msg.Key)        // refuse, never transform
_, err = sink.Commit(ctx, []topicsink.Record{{Key: chain, Content: msg.Value}})
```

## Where it stops

- **One checkpoint series per chain.** Thousands of chains means thousands of
  signatures per checkpoint run. One checkpoint over all chain heads is a
  separate design.
- **Erasure is per chain.** For a single entry, see `proof forget`.
- **The folder is the operator's.** `evidence.db` can be shared. The nonce file
  and `content/` cannot: they are what the chain commits to.
- **Checkpoints only count if they are kept where the writer cannot rewrite
  them.** Verify checks the checkpoints it finds. A folder cannot prove that
  none were deleted. Someone who can rewrite this folder can delete the
  checkpoints and then truncate a chain. The same holds for an erasure entry
  made after the last checkpoint: until a checkpoint covers it, it is only as
  trustworthy as the folder. Checkpoint after erasing, and publish the
  checkpoints, or copy them somewhere the writer cannot reach.
- **One process at a time.** The files are locked while an operation runs. Calls
  on one `Sink` queue. A second process, or a second `Sink` on the same folder,
  waits on the lock and fails after a few seconds.
