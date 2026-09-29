# sink: one chain per key

Logging and streaming systems split their data by key: a user, a topic, a
tenant. A **sink** keeps that split. Every key gets its own proof chain, all in
one file, and each chain is checkpointed, verified and **erased** on its own.

It needs no services. The integrations under
[`examples/integrations`](../examples/integrations) (NATS, Redis/Valkey, …) are
consumers in front of it and nothing more. The folder layout, entry types and
verification rules are specified in [`docs/sink-format.md`](../docs/sink-format.md).

```
  events.jsonl                      proof sink                          sink-data/
  {"user":"u-81",…}  ──►  key → chain id  ──► commit ──►  evidence.db          one chain per key
  {"user":"u-82",…}       (validated)         (salted)    evidence.db.nonces   secret, per event
                                                          evidence.db.sources  upstream positions
                                                          content/<chain>/     the events
                                              checkpoint ► anchors/<chain>/    signed, per chain
                              verify: every chain on its own
                              erase u-81: that chain's content + nonces gone; every chain still verifies
```

## Run it

```sh
go build -o proof ./cmd/proof
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

**Commit.** Each line is routed by its `user` field and committed exactly as it
arrived. Each chain gets one atomic append per batch.

```
$ proof sink commit --chain-field user < events.jsonl
committed    3 → chain u-81
committed    2 → chain u-82
committed    1 → chain u-90
```

**Checkpoint** each chain, then **verify** each chain on its own. "Opened" means
the stored event still matches its commitment.

```
$ proof sink checkpoint --key keys/ml-dsa-65-private.pem
checkpoint anchors/u-81/0001.json signed over 3 entries
checkpoint anchors/u-82/0001.json signed over 2 entries
checkpoint anchors/u-90/0001.json signed over 1 entry

$ proof sink verify --key keys/ml-dsa-65-public.pem
chain u-81         verifies 3 entries: 3 opened, 0 erased · 1 checkpoint, 0 unanchored
chain u-82         verifies 2 entries: 2 opened, 0 erased · 1 checkpoint, 0 unanchored
chain u-90         verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored
all 3 chains verify
```

**These are ordinary proof chains.** The plain chain verbs check one, with its
checkpoint, knowing nothing about sinks:

```
$ proof export --db sink-data/evidence.db --chain u-82 --out u-82.json
$ proof verify u-82.json --anchor sink-data/anchors/u-82/0001.json --key keys/ml-dsa-65-public.pem
INTACT, ANCHORED — 2 entries

ANCHOR BOUND — 2 entries covered
  signature verified (provided)
```

**Erase one user.** The erasure is committed to that user's chain first. Then
their events' nonces, content and upstream source positions are deleted, and the
files they lived in are rewritten, so the deleted values are gone from the live
files.

```
$ proof sink erase --chain u-81
erased 3 events on chain u-81; the erasure is entry sink-9a738784d7b65f36113c95f45a68f74f.
Their content, nonces and source positions are deleted, and the files rewritten: none can be
opened from this folder again, and the chain still verifies.
Not reached by this: backups or snapshots of sink-data/, SSD blocks, anyone an event or nonce was
disclosed to, and the chain id, which stays in the chain, its checkpoints and folder names.

$ proof sink verify --key keys/ml-dsa-65-public.pem
chain u-81         verifies 4 entries: 0 opened, 3 erased · 1 checkpoint, 1 unanchored
chain u-82         verifies 2 entries: 2 opened, 0 erased · 1 checkpoint, 0 unanchored
chain u-90         verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored
all 3 chains verify

$ proof sink checkpoint --key keys/ml-dsa-65-private.pem
checkpoint anchors/u-81/0002.json signed over 4 entries
```

The other users are untouched. `u-81`'s chain still verifies, and so does the
checkpoint signed before the erasure. None of its three events can be opened
again, because their nonces are gone.

**Keys must already be pseudonyms.** A chain id is permanent and is signed into
every checkpoint. The id rule refuses an email address, and the error does not
repeat the key. It checks **characters only**, though: `john.smith` or a phone
number would pass. Pseudonymize upstream.

```
$ echo '{"user":"jo@example.com","event":"login"}' | proof sink commit --chain-field user
proof sink commit: line 1: sink: key is not a valid chain id: lowercase letters, digits, . _ - (max 64), starting with a letter or digit. Keys must already be pseudonyms (a topic or an opaque id); this check cannot tell a name from one
```

**Tampering is caught on the chain it touched,** and `verify` exits 1. Here one
stored `u-82` event was edited:

```
$ proof sink verify --key keys/ml-dsa-65-public.pem
chain u-81         verifies 4 entries: 0 opened, 3 erased · 2 checkpoints, 0 unanchored
chain u-82         FAILS    2 entries: 1 opened, 0 erased · 1 checkpoint, 0 unanchored
    entry sink-67583453290d8850e1056d1ad9e37c3f was MODIFIED: its content no longer opens the commitment
chain u-90         verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored
1 of 3 chains FAILED
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

Steps 1 and 2 need only `evidence.db`, the checkpoints and the public key. The
plain chain verbs can do them too, one checkpoint at a time: `proof export` the
chain, then `proof verify --anchor NNNN.json --previous <NNNN-1>.json --key …`
for each checkpoint in turn. Steps 3 and 4 need the content folder and the nonce
file, which only the operator holds.

## Use it from Go

```go
s, err := sink.Open("sink-data")
chain, err := sink.ChainFor(msg.Key) // refuse, never transform
done, err := s.Commit(ctx, []sink.Record{{
	Key:     chain,
	Content: msg.Value,
	Source:  "EVIDENCE@1790641378694210056:42", // upstream position + incarnation: redelivery-safe
}})
```

## Where it stops

- **One checkpoint series per chain.** Thousands of chains means thousands of
  signatures per checkpoint run. One checkpoint over all chain heads is a
  separate design.
- **Erasure is per chain.** For a single entry, see `proof forget`.
- **The folder is the operator's.** `evidence.db` and the checkpoints hold no
  event content, but they are still pseudonymous personal data. They reveal
  chain ids, per-subject counts and timestamps, and who was erased and when
  (see [`docs/sink-format.md`](../docs/sink-format.md)). Share them on a lawful
  basis. The nonce and sources files and `content/` are secret.
- **What erasure does not reach** is listed in `docs/sink-format.md` §4:
  backups, snapshots, SSD blocks, earlier copies, anyone it was disclosed to,
  and the chain id itself.
- **Checkpoints only count if they are kept where the writer cannot rewrite
  them.** Verify checks the checkpoints it finds. A folder cannot prove that
  none were deleted. Someone who can rewrite this folder can delete the
  checkpoints and then truncate a chain. The same holds for an erasure entry
  made after the last checkpoint: until a checkpoint covers it, it is only as
  trustworthy as the folder. Checkpoint after erasing, and publish the
  checkpoints, or copy them somewhere the writer cannot reach.
- **One process at a time.** The files are locked while an operation runs. Calls
  on one `Sink` queue. A second process, or a second `Sink` on the same folder,
  waits on the lock and fails after a few seconds (`WithLockTimeout`).
