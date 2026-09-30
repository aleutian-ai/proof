# sink: evidence per subject, erasable per subject

Logging and streaming systems carry events about someone: a user, an account,
a device. A **sink** commits each event to a proof chain, one **opaque** chain
per (class, subject), all in one file. Each chain is checkpointed and verified
on its own, and a subject is **erased** in one call. A secret index is the only
thing that knows which chain is whose; the shareable evidence file and the
checkpoints never name a subject.

It needs no services. The integrations under
[`examples/integrations`](../examples/integrations) (NATS, Redis/Valkey, …) are
consumers in front of it and nothing more. The folder layout, entry types and
verification rules are specified in [`docs/sink-format.md`](../docs/sink-format.md).

```
  events.jsonl                     proof sink                            sink-data/
  {"user":"u-81","kind":"auth",…} ──► (class, subject) ──► commit ──►  evidence.db           opaque chains <class>.<hex>
  {"user":"u-82","kind":"auth",…}     validated            (salted)    evidence.db.secrets   secret, each event + its nonce
                                                                       evidence.db.sources   secret, upstream positions
                                                                       evidence.db.subjects  secret, subject ↔ chain
                                                          checkpoint ► anchors/<chain>/     signed, per chain
                             verify: every chain on its own, and the index accounts for every chain
                             erase --subject u-81: all its chains erased, the subject forgotten; every chain still verifies
```

## Run it

```sh
go build -o proof ./cmd/proof
./proof keygen --alg ml-dsa-65 --out-dir keys
```

`events.jsonl`:

```json
{"user":"u-81","kind":"auth","event":"login","ts":"2026-09-28T09:00:00Z"}
{"user":"u-82","kind":"auth","event":"login","ts":"2026-09-28T09:00:04Z"}
{"user":"u-81","kind":"payments","event":"export","rows":120}
{"user":"u-90","kind":"auth","event":"password_reset"}
{"user":"u-82","kind":"auth","event":"logout"}
{"user":"u-81","kind":"auth","event":"logout"}
```

Output below is from a real run (chain ids are random, so yours differ).

**Commit.** Each line is committed exactly as it arrived. Its subject comes from
`user`; its class from `kind`, which may only hold the listed classes. A class
is public and permanent (it is the chain id's prefix), so data never chooses one
freely. (Or give one class for every line: `--class events`.) Only counts are
printed: which chain holds whom is secret.

```
$ proof sink commit --class-field kind --classes auth,payments --subject-field user < events.jsonl
committed 6 entries on 4 chains (0 duplicates)
```

**Checkpoint** each chain, then **verify** each chain on its own. "Opened" means
the stored event still matches its commitment.

```
$ proof sink checkpoint --key keys/ml-dsa-65-private.pem
checkpoint anchors/auth.34a89dbf642fc6d85a114a87d300aa93/0001.json signed over 2 entries
checkpoint anchors/auth.8390b597f80588909fab3814240477c6/0001.json signed over 2 entries
checkpoint anchors/auth.932716f5a37d643a3af525ad7ab3e923/0001.json signed over 1 entry
checkpoint anchors/payments.f30c1281278d1b6f7961847a62467285/0001.json signed over 1 entry

$ proof sink verify --key keys/ml-dsa-65-public.pem
chain auth.34a89dbf642fc6d85a114a87d300aa93 verifies 2 entries: 2 opened, 0 erased · 1 checkpoint, 0 unanchored
chain auth.8390b597f80588909fab3814240477c6 verifies 2 entries: 2 opened, 0 erased · 1 checkpoint, 0 unanchored
chain auth.932716f5a37d643a3af525ad7ab3e923 verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored
chain payments.f30c1281278d1b6f7961847a62467285 verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored
all 4 chains verify
```

**Whose chain is whose** is read from the secret index only when asked, with a
warning, and the output is marked:

```
$ proof sink verify --key keys/ml-dsa-65-public.pem --show-subjects
subjects shown: this output is secret-index material; do not paste it into tickets, chats or logs
# SECRET: subject-index material (proof sink verify --show-subjects)
chain auth.34a89dbf642fc6d85a114a87d300aa93 verifies 2 entries: 2 opened, 0 erased · 1 checkpoint, 0 unanchored · subject u-82
chain auth.8390b597f80588909fab3814240477c6 verifies 2 entries: 2 opened, 0 erased · 1 checkpoint, 0 unanchored · subject u-81
chain auth.932716f5a37d643a3af525ad7ab3e923 verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored · subject u-90
chain payments.f30c1281278d1b6f7961847a62467285 verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored · subject u-81
all 4 chains verify
```

(That block is the one place this README shows subjects next to chains, and
only because the data is a demo.)

**These are ordinary proof chains.** The plain chain verbs check one, with its
checkpoint, knowing nothing about sinks:

```
$ proof export --db sink-data/evidence.db --chain auth.34a89dbf642fc6d85a114a87d300aa93 --out u-82.json
$ proof verify u-82.json --anchor sink-data/anchors/auth.34a89dbf642fc6d85a114a87d300aa93/0001.json --key keys/ml-dsa-65-public.pem
INTACT, ANCHORED — 2 entries

ANCHOR BOUND — 2 entries covered
  signature verified (provided)
  establishes: the holder of a key you supplied attests to this chain
```

**Erase one user**, in every class. The sink forgets the subject first, so a
later event for them can never rejoin the erased history. Then each of their
chains gets an erasure entry, and their events' nonces, content and upstream
source positions are deleted, and the secret files are rewritten, so the deleted
values are gone from the live files. The command does not repeat the subject.

```
$ proof sink erase --subject u-81
erased 1 subject: 2 chains, 3 events. The subject is forgotten: nothing in this folder
links it to the erased chains any more, and a later event for it starts a new chain.
Content, nonces and source positions are deleted and the files rewritten; every chain still verifies.
Not reached by this: backups or snapshots of sink-data/, SSD blocks, and anyone an event or nonce
was disclosed to.

$ proof sink verify --key keys/ml-dsa-65-public.pem
chain auth.34a89dbf642fc6d85a114a87d300aa93 verifies 2 entries: 2 opened, 0 erased · 1 checkpoint, 0 unanchored
chain auth.8390b597f80588909fab3814240477c6 verifies 3 entries: 0 opened, 2 erased · 1 checkpoint, 1 unanchored · subject erased (not yet checkpointed)
chain auth.932716f5a37d643a3af525ad7ab3e923 verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored
chain payments.f30c1281278d1b6f7961847a62467285 verifies 2 entries: 0 opened, 1 erased · 1 checkpoint, 1 unanchored · subject erased (not yet checkpointed)
all 4 chains verify

$ proof sink checkpoint --key keys/ml-dsa-65-private.pem
checkpoint anchors/auth.8390b597f80588909fab3814240477c6/0002.json signed over 3 entries
checkpoint anchors/payments.f30c1281278d1b6f7961847a62467285/0002.json signed over 2 entries

$ proof sink verify --key keys/ml-dsa-65-public.pem
chain auth.34a89dbf642fc6d85a114a87d300aa93 verifies 2 entries: 2 opened, 0 erased · 1 checkpoint, 0 unanchored
chain auth.8390b597f80588909fab3814240477c6 verifies 3 entries: 0 opened, 2 erased · 2 checkpoints, 0 unanchored · subject erased
chain auth.932716f5a37d643a3af525ad7ab3e923 verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored
chain payments.f30c1281278d1b6f7961847a62467285 verifies 2 entries: 0 opened, 1 erased · 2 checkpoints, 0 unanchored · subject erased
all 4 chains verify
```

The other users are untouched. `u-81`'s chains still verify, and so do the
checkpoints signed before the erasure. None of the three events can be opened
again, because their nonces are gone. Until a checkpoint covers the erasure it
is "not yet checkpointed": only as trustworthy as the folder, so checkpoint after
erasing. `--class payments` erases one class and keeps the subject's others.

**Subjects must already be pseudonyms; classes are never people.** The subject
rule refuses an email address, and the error does not repeat it. It checks
**characters only**, though: `john.smith` or a phone number would pass.
Pseudonymize upstream. A class taken from the data must be one of `--classes`:

```
$ echo '{"user":"jo@example.com","kind":"auth","event":"login"}' | proof sink commit --class-field kind --classes auth,payments --subject-field user
proof sink commit: line 1: sink: invalid record: sink: subject is not valid: lowercase letters, digits, . _ - (max 128), starting with a letter or digit. Subjects must already be pseudonyms (an opaque id); this check cannot tell a name from one

$ echo '{"user":"u-91","kind":"u-91","event":"login"}' | proof sink commit --class-field kind --classes auth,payments --subject-field user
proof sink commit: line 1: sink: invalid record: field "kind" holds a class that is not in the allowed list (a class is public and never erased, so only listed classes are taken from data)
```

**Tampering is caught on the chain it touched,** and `verify` exits 1. Here one
stored `u-82` event was edited:

```
$ proof sink verify --key keys/ml-dsa-65-public.pem
chain auth.34a89dbf642fc6d85a114a87d300aa93 FAILS    2 entries: 1 opened, 0 erased · 1 checkpoint, 0 unanchored
    entry sink-6039bb7816291b2b84b51bf2a755821c was MODIFIED: its content no longer opens the commitment
chain auth.8390b597f80588909fab3814240477c6 verifies 3 entries: 0 opened, 2 erased · 2 checkpoints, 0 unanchored · subject erased
chain auth.932716f5a37d643a3af525ad7ab3e923 verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored
chain payments.f30c1281278d1b6f7961847a62467285 verifies 2 entries: 0 opened, 1 erased · 2 checkpoints, 0 unanchored · subject erased
1 of 4 chains FAILED
```

## What verify checks

The steps of [`docs/sink-format.md`](../docs/sink-format.md) §6:

1. **Ids:** every id read back is valid before it is used. The file can be
   shared, so a crafted id such as `../../x` is reported, not read.
2. **Links:** no entry edited, reordered or removed mid-chain.
3. **Checkpoints:** each is signed by your key and is for this chain. Each binds
   the entries it covered, which catches entries removed from the front.
4. **Entries:** every stored event opens its salted commitment with its nonce.
   Events before a **genuine** erasure entry (checked by its hash, never by its
   type) are gone, content and nonce both. An event missing **without** one is
   MISSING: that is what deleting stored events by hand looks like.
5. **Nothing left over:** stored content that matches no entry (a commit that
   stopped before its append) is reported.
6. **Nothing removed:** checkpoints, or stored content and nonces, still here
   for a chain whose entries were removed from the evidence file.
7. **The index accounts for every chain:** bound to a subject (live), erased
   (checkpointed or not yet), or bound with no entries yet; or a problem:
   an interrupted erasure (pending: run `proof sink erase --resume`), a chain
   the index lost (unaccounted), an index restored from before an erasure that
   re-links an erased subject (relinked: `--resume` forgets it again), or a
   row that disagrees with the rest (malformed, shown by number only). No
   subject is ever printed unless you pass `--show-subjects`.

Steps 2 and 3 need only `evidence.db`, the checkpoints and the public key. The
plain chain verbs can do them too, one checkpoint at a time: `proof export` the
chain, then `proof verify --anchor NNNN.json --previous <NNNN-1>.json --key …`
for each checkpoint in turn. Steps 4 to 7 need the secrets file and the index,
which only the operator holds.

## Use it from Go

```go
s, err := sink.Open("sink-data")
out, err := s.Commit(ctx, []sink.Record{{
	Class:   "auth",            // public and permanent: a kind of evidence, never a person
	Subject: msg.Key,           // a pseudonym; refused, never transformed
	Content: msg.Value,
	Source:  "EVIDENCE@1790641378694210056:42", // upstream position + incarnation: redelivery-safe
}})
// One outcome per record, in order. Acknowledge exactly the committed ones.
for i, m := range msgs {
	if out != nil && out[i].Committed {
		m.Ack()
	}
}

res, err := s.EraseSubject(ctx, "u-81")          // every class; EraseSubjectClass for one
rep, err := s.Verify(ctx, keys)                  // never names a subject
rows, err := s.ChainSubjects(ctx)                // does: secret-index material, never log it
```

## Where it stops

- **One checkpoint series per chain.** Thousands of chains means thousands of
  signatures per checkpoint run. One checkpoint over all chain heads is a
  separate design.
- **Erasure is per subject** (or per subject and class). For a single entry,
  see `proof forget`.
- **The folder is the operator's.** `evidence.db` and the checkpoints hold no
  event content and name no subject, but they are still pseudonymous personal
  data: each chain's class, its counts and timestamps, and that it was erased
  and when (see [`docs/sink-format.md`](../docs/sink-format.md)). Share them on
  a lawful basis. The secrets, sources and subjects files are secret.
- **Events are stored with their nonces, durably.** `evidence.db.secrets` holds
  each event's exact bytes and its nonce, written in one transaction before the
  entries that commit to them: a power loss can't leave a committed entry whose
  content never reached the disk. Erasure deletes the rows and rewrites the
  file, so erased events leave the live file (not backups or SSD blocks).
- **Correlation leakage.** Erasure removes the stored subject→chain linkage,
  but historical timing may allow an observer to infer that several opaque
  chains belonged to one subject: a subject's chains are erased in the same
  moment, and a returning subject's new chain starts soon after. Timestamps are
  never altered to hide it.
- **Backups of the subjects file re-link.** A kept copy of
  `evidence.db.subjects` names the subject of every chain it knew, erased or
  not. Restoring one is detected (relinked) and repaired by `erase --resume`,
  but that does not undo what anyone holding the copy could already see.
- **What erasure does not reach** is listed in `docs/sink-format.md` §4:
  backups, snapshots, SSD blocks, earlier copies, anyone it was disclosed to,
  and the chain id itself.
- **Checkpoints only count if they are kept where the writer cannot rewrite
  them.** Verify checks the checkpoints it finds. A folder cannot prove that
  none were deleted. Someone who can rewrite this folder can delete the
  checkpoints and then truncate a chain, or append a well-formed erasure: that
  is why an erasure no checkpoint covers is reported as not yet checkpointed.
  Checkpoint after erasing, and publish the checkpoints, or copy them somewhere
  the writer cannot reach.
- **One process at a time.** The files are locked while an operation runs. Calls
  on one `Sink` queue. A second process, or a second `Sink` on the same folder,
  waits on the lock and fails after a few seconds (`WithLockTimeout`).
- **Whole-index reads.** Verify and `ChainSubjects` read the whole index; very
  large sinks are being measured (ticket `_74`).
