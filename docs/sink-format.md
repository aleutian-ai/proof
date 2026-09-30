# Sink format

**Status:** normative for everything outside §8. This describes what `proof sink`
(package `sink`) writes and how a sink folder is verified. Chain hashing,
checkpoints (anchors) and salted commitments are defined in
[`format-spec.md`](format-spec.md) and are referenced here, not repeated.

A **sink** is a folder holding one evidence file with **one opaque chain per
(class, subject)**, a secret index saying which chain is whose, and what is
needed to open, checkpoint and erase each chain on its own.

```
  sink-data/
    evidence.db                  the chains (proof store)        no event content; shareable, still personal data (below)
    evidence.db.nonces           one nonce per event             SECRET
    evidence.db.sources          upstream positions              SECRET: links chains to upstream messages
    evidence.db.subjects         subject ↔ chain index           SECRET: the only link from a subject to its chains
    content/<chain>/<entry>.json the events and erasure records  SECRET: the events (which name their subject)
    anchors/<chain>/NNNN.json    signed checkpoints              no event content; publish these (§5)
```

**What the shareable parts still reveal.** `evidence.db` and the checkpoints hold
no event content, only salted commitments, which cannot be reversed or guessed,
and no subject: chain ids are random (§1). They are still **pseudonymous
personal data** (GDPR Art. 4(5)). Share them only on a lawful basis, because they
reveal:
- every chain id, and so each chain's **class** (its prefix: payments, auth…);
- how many events each chain has, and when each was committed (µs
  timestamps: an activity timeline per chain);
- which chains were committed in the same batch (timestamps microseconds
  apart);
- **that a chain was erased, and when** (the erasure entry, signed into the
  next checkpoint).

**Correlation leakage.** Erasure removes the stored subject→chain linkage, but
historical timing may allow an observer to infer that multiple opaque chains
belonged to the same subject:
- erasing a subject erases all its chains within the same moment, which links
  them (the erasure entries' timestamps are signed into checkpoints);
- a returning subject's new chain starts soon after its old chains' erasure,
  and may continue their pattern.

This is correlation leakage, not a failure of erasure. Timestamps are never
altered to hide it: they record when things happened (chain temporal authority).
Kept copies of `evidence.db.subjects` (backups, snapshots) re-link every chain
they knew, erased or not: the shareable half is permanent, so any old copy of
the secret half suffices. Restoring one is detected and repaired (§4.4), but
that does not undo what anyone holding the copy could already see.

Sharing the shareable parts is the point of checkpoints: someone the writer
cannot influence should hold a copy. Weigh that against what is listed above.

The keywords MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Identifiers

| Identifier | Rule |
|---|---|
| class | `^[a-z0-9][a-z0-9_-]{0,30}$`: the kind of evidence (payments, auth, events), never a person. **Public and permanent:** it is the chain id's prefix, so it is in `evidence.db`, every checkpoint and folder names, and no erasure removes it. A writer MUST NOT take a class from record data unless it is one of an explicit allowlist, and MUST refuse a record whose class equals its subject. |
| subject | `^[a-z0-9][a-z0-9._-]{0,127}$`: who the record is about, a pseudonym. Stored ONLY in `evidence.db.subjects` (and in the events themselves, in `content/`). **The pattern checks characters only:** it refuses an email address or anything upper-case, but `john.smith` passes. Pseudonymizing is the caller's job, upstream. A subject that does not match MUST be refused, never transformed. |
| chain id | `^[a-z0-9][a-z0-9_-]{0,30}\.[0-9a-f]{32}$`: `<class>.<32 hex>`, the class and 128 random bits. Minted when a (class, subject) pair first commits, and checked unused (in `evidence.db` and the index) before it is bound. It MUST NOT be derived from the subject, a source, the content or the time: anything derived would be a correlator in the shareable files. |
| entry id | `^sink-[0-9a-f]{32}$`: 16 random bytes, assigned by the sink, never by the caller. |

A verifier MUST check the chain-id and entry-id patterns on every id it reads
from `evidence.db` or the index **before** building any path from it, or
printing it. The files may have been shared and crafted: a chain id of `../../x`
must be reported, not followed.

## 2. Entry types

Every entry in a sink chain is one of two types. The type tells a verifier which
check the entry's `content_hash` needs (format-spec §8: the chain itself does not
show it).

| `entry_type` | `content_hash` | content file |
|---|---|---|
| `sink.event` | salted commitment of the event bytes (format-spec §8) | the event, byte-for-byte as committed |
| `sink.erasure` | `hex(SHA-512("aleutian.sink.erasure.v1:" ‖ record))`: domain-separated, see below | the erasure record (§4.1) |

Any other type in a sink chain MUST be reported as a problem.

**A genuine erasure entry** is one that is not the chain's first entry, has
`entry_type` `sink.erasure`, and whose `content_hash` is the domain-separated
hash of exactly the §4.1 record for its predecessor's sequence. Writers and
verifiers MUST decide "is this an erasure" by that rule, never by `entry_type`
alone: an event relabelled as an erasure is an event.

**Why the erasure hash is domain-separated.** `entry_type` is not part of the
chain hash (format-spec §2) or of a checkpoint (§9.4), so a writer can relabel
an entry's type without breaking either. A salted commitment is itself a plain
SHA-512, of its 115-byte preimage. If an erasure record were checked by plain
SHA-512, a writer could relabel event *k* as an erasure and present *k*'s
preimage as the "record": the events before *k* would then verify as erased
under a valid checkpoint. With the `aleutian.sink.erasure.v1:` prefix, no record
can hash to a commitment. This closes the confusion **without changing
AleutianChain v3**. A future chain format may bind the entry type into the
chain preimage directly.

The genuine-erasure hash depends only on public data (the fixed record and a
position). It proves the entry is an erasure record for its position, not who
wrote it: an erasure is only as trustworthy as the folder until a checkpoint
covers it (§6, `erased-unanchored`).

Timestamps are assigned by the sink when it commits, 1 µs apart within a batch.
They are recorded, and hashed into the chain, but they are **advisory**: the
chain's sequence is the order.

## 3. Content and nonces

- `content/<chain>/<entry id>.json` holds the exact bytes committed. The `.json`
  suffix is a convention; the bytes are opaque to the sink. Size: 1 to 65,536
  bytes. Mode `0600`. A verifier MUST refuse a content file that is not a
  regular file (a symlink could point anywhere), or that is larger than 65,536
  bytes, rather than read it.
- The nonce for event *e* on chain *c* is 32 bytes, fresh per event. Opening *e*
  means: `commitment(nonce, content) == e.content_hash`, exactly as in
  format-spec §8.

## 4. The subject index and erasure

### 4.1 The erasure record

An erasure entry's content is exactly these bytes (ASCII, no whitespace, no
trailing newline), where `41` is the decimal sequence (`global_seq`) of the
entry immediately before the erasure entry on the same chain. It is a JSON
**string**, as format-spec §2.1 requires for sequence numbers outside exports:

```
{"erased":"every earlier event on this chain","through_global_seq":"41"}
```

A verifier rebuilds these bytes for the entry's position and compares them. It
never parses the record. The record is kept for good.

### 4.2 The index

`evidence.db.subjects` holds, for each bound (class, subject) pair, a
**forward** row (subject, class → chain) and a **reverse** row (chain → class,
subject). The two are written and removed together, in one transaction. A
reverse row may instead be the **pending marker** (§4.3), which holds no
subject.

A row is **consistent** when the class and subject are valid (§1), the chain is
a valid id with that class as its prefix, the reverse row names exactly that
pair, and the forward row points back at exactly that chain. Every reader
(commit, erase, verify) MUST apply this one rule, and MUST NOT follow a row
that fails it.

A new pair's rows are written **before** its chain gets its first entry, so a
chain never exists without its row. A crash in between leaves a row with no
chain (`index-only`, §6): harmless, and the next commit of the pair uses it.

A writer MUST NOT append to a chain whose last entry is a genuine erasure
through the index: a consistent live row on such a chain means the index was
restored from before the erasure, or edited (`relinked`, §6).

### 4.3 Erasing a subject

A subject is erased in every class, or in one class (its other classes are
kept, and it stays known through them). In this order:

1. **Check before forgetting.** Every chain of the subject in scope must be
   erasable: a valid id, readable to its end, a content folder holding only
   regular files. If one is not, the call refuses and nothing changes: a
   subject is never forgotten by an erasure already known to be stuck.
2. **Forget.** In ONE index transaction, delete the subject's forward rows in
   scope and turn each of their chains' reverse rows into the pending marker.
   From here, a new event for the subject gets a NEW chain: it can never rejoin
   an erased history.
3. **Complete every pending erasure**, this subject's and any an earlier,
   interrupted call left. For each chain:
   1. **append a genuine erasure entry** (§2), unless the chain already ends
      with one, or has no entries (a first commit that never reached it: its
      leftover files are removed instead);
   2. **delete every nonce** of the chain, **and every source position**
      recorded for it (§7): a position maps the chain to exact upstream
      messages, so keeping it would undo the erasure;
   3. **delete every content file** in `content/<chain>/` except the records of
      its genuine erasure entries, each kept only if it holds exactly its
      record; a content folder left empty goes too;
   4. **clear** the chain's pending row.

   A chain that fails stays pending, and the others go on.
4. **Rewrite the nonce, sources and subject-index files** into fresh copies
   (fsync, atomic rename), on every erasure call that got past step 1, even
   when nothing was pending, and even when a chain failed: deleting a key in
   bbolt leaves its bytes in free pages, and a rewrite an earlier call failed or
   crashed in is then always redone. (A call refused at step 1 changed nothing,
   and rewrites nothing; resume always rewrites.)

Appending first means a crash part-way leaves a chain that says "erased, but
something is still here" (run erase again), never one that looks tampered with.
The erasure entry is itself covered by the next checkpoint.

**The recovery invariant.** When an erasure call succeeds: the index holds no
row of the subject in scope; every chain it had there is erased as in step 3;
every erasure pending when the call began is complete; and the three files were
rewritten after the last deletion. When a call fails after forgetting, it
reports which chains are still pending (their rows hold no subject) and whether
the files were rewritten; any later erasure call, or a resume, completes them
without re-linking the subject.

### 4.4 Resume

**Resume** completes every pending erasure and rewrites the three files, naming
no subject. It also repairs a **relinked** index: a consistent live row on a
chain that ends with a genuine erasure (an index restored from before an
erasure) is forgotten again (step 2 for that one row) and completed like any
pending erasure.

**What erasure does not reach.** Only the live files in this folder. Not:
- backups, including backups of `evidence.db.subjects` (see Correlation
  leakage);
- filesystem snapshots or journals, or SSD wear-levelled blocks (content files
  are unlinked, not overwritten, and the old files' blocks are freed, not
  zeroed);
- copies taken before the erasure;
- anyone an event or nonce was disclosed to.

The chain id stays: in the chain, every checkpoint, and folder names. So do the
number of entries and their timestamps. The erasure entry itself is a signed
record that this chain was erased, and when: pseudonymous personal data, kept
for accountability. Who it was is gone: nothing in the folder links the chain to
the subject any more.

## 5. Checkpoints

- One series per chain: `anchors/<chain>/0001.json`, `0002.json`, … Names match
  `^\d{4,}\.json$`, are ordered by **number** (so `10000.json` follows
  `9999.json`), and MUST run 1..*n* with no gaps. Nothing else may be in the
  folder. Each file is at most 1 MiB, and MUST be a regular file (§3's rules).
- Each is a **v6 anchor** (format-spec §9) over the chain's entries from the
  first to the last at the time of signing, and its `subject` MUST equal the
  chain id (opaque: a checkpoint never names a person).
- Checkpoint *n* > 1 links to checkpoint *n* − 1 through `previous_anchor_id` and
  the anchor chain hash. Checkpoint 1 links to the seed values. Its `entry_count`
  MUST be strictly greater than checkpoint *n* − 1's: a series only grows.
- A new checkpoint is written only when the chain has entries the last one does
  not cover. The existing series MUST verify under the signing key before
  anything is signed on top of it.

## 6. Verification

A sink folder verifies when every chain passes all of the following, each chain
checked on its own, and the index accounts for every chain:

1. **Ids** match §1 before any path is built from them.
2. **Links:** the chain's hashes recompute (format-spec §2).
3. **Checkpoints:** the series is well formed (§5), and, in order, each has
   `subject` = the chain id, names its predecessor in `previous_anchor_id`,
   covers more entries than its predecessor and no more than the chain holds, is
   bound to exactly the first `entry_count` entries (format-spec §9.7), and is
   signed by a trusted key. A chain's entries after the last checkpoint are
   *unanchored*: reported, not a failure.
4. **Entries**, where *E* is the index of the chain's last **genuine** erasure
   entry (§2; none → −1):

   | entry | condition | result |
   |---|---|---|
   | `sink.erasure` | not the first entry; content is exactly the §4.1 record for the previous entry's sequence; `content_hash` = the domain-separated hash of it | ok |
   | `sink.erasure` | anything else | problem: missing, MODIFIED, or not the erasure record for its position |
   | `sink.event`, before *E* | content file AND nonce both absent | **erased** |
   | `sink.event`, before *E* | either still present | problem: erasure incomplete |
   | `sink.event`, after *E* | content absent | problem: **MISSING** (no erasure recorded) |
   | `sink.event`, after *E* | nonce absent | problem: cannot be opened |
   | `sink.event`, after *E* | commitment does not open | problem: **MODIFIED** |
   | `sink.event`, after *E* | opens | **opened** |
   | any other type | | problem |

5. **Nothing left over:** a file in `content/<chain>/` that matches no entry is a
   problem (a commit that stopped before its append, leaving personal data
   behind).
6. **Nothing removed:** a folder in `anchors/` for a chain with no entries in
   `evidence.db` is a problem: the chain was removed (checkpoints are written
   only for chains with entries). A folder in `content/` for a chain with no
   entries is a problem too: leftover personal data. It is reported as a
   removed chain unless the index binds the chain (`index-only`) or has it
   pending, where it is the leftovers of a first commit.
7. **Index accountability.** Each chain in `evidence.db`, and each index row,
   gets one state:

   | state | evidence.db | index | problem? |
   |---|---|---|---|
   | `live` | entries | consistent live row | no |
   | `erased` | ends with a genuine erasure that a verified checkpoint covers | no row | no |
   | `erased-unanchored` | ends with a genuine erasure no verified checkpoint covers yet | no row | no (normal right after an erasure; see below) |
   | `index-only` | no entries | consistent live row | no (the next commit of the pair uses it) |
   | `pending` | any | pending marker | **yes**: an erasure was interrupted; resume |
   | `unaccounted` | does not end with a genuine erasure | no row | **yes**: the index lost the chain, or another writer added it |
   | `relinked` | ends with a genuine erasure | consistent live row | **yes**: the index was restored from before an erasure, or edited; resume forgets it again (§4.4) |
   | `malformed` | any | a row failing §4.2's rule, in either direction (including a forward row whose chain is pending, bound to another pair, or absent) | **yes** |

   A verifier MUST NOT print an index key that is not a valid chain id, nor
   any forward-row key: either may hold a subject. It reports such rows by
   number (`<invalid index row #n>`). It MUST read the index read-only, and an
   absent index means no rows. A report MUST NOT name a subject; naming
   subjects is a separate, explicit operator action (`--show-subjects`), whose
   output is secret-index material.

**How files are reached.** A verifier (and a writer) MUST reach every file
under `content/` and `anchors/` without escaping the sink folder, and MUST
refuse any directory there that is not a real directory. A symlinked
`content/<chain>` pointing at another chain's folder would otherwise let one
chain's erasure delete another's files. Content and checkpoint files MUST be
read with the type and size checked on the file actually opened, not only by
name beforehand. This implementation uses Go's `os.Root`, `O_NONBLOCK` (a FIFO
cannot hang it) and a capped read.

**Verification changes nothing.** It opens the evidence, nonce and index files
read-only, creates no file or folder (a mistyped folder is an error, not a new
sink), reports a missing nonce file as events that cannot be opened, and a
missing index as chains with no row. Opening a crafted `evidence.db` with bbolt
is still parsing untrusted input with a library that may panic on corruption:
to verify a folder from someone else, use an exported bundle (future work,
ticket `_72`), not the files.

**What verification cannot establish:**
- that an entry's `entry_type` is what was written (it is bound by neither the
  chain nor the checkpoints; erasure records are protected by §2's domain
  separation and the genuine-erasure rule, not by the chain);
- that no checkpoint was deleted (a folder cannot vouch for its own
  completeness, so keep checkpoints where the writer cannot rewrite them);
- that an erasure entry made after the last checkpoint is genuine, rather
  than appended by someone with write access: hence `erased-unanchored`
  (checkpoint after erasing);
- which subject a chain belonged to once it is erased, by design.

Steps 2 and 3 need only `evidence.db`, the checkpoints and a public key. Steps 4
to 7 need the content folder, the nonces and the index, which only the operator
holds.

## 7. Idempotent commits

A committed record MAY carry a **source**: its position upstream, e.g.
`EVIDENCE@1790641378694210056:42` (a stream, its incarnation, a sequence).

- A source MUST be unique for good. It MUST include whatever changes when the
  upstream source is recreated (its incarnation), because positions restart
  then. A reused source is taken as already committed, and the new record is
  **dropped** (and reported as a committed duplicate).
- Before appending, the sink records `source → (entry id, global sequence)` for
  the record's chain.
- When the same source comes again for that chain, the record is a duplicate if
  the chain holds that entry id at that sequence. Otherwise the earlier attempt
  never reached the chain, and the record is committed.
- Sources are positions, not content. But they link a chain to exact upstream
  messages, so **erasure deletes them** (§4.3). The cost: a redelivery arriving
  after its subject's erasure is committed again, to the subject's NEW chain
  (the old one is forgotten). Consumers SHOULD acknowledge upstream before
  erasing a subject. The new chain is visible, and can be erased again.
- Timestamps and payload digests MUST NOT be used as sources: a timestamp is a
  claim, and identical bytes can be two distinct events.

**Per-record outcomes.** A commit call reports, for each record in the order
given, whether it is committed (newly, or as a duplicate) and whether it was a
duplicate; nothing else. It names neither a chain nor a subject: next to the
caller's own record, a chain id would be a row of the secret index, easily
logged beside the message. A consumer acknowledges upstream exactly the records
reported committed, and treats a report whose length differs from its records as
a failure (acknowledging nothing). Each (class, subject) pair's chain is
appended atomically; a call as a whole is not: after a failure, the pairs before
it are committed and reported so.

## 8. The Go implementation's files (informative, not an interface)

The four `evidence.db*` files are [bbolt](https://github.com/etcd-io/bbolt)
databases. They are this implementation's storage, documented so they can be
inspected. They are **not** an interchange format: another language verifies an
exported bundle, not these files.

| File | Bucket | Key | Value |
|---|---|---|---|
| `evidence.db` | proof's bolt store (`store/bolt`) | `chain ‖ 0x00 ‖ BE uint64(seq)` | entry |
| `evidence.db.nonces` | `nonces` | `chain ‖ 0x00 ‖ entry id` | 32-byte nonce |
| `evidence.db.sources` | `sources` | `chain ‖ 0x00 ‖ source` | `entry id ‖ BE uint64(seq)` |
| `evidence.db.subjects` | `forward` | `subject ‖ 0x00 ‖ class` | chain id |
| `evidence.db.subjects` | `reverse` | chain id | `class ‖ 0x00 ‖ subject`, or the pending marker `0x00 "pending-erasure"` |

The pending marker cannot be mistaken for a live row: a live row starts with a
class, which starts with `[a-z0-9]`.

Each MUST be a regular file: bbolt follows a symlink and would write wherever it
points. Every operation opens `evidence.db` first: writers with an exclusive
lock, which is what serializes them (holding it, a writer opens the secret files
in any order without deadlock); readers with a shared lock, so none can hold a
secret file while a writer holds the evidence file. Each file is locked while an
operation runs. One process at a time: calls on one `sink.Sink` queue, and
anything else waits on the lock (and fails as busy after the lock timeout).
