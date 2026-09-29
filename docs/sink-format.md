# Sink format

**Status:** normative for everything outside §8. This describes what `proof sink`
(package `sink`) writes and how a sink folder is verified. Chain hashing,
checkpoints (anchors) and salted commitments are defined in
[`format-spec.md`](format-spec.md) and are referenced here, not repeated.

A **sink** is a folder holding one evidence file with **one chain per key**, plus
what is needed to open, checkpoint and erase each chain on its own.

```
  sink-data/
    evidence.db                 the chains (proof store)        no event content; still personal data (below)
    evidence.db.nonces          one nonce per event             SECRET
    evidence.db.sources         upstream positions              SECRET: links pseudonyms to upstream messages
    content/<chain>/<entry>.json the events and erasure records SECRET (the events)
    anchors/<chain>/NNNN.json   signed checkpoints              no event content; publish these (§6)
```

**What the shareable parts still reveal.** `evidence.db` and the checkpoints hold
no event content, only salted commitments, which cannot be reversed or guessed.
They are still **pseudonymous personal data** (GDPR Art. 4(5)). Share them only
on a lawful basis, because they reveal:
- every chain id (each a pseudonym for a subject);
- how many events each subject has, and when each was committed (µs
  timestamps: an activity timeline);
- which subjects were committed in the same batch (timestamps microseconds
  apart);
- **that a subject was erased, and when** (the erasure entry, signed into the
  next checkpoint).

Sharing them is the point of checkpoints: someone the writer cannot influence
should hold a copy. Weigh that against what the list above discloses.

The keywords MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Identifiers

| Identifier | Rule |
|---|---|
| chain id | `^[a-z0-9][a-z0-9._-]{0,63}$`: the routing key, used unchanged. A key that does not match MUST be refused, never transformed. It is permanent (in every entry's chain and every checkpoint's `subject`), so it MUST already be a pseudonym. **The pattern checks characters only:** it refuses an email address or anything upper-case, but `john.smith` or a phone number passes. Pseudonymizing is the caller's job, upstream. The same rule as `proof-mcp`'s `commit`. |
| entry id | `^sink-[0-9a-f]{32}$`: 16 random bytes, assigned by the sink, never by the caller. |

A verifier MUST check both patterns on every id it reads from `evidence.db`
**before** building any path from it. The file may have been shared and
crafted: a chain id of `../../x` must be reported, not followed.

## 2. Entry types

Every entry in a sink chain is one of two types. The type tells a verifier which
check the entry's `content_hash` needs (format-spec §8: the chain itself does not
show it).

| `entry_type` | `content_hash` | content file |
|---|---|---|
| `sink.event` | salted commitment of the event bytes (format-spec §8) | the event, byte-for-byte as committed |
| `sink.erasure` | `hex(SHA-512("aleutian.sink.erasure.v1:" ‖ record))`: domain-separated, see below | the erasure record (§4) |

Any other type in a sink chain MUST be reported as a problem.

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

## 4. Erasure

Erasing a chain happens in this order:

1. **Append an erasure entry** to the chain (`sink.erasure`). Its content is
   exactly these bytes (ASCII, no whitespace, no trailing newline), where `41`
   is the decimal global sequence of the entry immediately before the erasure
   entry. It is a JSON **string**, as format-spec §2.1 requires for sequence
   numbers outside exports:

   ```
   {"erased":"every earlier event on this chain","through_global_seq":"41"}
   ```

   A verifier rebuilds these bytes for the entry's position and compares them.
   It never parses the record. The record is kept for good.
2. **Delete every nonce** of the chain, **and every source position** recorded
   for it (§7). A position maps the chain's pseudonym to exact upstream
   messages, so keeping it would undo the erasure.
3. **Delete every content file** in `content/<chain>/` except erasure records.
4. **Rewrite the nonce and sources files** into fresh copies (fsync, atomic
   rename). Deleting a key in bbolt leaves its bytes in free pages; the rewrite
   removes them from the **live** file.

Appending first means a crash part-way leaves a chain that says "erased, but
something is still here" (run erase again), never one that looks tampered with.
The erasure entry is itself covered by the next checkpoint.

**What erasure does not reach.** Only the live files in this folder. Not:
- backups;
- filesystem snapshots or journals, or SSD wear-levelled blocks (content files
  are unlinked, not overwritten, and the old nonce file's blocks are freed, not
  zeroed);
- copies taken before the erasure;
- anyone an event or nonce was disclosed to.

The chain id stays: in the chain, every checkpoint, and folder names. So do the
number of entries and their timestamps. The erasure entry itself is a signed
record that this chain was erased, and when: pseudonymous personal data, kept
for accountability.

## 5. Checkpoints

- One series per chain: `anchors/<chain>/0001.json`, `0002.json`, … Names match
  `^\d{4,}\.json$`, are ordered by **number** (so `10000.json` follows
  `9999.json`), and MUST run 1..*n* with no gaps. Nothing else may be in the
  folder. Each file is at most 1 MiB, and MUST be a regular file (§3's rules).
- Each is a **v6 anchor** (format-spec §9) over the chain's entries from the
  first to the last at the time of signing, and its `subject` MUST equal the
  chain id.
- Checkpoint *n* > 1 links to checkpoint *n* − 1 through `previous_anchor_id` and
  the anchor chain hash. Checkpoint 1 links to the seed values. Its `entry_count`
  MUST be strictly greater than checkpoint *n* − 1's: a series only grows.
- A new checkpoint is written only when the chain has entries the last one does
  not cover. The existing series MUST verify under the signing key before
  anything is signed on top of it.

## 6. Verification

A sink folder verifies when every chain passes all of the following, each chain
checked on its own:

1. **Ids** match §1 before any path is built from them.
2. **Links:** the chain's hashes recompute (format-spec §2).
3. **Checkpoints:** the series is well formed (§5), and, in order, each has
   `subject` = the chain id, names its predecessor in `previous_anchor_id`, covers
   more entries than its predecessor and no more than the chain holds, is bound to exactly the first `entry_count` entries
   (format-spec §9.7), and is signed by a trusted key. A chain's entries after the
   last checkpoint are *unanchored*: reported, not a failure.
4. **Entries**, where *E* is the index of the chain's last erasure entry (none
   → −1):

   | entry | condition | result |
   |---|---|---|
   | `sink.erasure` | not the first entry; content is exactly the §4 record for the previous entry's sequence; `content_hash` = the domain-separated hash of it | ok |
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
6. **Nothing removed:** a folder in `anchors/` or `content/` for a chain that has
   no entries in `evidence.db` is a problem: the chain was removed.

**How files are reached.** A verifier (and a writer) MUST reach every file
under `content/` and `anchors/` without escaping the sink folder, and MUST
refuse any directory there that is not a real directory. A symlinked
`content/<chain>` pointing at another chain's folder would otherwise let one
chain's erasure delete another's files. Content and checkpoint files MUST be
read with the type and size checked on the file actually opened, not only by
name beforehand. This implementation uses Go's `os.Root`, `O_NONBLOCK` (a FIFO
cannot hang it) and a capped read.

**Verification changes nothing.** It opens the evidence and nonce files
read-only, creates no file or folder (a mistyped folder is an error, not a new
sink), and reports a missing nonce file as events that cannot be opened.
Opening a crafted `evidence.db` with bbolt is still parsing untrusted input with
a library that may panic on corruption: to verify a folder from someone else,
use an exported bundle (future work, ticket `_72`), not the files.

**What verification cannot establish:** that an entry's `entry_type` is what
was written (it is bound by neither the chain nor the checkpoints; erasure
records are protected by §2's domain separation, not by the chain), that no
checkpoint was deleted (a folder
cannot vouch for its own completeness, so keep checkpoints where the writer
cannot rewrite them), and that an erasure entry made after the last checkpoint
is genuine (checkpoint after erasing). Steps 2 and 3 need only `evidence.db`, the
checkpoints and a public key. Steps 4 and 5 need the content folder and the
nonces, which only the operator holds.

## 7. Idempotent commits

A committed record MAY carry a **source**: its position upstream, e.g.
`EVIDENCE@1790641378694210056:42` (a stream, its incarnation, a sequence).

- A source MUST be unique for good. It MUST include whatever changes when the
  upstream source is recreated (its incarnation), because positions restart
  then. A reused source is taken as already committed, and the new record is
  **dropped**.
- Before appending, the sink records `source → (entry id, global sequence)`.
- When the same source comes again, the record is a duplicate if the chain holds
  that entry id at that sequence. Otherwise the earlier attempt never reached
  the chain, and the record is committed.
- Sources are positions, not content. But they link the chain's pseudonym to
  exact upstream messages, so **erasure deletes them** (§4). The cost: a
  redelivery arriving after an erasure is committed again. It lands after the
  erasure entry, visibly, and can be erased again.
- Timestamps and payload digests MUST NOT be used as sources: a timestamp is a
  claim, and identical bytes can be two distinct events.

## 8. The Go implementation's files (informative, not an interface)

The three `evidence.db*` files are [bbolt](https://github.com/etcd-io/bbolt)
databases. They are this implementation's storage, documented so they can be
inspected. They are **not** an interchange format: another language verifies an
exported bundle, not these files.

| File | Bucket | Key | Value |
|---|---|---|---|
| `evidence.db` | proof's bolt store (`store/bolt`) | `chain ‖ 0x00 ‖ BE uint64(seq)` | entry |
| `evidence.db.nonces` | `nonces` | `chain ‖ 0x00 ‖ entry id` | 32-byte nonce |
| `evidence.db.sources` | `sources` | `chain ‖ 0x00 ‖ source` | `entry id ‖ BE uint64(seq)` |

Each MUST be a regular file: bbolt follows a symlink and would write wherever it
points. Writers open them in that order (evidence, nonces, sources), so two
processes cannot deadlock; readers take shared locks. Each is locked while an
operation runs.
One process at a time: calls on one `sink.Sink` queue, and anything else waits on
the lock.
