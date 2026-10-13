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
    evidence.db.secrets          each event's content + nonce,   SECRET: the events (which name their subject) and
                                 and the erasure records          what opens their commitments
    evidence.db.sources          upstream positions              SECRET: links chains to upstream messages
    evidence.db.subjects         subject ↔ chain index           SECRET: the only link from a subject to its chains
    evidence.db.signatures       record signatures (optional §9) shareable with evidence.db; still personal data (below)
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

**Erasure timestamps.** Every erasure entry one erase call writes (for the
subject's chains, and for pending chains of earlier calls that it completes)
carries the same timestamp: the moment the call decided them, before signing
and forgetting, not each append's. Equal erasure timestamps therefore mean "the
same call", which usually means the same subject.

**A record signer is a processor.** In a signing sink (§9) every envelope (chain
id, entry id and type, sequence, hashes, timestamp) goes to the record signer;
for a remote one (a KMS), that service sees each commit and, as one burst, each
erasure's chains. It sees nothing `evidence.db` does not hold.

`evidence.db.signatures` (§9) reveals nothing beyond `evidence.db` except the
record key ids, which show when keys were rotated and link sinks that share a
record key. It may also hold rows for chain positions a failed or crashed
commit never filled (§9.3), including, after a first commit that never reached
its chain, rows for a chain id `evidence.db` does not hold; erasing that
subject removes them.

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
| subject | `^[a-z0-9][a-z0-9._-]{0,127}$`: who the record is about, a pseudonym. Stored ONLY in `evidence.db.subjects` (and in the events themselves, in `evidence.db.secrets`). **The pattern checks characters only:** it refuses an email address or anything upper-case, but `john.smith` passes. Pseudonymizing is the caller's job, upstream. A subject that does not match MUST be refused, never transformed. |
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

| `entry_type` | `content_hash` | stored content |
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
covers it (§6, `erased-unanchored`), and a checkpoint covers one only with
evidence that the operator made it (§5.1).

Timestamps are assigned by the sink when it commits, 1 µs apart within a batch.
They are recorded, and hashed into the chain, but they are **advisory**: the
chain's sequence is the order.

## 3. Content and nonces

- An event's content is the exact bytes committed, 1 to 65,536 bytes, opaque
  to the sink. It is stored with the event's nonce in `evidence.db.secrets`
  (§8), keyed by chain and entry id. A verifier MUST refuse to check content
  larger than 65,536 bytes.
- The nonce for event *e* on chain *c* is 32 bytes, fresh per event. Opening *e*
  means: `commitment(nonce, content) == e.content_hash`, exactly as in
  format-spec §8.
- **Content and nonces are written in ONE durable transaction, before the
  entries that commit to them** (§7). A crash, or a power loss, can never leave
  a committed entry whose content never reached the disk.

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
   erasable: a valid id, and readable to its end. If one is not, the call
   refuses and nothing changes: a subject is never forgotten by an erasure
   already known to be stuck.

   Then **decide every erasure entry** this call will append (for this
   subject's chains and every pending one): its id, timestamp (one for the
   whole call: the decision time) and predicted chain hash; in a signing sink
   (§9) sign each, verified. A signer failure refuses the call and changes
   nothing. A chain that cannot be read or hashed gets no entry decided; it
   fails alone in step 3 and stays pending. (Every call re-decides every
   pending chain: a sink with many stuck chains signs them all, each call.)
2. **Forget.** In ONE index transaction, delete the subject's forward rows in
   scope and turn each of their chains' reverse rows into the pending marker.
   From here, a new event for the subject gets a NEW chain: it can never rejoin
   an erased history.
3. **Complete every pending erasure**, this subject's and any an earlier,
   interrupted call left. For each chain:
   1. **append a genuine erasure entry** (§2), unless the chain already ends
      with one, or has no entries (a first commit that never reached it: its
      leftover files are removed instead): its record row (and, signing, its
      signature) durable first, then the entry, pinned to its predicted chain
      hash, so a chain that moved since step 1 is refused and stays pending;
   2. **delete every nonce and every content row** of the chain, in one
      transaction, except the records of its genuine erasure entries, each kept
      only while it holds exactly its record. A genuine erasure entry whose
      record row is missing gets it back in the same transaction (the record is
      public and fixed);
   3. **delete every source position** recorded for it (§7): a position maps
      the chain to exact upstream messages, so keeping it would undo the
      erasure.

   A chain that fails stays pending, and the others go on.
4. **Rewrite the secrets, sources, subject-index and signatures files** into fresh copies
   (fsync, atomic rename), on every erasure call that got past step 1, even
   when nothing was pending, and even when a chain failed: deleting a key in
   bbolt leaves its bytes in free pages, and a rewrite an earlier call failed or
   crashed in is then always redone. (A call refused at step 1 changed nothing,
   and rewrites nothing; resume always rewrites.)
5. **Only after the rewrite succeeds, clear** the pending rows of the chains
   completed in step 3, and rewrite the subject index once more. If the rewrite
   failed, they stay pending. A chain therefore stops being pending only when its
   content and nonces have left the live files.

Appending first means a crash part-way leaves a chain that says "erased, but
something is still here" (run erase again), never one that looks tampered with.
The erasure entry is covered by a checkpoint made with evidence of who wrote it
(§5.1): in practice, by the erase call's own process.

**The recovery invariant.** When an erasure call succeeds: the index holds no
row of the subject in scope; every chain it had there is erased as in step 3;
every erasure pending when the call began is complete; and the secrets, sources
and subject-index files were
rewritten after the last deletion. A pending marker is cleared only after that
rewrite, so a chain that is not pending has no erased content in the live files.
When a call fails (or crashes) after forgetting, the chains not finished,
including those whose rewrite failed, are still pending (their rows hold no
subject); the error says which, and whether the files were rewritten. Any later
erasure call, or a resume, completes them without re-linking the subject.

### 4.4 Resume

**Resume** completes every pending erasure and rewrites the four files, naming
no subject. It also repairs a **relinked** index: a consistent live row on a
chain that ends with a genuine erasure (an index restored from before an
erasure) is forgotten again (step 2 for that one row) and completed like any
pending erasure. A relinked chain's erasure entry was on the chain before the
call, with an index that did not record an erasure: the call reports such a
chain as relinked, and that erasure entry is NOT one it vouches for (§5.1).

**What erasure does not reach.** Only the live files in this folder. Not:
- backups, including backups of `evidence.db.subjects` (see Correlation
  leakage);
- filesystem snapshots or journals, or SSD wear-levelled blocks (the rewritten
  files' old blocks are freed, not zeroed);
- copies taken before the erasure;
- anyone an event or nonce was disclosed to;
- process memory or swap of anything that read the content;
- a rewrite's temporary copy left behind by a crash (the next erasure call
  removes it);
- deleted rows in the window before the rewrite (a crash there leaves the chain
  pending, and the next call rewrites).

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
  anything is signed on top of it, and the chain MUST pass every check of §6:
  nothing is signed that verification would fail.

### 5.1 Checkpointing an erasure

An erasure record takes no key (§2). A checkpoint over one is the operator's
signature that the chain was erased, so a writer MUST NOT checkpoint a chain
that ends with a genuine erasure no verified checkpoint covers (state
`erased-unanchored`, §6) unless it has evidence that the operator made that
erasure. Two kinds count:

1. **Confirmation in the same process.** The erase call returns, for each
   chain, its erasure entry's id, and the checkpoint is told those (chain,
   entry id) pairs: a chain is confirmed only when it ends with exactly the
   entry confirmed FOR THAT CHAIN. (An entry id alone is not enough: it is in
   the evidence file for anyone to read, and can be written onto another
   chain.) `proof sink erase --key K` and `proof sink erase --resume --key K`
   do this in one run. Neither id is printed: beside the subject on the
   command line it would map the subject to its chain. An erasure entry that
   was already on a chain the index still bound to a subject when the erase
   call began is NOT confirmed by that call, whichever call it is (§4.4).
2. **A record signature** (§9). In a signing sink the erasure entry is signed.
   A checkpoint given record trust (`proof sink checkpoint --record-trust PUB`)
   signs over an erasure whose own signature verifies, when nothing else about
   the chain fails and it has no orphan signature rows (R6, §9.4).

3. **The operator's word, by chain.** An honest erasure can miss both: on a
   sink that does not sign, an erase without `--key`, a run that died between
   erasing and checkpointing, or a checkpoint that failed. Afterwards nothing
   in the folder can attribute it. The operator names the chain, taken from
   `proof sink verify` (which names no subject), and vouches for it:
   `proof sink checkpoint --key K --confirm-erased-chain <chain id>`. The chain
   MUST still be exactly in that state (it ends with a genuine erasure no
   verified checkpoint covers, has no index row, and passes every check of
   §6); otherwise nothing is signed for it and it is reported. A writer MUST
   warn that this signs an erasure it cannot attribute.

With none of these, the chain is reported as not checkpointed, with what to
do, and stays `erased-unanchored`. A forged erasure is therefore never turned
into a signed `erased` unless the operator vouches for it. It is not undone
either: the events it covered are gone, and the chain is reported on every
checkpoint run until someone does.

**What this does not close.** An erase call completes every erasure the index
marks pending (§4.3 step 3), and vouches for those too. The pending marker is a
row in the folder, and takes no key: someone who can write the index can mark a
chain pending, and the operator's next erase call then erases it, with a real
erasure entry of its own. A chain the index had *relinked* (§4.4) is the
exception: its erasure entry was already there, and the call does not vouch for
it.

### 5.2 Series heads (optional)

A folder cannot show that its checkpoints are complete: with
`anchors/<chain>/` removed, a writer starts a new series at `0001.json` over
the chain as it stands. A writer and a verifier MAY be given a record of each
chain's **series head**, kept where whoever can rewrite the folder cannot
rewrite it: the number of checkpoints, and the last one's anchor chain hash
(its `chain_hash`, format-spec §9).

- A series with fewer checkpoints than its head, or with another anchor chain
  hash at the head's number, "was cut or restarted". A verifier MUST report it
  as a problem; a writer MUST NOT extend it.
- After writing a checkpoint durably, a writer records the new head. A series
  longer than its head is therefore not a problem (a crash between the two);
  the writer verifies such a chain in full and records its head on its next
  run. The same applies to a chain that had checkpoints before heads were
  first kept: its series is recorded as it stands (trust on first use).
- This implementation's `proof sink checkpoint --heads FILE` and
  `proof sink verify --heads FILE` keep heads in one JSON file, replaced
  atomically on each write and never reached through a symlink, and refuse a
  file inside the sink folder:

  ```
  {"format": "aleutian.proof.sink.heads.v1",
   "heads": {"<chain id>": {"checkpoints": 2, "anchor_chain_hash": "<128 hex>"}}}
  ```

  It holds chain ids, like `anchors/`: no subject, and still pseudonymous
  personal data.
- Without heads nothing changes, and the limitation stands. Heads are asked
  about chains the evidence file holds: a chain removed whole, with its
  checkpoints, is not noticed through them. They do not help against someone
  who can rewrite the heads too; that needs a witness outside the operator.

## 6. Verification

(To verify a sink's evidence **elsewhere**, without the folder or proof, export
it as a bundle: `bundle-format.md`. Its rules derive from these, with the
differences listed in its §14.)


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
   | `sink.event`, before *E* | content AND nonce both absent | **erased** |
   | `sink.event`, before *E* | either still present | problem: erasure incomplete |
   | `sink.event`, after *E* | content absent | problem: **MISSING** (no erasure recorded) |
   | `sink.event`, after *E* | nonce absent | problem: cannot be opened |
   | `sink.event`, after *E* | commitment does not open | problem: **MODIFIED** |
   | `sink.event`, after *E* | opens | **opened** |
   | any other type | | problem |

5. **Nothing left over:** a content or nonce row that matches no entry of its
   chain is a problem (a commit that stopped before its append, leaving
   personal data behind), and so is a nonce stored beside an erasure record.
   Entry ids are printed only when they have the sink's shape; others are
   counted. A row whose key is not `chain ‖ 0x00 ‖ entry id` with a valid chain
   id and entry id is reported by number only (`<invalid secrets row #n>`).
6. **Nothing removed:** a folder in `anchors/` for a chain with no entries in
   `evidence.db` is a problem: the chain was removed (checkpoints are written
   only for chains with entries). Content or nonces for a chain with no entries
   are a problem too: leftover personal data. That is reported as a removed
   chain unless the index binds the chain (`index-only`) or has it pending,
   where it is the leftovers of a first commit. Rows under an id this sink
   never mints are reported by number only.
7. **Index accountability.** Each chain in `evidence.db`, and each index row,
   gets one state:

   | state | evidence.db | index | problem? |
   |---|---|---|---|
   | `live` | entries | consistent live row | no |
   | `erased` | ends with a genuine erasure that a verified checkpoint covers, **or** whose own record signature verifies under the record trust given (§9.4), the chain having no problem at all | no row | no |
   | `erased-unanchored` | ends with a genuine erasure no verified checkpoint covers yet | no row | no (normal right after an erasure; see below) |
   | `index-only` | no entries | consistent live row | no (the next commit of the pair uses it) |
   | `pending` | any | pending marker | **yes**: an erasure was interrupted; resume |
   | `unaccounted` | does not end with a genuine erasure | no row | **yes**: the index lost the chain, or another writer added it |
   | `relinked` | ends with a genuine erasure | consistent live row | **yes**: the index was restored from before an erasure, or edited; resume forgets it again (§4.4) |
   | `malformed` | any | a row failing §4.2's rule, in either direction (including a forward row whose chain is pending, bound to another pair, or absent) | **yes** |

8. **Record signatures** (§9.4), when the verifier gives record trust; and,
   always, signature rows for chains `evidence.db` does not hold (REMOVED
   unless the index binds the chain or has it pending) and rows keyed off the
   layout (by number).
9. **Source positions** (§7): every row of `evidence.db.sources` MUST point at
   an entry that its chain holds with that id at that sequence, and no entry
   may have more than one. A position that points at no entry is what a commit
   that stopped leaves (`proof sink repair` removes it); an entry with several
   is rows written into the file. Both are counted per chain. A source is
   never shown, and a row that is not a position is reported by number
   (`<invalid sources row #n>`).

A verifier MAY additionally be told to compare each series with its recorded
head (§5.2), and to treat a chain no verified checkpoint covers as a failure
(`--require-checkpoint`: without it, a folder whose `anchors/` was removed
still verifies).

   A verifier MUST NOT print an index key that is not a valid chain id, nor
   any forward-row key: either may hold a subject. It reports such rows by
   number (`<invalid index row #n>`). It MUST read the index read-only, and an
   absent index means no rows. A report MUST NOT name a subject; naming
   subjects is a separate, explicit operator action (`--show-subjects`), whose
   output is secret-index material.

**How files are reached.** Checkpoints are the only files a sink reads by
name. A verifier (and a writer) MUST reach every file under `anchors/` without
escaping the sink folder, and MUST refuse any directory there that is not a
real directory. Checkpoint files MUST be read with the type and size checked
on the file actually opened, not only by name beforehand. This implementation
uses Go's `os.Root`, `O_NONBLOCK` (a FIFO cannot hang it) and a capped read.

**Verification reads a page at a time, and is not one snapshot.** A verifier
MAY release the files between chains so writers are not held up (this
implementation releases them every ~50 ms of work, pausing longer than bbolt's
50 ms lock retry so a waiting writer gets in). Every chain MUST be read whole
under one hold, so each chain's verdict is consistent. The report as a whole is
then a sequence of per-chain readings, not one snapshot of the folder: a chain
committed during the run may or may not be reported, and the cross-chain checks
(index rows, checkpoint folders, secrets and signature rows for chains the
evidence file does not hold) MUST look at the evidence file when they run, so a
chain committed meanwhile is never reported as removed. For a point-in-time
verdict, stop the writers or verify a copy.

**Verification changes nothing.** It opens the evidence, secrets, sources, signatures and index
files read-only, creates no file or folder (a mistyped folder is an error, not a
new sink), reports a missing secrets file as events whose content is gone, and a
missing index as chains with no row. A file that is truncated or whose pages
were overwritten makes verification fail with an error (§8), not crash. Opening
a *crafted* `evidence.db` with bbolt is still parsing untrusted input with a
library written for its own files (pages that point back at each other are
followed without end): to verify a folder from someone else, use an exported
bundle (`proof sink export`, then `proof sink verify-bundle`; see
bundle-format.md), not the files.

**What verification cannot establish:**
- that an entry's `entry_type` is what was written (it is bound by neither the
  chain nor the checkpoints; erasure records are protected by §2's domain
  separation and the genuine-erasure rule, not by the chain), unless record
  signatures were checked (§9.4), which bind it;
- that no checkpoint was deleted, from the folder alone (a folder cannot vouch
  for its own completeness, so keep checkpoints where the writer cannot
  rewrite them). **Closed with series heads** (§5.2): a series shorter than
  its recorded head, or restarted, is a problem, and is not extended. **Not
  closed** without them: with `anchors/<chain>/` removed, the next checkpoint
  signs a new `0001.json` over the chain as it stands, and verification
  passes. Nor against someone who can rewrite the heads as well;
- that an erasure entry made after the last checkpoint is genuine, rather
  than appended by someone with write access: hence `erased-unanchored`,
  unless its record signature verifies under the record trust given. A forged
  erasure at the END of a chain, with its index row removed, verifies exactly
  as a real one does. **Closed:** a checkpoint no longer covers it (§5.1), so
  it never reads `erased`; an `erased` chain is one whose erasure the
  checkpointing process made, or whose record signature verified. **Not
  closed:** the forged erasure is not undone, and stays `erased-unanchored`
  for good; and an erasure the sink itself completed because the index marked
  the chain pending is vouched for like any other, though the marker takes no
  key (§5.1);
- that a record reported as a duplicate was one, when both the sources file
  and the stored content were rewritten to match it, or when its source was
  pointed at an entry that already holds the same bytes (§7);
- which subject a chain belonged to once it is erased, by design.

Steps 2 and 3 need only `evidence.db`, the checkpoints and a public key; step 8
also needs `evidence.db.signatures` and a record public key. Steps 4 to 7 (and
the `erased` verdict) need the secrets file and the index, which only the
operator holds.

Step 2 includes the STORED linkage: every entry's `previous_hash` field MUST be
the previous entry's chain hash, and a sink chain MUST start at `global_seq` 0
with an empty `previous_hash`. Recomputing the hashes is not enough on its own:
the hashes take no key, and a record signature covers the stored field.

## 7. Idempotent commits

A committed record MAY carry a **source**: its position upstream, e.g.
`EVIDENCE@1790641378694210056:42` (a stream, its incarnation, a sequence).

- A source MUST be unique for good. It MUST include whatever changes when the
  upstream source is recreated (its incarnation), because positions restart
  then.
- Before appending, the sink records `source → (entry id, global sequence)` for
  the record's chain.
- When the same source comes again for that chain: if the chain does not hold
  that entry id at that sequence, the earlier attempt never reached the chain,
  and the record is committed. If it does, the record is a duplicate **only if
  that entry's stored content equals the record's**, byte for byte. A
  duplicate is a record the chain already holds; a position alone proves
  nothing, because the sources file takes no key.
- A record whose source is already committed with **different** content, or
  whose committed content is missing or unreadable, MUST be refused (this
  implementation: `ErrSourceConflict`), not dropped: nothing in the call is
  committed, and the record is reported as not committed. It fails the same
  way on every redelivery, so a consumer dead-letters it. The same holds for a
  source given twice in one call. Rows written into the sources file for
  sources that have not arrived yet therefore cannot make new records vanish.
  **Not closed:** a writer of the folder who knows a future record's exact
  bytes can rewrite the stored content to match, or point the source at an
  entry that already holds those bytes (events that repeat byte for byte);
  verification reports an entry with more than one source position (§6
  step 9).
- Sources are positions, not content. But they link a chain to exact upstream
  messages, so **erasure deletes them** (§4.3). The cost: a redelivery arriving
  after its subject's erasure is committed again, to the subject's NEW chain
  (the old one is forgotten). Consumers SHOULD acknowledge upstream before
  erasing a subject. The new chain is visible, and can be erased again.
- Timestamps and payload digests MUST NOT be used as sources: a timestamp is a
  claim, and identical bytes can be two distinct events.

**From the command line.** `proof sink commit --source-field F` takes each
line's source from a top-level JSON field (a string, or a whole number);
`--source-prefix P` gives line *n* of the input the source `P:n`, for input
with no id of its own. With either, committing the same input again commits
nothing new. A prefix MUST name the input for good: the same prefix on other
input is a conflict, line by line.

**Per-record outcomes.** A commit call reports, for each record in the order
given, whether it is committed (newly, or as a duplicate) and whether it was a
duplicate; nothing else. It names neither a chain nor a subject: next to the
caller's own record, a chain id would be a row of the secret index, easily
logged beside the message. A consumer acknowledges upstream exactly the records
reported committed, and treats a report whose length differs from its records as
a failure (acknowledging nothing).

**Commit point and atomicity.** A call's content and nonces are written first,
in one durable transaction of the secrets file; in a signing sink, then its
record signatures, in one durable transaction of the signatures file (§9). Every
entry's chain hash is predicted and pinned: the append writes those entries at
those positions, or nothing. The records are then committed
by ONE transaction that appends every chain's entries and heads together: that
transaction is the commit point. For ordinary returned errors, a call is
all-or-none across its records: on any error no record is committed, and the
call leaves nothing new behind (its content and nonce rows, source positions and
new index rows are removed; if removal itself fails, the error says so). The one
exception: when an append fails and whether it landed cannot be checked,
nothing is removed.

A failure that belongs to one (class, subject) pair's stored state (an
inconsistent index row, an index restored from before an erasure) names that
pair's records, and a source conflict names its one record, so a consumer can
set those aside and retry the rest; every other failure is retried whole.
Errors never name a chain, a source or content.

The files are separate, so this is not crash atomicity: a crash (or a failed
removal) may leave preparatory state (index rows, content, nonces, record
signatures, source positions) in individual files. It is never committed
evidence until the append succeeds. Committing the same records again does
NOT clear it: the retry gets new entry ids, so it reuses the index row and
replaces the source positions, and the earlier attempt's content, nonce and
signature rows stay, matching no entry. They persist until **`proof sink
repair`** removes them, or the subject is erased (which removes all of it: the
index rows come first, so everything is reachable). If removing a failed call's
rows itself fails, the new index rows are kept, so the subject's erasure still
reaches them. Rows a failed commit deleted stay in the secrets file's free pages
until the next erasure or repair rewrites it. Verify reports leftover content
and nonce rows, source positions that point at no entry, and index-only rows;
orphan signature rows are a note (§9.4).

**Repair.** `proof sink repair` holds the folder and removes, for every chain
with entries, each content row, nonce, source position and record signature row
that no entry of the chain accounts for; for a chain the index binds that has
no entries yet (a first commit that stopped), its content, nonces and source
positions, keeping the index row. It then rewrites the secrets, sources and
signatures files, and prints counts only. It is not run on every commit:
finding the rows means reading the chain.

Rows that match no entry are also what REMOVING entries leaves, and nothing
proves that a row never belonged to a committed entry. So repair MUST leave a
chain alone, and count it, when anything it can see says the chain held more
than it holds now, or the rows are another operation's to finish:

| chain | left alone when |
|---|---|
| any | its erasure is pending (resume removes the rows); its checkpoints cannot be read; a checkpoint covers more entries than it holds; its checkpoint series is behind its recorded head (`--heads`, §5.2); it cannot be read to its end |
| with no entries | also: the index does not bind it; it has any checkpoint; it has a recorded head; it has any record signature row |

A chain with no entries, a live index row and a checkpoint is a chain whose
entries were removed (or an evidence file restored from an older copy), not a
first commit: its content is the only copy of those events, and is kept. On a
sink that signs, a first commit that stopped has signature rows (they are
stored before the append), as a chain whose signed entries were removed does:
it is left alone until the pair commits again, after which what the first
attempt left is an ordinary leftover. One chain that cannot be read does not
stop the others.

**What repair cannot tell:** on a chain no checkpoint (and no head) covers,
entries removed from the END leave rows exactly like a crashed commit's, and
repair deletes them. What it deletes is not recoverable. On a chain with
entries, orphan signature rows are removed with the rest, although
verification only notes them: the same ambiguity applies to them, and a
trailing run of orphan signatures is what could stand in for removed entries
(§9.3).

## 8. The Go implementation's files (informative, not an interface)

The five `evidence.db*` files are [bbolt](https://github.com/etcd-io/bbolt)
databases. They are this implementation's storage, documented so they can be
inspected. They are **not** an interchange format: another language verifies an
exported bundle, not these files.

| File | Bucket | Key | Value |
|---|---|---|---|
| `evidence.db` | proof's bolt store (`store/bolt`) | `chain ‖ 0x00 ‖ BE uint64(seq)` | entry |
| `evidence.db.secrets` | `content` | `chain ‖ 0x00 ‖ entry id` | the exact bytes committed, or an erasure record |
| `evidence.db.secrets` | `nonces` | `chain ‖ 0x00 ‖ entry id` | 32-byte nonce (none for an erasure record) |
| `evidence.db.sources` | `sources` | `chain ‖ 0x00 ‖ source` | `entry id ‖ BE uint64(seq)` |
| `evidence.db.subjects` | `forward` | `subject ‖ 0x00 ‖ class` | chain id |
| `evidence.db.subjects` | `reverse` | chain id | `class ‖ 0x00 ‖ subject`, or the pending marker `0x00 "pending-erasure"` |
| `evidence.db.signatures` | `signatures`, `meta` | see §9.2 | see §9.2 |

The pending marker cannot be mistaken for a live row: a live row starts with a
class, which starts with `[a-z0-9]`.

**A damaged file.** bbolt reads its file through a memory map and trusts every
page: a file cut short, or one whose pages were overwritten, makes it panic or
fault. No operation lets that out. Before bbolt is given a file at all, on
every open, the page size, page ids and freelist count in its meta pages and
freelist header are checked against the file's length, and a value that cannot
fit is refused (bbolt would otherwise allocate what a crafted count asks for,
until the process dies). **This covers damage, not design:** a file crafted
beyond that (pages that point back at each other, a count inside a data page)
is outside what is promised, and can hang or end the process. Every call into bbolt is guarded and
returns an error (`ErrCorrupt`); a file that failed that way is not used again
by that operation and is abandoned rather than closed (closing can wait for
good on a lock the failed transaction left held), with its lock released. The
operations that write also read each file through, read-only, before first
writing to it, once per file per process, and refuse a damaged one before
anything is written (about 0.1 s per GiB with the file in the page cache;
`--skip-check` on the command line, `WithoutIntegrityCheck` in Go). From the
command line a damaged file is exit 1 for `verify` and exit 3 for every other
verb.

Each MUST be a regular file: bbolt follows a symlink and would write wherever it
points. Each is opened with `O_NOFOLLOW` and checked to be a regular file on the
opened handle, so a symlink swapped in after a check by name is still refused. When a file is created, its folder is fsynced, so the file's name is as
durable as its contents. Every operation opens `evidence.db` first: writers with an exclusive
lock, which is what serializes them (holding it, a writer opens the secret files
in any order without deadlock); readers with a shared lock, so none can hold a
secret file while a writer holds the evidence file. Each file is locked while an
operation runs. One process at a time: calls on one `sink.Sink` queue, and
anything else waits on the lock (and fails as busy after the lock timeout).

## 9. Record signatures (optional)

> Status: implemented. Commit and erase write record signatures in a signing
> sink; Verify checks them when given record trust (§9.4).

A sink MAY sign every record it writes with ML-DSA-65, under a **record key**
separate from the checkpoint key (recommended, not required). A record
signature says: *this signer assigned this record sequence N in chain X, after
the entry whose chain hash is P*. Because `previous_hash` is signed, record
signatures chain like the entries do.

### 9.1 The envelope `aleutian.proof.record.v1`

The exact bytes signed, with the **empty** ML-DSA context (the domain is in the
message):

```
envelope = "aleutian.proof.record.v1" 0x00
         ‖ field(0x01, chain_id)
         ‖ field(0x02, entry_id)
         ‖ field(0x03, entry_type)
         ‖ field(0x04, global_seq)
         ‖ field(0x05, previous_hash)
         ‖ field(0x06, timestamp)
         ‖ field(0x07, content_hash)
         ‖ field(0x08, signing_key_id)

field(tag, v) = tag (1 byte) ‖ length of v (uint32, big-endian) ‖ v
```

| Field | Value (ASCII) |
|---|---|
| `chain_id` | a chain id (§1) |
| `entry_id` | an entry id this sink assigns: `sink-` + 32 lowercase hex |
| `entry_type` | `sink.event` or `sink.erasure` |
| `global_seq` | the entry's sequence, base-10 ASCII as in format-spec §2.1 |
| `previous_hash` | the previous entry's chain hash, 128 lowercase hex; **empty exactly when `global_seq` is 0** |
| `timestamp` | the entry's timestamp as in format-spec §4 (UTC, six digits, truncated); year 0001–9999 |
| `content_hash` | the entry's `content_hash`: 128 lowercase hex |
| `signing_key_id` | the signing key's id: format-spec key id, 32 lowercase hex |

- All eight fields, in this order, exactly once; no other tags. Only
  `previous_hash` may be empty, and only at `global_seq` 0. A signer MUST
  refuse to sign, and a verifier MUST report as unverifiable, any value outside
  this table.
- The version is the domain string; there is no other version field.
  **`record.v1` is ML-DSA-65 only.** A verifier MUST NOT take the algorithm from
  the file, and MUST check that the public key it verifies with has exactly the
  row's key id. A different algorithm needs a new domain string.
- Vectors: `fixtures/testdata/record_v1_vectors.json`: envelopes computed
  independently in Python from this section (including a timestamp formatted
  from a nanosecond instant), field values that MUST be refused, and a pinned
  deterministic signature (a regression value from proof's signer, not an
  independent one).

**Not bound, deliberately:** the content and the nonce (a signature must never
help open erased content), and **which sink** the chain is in. A sink's chain
ids are random, but a record key used for several sinks lets a whole chain be
copied from one to another and still verify: use one record key per sink when
sinks are shared with different parties (this also keeps key ids from linking
sinks).

### 9.2 The signatures file

`evidence.db.signatures` is shareable with `evidence.db` and, like it,
pseudonymous personal data:

| Bucket | Key | Value |
|---|---|---|
| `signatures` | `chain ‖ 0x00 ‖ entry id` | key id (16 bytes) ‖ ML-DSA-65 signature (3309 bytes) |
| `meta` | `record_signing` | `ml-dsa-65`: this sink signs its records |
| `meta` | `record_key ‖ 0x00 ‖ key id` (hex) | empty: every record key the sink has signed with |

- A writer MUST write a record's signature durably, in one transaction per
  call, **before** the evidence transaction that commits the record (ordered
  durability with fail-closed commit, as for content in §3; not atomicity
  across the files), and MUST verify each signature before storing it. It MUST
  refuse to append if a chain's tail is not the one the signatures were made
  against.
- A value that is not exactly 3325 bytes is malformed and MUST NOT be parsed.
  A `record_signing` value other than `ml-dsa-65` is an error.
- **The signing mode** is set by `proof sink init` (before the sink has any
  entry, so that a first commit without a record key is refused instead of
  making the sink unsigned for good), or else by the first commit whose
  signatures were *stored*, even if its append then fails, and never cleared
  (fail closed). A
  signer failure stores nothing and sets nothing. The mode only guards the writer: whether signatures are
  required is the verifier's policy (a trusted record key given), never read
  from the folder, because anyone who can delete signatures can delete the mode.
  A lost or deleted signatures file is therefore noticed only by a verifier
  given a record key.
- **Erasure** adds the signatures of its erasure entries and never deletes the
  row of an entry: a signature covers a salted commitment whose nonce erasure
  deletes, and keeps the erased chain verifiable. (Repair removes rows that
  are no entry's, §7.) The file is rewritten (compacted) with the
  other files on every erasure (§4.3 step 4), so rows a failed commit deleted
  leave its free pages.
- Opening a crafted signatures file with bbolt is parsing untrusted input, as
  for `evidence.db` (§6); a damaged one is an error (§8).

### 9.3 What record signatures do not establish

- **Truncation:** removing a chain's last entries and their signature rows
  leaves every remaining signature valid. Checkpoints bound it.
- **Signatures orphaned at the tail:** a failed or crashed commit (or erasure)
  can leave signatures for positions that were later filled by other records,
  or never. A failed k-record commit's orphans chain to each other. Because
  `previous_hash` is signed, they can only stand in for a **trailing run** of
  entries after truncating to where they begin: the truncation case above,
  never a splice into the middle. That includes **reversing an erasure**:
  orphaned event signatures at the erasure's position could replace it after
  truncation, making the chain look never erased. A checkpoint over the
  erasure (or `--record-trust` plus the index state) bounds it, as for any
  truncation. `proof sink repair` removes orphan rows (§7).
- **A compromised record key** can sign anything until it is distrusted;
  records a checkpoint covers stay pinned by the checkpoint key.
- **An erasure that crashed after storing its signature**, before its entry
  was appended, leaves a signature someone with write access could complete
  (the entry rebuilt, its timestamp found by trial, the content deleted),
  giving a clean `erased`. That only finishes an erasure the operator began.

### 9.4 Verifying record signatures

The verifier decides whether record signatures are required, never the folder.

- **Given record trust** (trusted record public keys, separate from the
  checkpoint keys), EVERY entry MUST carry a valid signature, whatever the
  folder says. For each entry: its signature row; the key its row names, which
  MUST be one the verifier trusts **and** have exactly that key id; and the
  envelope rebuilt **from the entry as stored**, including its own stored
  `previous_hash`. Failures are reported per kind, each once per chain with its
  count and the first entry id of this sink's shape (never a crafted id):
  *no record signature*, *a malformed row*, *a key not trusted for records*,
  *BAD: the stored entry is not what was signed*.
- **Without record trust**, signatures are not checked, and a sink that signs
  MUST be reported as such (`Record signatures: NOT CHECKED`): not a failure,
  and never presented as verified.
- **Orphan rows** (a signature matching no entry of its chain: a crash or a
  failed cleanup) are counted as a note, not a problem: a folder cannot tell
  them from a crash. See §9.3 for why that is not the same as harmless.
  `proof sink repair` removes them (§7).
- **R6.** A chain ending with a genuine erasure counts as `erased` without a
  checkpoint when the erasure entry's own record signature verified under the
  record trust given AND the chain has no problem at all (content and nonces
  gone, index, nothing pending, every signature valid). The signature stands
  in for the checkpoint's coverage only; it never establishes deletion.
