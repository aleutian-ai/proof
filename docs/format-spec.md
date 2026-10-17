# AleutianChain format specification

**Status:** normative for what it covers · **Audience:** anyone implementing a
verifier in any language

**Covered here:** chain hash **v4** (the current format, written by
`proof commit`), **v3** and **v2** (frozen: verified forever, never written by
this project after v0.5.0; §2.6), capture leaf v3, salted commitments, and
**anchors**: the canonical form of every version, the anchor chain hash, the
ML-DSA-65 signature, and key ids.

Three implementations agree on everything here: Go (the reference) and the
Python and JavaScript verification SDKs. The conformance vectors in §10 are
computed by scripts, independently of all three, with the exceptions §10 lists.

This document exists because of a specific failure. The rule about tombstones in
§5 previously lived in exactly one implementation's source comments. Three
independently written SDKs — Go, Python, JavaScript — got it wrong the same way,
and each shipped a verifier that reported intact chains as broken. None of their
authors did anything unreasonable; the rule was simply not written anywhere they
could find it.

**If you are implementing a verifier, §2.0, §2.5, §5, §6 and §9.2 are the
parts you cannot infer.**

---

## 1. Notation

- `‖` is byte concatenation.
- `SHA-512` is FIPS 180-4, output as **128 lowercase hex characters** unless
  stated otherwise.
- Hex is always lowercase. An uppercase digest is invalid, not equivalent.
- "Empty" means the zero-length string, which is distinct from absent.

---

## 2. Chain hash

Each entry's hash covers its predecessor's, which is what makes the chain
tamper-evident. There are three formats. **Each entry declares its own** (§2.2).
One chain may contain v2 and v3 entries, and may continue in v4 (§2.5), but
never goes back from v4.

### 2.0 v4 — the current format

v4 separates what links the chain from what erasure removes. Each entry has a
**leaf hash**, a salted commitment to the entry's id, type and content hash, and
the chain links through the leaf hash. Erasure removes the salt and those three
fields and keeps the leaf hash (§5.0), so every link of a v4 chain is
recomputed by a verifier, erased entries included.

```
leaf_hash = SHA-512(
    "aleutian.chain.leaf.v4:"
    ‖ len(entry_id)   ‖ entry_id
    ‖ len(entry_type) ‖ entry_type
    ‖ content_hash
    ‖ salt
)

chain_hash = SHA-512(
    "aleutian.chain.v4:"
    ‖ previous_hash  ‖ "|"
    ‖ global_seq     ‖ "|"
    ‖ timestamp      ‖ "|"
    ‖ leaf_hash
)
```

| Field | Encoding | Notes |
|---|---|---|
| `entry_id` | UTF-8 bytes **as stored**, 1 to 256 bytes | no control characters (U+0000 to U+001F, U+007F); not normalised |
| `entry_type` | as `entry_id` | `tombstone` is refused (below) |
| `len(x)` | 4-byte big-endian count of the bytes of `x` | the length prefix of §6.1, without its NFC step |
| `content_hash` | 128 lowercase hex characters | always; v4 has no tombstone value |
| `salt` | 64 lowercase hex characters | 32 bytes from a cryptographically secure random source, fresh for every entry |
| `leaf_hash` | 128 lowercase hex characters | the hex text is what `chain_hash` hashes |
| `previous_hash` | 128 lowercase hex, **or empty** for the first entry | see §3 |
| `global_seq` | as v3 (§2.1) | **0** for the first entry of a chain |
| `timestamp` | as v3 (§4) | |

- **The salt is minted by the writer** that links the entry, never supplied by
  the caller, so that two entries never share one and a caller cannot choose
  one that makes a leaf guessable. Disclosing an entry's salt discloses nothing
  about any other entry.
- `entry_id` and `entry_type` are hashed exactly as stored. An implementation
  MUST NOT normalise them (NFC or otherwise) before hashing: two spellings that
  hash the same would be a field an editor can change without detection, the
  same reason §4 fixes one timestamp spelling. They are length-prefixed, so `|`
  and every other printable character are allowed in them.
- The chain hash preimage has the shape of v3's with `content_hash` replaced by
  `leaf_hash`, which is fixed-shape, so §3's rule (validate `previous_hash`)
  is again the only one that keeps the boundaries recoverable.
- **The first entry.** An entry whose `previous_hash` is empty has `global_seq`
  0, and an entry whose `previous_hash` is not empty has `global_seq` above 0.
  A v4 entries file therefore says by itself whether it starts at the chain's
  first entry or is a segment: it is a segment exactly when its first entry's
  `global_seq` is above 0. A verifier walking a segment from nothing (no
  predecessor hash supplied) reports this rule's break, `invalid_field`, on the
  first entry, and so does one given a predecessor hash for an entry at 0.
  (v2 and v3 fix no first `global_seq`; §5.5.)
- **Run fields.** v4 entries carry no `run_id` and no `sequence_num`: those
  members are absent, not zero. A v4 entry carrying either, with any value, is
  `format_field_misuse`.
- **No tombstones.** A v4 entry with `entry_type` `tombstone`, or an `entry_id`
  starting with `tomb_`, or a `content_hash` starting with `TOMBSTONE:`, is
  `format_field_misuse`. Erasure in v4 is §5.0.

**An entry as exported.** A live entry carries every field above except
`previous_hash`, which is the chain hash of the entry before it (exports do not
repeat it), plus `format_version: 4` and its `chain_hash`. An **erased** entry
carries exactly `format_version`, `global_seq`, `timestamp`, `leaf_hash`,
`chain_hash` and `erased: true`. `entry_id`, `entry_type`, `content_hash` and
`salt` are **absent** from an erased entry, not empty, and a live entry carries
no `erased` member (`erased: false` is refused). Any other combination is
malformed (`invalid_field`).

### 2.1 v3 — frozen

```
chain_hash = SHA-512(
    "aleutian.chain.v3:"
    ‖ previous_hash  ‖ "|"
    ‖ global_seq     ‖ "|"
    ‖ timestamp      ‖ "|"
    ‖ content_hash
)
```

| Field | Encoding | Notes |
|---|---|---|
| `previous_hash` | 128 lowercase hex, **or empty** for the first entry | see §3 |
| `global_seq` | base-10 ASCII: no sign, no leading zeros, 0 ≤ n ≤ 2⁶³−1 | the entry's position **in the chain** |
| `timestamp` | `YYYY-MM-DDTHH:MM:SS.ffffffZ` | see §4 |
| `content_hash` | 128 lowercase hex, **or** a tombstone value (§5) | |

- `global_seq` exceeds the range a JSON number carries exactly (2⁵³). Parse it
  as a 64-bit integer. Where it travels as JSON outside an export, carry it as a
  decimal string.
- **v3 binds neither `run_id` nor `sequence_num`.** A v3 entry carrying a
  non-empty `run_id` or a non-zero `sequence_num` is **malformed**; report it as
  `format_field_misuse`, not as a hash mismatch. Exports always write
  `"run_id": ""` and `"sequence_num": 0`; those zero values are structural, not
  misuse.
- v3 is **batch-independent**: the same entries in the same order produce the
  same hashes however they were grouped into commits. (v2 is not; see §2.4.)

### 2.2 Which format an entry uses

An entry's `format_version` is `4`, `3` or `2`. Exports **omit** the field for
v2 entries, because v2 entries were written before it existed. A verifier
reading an entry with no `format_version` therefore treats it as v2. That
describes existing data, not a default a writer may rely on: every v3 writer
emits `3`, and `format_version: 4` is **required** on every v4 entry and never
omitted. Any other value is an unknown format. Report it as such; never guess.

Members that belong to another format are refused, not ignored: `salt`,
`leaf_hash` or `erased` on a v2 or v3 entry, or `run_id` or `sequence_num` on a
v4 entry, is `format_field_misuse`.

### 2.3 v2 — frozen

```
chain_hash = SHA-512(
    "aleutian.chain.v2:"
    ‖ previous_hash  ‖ "|"
    ‖ run_id         ‖ "|"
    ‖ sequence_num   ‖ "|"
    ‖ timestamp      ‖ "|"
    ‖ content_hash
)
```

| Field | Encoding | Notes |
|---|---|---|
| `previous_hash` | 128 lowercase hex, **or empty** for the first entry | see §3 |
| `run_id` | UTF-8, no `\|` | identifies the batch that linked the entry |
| `sequence_num` | base-10 ASCII, non-negative | position **within the run**, not chain-wide |
| `timestamp` | `YYYY-MM-DDTHH:MM:SS.ffffffZ` | see §4 |
| `content_hash` | 128 lowercase hex, **or** a tombstone value (§5) | |

`v2` denotes SHA-512; v1 used SHA-256 and is not supported. **`global_seq` is NOT
part of the v2 preimage.** Ordering is protected by the previous-hash linkage. A
verifier may check `global_seq` for gaps, but must not hash it.

### 2.4 v2: batch grouping is part of the artefact

`run_id` and `sequence_num` are both preimage fields, and both describe the
*batch* an entry was linked in rather than the entry itself. The consequence is
easy to miss and expensive to discover later:

> **The same entries, in the same order, produce different hashes depending on
> how they were grouped into append calls.**

```
append(A, B)             A: run1 / seq 0     B: run1 / seq 1
append(A); append(B)     A: run1 / seq 0     B: run2 / seq 0   ← B's hash differs
```

Both chains are valid and both verify. They are simply different chains.

Two rules follow, and neither is optional:

1. **A chain cannot be reconstructed from its entries.** Re-linking an exported
   chain does not reproduce it, because the original `run_id` values and batch
   boundaries are not derivable from the entry contents. Preserve exports.
2. **Loading an existing chain is not appending.** An importer must write
   `run_id` and `sequence_num` through unchanged and verify the hashes it was
   given. An importer that re-links has destroyed the artefact it was asked to
   carry, and will do so silently — the result verifies.

Implementations must not "helpfully" renumber, regroup, or re-link on import.

### 2.5 Continuing a v2 or v3 chain in v4

A v2 or v3 chain is never rewritten: its hashes are signed into anchors, and a
migration that recomputed them would destroy the evidence it was asked to keep.
It is **continued** instead. The next entry written to it is v4 and links from
the existing head like any other entry:

```
  … ── v3 e(k−1) ── v3 e(k) ── v4 e(k+1) ── v4 e(k+2) ── …
                        │           │
                        │           previous_hash = e(k).chain_hash
                        │           global_seq    = e(k).global_seq + 1
                        last v3 entry
```

- From the first v4 entry on, every entry is v4. **A v2 or v3 entry after a v4
  entry is `format_field_misuse`.** This rule is load-bearing, not tidiness: a
  v3 tombstone's chain hash is taken as stored (§5.1), so a v3 tombstone
  appended after v4 entries would make every entry before it unlinked again.
- The v4 entries are fully linked and recomputed (§2.0). The v2 and v3 prefix
  keeps exactly the guarantee it had: if it contains a tombstone, the entries up
  to the last tombstone are reported as not bound (§5.5), and nothing after it.
- The first v4 entry of a continued chain has a `previous_hash`, so the "first
  entry" rule of §2.0 does not apply to it; it applies only to an entry with an
  empty `previous_hash`, which in a continued chain is a v2 or v3 entry.
- There is no migration tool, and there must not be one.

### 2.6 v2 and v3 are frozen

v2 and v3 are verified by this project forever and never written by it after
v0.5.0. Their known weaknesses (§2.4 and §5.5, and that v2 does not hash
`global_seq`) are permanent properties of those formats, not defects awaiting a
fix: fixing them would mean rewriting signed history. The remedy is §2.5. Their
conformance vectors will never change.

---

## 3. Delimiter safety — the non-obvious part

The preimage is `|`-delimited and **is not self-delimiting**. Field boundaries
are recoverable only because every field except `run_id` has a fixed shape.

If `previous_hash` is not validated, two different entries produce **the same
hash**:

```
previous_hash = "abc|d"   run_id = "ef"     ─┐
                                             ├─►  "…:abc|d|ef|0|<ts>|<content>"
previous_hash = "abc"     run_id = "d|ef"   ─┘     identical preimage
```

Note which rule prevents this. **Banning `|` in `run_id` does not** — with a
well-formed `previous_hash`, pipes inside `run_id` are harmless, because
`sequence_num`, `timestamp` and `content_hash` are all fixed-shape and the
boundaries are recoverable from the right.

> **The load-bearing rule: `previous_hash` MUST be empty or exactly 128
> lowercase hex characters.** Validate it before hashing.

The rule is the same for v3 and v4. Their other fields are all fixed-shape (v4's
free-form fields are length-prefixed inside the leaf hash), so an unvalidated
`previous_hash` is again the one way to shift a boundary.

A producer that controls its own inputs is safe by provenance. A **library** is
not — it hashes whatever a caller passes.

---

## 4. Timestamps

Formatted with **microsecond** precision:

```
YYYY-MM-DDTHH:MM:SS.ffffffZ        e.g. 2026-01-20T12:00:01.123456Z
```

- Always UTC, always the literal `Z`.
- Always exactly six fractional digits, zero-padded.
- Sub-microsecond precision is **truncated, not rounded**.
- All components are zero-padded to fixed width.

**Never route a timestamp through a millisecond representation before hashing.**
`123456µs` and `123000µs` produce different hashes for what is logically the same
entry, and the failure appears much later as an unverifiable chain rather than as
an error at the point of the mistake.

Store the timestamp as exactly the string that was hashed. A verifier MUST
report an entry whose stored `timestamp` is any other spelling of the instant
(an offset such as `+05:30`, no fractional digits, more than six) as a break,
`invalid_timestamp`: the hash covers one spelling, and a second one that hashes
the same is a field an editor can change without detection.

The year is `0000` to `9999`. A timestamp outside that range has no
four-digit form and MUST be refused by a producer.

---

## 5. Erasure

### 5.0 v4: the salt and the fields go, the leaf hash stays

Erasing a v4 entry deletes its `entry_id`, `entry_type`, `content_hash` and
`salt`, and keeps `global_seq`, `timestamp`, `leaf_hash` and `chain_hash`. The
entry is marked `erased: true` (§2.0). Nothing else in the chain changes.

A verifier treats an erased entry like a live one, except that it cannot
recompute the leaf hash: it checks that `leaf_hash` is 128 lowercase hex,
recomputes `chain_hash` from `previous_hash`, `global_seq`, `timestamp` and the
stored `leaf_hash`, and compares. There is no branch that takes a stored chain
hash on trust.

```
    for each v4 entry:
        if entry.erased:
            leaf = entry.leaf_hash                         ← checked for shape only
        else:
            leaf = compute_leaf_hash(entry_id, entry_type, content_hash, salt)
            if leaf != entry.leaf_hash:  report a break
        expected = compute_chain_hash_v4(previous_hash, global_seq, timestamp, leaf)
        if expected != entry.chain_hash:  report a break
        previous_hash = expected
```

A live entry whose recomputed leaf hash differs from its stored `leaf_hash` is
`hash_mismatch`, and the walk continues from the chain hash the **recomputed**
leaf gives, as a v3 walk continues from the expected chain hash after a
mismatch.

What this gives, and why each property holds:

- **Every link is checked.** Changing anything before an erased entry changes
  the `previous_hash` it is recomputed from, so its chain hash, and the head an
  anchor signed, change. (v3's hole, §5.5, does not exist in v4.)
- **Erasure does not break anchors.** The leaf hash, the chain hash, the count
  and the sequence numbers all survive erasure, and v7 anchors name their range
  by sequence (§9), so an anchor over an erased entry still binds, whichever
  entry of its range was erased.
- **The erased content cannot be correlated.** `leaf_hash` is a salted
  commitment: without the salt, someone who holds the original entry (its id,
  type and content) cannot confirm that it was the entry at this position,
  because they cannot recompute the leaf. This is the property v3's random
  tombstone value and new id (§5.4) exist for, kept without either. Only once
  every copy of the salt is gone (backups, replicas, anyone the entry was
  disclosed to) is that true; §8's paragraph on erasure applies to the salt in
  the same way.
- **Nothing maps the old id.** The erased entry carries no id, so the original
  id cannot resolve to it.

What it does not give: **an erasure is not authenticated by the chain.**
Whoever can write the store can erase a live entry, and the result is
indistinguishable from a lawful erasure: the chain stays intact and the anchor
stays bound. It proves an entry existed at that position, not why its content
is gone. Who may erase is decided outside the chain (in the sink, by a signed
erasure record; sink-format.md).

v4 has no tombstone. §5.1 to §5.5 apply to v2 and v3 only.

### Tombstones (v2 and v3) — the rule most likely to be got wrong

When an entry's content is erased, the entry **stays in place**. Its
`content_hash` is replaced, its `entry_type` becomes `tombstone` and its
`entry_id` is replaced (§5.4); `chain_hash`, `global_seq` and `timestamp` are
unchanged.

```
content_hash = "TOMBSTONE:" ‖ 64 lowercase hex characters      (74 chars total)
```

The 64 hex characters are **32 cryptographically random bytes**. They are *not* a
hash of anything, so nothing can recompute or correlate them.

An entry is a tombstone when **both** hold:
- `entry_type == "tombstone"`
- `entry_id` starts with `tomb_`

### 5.1 The rule

> **A tombstone RETAINS the original entry's `chain_hash`.**
>
> That hash was computed from the entry's real `content_hash` before erasure, so
> it is **not reproducible from the fields of a tombstoned row**.
>
> **A verifier MUST NOT recompute a tombstone's chain hash.** Validate the
> content-hash format, then advance using the STORED value — subsequent entries
> were chained against it.

```
    for each entry:
        if is_tombstone(entry):
            validate_tombstone_format(entry.content_hash)
            previous_hash = entry.chain_hash          ← stored, not recomputed
            continue
        expected = compute_chain_hash(previous_hash, …, entry.content_hash)
        if expected != entry.chain_hash:  report a break
        previous_hash = expected
```

### 5.2 Why it is designed this way

The obvious-looking alternative — recompute the tombstone's hash from its new
content — breaks two things:

1. Every entry after it, since they were chained against the original value.
2. **Every anchor covering that range**, because anchors sign the chain hash.

(2) is the decisive one: it would mean **exercising a right to erasure destroys
the proof that the data ever existed.** Preserving the hash is what keeps erasure
and provability compatible.

### 5.3 The failure mode if you get it wrong

A verifier that recomputes reports `hash_mismatch` on every erased entry:

```
stored chain_hash (from the real content) : 6159692d235ae316f6535340fd5c2ffc…
recomputed        (from TOMBSTONE:…)      : c18a56d4db9b6558ccdf7baf70a8b77f…
```

A customer who exercised a deletion right is told their audit chain is broken —
precisely when they are demonstrating that they honoured it.

### 5.4 Erased entry identifiers

Erasure assigns a **new** `entry_id` (`tomb_` + a fresh UUID). The original id
ceases to exist and MUST NOT resolve.

Keeping it alive would let anyone holding the old id look it up, receive the
tombstone, and confirm that *that specific entry* was erased — defeating the
anti-correlation property the random content hash exists to provide.

### 5.5 What a verifier checks on every entry, and what a tombstone leaves unchecked

One rule decides whether an entry is a tombstone, in every code path: the two
conditions above (`entry_type` and the `tomb_` prefix). A `content_hash` that
begins `TOMBSTONE:` on an entry of any other type does **not** make it one; that
entry is recomputed like any other and reports `hash_mismatch`.

Before recomputing, a verifier MUST check the shape of what it was given, and
report a break (`invalid_field`, or `invalid_timestamp` for the timestamp) when:

- `chain_hash` is not 128 lowercase hex characters, on any entry, tombstones
  included;
- `content_hash` is neither 128 lowercase hex characters nor a well-formed
  tombstone value;
- `global_seq` is negative, or (v2) `sequence_num` is negative or `run_id` is
  empty;
- `timestamp` is not exactly the form in §4;
- (v4) `leaf_hash` is not 128 lowercase hex, `salt` is not 64 lowercase hex,
  `entry_id` or `entry_type` is empty, longer than 256 bytes, not valid UTF-8
  or contains a control character, or the members present are not one of the
  two shapes of §2.0.

A hash recomputed over malformed fields can equal the stored one, so the shape
is checked on its own and not left to the comparison.

**Which break is reported first.** One entry can fail several checks; a
verifier reports them in this order, so that the first break of a result is
the same in every implementation:

1. `sequence_gap`: `global_seq` is not the previous entry's plus one;
2. `invalid_field`: `chain_hash` is not 128 lowercase hex;
3. `format_field_misuse`: a v2 or v3 entry after a v4 entry (§2.5), a v4
   member on a v2 or v3 entry (§2.2), or a v4 entry with run fields or a
   tombstone shape (§2.0);
4. (v2 and v3) a tombstone's own checks, and then nothing else;
5. `invalid_timestamp`;
6. the declared format: `unknown_format`, or a v3 entry with run fields,
   `format_field_misuse` (§2.1);
7. `invalid_field`: the field shapes above, and for v4 the two entry shapes and
   the first-entry rule of §2.0;
8. `hash_mismatch`: for v4 the leaf hash first, then the chain hash.

After a break in steps 2 to 7 the walk continues from the entry's stored
chain hash, so the next entry is judged on its own.

**What a result counts.** An entry is counted only once it passes step 2 (its
`chain_hash` is in shape). `tombstones_found` then counts the entries read as
tombstones (both conditions of §5, and not refused at step 3), whatever their
declared format and whatever else is wrong with them; `last_tombstone` is the
last one's index. `erased_found` counts the v4 entries carrying `erased: true`,
whatever else is wrong with them. Both count every entry walked, including
entries after the first break.

`global_seq` in an entries file is a JSON number, read as a 64-bit integer; any
other JSON type makes the file not entries, an error rather than a break.

v2 and v3 do not fix the first `global_seq`: this module's linker starts a
chain at 0 and the hosted platform's at 1. A verifier MUST NOT treat either as
a break in a v2 or v3 chain. (v4 fixes it: §2.0.) `global_seq` must still rise
by one from each entry to the next, in every format.

**The limitation.** A tombstone's chain hash is taken as stored, so nothing
links the entries before a tombstone to the entries after it. Whoever can write
the store can replace every entry before a tombstone, and can turn an entry
into a tombstone to do so, because `entry_type` and `entry_id` are in no hash.
A verifier cannot detect this. It MUST report how many entries a result leaves
exposed (every entry up to and including the last tombstone) and MUST NOT
describe those entries as verified or as bound by an anchor. See
verification-model.md, "What a tombstone leaves unverified".

This is a permanent property of v2 and v3 (§2.6). A chain stops accumulating
exposure the moment it continues in v4 (§2.5): no tombstone can follow a v4
entry.

---

## 6. Capture leaf (`capture.request.v3`)

A leaf is canonicalised to a length-prefixed TLV byte string, then hashed.

```
content_hash = SHA-512("aleutian.chain.entry.v3:" ‖ canonical_bytes)
```

### 6.1 Encoding primitives

| Type | Encoding |
|---|---|
| string | NFC-normalise → 4-byte big-endian **byte** length → the UTF-8 bytes |
| u64 | 8-byte big-endian |
| bool | as u64 `0` or `1` |

The length prefix counts **bytes after NFC normalisation**, not characters and
not UTF-16 units. Cap: 256 bytes per field, post-NFC.

### 6.2 Field order

Exactly 19 records — 4 header, then 15 body — each alphabetical:

```
HEADER   subject · entry_type · signing_key_id · timestamp_ms(u64)
         └── was `company_id` until 2026-09-23. The canonical form encodes
             VALUES positionally and never writes a key name, so the rename
             changed no byte and the ORDER still follows the old names.

BODY     capture_method · content_hash · dlp · encryption_mode · model ·
         pii_action · pii_categories · pii_detected(bool) ·
         pii_digest_key_version · processing_mode · provider · region ·
         source_type · trust_level · user_id
```

Total canonical form: **maximum 4096 bytes**. Per-field caps do not bound the
sum, so this is a separate check — enforce it on both encode and verify.

### 6.3 Validation

All fields EXCEPT `subject` are ASCII-restricted by regex. NFC normalisation is
therefore not a no-op: a subject may carry free text, and a producer and a
verifier that normalise differently would disagree about every hash.

- `subject` — any non-empty string within the shared field rules (≤256 bytes,
  no control bytes, no `|`). It names the namespace the entry belongs to: a
  hostname, a project, an account, an opaque id. It is hashed in, so an entry
  cannot be replayed into a chain with a different subject — but nothing
  authenticates it, so it separates namespaces rather than proving one.
  Until 2026-09-23 this was `company_id` and had to match
  `^comp_[0-9A-HJKMNP-TV-Z]{26}$`, a private platform's tenant scheme; that
  value is still a valid subject, and the old JSON key is still read.
- `signing_key_id` — `^[A-Za-z0-9_./-]{1,128}$`
- `content_hash`, `user_id` — `^[0-9a-f]{128}$`
- `encryption_mode` ∈ {`zero-knowledge`, `aleutian-managed`, `cmek`}
- `processing_mode` ∈ {`zk`, `pii_inspection`}
- `pii_action` ∈ {`none`, `flagged`, `blocked`, `redacted`}
- `timestamp_ms` positive, below the year-2200 ceiling (`7258118400000`)

**The zk invariant:** when `processing_mode == "zk"`, the compliance surface must
be empty — `pii_detected` false, `pii_action` `"none"`, and `pii_categories`,
`dlp` both empty. An entry violating this is rejected at encode time, because a
zero-knowledge record that carries inspection findings is a contradiction.

---

## 7. Merkle trees

RFC 9162. Leaf and interior hashes are domain-separated, so a leaf can never be
reinterpreted as an interior node — the classic second-preimage attack on naive
Merkle constructions.

Leaves are the **raw decoded bytes** of each `content_hash`, not its hex text.
Hex-decode before leaf-hashing, or your roots will differ from everyone else's.

---

## 8. Salted commitments

`content_hash` is public. When content is committed **unencrypted** and has low
entropy, a plain SHA-512 can be guessed: hash `consent: yes` and `consent: no`
and see which matches. A salted commitment prevents this without any shared
secret:

```
commitment = SHA-512( "aleutian.commit.v1:" ‖ nonce ‖ SHA-512(content) )
```

- `nonce` is **exactly 32 bytes** from a cryptographically secure random source,
  **fresh for every item**. A nonce of any other length MUST be refused, not
  hashed. Nonces MUST NOT be reused or derived (e.g. from a key and an id):
  disclosing one item would then expose the other to guessing, and identical
  content under one nonce yields identical, linkable commitments.
- The content is hashed **first**, so the outer input is always exactly 115 bytes
  (19-byte domain + 32-byte nonce + 64-byte digest). That makes it unambiguous,
  and it closes length extension: with `SHA-512(domain ‖ nonce ‖ content)`,
  anyone could derive a second commitment from a public one without the nonce,
  publish it, and — after the first item is disclosed — open it to that content
  plus appended bytes, falsely claiming to have committed first.
- The result is 128 lowercase hex characters, used directly as the entry's
  `content_hash`. Comparison is exact: an uppercase commitment does not match.
  The chain hash is computed over it like any other `content_hash`; **nothing in
  §2 changes.**
- **Plain hash or commitment is not visible on the chain.** A verifier MUST learn
  which an entry is from outside the chain — its entry type, or the disclosure.
- **Disclosure** of one item reveals its content and nonce. Anyone recomputes the
  commitment and compares it to the chain entry. No other item's content is
  revealed, but the disclosed content becomes tied to that entry's timestamp and
  position.
- **Erasure** destroys an item's content and nonce. Only once EVERY copy of the
  nonce is gone — backups, replicas, and anyone it was disclosed to — can the
  commitment no longer be opened or tied to the content; the chain still
  verifies. If any copy survives, the item is pseudonymised, not erased. Entry
  metadata (entry id, type) MUST carry no subject identifiers, or erasing the
  content erases nothing.
- Content encrypted with **randomized** encryption (fresh nonce/IV per item, as
  HPKE does) does not need this: commit the ciphertext's plain SHA-512.
  Deterministic encryption (e.g. AES-SIV with a fixed nonce) leaks equality and
  needs a salted commitment too.

A keyed hash (one HMAC key for all items) was rejected: disclosing a single item
would require revealing the key, exposing every other item to guessing. Chain
verification needs no secret under either scheme; the difference is entirely in
disclosure.

Reference implementation: `commitment` package. Vectors:
`commitment_vectors.json` (§10) — `vectors` MUST reproduce exactly, and every
`reject` case MUST fail verification.

---

## 9. Anchors

An anchor is a signed checkpoint. It commits to a chain's head, to the range of
entries it covers, and to the anchor before it, so a verifier can detect entries
**removed from the front**, which linkage alone cannot (§2).

### 9.1 Fields

| Field | Type | Meaning |
|---|---|---|
| `version` | integer | the canonical form in use (§9.2) |
| `anchor_id` | string | this anchor's id |
| `subject` (v6, v7) / `company_id` (v1–v5) | string | what the chain is about. Same value, key renamed in v6 |
| `chain_hash` | 128 lowercase hex | the **anchor** chain hash (§9.4), not the tip entry's |
| `range` | v7: `{start_seq, end_seq}`; v1–v6: `{start_entry_id, end_entry_id}` | the entries covered. v7 names them by `global_seq`, inclusive, as decimal strings (§2.1's grammar) |
| `entry_count` | v7: decimal string; v1–v6: integer | entries covered, counted from the chain's first entry. v7: exactly `end_seq − start_seq + 1` |
| `signing_key_id` | string, non-empty | the signing key. 32 lowercase hex when derived as §9.6 says; a verifier looks the id up and does not derive or check its form |
| `created_at_ms` | integer | Unix milliseconds. Advisory; order comes from the chain |
| `previous_anchor_id` | string | the anchor before this one, or the seed id (§9.4) |
| `previous_anchor_hash` | 128 lowercase hex | v7 only: the previous anchor's `chain_hash`, or the seed hash (§9.4) |
| `verified_through` | integer | v4 and v6 only: the producer verified the chain through this count. Removed in v7: it was never compared with anything |
| `signature` | base64 | §9.5. **Excluded** from the canonical form |

v7's sequence numbers and count are strings because they may exceed 2⁵³, the
largest integer a JSON number carries exactly in every language: a JavaScript
verifier that parsed them as numbers would canonicalize different bytes.

`subject` is inside the signed bytes. It can never be erased or corrected
afterwards, so it **MUST NOT** carry personal data. Use a topic or a pseudonym.

### 9.2 Canonical form: the bytes that are signed

- Compact JSON: no whitespace, keys in **strict alphabetical order**, including
  inside `range` (`end_entry_id` before `start_entry_id`; v7 `end_seq` before
  `start_seq`). `signature` is left out.
- Integers are plain decimal.
- Strings are escaped **exactly as Go's `encoding/json` does, with HTML escaping
  on**:

  | Character | Written as |
  |---|---|
  | `"` | `\"` |
  | `\` | `\\` |
  | `<` | `\u003c` |
  | `>` | `\u003e` |
  | `&` | `\u0026` |
  | U+2028 | `\u2028` |
  | U+2029 | `\u2029` |
  | U+0008, U+0009, U+000A, U+000C, U+000D | `\b`, `\t`, `\n`, `\f`, `\r` |
  | any other character below U+0020 | `\u00XX`, lowercase hex (`\u001f`) |

  These are Go 1.22 and later (proof builds with Go 1.24); Go 1.21 and earlier
  wrote `\u0008` and `\u000c` instead of `\b` and `\f`. U+007F is written as
  itself. All other non-ASCII characters are written as UTF-8, not as `\u` escapes. A
  standard JSON library in another language does **not** do this by default, and
  getting it wrong produces a valid-looking signature check that fails.
- **Dispatch on the declared `version` only.** Never infer the version from which
  fields are present: an attacker who can influence a field could otherwise
  choose a weaker form.

| Version | Fields, in canonical order | |
|---|---|---|
| 1, 2, 3 | `anchor_id`, `chain_hash`, `company_id`, `created_at_ms`, `entry_count`, `previous_anchor_id`, `range`, `signing_key_id`, `version` | 9 fields |
| 4 | as above, plus `verified_through` between `signing_key_id` and `version` | 10 fields |
| 5 | **withdrawn.** Refuse it by name; it has no canonical form, and the number is never reused | — |
| 6 | `anchor_id`, `chain_hash`, `created_at_ms`, `entry_count`, `previous_anchor_id`, `range`, `signing_key_id`, `subject`, `verified_through`, `version` | 10 fields. `subject` sorts **8th**, where `company_id` sorted 3rd |
| 7 | `anchor_id`, `chain_hash`, `created_at_ms`, `entry_count`, `previous_anchor_hash`, `previous_anchor_id`, `range` (`end_seq`, `start_seq`), `signing_key_id`, `subject`, `version` | 10 fields. `previous_anchor_hash` sorts before `previous_anchor_id`; `entry_count`, `end_seq` and `start_seq` are JSON **strings** |

Any other version: refuse. Never canonicalize it as the closest known form.

A v7 anchor, canonical (wrapped here for width; the real bytes have no
whitespace):

```
{"anchor_id":"anchor_…","chain_hash":"<128 hex>","created_at_ms":1760000000000,
 "entry_count":"3","previous_anchor_hash":"<128 hex>","previous_anchor_id":"anchor_00000000-0000-0000-0000-000000000000",
 "range":{"end_seq":"2","start_seq":"0"},"signing_key_id":"<32 hex>","subject":"orders","version":7}
```

### 9.3 Version invariants: check them before canonicalizing

| Version | Must hold |
|---|---|
| 1–3 | `verified_through` = 0 |
| 4 | `verified_through` > 0 |
| 5 | refused |
| 6 | `verified_through` > 0 **and** `subject` non-empty |
| 7 | `subject` non-empty; `start_seq`, `end_seq` and `entry_count` in §2.1's decimal grammar; `start_seq ≤ end_seq`; `entry_count = end_seq − start_seq + 1`; `previous_anchor_hash` 128 lowercase hex; `previous_anchor_id` is the seed id **exactly when** `previous_anchor_hash` is the seed hash |

`version` is inside the signed bytes, so an anchor that breaks its invariants
carries a valid signature over malformed content. Report it as malformed, not as
tampering.

### 9.4 Anchor chain hash

```
chain_hash = SHA-512(
    "aleutian.anchor.v2:"
    ‖ previous_anchor_hash ‖ "|"
    ‖ subject              ‖ "|"
    ‖ start_entry_id       ‖ "|"
    ‖ end_entry_id         ‖ "|"
    ‖ tip_chain_hash
)
```

- `previous_anchor_hash` is the previous anchor's `chain_hash`. For the **first**
  anchor it is the seed hash, `SHA-512("aleutian.anchor.seed.v2")` =
  `03443d96d3b369839f63f98b712463efba04c00551822743108d60c5f291627859ff0b7dc29f99e3c847b07b0b18bb385426c744847c1b070563f8dd07271f27`,
  and that anchor's `previous_anchor_id` is the seed id
  `anchor_00000000-0000-0000-0000-000000000000`.
- `subject` is the `company_id` value for v1–v5. The position is the same.
- `tip_chain_hash` is the chain hash (§2) of the entry at `end_entry_id`.
- The result is **not** the tip entry's chain hash. Recompute it and compare it;
  never byte-compare it with the tip.
- The preimage is not self-delimiting (§3). Its fields must not contain `|`.

**v7** has its own preimage, which names the range by sequence and
length-prefixes the subject:

```
chain_hash = SHA-512(
    "aleutian.anchor.v7:"
    ‖ previous_anchor_hash ‖ "|"
    ‖ len(subject) ‖ subject ‖ "|"
    ‖ start_seq            ‖ "|"
    ‖ end_seq              ‖ "|"
    ‖ tip_chain_hash
)
```

- `len` is the 4-byte big-endian byte count of §2.0; the subject is hashed as
  its UTF-8 bytes, not normalised, so it may contain `|`. Every other field is
  fixed-shape or a decimal number.
- `previous_anchor_hash` is the anchor's own `previous_anchor_hash` member: a
  v7 anchor carries its predecessor's hash in its signed bytes, so a verifier
  needs no second file to bind it. The seed hash is the same value as above.
- `tip_chain_hash` is the chain hash of the entry at `end_seq`. An erased v4
  entry keeps its chain hash (§5.0), so erasing any entry of the range,
  including the first or the last, changes nothing this hash covers.

### 9.5 Signature

- **ML-DSA-65** (FIPS 204), in pure mode (not HashML-DSA), over the canonical
  bytes of §9.2.
- The **context string** (FIPS 204's `ctx`) is `aleutian.proof.anchor.v7`
  (24 ASCII bytes) for v7, and **empty** for v1 to v6. The context is part of
  what is signed: a v7 signature does not verify with an empty context, and a
  signature made by the same key in another protocol, with another context or
  none, never verifies as a v7 anchor. The verifier chooses the context from
  the declared `version`, never from the signature.
- The signature is 3309 bytes, written as standard base64 with padding. The
  public key is 1952 bytes.
- A verifier MUST refuse any other spelling of the signature: a line break
  inside it, missing padding, or non-zero trailing bits.

### 9.6 Key ids

- **ML-DSA** (and ML-KEM) keys: the first 16 bytes of
  `SHA-512("proof.keyid.v1:" ‖ SubjectPublicKeyInfo DER)`, as 32 lowercase hex.
  The SPKI follows RFC 9881: its AlgorithmIdentifier is the algorithm OID with
  **parameters absent**, and its BIT STRING holds the raw public key.
- **X-Wing** keys, a legacy rule: the first 16 bytes of `SHA-512(raw public key)`,
  with no domain string.

A key id only names a key. **Whether to trust that key is the verifier's
decision.** This format ships no trust store.

### 9.7 Verifying an anchor

1. Check the version invariants (§9.3).
2. Look up the key by `signing_key_id`. An unknown key is its own error, not a
   bad signature.
3. Decode the signature and check its length before running any cryptography.
4. Verify the signature over the canonical bytes (§9.2).

To **bind** an anchor to a chain, recompute §9.4 over the entries it covered, as
the chain was when it was signed: entries `0 … entry_count−1`, not entries added
since. Use the previous anchor's `chain_hash`, or the seed hash for the first
anchor.

To bind a **v7** anchor, refuse as errors, with no outcome: an anchor that
breaks §9.3 or §9.8, and entries walked from a predecessor hash (a segment;
§9.8). Then check, in this order; the first that fails is the outcome:

1. **The chain.** Walk every entry as §5.5 says. Any break: `chain_broken`.
2. **The start.** The first entry's `global_seq` must be `start_seq`:
   otherwise `range_start_mismatch`. (The first entry of a walk that is not a
   segment is the chain's first entry.)
3. **The end.** There must be an entry whose `global_seq` is `end_seq`:
   otherwise `height_mismatch`, because the anchor covers entries the verifier
   was not given. Its chain hash is the tip. Entries after it are not the
   anchor's concern; a chain that has grown since still binds.
4. **The predecessor.** If the caller expected a predecessor hash, the
   anchor's `previous_anchor_hash` must equal it: otherwise
   `predecessor_mismatch`.
5. **The subject.** If the caller expected a subject, the anchor's `subject`
   must equal it, byte for byte: otherwise `tenant_mismatch`.
6. **The head.** Recompute §9.4 with the anchor's own `previous_anchor_hash`
   and the tip, and compare with its `chain_hash`: otherwise `head_mismatch`.
   All six passed: `bound`.

A verifier that was given no expected subject MUST say in its result that the
subject was not checked: the signature proves who signed the anchor, not that
it is about the chain the reader meant. A bound result also reports
`entries_not_bound`: the entries up to and including the last v2 or v3
tombstone at or before `end_seq` (its index plus one), or 0. The signature
(§9.5) is checked whatever the bind found.

### 9.8 What a verifier refuses

**Parsing.** An anchor is read strictly: only the member names of §9.1, spelled
exactly, each at most once; `range` likewise. The subject is under the name its
version uses (`subject` from v6, `company_id` before), and an anchor carrying
the other name, or both, is refused. A lenient parser accepts members the
signature does not cover and lets two readers see two different anchors.

**Counts** (v4 and v6). `entry_count ≥ 1`, `0 < verified_through ≤ entry_count`,
`created_at_ms ≥ 0`. (v7: §9.3, and `created_at_ms ≥ 0`.)

**The wrong range shape.** A v7 anchor whose `range` carries
`start_entry_id` or `end_entry_id`, or a v1 to v6 anchor whose `range` carries
`start_seq` or `end_seq`, is refused. So is a v7 anchor carrying
`verified_through`, or one without `previous_anchor_hash`.

**Key id.** An anchor with an empty `signing_key_id` is refused, and a key
source holds no key under the empty id. A key id is otherwise whatever the key's
holder assigned (§9.6): a verifier looks it up and does not derive it.

**The predecessor, named twice.** `previous_anchor_id` is the seed id exactly
when the predecessor hash used in §9.4 is the seed hash. Disagreement is
`predecessor_mismatch`, not a bind. (v7 carries both in the anchor, so there
the disagreement is a §9.3 invariant, refused as malformed.)

**v7 members.** Every member of §9.1 for v7 is required, `signature`
included, and each is read with the JSON type the canonical form gives it:
`version` and `created_at_ms` as JSON integers with no fraction or exponent,
`entry_count`, `start_seq` and `end_seq` as strings, everything else as a
string. Its `chain_hash` is 128 lowercase hex, or the anchor is malformed.

**A segment.** `entry_count` is counted from the chain's first entry. A verifier
MUST NOT bind an anchor to entries it verified from a predecessor hash, and a
producer MUST NOT build one over them.

**A series.** Several anchors over one chain are a series, oldest first, and a
verifier given more than one checks all of:

- every anchor is for the same subject;
- the first names the seed id; each later one names the `anchor_id` of the one
  before and binds with that anchor's `chain_hash` (v7: its
  `previous_anchor_hash` equals that anchor's `chain_hash`);
- `entry_count` strictly rises;
- `created_at_ms` does not fall;
- each binds to the prefix of its own length and its signature verifies.

The first failure ends the check: later anchors are not judged against a
predecessor that did not verify. A series cannot show that it is complete; an
anchor deleted from its end leaves a shorter series that verifies.

---

## 10. Test vectors

(Sink export bundles, built on this format, have their own normative spec and
vectors: `bundle-format.md` and `bundle_v1_vectors.json`.)


`fixtures/testdata/` carries the cross-language golden vectors. Reproduce them
exactly, or your implementation is not compatible. `fixtures/MANIFEST.json`
records each file's SHA-256, so a vendored copy that drifts is detectable.

| File | Covers |
|---|---|
| `chain_v4_vectors.json` | chain hash and leaf hash v4 (§2.0): first entry, linked, continued from a v3 head (§2.5), erased (§5.0), non-ASCII and `\|` in ids, and cases that MUST be refused |
| `anchor_v7_canonical_vectors.json` | anchor v7 canonical bytes (§9.2), chain hash (§9.4) and signatures with the v7 context (§9.5), and anchors that MUST be refused |
| `chain_v3_vectors.json` | chain hash v3 (§2.1): first, linked, `global_seq` above 2⁵³ and at 2⁶³−1, tombstone, sub-microsecond truncation, and cases that MUST be refused |
| `chain_vectors.json` | chain hash v2 (§2.3): genesis, linked, tombstone |
| `anchor_v6_canonical_vectors.json` | anchor v6 canonical bytes (§9.2), incl. HTML escaping, U+2028/U+2029, non-ASCII, quote and backslash |
| `anchor_v4_canonical_vectors.json` | anchor canonical bytes for v1, v3 and v4 (§9.2) |
| `anchor_chain_hash_vectors.json` | anchor chain hash (§9.4) |
| `keyid_vectors.json` | key ids (§9.6), incl. the ML-DSA-65 SPKI DER |
| `v3_golden_capture_request.json` | leaf canonical bytes + content hash (§6) |
| `merkle_golden.json` | roots, inclusion, consistency (§7) |
| `commitment_vectors.json` | salted commitments (§8), incl. multi-block content and cases that MUST be refused |

Each vector pairs inputs with the expected output. **The expected outputs are
data, never regenerated by an implementation under test.** No Go test writes a
vector file. Each file is written, with its `MANIFEST.json` entry, by a Python
script that computes the values from this document:

| Script | Writes |
|---|---|
| `scripts/independent-vectors.py` | `chain_v3_vectors.json`, `anchor_v6_canonical_vectors.json`, `keyid_vectors.json`, `record_v1_vectors.json` |
| `scripts/spec-vectors.py` | `chain_vectors.json`, `v3_golden_capture_request.json`, `merkle_golden.json`, `commitment_vectors.json`, `anchor_chain_hash_vectors.json` |
| `scripts/v4-vectors.py` | `chain_v4_vectors.json`, `anchor_v7_canonical_vectors.json` (needs `dilithium-py` for the anchor signatures) |
| `scripts/verdict-vectors.py` | `verify_verdict_vectors.json` |
| `scripts/bundle-vectors.py` | `bundle_v1_vectors.json` (needs `dilithium-py` for its signatures; the others use the standard library only) |

Three things that sentence does not cover:

- `anchor_v4_canonical_vectors.json` is written by no script. It is a
  hand-maintained file that the three implementations are each checked against.
- The five files `spec-vectors.py` writes were first written some other way
  (two by Go tests, one taken from the JavaScript verifier, one by the
  producer, one by hand). Before the script became their writer it reproduced
  `merkle_golden.json`, `v3_golden_capture_request.json` and
  `anchor_chain_hash_vectors.json` byte for byte, and every value then stored
  in the other two. Three things were then changed on purpose:
  `chain_vectors.json` had two cases with 64-character content hashes, which
  §2.3 refuses, and they were replaced; the three wrong-length-nonce cases of
  `commitment_vectors.json` now store the value the formula gives when the
  length is not checked, so that only a refusal passes them; and the comment
  inside `anchor_chain_hash_vectors.json`, which said the producer generated
  it, was corrected. No expected value of a valid case changed except in the
  two replaced `chain_vectors.json` cases and the one that links from them.
- `record_v1_vectors.json` carries one `regression_signature` produced by this
  repository's Go signer. The file says so. It pins bytes; it is not an
  independent value.

If you reproduce every file listed here byte-for-byte, you agree with every
other implementation.

---

## 11. Conformance checklist

- [ ] Leaf hash and chain hash v4 reproduce `chain_v4_vectors.json` `vectors`, and every `reject` case is refused (§2.0)
- [ ] `entry_id` and `entry_type` hashed as stored, never normalised (§2.0)
- [ ] A v4 first entry has `global_seq` 0; a v4 entry with run fields or a tombstone shape is `format_field_misuse` (§2.0)
- [ ] A v2 or v3 entry after a v4 entry is `format_field_misuse` (§2.5)
- [ ] An erased v4 entry is recomputed from its stored leaf hash; no stored chain hash is taken on trust (§5.0)
- [ ] Anchor v7 canonical bytes, chain hash and signatures reproduce `anchor_v7_canonical_vectors.json`; every `reject` case is refused (§9.2, §9.4)
- [ ] v7 signatures verified with the context `aleutian.proof.anchor.v7`, v1 to v6 with the empty context (§9.5)
- [ ] A v7 anchor bound by sequence; expected subject and predecessor compared, and an unchecked subject said so (§9.7)
- [ ] Chain hash v3 reproduces `chain_v3_vectors.json` `vectors` and refuses every `reject` case (§2.1)
- [ ] `global_seq` handled as a 64-bit integer, not a floating-point number (§2.1)
- [ ] A v3 entry with a non-empty `run_id` or a non-zero `sequence_num` is reported as malformed, not as a hash mismatch (§2.1)
- [ ] An entry with no `format_version` is treated as v2; an unknown one is reported, never guessed (§2.2)
- [ ] Chain hash v2 reproduces all `chain_vectors.json` vectors (§2.3)
- [ ] `previous_hash` validated as empty-or-128-hex **before** hashing (§3)
- [ ] Timestamps formatted to exactly six fractional digits, truncated (§4)
- [ ] A stored timestamp in any other spelling is a break (§4)
- [ ] Field shapes checked before recomputing; no rule on the first `global_seq` (§5.5)
- [ ] One tombstone rule in every path; the entries a tombstone leaves unbound are reported (§5.5)
- [ ] Anchors parsed strictly; counts, key id, predecessor and segment rules enforced (§9.8)
- [ ] An anchor series checked as a series (§9.8)
- [ ] An entries file that is not entries is an error, never a broken chain
- [ ] Tombstones: format validated, hash **NOT** recomputed (§5.1)
- [ ] A chain containing a tombstone verifies as **intact**
- [ ] Erased entries' original ids do not resolve (§5.4)
- [ ] Leaf canonical bytes reproduce `v3_golden_capture_request.json`
- [ ] 4096-byte cap enforced on encode **and** verify
- [ ] zk invariant rejected at encode time (§6.3)
- [ ] Merkle leaves hex-decoded before hashing (§7)
- [ ] Salted commitments reproduce `commitment_vectors.json` `vectors`, and fail every `reject` case (§8)
- [ ] Anchor canonical bytes reproduce `anchor_v6_canonical_vectors.json` and `anchor_v4_canonical_vectors.json`, including Go-style HTML escaping (§9.2)
- [ ] Anchor version dispatched on the declared value only; v5 and unknown versions refused (§9.2)
- [ ] Version invariants checked before canonicalizing (§9.3)
- [ ] Anchor chain hash reproduces `anchor_chain_hash_vectors.json`; seed hash used for the first anchor (§9.4)
- [ ] Signature verified as pure ML-DSA-65, with the context its version names (§9.5)
- [ ] Key ids reproduce `keyid_vectors.json` (§9.6)
- [ ] An anchor is bound against the entries it covered, not against entries added since (§9.7)
- [ ] Verdicts distinguish consistency from existence
      ([verification-model.md](verification-model.md))
