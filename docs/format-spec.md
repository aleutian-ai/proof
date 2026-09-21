# AleutianChain format specification

**Status:** normative · **Version:** chain hash v2, capture leaf v3
**Audience:** anyone implementing a verifier in any language

This document exists because of a specific failure. The rule about tombstones in
§5 previously lived in exactly one implementation's source comments. Three
independently written SDKs — Go, Python, JavaScript — got it wrong the same way,
and each shipped a verifier that reported intact chains as broken. None of their
authors did anything unreasonable; the rule was simply not written anywhere they
could find it.

**If you are implementing a verifier, §5 and §6 are the parts you cannot infer.**

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
tamper-evident.

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
| `sequence_num` | base-10 ASCII, non-negative | position **within the run** — not chain-wide |
| `timestamp` | `YYYY-MM-DDTHH:MM:SS.ffffffZ` | see §4 |
| `content_hash` | 128 lowercase hex, **or** a tombstone value (§5) | |

The domain prefix `aleutian.chain.v2:` is part of the preimage. `v2` denotes
SHA-512; v1 used SHA-256 and is not supported.

**`global_seq` is NOT part of the preimage.** Chain-wide ordering is protected by
the previous-hash linkage. A verifier may check `global_seq` for gaps, but must
not include it when computing a hash.

### 2.1 Batch grouping is part of the artefact

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

Store the timestamp in the precision it was hashed at. A verifier that re-parses
a stored string and re-formats it to microseconds reproduces the hash; one that
round-trips through milliseconds does not.

---

## 5. Tombstones — the rule most likely to be got wrong

When an entry's content is erased, the entry **stays in place**. Its
`content_hash` is replaced; everything else about the row is unchanged.

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
HEADER   company_id · entry_type · signing_key_id · timestamp_ms(u64)

BODY     capture_method · content_hash · dlp · encryption_mode · model ·
         pii_action · pii_categories · pii_detected(bool) ·
         pii_digest_key_version · processing_mode · provider · region ·
         source_type · trust_level · user_id
```

Total canonical form: **maximum 4096 bytes**. Per-field caps do not bound the
sum, so this is a separate check — enforce it on both encode and verify.

### 6.3 Validation

All fields are ASCII-restricted by regex, so NFC normalisation is a no-op for
this entry type in practice — but perform it anyway; a future entry type may
carry free text.

- `company_id` — `^comp_[0-9A-HJKMNP-TV-Z]{26}$`
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

## 8. Test vectors

`fixtures/testdata/` carries the cross-language golden vectors. Reproduce them
exactly, or your implementation is not compatible:

| File | Covers |
|---|---|
| `chain_vectors.json` | chain hash: genesis, linked, **tombstone** |
| `v3_golden_capture_request.json` | leaf canonical bytes + content hash |
| `merkle_golden.json` | roots, inclusion, consistency |

Each vector pairs inputs with the expected output. If you reproduce all three
files byte-for-byte, you agree with every other implementation.

---

## 9. Conformance checklist

- [ ] Chain hash reproduces all `chain_vectors.json` vectors
- [ ] `previous_hash` validated as empty-or-128-hex **before** hashing (§3)
- [ ] Timestamps formatted to exactly six fractional digits, truncated (§4)
- [ ] Tombstones: format validated, hash **NOT** recomputed (§5.1)
- [ ] A chain containing a tombstone verifies as **intact**
- [ ] Erased entries' original ids do not resolve (§5.4)
- [ ] Leaf canonical bytes reproduce `v3_golden_capture_request.json`
- [ ] 4096-byte cap enforced on encode **and** verify
- [ ] zk invariant rejected at encode time (§6.3)
- [ ] Merkle leaves hex-decoded before hashing (§7)
- [ ] Verdicts distinguish consistency from existence
      ([verification-model.md](verification-model.md))
