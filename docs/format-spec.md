# AleutianChain format specification

**Status:** normative for what it covers · **Audience:** anyone implementing a
verifier in any language

**Covered here:** chain hash **v3** (the current format, written by
`proof commit`) and **v2** (legacy, for existing chains), capture leaf v3,
salted commitments, and **anchors**: the canonical form of every version,
the anchor chain hash, the ML-DSA-65 signature, and key ids.

Three implementations agree on everything here: Go (the reference) and the
Python and JavaScript verification SDKs. The conformance vectors in §10 were
computed independently of all three.

This document exists because of a specific failure. The rule about tombstones in
§5 previously lived in exactly one implementation's source comments. Three
independently written SDKs — Go, Python, JavaScript — got it wrong the same way,
and each shipped a verifier that reported intact chains as broken. None of their
authors did anything unreasonable; the rule was simply not written anywhere they
could find it.

**If you are implementing a verifier, §5, §6 and §9.2 are the parts you cannot infer.**

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
tamper-evident. There are two formats. **Each entry declares its own** (§2.2),
and one chain may contain both.

### 2.1 v3 — the current format

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

An entry's `format_version` is `3` or `2`. Exports **omit** the field for v2
entries, because v2 entries were written before it existed. A verifier reading an
entry with no `format_version` therefore treats it as v2. That describes existing
data, not a default a writer may rely on: every v3 writer emits `3`. Any other
value is an unknown format. Report it as such; never guess.

### 2.3 v2 — legacy, for existing chains

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

The rule is the same for v3. Its other fields are all fixed-shape, so an
unvalidated `previous_hash` is again the one way to shift a boundary.

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
| `subject` (v6) / `company_id` (v1–v5) | string | what the chain is about. Same value, key renamed in v6 |
| `chain_hash` | 128 lowercase hex | the **anchor** chain hash (§9.4), not the tip entry's |
| `range` | `{start_entry_id, end_entry_id}` | the entries covered |
| `entry_count` | integer | entries covered, counted from the chain's first entry |
| `signing_key_id` | 32 lowercase hex | the signing key (§9.6) |
| `created_at_ms` | integer | Unix milliseconds. Advisory; order comes from the chain |
| `previous_anchor_id` | string | the anchor before this one, or the seed id (§9.4) |
| `verified_through` | integer | v4+: the producer verified the chain through this count |
| `signature` | base64 | §9.5. **Excluded** from the canonical form |

`subject` is inside the signed bytes. It can never be erased or corrected
afterwards, so it **MUST NOT** carry personal data. Use a topic or a pseudonym.

### 9.2 Canonical form: the bytes that are signed

- Compact JSON: no whitespace, keys in **strict alphabetical order**, including
  inside `range` (`end_entry_id` before `start_entry_id`). `signature` is left
  out.
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

Any other version: refuse. Never canonicalize it as the closest known form.

### 9.3 Version invariants: check them before canonicalizing

| Version | Must hold |
|---|---|
| 1–3 | `verified_through` = 0 |
| 4 | `verified_through` > 0 |
| 5 | refused |
| 6 | `verified_through` > 0 **and** `subject` non-empty |

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

### 9.5 Signature

- **ML-DSA-65** (FIPS 204), in pure mode (not HashML-DSA), with an **empty
  context string**, over the canonical bytes of §9.2.
- The signature is 3309 bytes, written as standard base64 with padding. The
  public key is 1952 bytes.

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

---

## 10. Test vectors

(Sink export bundles, built on this format, have their own normative spec and
vectors: `bundle-format.md` and `bundle_v1_vectors.json`.)


`fixtures/testdata/` carries the cross-language golden vectors. Reproduce them
exactly, or your implementation is not compatible. `fixtures/MANIFEST.json`
records each file's SHA-256, so a vendored copy that drifts is detectable.

| File | Covers |
|---|---|
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
data, never regenerated by an implementation under test.** The v3, v6, key-id
and commitment values were computed in Python, from this document alone
(`scripts/independent-vectors.py`). If you reproduce every file listed here
byte-for-byte, you agree with every other implementation.

---

## 11. Conformance checklist

- [ ] Chain hash v3 reproduces `chain_v3_vectors.json` `vectors` and refuses every `reject` case (§2.1)
- [ ] `global_seq` handled as a 64-bit integer, not a floating-point number (§2.1)
- [ ] A v3 entry with a non-empty `run_id` or a non-zero `sequence_num` is reported as malformed, not as a hash mismatch (§2.1)
- [ ] An entry with no `format_version` is treated as v2; an unknown one is reported, never guessed (§2.2)
- [ ] Chain hash v2 reproduces all `chain_vectors.json` vectors (§2.3)
- [ ] `previous_hash` validated as empty-or-128-hex **before** hashing (§3)
- [ ] Timestamps formatted to exactly six fractional digits, truncated (§4)
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
- [ ] Signature verified as pure ML-DSA-65 with an empty context (§9.5)
- [ ] Key ids reproduce `keyid_vectors.json` (§9.6)
- [ ] An anchor is bound against the entries it covered, not against entries added since (§9.7)
- [ ] Verdicts distinguish consistency from existence
      ([verification-model.md](verification-model.md))
