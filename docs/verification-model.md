# What a verification verdict means

**Audience:** anyone reporting verification results to a human, or deciding what
to claim on the strength of them.

The word "verified" carries more weight than this library can support on its own.
This document draws the line precisely, because the gap between what is proven
and what a reader assumes is where a compliance tool does real damage.

---

## The two claims

```
   ┌─────────────────────────────────────────────────────────────────┐
   │  CONSISTENCY          "nothing was edited under me"             │
   │                        ✅ provable from the chain alone          │
   ├─────────────────────────────────────────────────────────────────┤
   │  EXISTENCE            "…and this is the same chain you saw"     │
   │                        ❌ requires an anchor                     │
   └─────────────────────────────────────────────────────────────────┘
```

They are different claims, and only the first is free.

---

## What consistency actually gets you

Each entry's hash covers its predecessor's, so altering an entry changes its
hash, and the next entry's stored predecessor no longer matches:

```
  entry 3          entry 4
  hash=AAA ──────► prev=AAA
                   hash=BBB

  edit entry 3 → its hash becomes AAA'
                 entry 4 still stores prev=AAA   ✗ MISMATCH
```

The guarantee, stated exactly:

> **An entry cannot be changed by anyone who cannot also rewrite every entry
> that follows it.**

That is genuinely useful — an operator who quietly edits one row is caught, and
so is a storage layer that corrupts one. But the condition is doing real work in
that sentence.

---

## What consistency does not get you

### Truncation

Removing entries from the front is not an edit-with-the-rest-intact. It is
presenting a valid suffix as the whole:

```
  ORIGINAL   [0]→[1]→[2]→[3]→[4]→[5]

  delete 0,1,2 · clear entry 3's previous_hash · recompute 3,4,5

  PRESENTED            [3]→[4]→[5]      internally flawless
```

Nothing inside a chain records how long it should be or where it began. The first
entry is simply the one whose previous hash is empty, so a verifier handed a
chain starting at entry 3 has no way to know entries 0–2 ever existed.

Put differently: swap a paperclip in the middle and the chain won't fit together;
remove the first ten and hand over the rest, and it is still a perfectly good
chain — just shorter. Nothing about it says it used to be longer.

### Wholesale replacement

The same argument, generalised. An adversary who can rewrite **everything** can
produce an internally consistent chain of their choosing. Consistency constrains
someone who can only make *local* edits.

### Who did it

The chain proves that something changed, never who changed it.

### That the content is what it says

`content_hash` commits to content stored elsewhere. If that payload is gone or
was never what the hash covered, the chain cannot tell you — it verifies the
commitment, not the thing committed to.

---

## What closes the gap: anchors

An anchor is a signed statement that at a particular time, a chain's head was `H`
over a stated entry range:

```
   Anchor {
     chain_hash    the head at the time of signing
     range         which entries it covers
     entry_count
     signature     ML-DSA-65
   }
```

Hold Tuesday's anchor, and a chain that no longer contains that head is provably
not the same chain. The `range` and `entry_count` are what make truncation
detectable — a chain starting at entry 50 contradicts an anchor that says
entries 0–500.

> **Producing anchors** is `anchor.SignAnchor`; see
> [anchor-model.md §6a](anchor-model.md#6a-producing-an-anchor-why-signing-is-one-call).
> It verifies every signature before returning it, which establishes
> CONSISTENCY — the signature matches the key the signer advertises — and not
> authenticity. The distinction below is the one that matters.

**An anchor is exactly as trustworthy as the key that signed it.** A locally
generated key proves the holder's own assertion and nothing more — real, but
strictly weaker than a third party's attestation, and callers must surface the
difference rather than reporting a uniform "verified".

Anchor signature verification is implemented: `anchor.VerifySignature`, reached
through `verify.VerifyAnchor`. Producing anchors is `anchor.SignAnchor`. What
remains outside this repository is the part no code settles — key custody and a
delivery path the anchor's subject cannot rewrite.

---

## Reporting results honestly

**Do not** report a locally verified chain as simply "verified". A reader will
hear the second claim.

Suggested vocabulary:

| Verdict | Means |
|---|---|
| `INTACT` | consistency holds; no anchor was checked |
| `INTACT, SELF-ANCHORED` | an anchor verified, signed by a locally generated key — the holder attesting their own claim |
| `INTACT, ANCHORED` | an anchor verified against a key in the trust store |
| `BROKEN AT <index>` | consistency failed; the index is the first break |

The distinction between the middle two is the one people will want to blur. Keep
it.

---

## Reading a break report

**One tampered entry cascades.** Verification advances using the *expected* hash,
so once an entry mismatches, every later entry mismatches too.

> **The first break index is the signal. The count is noise.**

A report saying "47 breaks" after a single edited row is not describing 47
problems.

### Break types

| Type | Meaning |
|---|---|
| `hash_mismatch` | the recomputed chain hash differs from the stored one |
| `sequence_gap` | `global_seq` is not contiguous — entries missing or reordered |
| `invalid_tombstone` | an entry claims to be a tombstone but its content hash is malformed |
| `invalid_timestamp` | the stored timestamp is not in the form `YYYY-MM-DDTHH:MM:SS.ffffffZ` |
| `invalid_field` | a hash, salt, sequence number, id or run id is not in the shape its format requires, or a v4 entry is neither the live nor the erased shape |
| `format_field_misuse` | an entry carries a field its format does not have (a v3 run id, a v4 tombstone), or a v2 or v3 entry follows a v4 entry |
| `unknown_format` | `format_version` names no format this verifier knows |
| `anchor_mismatch` | the chain does not match the anchor covering it |

### An erased entry must never produce a break

An erased entry is a **normal, lawful** state. In v2 and v3, a verifier that
reports a break on a tombstone is recomputing a hash it should be reading
(format-spec.md §5; three shipped SDKs had this bug). In v4 the opposite holds:
an erased entry is recomputed from its stored leaf hash like any other, and a
verifier that skips it has left a link unchecked (§5.0).

---

## Threat model, briefly

| Adversary | v4 | v2 / v3 |
|---|---|---|
| edits one entry, no other access | ✅ | ✅ |
| edits one entry, can rewrite everything after it | ✅ with an anchor | ✅ with an anchor |
| deletes entries from the front, re-links the rest | ✅ with an anchor | ✅ with an anchor |
| reorders entries | ✅ | ✅ |
| inserts a forged entry | ✅ | ✅ |
| replays an existing entry as a new one | ✅ | ✅ |
| destroys the payload but leaves the chain | ✅ — the commitment survives; the content is gone | ✅ |
| erases an entry lawfully | not an attack — verifies as intact, anchors still bind | not an attack — verifies as intact |
| rewrites the entries **before an erased entry** | ✅ with an anchor | ❌ — with or without an anchor; see below |
| changes an entry's `entry_id` or `entry_type` | ✅ — both are in the leaf hash | ❌ — neither is in any hash |
| appends a v3 tombstone after v4 entries | ✅ — refused, `format_field_misuse` | — |
| erases a live entry without the right to | ❌ — erasure is not authenticated by the chain; see below | ❌ |

"With an anchor" means an anchor the adversary cannot rewrite
(anchor-model.md §4). In a v2 or v3 chain, every ✅ row assumes the edited entry
comes **after the chain's last tombstone**. A v3 chain continued in v4
(format-spec §2.5) has the v4 column for every entry after its last tombstone.

Every row above is exercised by the integration tests in this repository, including
the truncation and tombstone rows, which assert the failure *is* undetectable — so
that if a defence is ever added, the documentation claiming otherwise fails loudly.

### Who may erase

A v4 erased entry proves that an entry existed at its position and was linked
like every other; it does not prove that whoever erased it was allowed to. The
erased shape (format-spec §2.0) is something anyone who can write the store can
produce. Authorization to erase is recorded outside the chain: the sink signs
its erasure records, and its checkpoint refuses an erasure that was neither
signed nor confirmed (sink-format.md).

### What a tombstone leaves unverified (v2 and v3)

A tombstone keeps the erased entry's original chain hash, and a verifier takes
that hash as stored: it cannot be recomputed, because the content hash it was
computed from is gone ([format-spec.md §5](format-spec.md)). So nothing links
the entries *before* a tombstone to the entries after it.

```
  e0 ── e1 ── T2 ── e3 ── e4          T2 = tombstone, chain hash taken as stored
  └──┬──┘           └──┬──┘
  not linked to     linked to the head,
  anything after    and so bound by an anchor
```

Someone who can write the store can replace `e0` and `e1` with different entries
that link among themselves, leave `T2`'s chain hash alone, and the chain still
verifies as `INTACT`. A signed anchor still binds, because the head it signed
depends only on `T2`'s stored hash and what follows. They can also do this to a
chain with no tombstone, by turning an entry into one: `entry_type` and
`entry_id` are in no hash, and they are what marks an entry as erased.

The verifier reports the exposure and does not hide it:

- `verify.Result` carries `tombstones_found` and `last_tombstone`.
- `verify.BindResult` carries `tombstones` and `entries_not_bound`, and its
  `proven` / `not_proven` text names the entries the anchor does not bind.
- `proof verify` prints the same.

Closing it needed a format change, and v4 is that change: an erased v4 entry
keeps its leaf hash, so every link is recomputed (format-spec §5.0). v2 and v3
are frozen, so this stays a property of every v2 or v3 entry up to a chain's
last tombstone; a chain continued in v4 stops adding to it. The sink (`docs/sink-format.md`) is not affected: it erases by
destroying a nonce and keeps the content hash, so every entry stays recomputable.
