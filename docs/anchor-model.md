# The anchor model

What an anchor is, what it proves, what it does not, and which parts of the
design are load-bearing versus incidental.

This is written from a read of the production anchor generator and the published
SDK, not from design documents. Where the two disagreed, the code won and the
disagreement is recorded.

---

## 1. Why anchors exist at all

The per-entry chain hash proves **nothing was edited**. It cannot prove **this is
the whole chain**.

```
      chain as held by the customer          chain as held by the operator
      ┌───┬───┬───┬───┬───┐                  ┌───┬───┬───┐
      │ 1 │ 2 │ 3 │ 4 │ 5 │                  │ 3 │ 4 │ 5 │
      └───┴───┴───┴───┴───┘                  └───┴───┴───┘
                                              re-linked from a new genesis
                                              — internally consistent
                                              — verifies INTACT
                                              — entries 1 and 2 are gone
```

Front-truncation followed by re-linking produces a chain that passes every
linkage check. The verifier walks it, every `prev_hash` matches, and it reports
success. Nothing inside the chain can detect this, because the evidence that
entries 1 and 2 existed *was* entries 1 and 2.

An anchor is the external commitment that closes this. It is a signed statement,
made at a point in time, that says "at sequence N, the chain head was H, and the
range started at entry S". Truncate below S and the anchor no longer matches
anything.

**This is the entire justification for anchors.** Every other property they have
is secondary.

---

## 2. It is a second chain, not a signature over the first

The most common wrong mental model — and one this document exists partly to
correct — is that an anchor's `chain_hash` is the tip entry's `chain_hash`,
signed. It is not.

```
   ENTRY CHAIN                              ANCHOR CHAIN
   domain "aleutian.chain.v2:"              domain "aleutian.anchor.v2:"

   e1 ──► e2 ──► e3 ──► e4 ──► e5           A1 ──────────► A2
                        ▲     ▲              │              │
                        │     │              │ commits      │ commits
                        └─────┴──────────────┴──────────────┘
                          range start / end + tip chain hash
```

The anchor's `chain_hash` is a **domain-separated SHA-512 over five fields**:

```
SHA-512( "aleutian.anchor.v2:"
         ‖ previousAnchorHash ‖ "|"    prior anchor's chain_hash, or SeedAnchorHash
         ‖ companyID          ‖ "|"
         ‖ startEntryID       ‖ "|"    range.start_entry_id
         ‖ endEntryID         ‖ "|"    range.end_entry_id
         ‖ tipChainHash )              the ENTRY chain's hash at endEntryID
```

Two separate domains, deliberately. `aleutian.chain.v2:` for entry links,
`aleutian.anchor.v2:` for anchor links. An anchor therefore binds in two
directions at once: **backwards** to the previous anchor, and **downwards** to a
specific entry-chain head.

Genesis uses `SeedAnchorHash = SHA-512("aleutian.anchor.seed.v2")`, with
`PreviousAnchorID = "anchor_00000000-0000-0000-0000-000000000000"` as the
sentinel.

> The producer's own doc comment warns verifiers to recompute this rather than
> assume byte-equality with the tip. The warning is there because the wrong model
> is the intuitive one.

---

## 3. What verification actually does

Reading the verifier rather than describing it from the struct, the head bind is
four ordered checks. Order matters and is deliberate.

```
   ┌─ 1 ─────────────────────────────────────────────────────────────┐
   │ SIGNATURE                                                        │
   │ ML-DSA-65 over the canonical JSON. Fail closed.                  │
   │ Without this first, a planted anchor whose chain_hash matches a   │
   │ forged head would pass the bind despite never being signed.       │
   └──────────────────────────────────────────────────────────────────┘
   ┌─ 2 ─────────────────────────────────────────────────────────────┐
   │ VERSION INVARIANT                                                │
   │ Version is INSIDE the signed bytes, so a V≥5 anchor with an empty │
   │ root_hash is malformed — a valid signature over invalid content — │
   │ not a benign older anchor.                                       │
   └──────────────────────────────────────────────────────────────────┘
   ┌─ 3 ─────────────────────────────────────────────────────────────┐
   │ BOUNDS                                                           │
   │ endSeq within [minSeq, maxSeq]. A planted EntryCount is a bounded │
   │ break rather than an unexplained map miss.                        │
   └──────────────────────────────────────────────────────────────────┘
   ┌─ 4 ─────────────────────────────────────────────────────────────┐
   │ HEAD BIND  ← this is the one that closes truncation               │
   │ Recompute the entry chain to endSeq; recompute the anchor chain    │
   │ hash from the signed range + that head; compare.                  │
   └──────────────────────────────────────────────────────────────────┘
```

Truncation surfaces at step 3/4 with a message that names it directly:

> `anchor committed range end not found in chain (entries truncated below the
> anchored head)`

So the claim "anchors close truncation" is true, and this is where. But it comes
with a boundary that is easy to lose.

---

## 4. The boundary: anchors close truncation *conditionally*

Two conditions, both load-bearing.

**(a) Only for ranges an anchor covers.** Entries appended after the last anchor
are unanchored. The producer emits an `unanchored_tail` gauge —
`head_seq − prev_anchor_entry_count` — precisely so an operator can alert when
the anchor job stalls and that window grows. Everything in that window has
linkage proof only.

**(b) Only if the anchor reaches the verifier by a path the truncator cannot
also rewrite.** This is the one that matters and the one most easily hand-waved.

An anchor stored in the same bucket as the chain, under the same credentials,
proves nothing against an adversary holding those credentials: they rewrite the
chain and re-sign the anchor. The signature is not the barrier — **possession of
the signing key is** — so the property has to come from somewhere other than
cryptography.

It comes from delivery topology:

```
   ALEUTIAN                                    CUSTOMER
   ┌────────────────────────┐                 ┌──────────────────────────┐
   │ per-tenant bucket      │                 │ customer's own bucket    │
   │ anchors + latest.json  │ ──deliver────►  │ anchors                  │
   │                        │                 │                          │
   │ full read/write        │                 │ Aleutian SA holds ONLY   │
   │                        │                 │ roles/storage.objectCreator│
   └────────────────────────┘                 │ → write-only             │
                                              │ → CANNOT read            │
                                              │ → CANNOT delete/overwrite│
                                              └──────────────────────────┘
```

`objectCreator` and nothing more is what makes the customer's copy an
**independent witness**. Aleutian can add an anchor there; it cannot retract or
alter one it already delivered. A customer holding their own anchor copy can
detect a rewritten history that a customer relying on Aleutian's copy cannot.

**Therefore:** an anchor verified against the operator's own store is a
consistency check, not an external commitment. It is only an external commitment
when checked against a copy the operator cannot reach. Any verdict wording that
does not carry this distinction is overclaiming.

Delivery is explicitly **non-fatal** to anchor generation — a delivery failure is
recorded as telemetry and the anchor is still written. Correct for availability,
but it means the witness property is best-effort and its absence is silent to the
customer.

---

## 5. Version landscape, and a staged format that is not live

| Version | Fields | Adds | Emitted in production? |
|---|---|---|---|
| ≤3 | 9 | baseline | **yes — default** |
| 4 | 10 | `verified_through` | yes, behind `minAnchorVersion` opt-in |
| 5 | 12 | `root_hash`, `tree_size` | **no — nothing emits it** |

V4 is interesting design: before signing, the generator *verifies* the range it
is about to attest to, and `verified_through` records how far that verification
reached. A resource failure (BQ timeout, KMS transient) **circuit-breaks to V3**
rather than emitting a failure record — resource failures are not tamper signals.
That distinction is a good one and worth preserving in any port.

V5 is the notable finding. `MerkleAnchorVersion = 5` has a full canonical form, a
malformed-if-`root_hash`-empty guard in the verifier, and tests — but **no
production code path stamps `Version = 5`**. Every non-test reference is a guard
or a constant.

Two consequences:

1. **Merkle inclusion and consistency proofs are unavailable in production.**
   `ProofBuilder.requireMerkleAnchor` returns `ErrProofNoMerkleAnchor` for any
   anchor below V5, so every proof request would fail. This is doubly dormant:
   `ProofBuilder` also has **no non-test callers** — no endpoint, no CLI.
2. **The published SDKs reject V5 outright.** `VerifyAnchorLocally` returns
   "unsupported anchor version" for anything above 4; a Go SDK test literally
   labels version 5 "unknown". The day the generator flips to V5, every SDK
   verifier fails closed on every anchor.

That second point is the same shape as the tombstone bug already fixed this
month: a producer-side change that no verifier was taught about. The ordering is
not optional — **verifiers first, producer second.**

### V6 (2026-09-24): `company_id` becomes `subject`

`proof` is a tool for putting your own inputs into a hash-linked chain. It had
no business asking for a customer identifier, so the field is now a **subject**:
the namespace the chain is about, any non-empty string. It stays inside the
signed bytes, because an anchor that does not commit to its subject can be
replayed onto another chain — but nothing authenticates it, so it separates
namespaces rather than proving one.

The key is part of what gets signed, so this is a version, not a rename:

```
  v3–v5   "company_id"     unchanged forever; existing anchors verify as they did
  v6      "subject"        v4's layout, the field moves from 3rd to 8th (alphabetical)
```

V6 is built on **V4, not V5**: V5 commits to a Merkle root and has no
cross-language vectors, so building on it would inherit a form nothing can
verify. V6 therefore carries no `root_hash` or `tree_size`, and declaring
either is rejected.

Two things this change fixed that were not about naming:

- The version guard read `if a.Version >= MerkleVersion`. It was written to
  exclude V5 and silently excluded **every version after it**, so a V6 anchor
  would have verified nowhere. Merkle is one version, not a floor.
- V6 requires a non-empty subject. V3–V5 never required a non-empty
  `company_id`, and they still do not — tightening that retroactively would flip
  historical anchors from passing to broken.

**Verifiers first still applies.** No SDK implements V6, so nothing should emit
V6 anchors to a consumer that has not been taught them. The Go implementation
pins the canonical bytes with a golden vector; that guards against drift, and is
weaker than the cross-language agreement V3/V4 have.

---

## 6. Canonicalization

Signatures are over compact, alphabetically-keyed JSON (RFC 8785 / JCS
principles), with `signature` excluded. Dispatch is **by `Version`, never by
field presence**:

```go
switch anchor.Version {
case 5:  return anchorCanonicalJSONV5(anchor)
case 4:  return anchorCanonicalJSONV4(anchor)
default: return anchorCanonicalJSONV3(anchor)
}
```

Probing for a field would be a **downgrade oracle** — an attacker could induce the
weaker canonical form by omitting a field. Version is inside the signed bytes, so
dispatching on it is safe; dispatching on anything else is not. The SDK enforces
the matching invariants *before* canonicalizing (a V≤3 anchor must have
`verified_through == 0`; a V4 must have it positive), which is the right order:
reject the downgrade before doing work that depends on the version.

Key ordering is subtle enough to be worth stating: `root_hash` sorts between
`range` and `signing_key_id` (`ra < ro < s`), and `tree_size` between
`signing_key_id` and `verified_through`. Alphabetical, but not in struct order.

`signing_key_id` is inside the canonical form. It was not always — anchors signed
before the fix carried an empty `signing_key_id` and were unverifiable.

**That incident is the reason the producer API has the shape it does.** See §6a.

---

## 6a. Producing an anchor: why signing is one call

`signing_key_id` being inside the signed bytes has a consequence that reads as
obvious once stated and is missed every time it is not enforced:

```
   a.SigningKeyID = ""
   canonical := Canonicalize(a)        ← signs  "signing_key_id":""
   sig, id   := sign(canonical)
   a.SigningKeyID = id                 ← publishes "signing_key_id":"abc…"
   ────────────────────────────────────────────────────────────────────
   the verifier re-canonicalizes the PUBLISHED anchor, gets different
   bytes, and reports ErrInvalidSignature. Forever. With no diagnostic
   that distinguishes it from an actually forged anchor.
```

This project has already shipped that bug once, in the platform, where every
anchor produced over a period of months was unverifiable and the cause was not
visible from the failure. It was re-introduced a second time — in the
documentation of the open-source signer — and caught in review before release.
Twice is a design signal, not carelessness: **an API that hands a caller the
pieces and trusts them to assemble them in order will eventually be assembled
out of order.**

So `anchor.SignAnchor(ctx, signer, a)` does the whole sequence and returns a
finished anchor:

```
   1. derive key id + public key from the signer      (KeyIDOf, ONE Public() call)
   2. stamp signing_key_id                            (unless the caller set one)
   3. ValidateVersionInvariants, and refuse v5        (exactly what VerifySignature refuses)
   4. Canonicalize
   5. sign
   6. VERIFY the signature just produced              (unconditional)
```

Step 3 exists so this package cannot emit an anchor it would itself reject — a
v5 anchor, or a v6 with an empty subject, would otherwise get a perfectly good
signature and fail at verification.

Step 6 exists because `crypto.Signer`'s byte slice is ambiguous by design:

| algorithm | what the `[]byte` means |
|---|---|
| RSA, ECDSA | a **digest** the caller already hashed |
| Ed25519, ML-DSA | the **whole message**; the algorithm hashes internally |

A third-party signer written for the first convention returns a structurally
perfect signature over `SHA-256(canonical)`. Correct length, correct algorithm,
parses cleanly, verifies nowhere. Only verifying the output catches it.

The lower-level `SignCanonical` remains for callers who must control
canonicalization, and it refuses an empty `signing_key_id` outright — the one
shape that is never legitimate.

### What step 6 does *not* establish

Consistency, not authenticity. It proves the signature matches the key the
signer **advertises**. A substituted or compromised signer that swaps in its own
keypair passes every check and returns a perfect signature under the attacker's
key. Catching that needs a key obtained independently — a `TrustPlatform` or
`TrustProvided` ring — never a `TrustSelf` ring built from the key that
travelled with the anchor.

### Key ids come from two different namespaces

| source | shape | example |
|---|---|---|
| `proof keygen` / `KeyIDOf` | `^[0-9a-f]{32}$`, content-derived | `4f2b…` |
| KMS / registry | assigned label | `aleutian-anchor-2026-01-v2` |

Both are legal on the wire. `SignAnchor` derives an id only when the field is
empty; a caller-set id is kept, because re-labelling a KMS key would make the
anchor unresolvable against the trust store that holds it. The trade is
explicit: a derived id cannot be wrong, an assigned one is the caller's
assertion.

### The subject is not erasable

The subject is inside the signed bytes — which is what stops an anchor being
replayed onto another chain, and also means it can never be removed, redacted
or corrected. Changing it invalidates the signature, and through `chain_hash`
and `previous_anchor_id` it invalidates every anchor after it. Anchors are meant
to be published and escrowed.

**A subject must therefore be a stable pseudonym or an opaque id, never a name,
an email address, a username or a device hostname.** If the natural subject is
personal, hash it with a secret salt held separately, so the anchor commits to
the pseudonym and the mapping stays erasable. A tool that makes the subject
permanent cannot also honour a request to delete it.

---

## 7. Delimiter injection in the anchor chain hash

The preimage is `|`-delimited and **not self-delimiting**. Three of the five
fields — `companyID`, `startEntryID`, `endEntryID` — are adjacent and
variable-length, so a `|` inside any of them shifts a field boundary without
changing the preimage:

```
start = "entry_aaa|entry_bbb"   end = "entry_ccc"           ─┐ identical
start = "entry_aaa"             end = "entry_bbb|entry_ccc"  ─┘ SHA-512
```

Two results that are easy to get backwards, both established by testing rather
than reasoning:

1. **Validating the subject does not help.** The collision above uses a
   well-formed subject. The ambiguity is between the two entry IDs. This is
   the opposite of the entry chain hash, where `previous_hash` being fixed-shape
   is what carries the guarantee (D4).
2. **Banning `|` is necessary AND sufficient.** With no pipe in any field,
   splitting the preimage on `|` recovers the tuple uniquely — the encoding is
   injective. Verified over 7,776 distinct pipe-free tuples.

**Reachability:** not exploitable in the producer today. Every input is
server-minted from a pipe-free alphabet, and the ingest path quarantines
caller-supplied identifiers into a separate `ClientEntryID` field. The safety
property is *provenance*, not validation — which is exactly the fragile kind.

**Where it stops being theoretical:** keyless anchor-linkage verification.
Against a signature-checking verifier the collision buys little, since `range.*`
and the subject are inside the signed bytes and forging a colliding anchor needs
the signing key. But recomputing the anchor-of-anchors chain needs **no key** —
and that is precisely the offline mode this library wants to offer. In that mode
nothing else stands behind the boundary.

Guarded in the reference producer as well, with a deliberate asymmetry that
should be preserved in any port:

| Path | Guard | Why |
|---|---|---|
| Producer | full shape validation | inputs are ours; malformed means corruption |
| Verifier | **pipe rejection only** | must not false-break historical anchors |

Applying strict shape validation at verification time would flip historical
anchors with non-UUID entry IDs from passing to broken — reporting a valid chain
as invalid, which is the failure mode that shipped in three SDKs this month.

---

## 8. What a verdict may honestly claim

| Checked | Proven | NOT proven |
|---|---|---|
| Entry linkage only | nothing was edited | that this is the whole chain |
| \+ anchor, operator's copy | the operator's chain matches the operator's commitment | anything against an operator holding the signing key |
| \+ anchor, customer's copy | the chain matches a commitment the operator **cannot retract** | anything past the last anchored entry |
| \+ inclusion proof | a specific entry is in the committed tree | *(unavailable — needs V5)* |

The third row is the real product. The first is what a keyless verifier can do
alone, and it is worth saying plainly that it is the weakest row.

---

## 9. Implications for this library

1. **Port the primitive, not the policy.** The producer's verifier carries
   revocation, supersession downgrades, two-pass evaluation and
   tombstone-indeterminate states — all tied to Aleutian's trust store. Porting
   that would ship a verifier that needs a trust store to mean anything, which
   defeats a keyless tool. Take: canonicalize → verify signature → bind head.
2. **`_07` must carry the delimiter guard from the start.** Porting the unguarded
   primitive and hardening later inverts the order in the one mode where it
   matters.
3. **V3 and V4 only.** Define V5's canonical form and pin, by test, that it is
   *not* accepted — recording the format without claiming support.
4. **ML-DSA-65 breaks the zero-dependency claim.** Not in the Go standard library
   (`crypto/mlkem` is; ML-DSA is not). `cloudflare/circl` is required, confined by
   `deps_test.go` to the anchor package. Honest framing becomes: *KEM core zero
   dependencies, format core one, anchor verification two.*
5. **Anchor provenance must be in the output.** "Verified against an anchor" is
   not one claim, it is three (§8). A verdict that does not say *which copy of
   the anchor* it checked is not answering the question the user has.

