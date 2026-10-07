# Sink export bundle: `aleutian.proof.bundle.v1`

**Status: NORMATIVE, revision 3** (`_72a`, accepted by the owner 2026-10-07).
Revision 2 applied a four-agent review (28 findings) and the owner's decisions
U1–U3; revision 3 applied the re-review. Implementations derive their behaviour
from this document. If the conformance vectors expose a contradiction, this
document changes, with a note, rather than an implementation inventing
behaviour.

A **bundle** is a sink's evidence, exported so that someone else can verify it
without the sink, without the writer, and without proof's code. This document
is everything an implementation needs: the grammar, the checks, and the result,
which every implementation must produce **identically**.

References: `format-spec.md` (chain hash v3 §2.1, delimiter safety §3,
timestamps §4, salted commitments §8, anchors §9, key ids §9.6) and
`sink-format.md` (identifiers §1, entry types §2, the erasure record §4.1,
checkpoints §5, record signatures §9). The key words MUST, MUST NOT, SHOULD and
MAY are as in RFC 2119.

## 1. What a verdict means

| Verdict | Meaning | Exit |
|---|---|---|
| `ok` | No problem found, and **every entry is authenticated** (§7.8) by a key the verifier supplied | 0 |
| `unauthenticated` | No problem found, but at least one entry is not authenticated: the evidence is internally consistent, and **its provenance is not established** | 4 |
| `failed` | At least one problem (§12) | 1 |

Precedence: `failed` over `unauthenticated` over `ok`. A bad signature and an
uncovered entry together are `failed`.

**Why `unauthenticated` exists.** Chain hashes need no key. Anyone can fabricate
a chain whose hashes recompute. Only a checkpoint signed by a trusted key, or a
record signature by a trusted key, says who produced an entry.

**A passing (`ok`) bundle proves**, for each chain:
- the entries are linked, in order, from the chain's first entry, and every
  chain hash recomputes;
- every entry is covered by a checkpoint, or carries a record signature, made
  by a key the verifier trusts. **What each authenticates differs:** a
  checkpoint fixes the chain hashes (so every entry's sequence, previous hash,
  timestamp and content hash) and its range's first and last entry ids, but
  **not** the `entry_id` or `entry_type` of the entries in between; a record
  signature fixes every field of its entry. Under checkpoint trust alone, inner
  entry ids are labels, not evidence;
- each disclosed event's content and nonce open its commitment;
- each erasure is a genuine erasure record for its position, and nothing
  follows it on its chain.

**It does not prove:**
- **that the bundle holds every chain.** Omission is invisible without a record
  kept outside the writer.
- **that a chain is complete to its end.** An exporter can cut a chain back to
  an earlier checkpoint (or, under record trust alone, to any entry), dropping
  later entries, including an erasure. The erasure state describes the entries
  exported, not the chain. A checkpoint kept where the writer cannot rewrite it
  is what detects this.
- that an erased event's content is gone from anywhere. A bundle shows that an
  erasure was recorded, not that anything was deleted.
- that a timestamp is true time. The chain proves order; timestamps describe.
- which sink a chain came from. Keys don't bind it: a chain can be copied
  between sinks that share a key (sink-format §9.1).
- **anything against a writer who controls the evidence store and every signing
  key the verifier trusts.** Such a writer can rewrite history and export a
  newly valid bundle. External retention or witnessing of earlier checkpoints is
  what makes that detectable.
- anything about what happened after the export. **A bundle is a historical
  artifact:** a later erasure does not reach it, and an old bundle that passes
  says nothing about erasures since.

Every verifier MUST state these limits in its human-readable output (§10).

## 2. What a bundle reveals (privacy)

A bundle carries no subject, no source position, no index row, and no content
or nonce unless disclosed. It is still **pseudonymous personal data** (GDPR
Art. 4(5)), as sink-format describes for the shareable files:
- chain ids, which include the class, and are stable across exports;
- per-chain entry counts and microsecond timestamps: an activity timeline;
- erasures and when they were recorded;
- key ids, which link sinks that share a key and show key rotations. Use one
  record key per sink when bundles go to different parties.

Exports taken at different times can be compared: new activity, a chain that
stopped, an erasure that appeared. Within one bundle, as sink-format warns for
the shareable files:
- records committed in one batch carry timestamps microseconds apart across
  chains, which links those chains;
- equal erasure timestamps mean one erase call: usually one subject;
- a subject-scoped bundle with several chains groups them as one person, even
  without a name, and the grouping survives erasure.

The structured result (§9) is keyed by chain id, so it is pseudonymous too.

**Two things a later erasure cannot undo:**
1. **A subject-scoped bundle** (exported for one subject), together with
   knowledge of who it is about, **is the secret-index row** for that subject:
   subject → chains. Once it leaves the writer, erasing the subject does not
   reach the copy. Send it only to the subject, or to a recipient with a lawful
   basis.
2. **Disclosed content and nonces** outlive any later erasure of their subject
   (format-spec §8: while any copy of a nonce survives, the item is
   pseudonymised, not erased).

**A subject cannot get proof of their own erasure** through a subject-scoped
export in v1. Erasure removes the subject → chain link, by design.

Disclosed content may name third parties. Screening it is the exporter's
operator's job, not the format's.

## 3. Grammar

These **JSON-level** rules govern the bundle and **the text of every checkpoint
inside it**. In the bundle, a violation makes it **unreadable** (§9.1: `json`
or `duplicate-key`). In a checkpoint's text, it is `checkpoint-malformed`
(§7.6).

- **UTF-8**, valid, with no byte-order mark. JSON per RFC 8259, with these
  restrictions:
  - **Member names match exactly and case-sensitively.** No parser's case
    folding may be relied on. (A name that matches no defined member is a
    `structure` violation in the bundle: §4.)
  - **Duplicate member names, compared after unescaping**, are a violation.
    `"format"` and `"f\u006frmat"` are the same name.
  - Strings MUST NOT contain a lone surrogate, raw or as a `\u` escape.
  - **Nesting depth** is at most 8. The top-level value is depth 1; each array
    or object inside another adds one.
  - **Numbers,** where a member allows one (only in checkpoint text, §4.4), MUST
    match `0|[1-9][0-9]*` and be at most 2⁵³−1: no sign, fraction, exponent or
    leading zero. A number anywhere else is a member of the wrong JSON type
    (§4).

**Value shapes** (lowercase hex, canonical base64, timestamps) are not grammar.
They are judged only where each member is checked: `field-shape` (§7.1),
`malformed-signature` (§7.7), or checkpoint step a (§7.6). Canonical base64
means the standard alphabet with padding (RFC 4648 §4), no whitespace, and the
unused bits of the last character zero.

## 4. Structure

### 4.1 The bundle

```json
{ "format": "aleutian.proof.bundle.v1", "chains": [ … ] }
```

The top-level value MUST be an object. An exporter MUST write `format` first,
and a chain's members in the order `chain_id`, `entries`, `checkpoints`, so that
a verifier can stream. A verifier MUST accept any member order.

| Member | Type | Rule |
|---|---|---|
| `format` | string | exactly `aleutian.proof.bundle.v1` |
| `chains` | array of chain objects | zero or more. **Order is not meaningful** (§9.3) |

### 4.2 A chain

| Member | Type | Rule |
|---|---|---|
| `chain_id` | string | a sink chain id (sink-format §1) |
| `entries` | array of entry objects | the WHOLE chain, entry 0 first, in chain order. **Not empty** |
| `checkpoints` | array of strings | each the exact text of one checkpoint file, in number order (`0001.json` first). May be empty |

### 4.3 An entry

| Member | Type | Shape |
|---|---|---|
| `entry_id` | string | `^sink-[0-9a-f]{32}$` |
| `entry_type` | string | any string (§7.4 judges it) |
| `global_seq` | string | base-10, no sign, no leading zeros, 0 ≤ n ≤ 2⁶³−1 |
| `previous_hash` | string | empty, or 128 lowercase hex |
| `timestamp` | string | exactly `YYYY-MM-DDTHH:MM:SS.ffffffZ` (format-spec §4), AND a real UTC instant: year 0001–9999, a valid month and day (leap years included), hour ≤ 23, minute ≤ 59, second ≤ 59 |
| `content_hash` | string | 128 lowercase hex |
| `chain_hash` | string | 128 lowercase hex |
| `record_signature` | object, optional | `{"key_id": string, "signature": string}` (shapes judged in §7.7 only, under record trust) |
| `disclosed` | object, optional | `{"content": canonical base64 of 1–65,536 bytes, "nonce": 64 lowercase hex}` |

- A member that is missing, unknown, or of the wrong JSON type (including a
  non-object top level) makes the bundle unreadable: `structure` (§9.1).
- A string member whose value is outside its shape is the chain problem
  `field-shape` (§7.1). The rest of the chain is still checked.
- **Never in a bundle:** subjects, sources, index rows, keys of any kind,
  content or nonces of entries not disclosed.

### 4.4 Checkpoint text

Each element of `checkpoints` is the complete text of a **v6 anchor**
(format-spec §9), at most **1 MiB of UTF-8**. It satisfies §3 and has exactly
these members, each of this type and shape; `company_id` MUST NOT appear.
Anything else is `checkpoint-malformed` (step a, §7.6), all judged before any
other step:

| Member | Type | Shape |
|---|---|---|
| `version` | number | exactly 6 |
| `anchor_id` | string | non-empty, no `\|` |
| `chain_hash` | string | 128 lowercase hex |
| `created_at_ms` | number | ≥ 0 (advisory; never used in a decision) |
| `entry_count` | number | ≥ 1 |
| `previous_anchor_id` | string | non-empty, no `\|` |
| `range` | object | exactly `start_entry_id` and `end_entry_id`, each a string of sink entry-id shape |
| `signature` | string | canonical base64 of exactly 3309 bytes |
| `signing_key_id` | string | 32 lowercase hex |
| `subject` | string | non-empty, no `\|` |
| `verified_through` | number | ≥ 1 (format-spec §9.3) |

## 5. Limits

Every implementation MUST accept a bundle within these limits, and MUST treat a
bundle beyond them as unreadable (`too-large`), before any signature is
verified:

| Limit | Value |
|---|---|
| Bundle size | 256 MiB |
| Chains per bundle | 100,000 |
| Entries in the bundle, all chains together | 1,000,000 |
| Checkpoints in the bundle, all chains together | 100,000 |
| One checkpoint's text | 1 MiB (UTF-8 bytes) → `checkpoint-malformed` |
| Nesting depth | 8 → unreadable `json` |

These bound the work too: at most 100,000 checkpoint signatures, and record
signatures bounded by the bundle size (about 58,000 in 256 MiB).

## 6. Trust is the verifier's

The verifier is given two key sets, out of band:
- **checkpoint trust:** ML-DSA-65 public keys trusted for checkpoints;
- **record trust:** ML-DSA-65 public keys trusted for record signatures.

A dimension is **checked** exactly when its set is non-empty.

- **Key files** are PEM: **exactly one** block, label `PUBLIC KEY`, no headers,
  canonical base64 body, and nothing but whitespace after it. The block holds
  exactly the RFC 9881 SubjectPublicKeyInfo DER of a 1952-byte ML-DSA-65 key:
  the same bytes the key id hashes (format-spec §9.6). Any other file is a
  usage error (exit 2). This is what `proof keygen` and `proof sink init`
  write.
- A verifier MUST compute each key's id and match signatures by it.
- A key in both sets is allowed. The verifier SHOULD warn: one key for both
  roles means one compromise forges both.
- A bundle never adds a key.

## 7. Checks

Each chain is checked on its own, in this order. "Problem *p* at index *i*"
means the code *p* (§12), counted once per occurrence. Indexes are 0-based
positions in the chain's `entries` array, or in its `checkpoints` array for
`checkpoint-*` codes. **For every code, `first` is the lowest index at which it
occurred.**

### 7.1 Shape

1. `chain_id` matches sink-format §1, or problem `invalid-chain-id`. The chain
   is then keyed by position (§9.3), and its other checks still run.
2. Each entry's members are checked against §4.3's shapes, except
   `record_signature` (§7.7 only). An out-of-shape member is problem
   `field-shape` at that entry, at most once per entry. So is a `disclosed`
   member on an entry whose `entry_type` is not `sink.event`.
3. An entry is **well-formed** when `entry_id`, `global_seq`, `previous_hash`,
   `timestamp`, `content_hash` and `chain_hash` are all in shape. (`entry_type`
   and `disclosed` don't count.) **A malformed entry is not hashed, linked,
   classified or authenticated.** It counts as unauthenticated.
   **Any** well-formed entry whose `disclosed` is out of shape or misplaced is
   hashed, linked and authenticated, but gets no §7.4 outcome other than
   `after-erasure`: its `field-shape` is its outcome. (It still counts in §7.3
   if it holds the erasure hash.)
4. An `entry_id` equal to an earlier well-formed entry's is problem
   `duplicate-entry-id` at the repeat.

### 7.2 Links

For each well-formed entry *i*:
1. *i* = 0: `global_seq` is `"0"` and `previous_hash` is empty, or problem
   `first-entry`.
2. *i* > 0, **if entry *i*−1 is well-formed:** `global_seq` is entry *i*−1's
   plus one, or problem `sequence`; and `previous_hash` equals entry *i*−1's
   stored `chain_hash`, or problem `link`. If entry *i*−1 is malformed, neither
   is checked: its malformation is already a problem.
3. `chain_hash` equals chain hash v3 (format-spec §2.1) over the entry's own
   `previous_hash`, `global_seq`, `timestamp` and `content_hash`, or problem
   `chain-hash`.

### 7.3 Erasure positions

For each well-formed entry *i* ≥ 1 whose predecessor *i*−1 is well-formed, let
`EH(i) = hex(SHA-512("aleutian.sink.erasure.v1:" ‖ R))`, where R is the
sink-format §4.1 record built from **entry *i*−1's stored `global_seq`**. Entry
*i* **holds the erasure hash** when its `content_hash` equals `EH(i)`.

**E** is the index of the last entry that holds the erasure hash, **whatever its
label**, or −1 if none does. The label never decides what is an erasure: an
attacker controls the label.

### 7.4 Entries

| Entry (well-formed) | Outcome |
|---|---|
| index > E ≥ 0 (anything after the last erasure) | problem `after-erasure` |
| holds the erasure hash, `entry_type` `sink.erasure` | a **genuine erasure** |
| holds the erasure hash, any other `entry_type` (a relabelled erasure) | problem `erasure-invalid` |
| `sink.erasure` that does not hold the erasure hash (including entry 0) | problem `erasure-invalid` |
| `sink.event` before E, not disclosed | **erased** |
| `sink.event` before E, disclosed | problem `erased-event-disclosed`: the content outlived its erasure |
| `sink.event`, no erasure on the chain (E = −1), disclosed, opens | **opened** |
| `sink.event`, E = −1, disclosed, does not open | problem `modified` |
| `sink.event`, E = −1, not disclosed | **committed**: integrity checked, content not shown. Not a problem |
| any other `entry_type` | problem `entry-type` |

"Opens" means `hex(SHA-512("aleutian.commit.v1:" ‖ nonce ‖ SHA-512(content)))`
equals `content_hash` (format-spec §8). Rows are matched top to bottom; the
first match decides.

### 7.5 What a checkpoint covers

Checkpoint *k* covers entries 0 … `entry_count`−1.

### 7.6 Checkpoints

Checkpoints are checked in order. **The first failing step of any checkpoint is
its one problem, and it ends this chain's checkpoint checks.** Checkpoints
after it are not checked, and do not count. For checkpoint *k* (index *k*):

| Step | Check | Problem |
|---|---|---|
| a | The text satisfies §3 and §4.4 | `checkpoint-malformed` |
| b | The chain id is valid, and `subject` equals it | `checkpoint-subject` |
| c | `previous_anchor_id` is the previous checkpoint's `anchor_id` (the seed id `anchor_00000000-0000-0000-0000-000000000000` for *k* = 0); `entry_count` ≥ 1, and greater than the previous checkpoint's | `checkpoint-sequence` |
| d | `entry_count` ≤ the number of entries | `checkpoint-overreach` |
| e | Entries 0 … `entry_count`−1 are all well-formed; `range.start_entry_id` is entry 0's id and `range.end_entry_id` is entry `entry_count`−1's; `chain_hash` equals the anchor chain hash (format-spec §9.4) over the previous checkpoint's `chain_hash` (the seed hash for *k* = 0), the chain id, the two range ids, and entry `entry_count`−1's stored `chain_hash` | `checkpoint-binding` |
| f | **Checkpoint trust only:** `signing_key_id` is the computed id of a trusted checkpoint key | `checkpoint-unknown-key` |
| g | **Checkpoint trust only:** `signature` is canonical base64 of 3309 bytes, and verifies (ML-DSA-65, pure, empty context) over the canonical bytes (format-spec §9.2) | `checkpoint-bad-signature` |

Step e hashes only values already checked: the chain id (step b) and
well-formed entries. Without checkpoint trust, steps f and g don't run.

- `checkpoints` (the count) is the number that passed every step that ran.
- `unanchored` is the number of entries the last passing checkpoint does not
  cover (all of them if none passed).

### 7.7 Record signatures (record trust only)

Without record trust, this section doesn't run, and `record_signature` members
are neither problems nor evidence. With record trust, for **every** entry, the
first matching row decides:

| Condition | Problem |
|---|---|
| no `record_signature` | `unsigned` |
| `key_id` is not 32 lowercase hex, or `signature` is not canonical base64 of 3309 bytes | `malformed-signature` |
| `key_id` is not the computed id of a trusted record key | `unknown-key` |
| no envelope can be built: the entry is malformed; the chain id is invalid; `entry_type` is neither `sink.event` nor `sink.erasure`; or `previous_hash` is empty at a non-zero `global_seq`, or non-empty at 0 (sink-format §9.1). Reported **without** verifying | `bad-signature` |
| the signature does not verify (ML-DSA-65, pure, empty context) over the envelope below | `bad-signature` |
| otherwise | the entry is **record-authenticated** |

The envelope is sink-format §9.1's `aleutian.proof.record.v1`, with: 0x01 the
chain's `chain_id`; 0x02–0x07 the entry's `entry_id`, `entry_type`,
`global_seq`, `previous_hash`, `timestamp` and `content_hash`, **as the stored
strings** (never re-formatted from a parsed value); and 0x08 the
`record_signature`'s `key_id`.

### 7.8 Authentication

A well-formed entry is **checkpoint-authenticated** when checkpoint trust is
given and the last passing checkpoint covers it. It is **authenticated** when
it is checkpoint-authenticated or record-authenticated. Every other entry is
unauthenticated.

### 7.9 Erasure state

| State | When |
|---|---|
| `none` | E = −1, or entry E is not a genuine erasure (§7.4) |
| `recorded` | entry E is a genuine erasure, and neither of the below. Only as trustworthy as the bundle |
| `anchored` | E ≥ 0, the chain has no problem, and entry E is checkpoint-authenticated |
| `signed` | E ≥ 0, the chain has no problem, entry E is record-authenticated, and not `anchored` (sink-format §9.4, R6) |

"No problem" includes `after-erasure`, so `anchored` and `signed` both imply
that the chain, **as exported**, ends with its erasure (§1: a chain can be cut
back before its erasure, which then reads `none`).

### 7.10 The chain's verdict

`failed` if it has any problem; otherwise `unauthenticated` if any entry is
unauthenticated; otherwise `ok`.

## 8. Bundle-level checks

A `chain_id` that occurs more than once (compared as strings, valid or not) is
the bundle problem `duplicate-chain`. Its `count` is the number of extra copies
over all such ids (`[A, B, A, B, A]` counts 3), and `first` is the lowest
bundle position of an extra copy. **Every** copy of a duplicated id is keyed by
position (§9.3), and each is checked.

## 9. The result

### 9.1 An unreadable bundle

```json
{ "result": "aleutian.proof.bundle-result.v1", "readable": false, "reason": "<code>" }
```

An implementation determines **every** reason that applies, then reports the
**lowest-numbered** one, whatever order its parser met them in. It need not
hold entries beyond a count limit in memory to do so.

1. `too-large`: over the size limit;
2. `json`: not valid UTF-8 JSON under §3, including depth and lone surrogates;
3. `duplicate-key`;
4. `format`: the top level is an object, and `format` is missing or not
   exactly the v1 string;
5. `structure`: any other §4 violation (a non-object top level, an unknown or
   missing member, a wrong type, empty `entries`);
6. `too-large`: over a count limit.

Exit 3.

### 9.2 A readable bundle

```json
{
  "result": "aleutian.proof.bundle-result.v1",
  "readable": true,
  "checkpoint_trust": "checked",
  "record_trust": "not_checked",
  "verdict": "ok",
  "bundle_problems": [],
  "chains": {
    "app-logs.5707d4504f93a3d07abe3f0aa243bbf9": {
      "verdict": "ok",
      "erasure": "none",
      "counts": {
        "entries": 4, "events": 4, "erasures": 0,
        "opened": 1, "committed": 3, "erased": 0,
        "checkpoints": 1, "unanchored": 0,
        "authenticated": 4, "unauthenticated": 0,
        "checkpoint_authenticated": 4, "record_authenticated": 0,
        "record_signatures_present": 0
      },
      "problems": []
    }
  }
}
```

- The bundle `verdict` is `failed` if there is a bundle problem or a chain
  `failed`; otherwise `unauthenticated` if a chain is `unauthenticated`;
  otherwise `ok`. **A bundle with no chains is `unauthenticated`** (exit 4): it
  proves nothing, and an empty export must never read as a pass.
- `checkpoint_trust` and `record_trust` are each exactly `checked` or
  `not_checked` (§6).
- `problems` and `bundle_problems` list `{"code": …, "count": n, "first": i}`,
  one per code that occurred, sorted by `code` in byte order. `first` is the
  lowest index (§7, §8). `invalid-chain-id` has `first: null`.
- Every count is present, even when zero.

**Counts and their invariants:**

| Count | Definition |
|---|---|
| `entries` | length of `entries` |
| `events` | entries whose `entry_type` is `sink.event` |
| `erasures` | genuine erasures (§7.4) |
| `opened`, `committed`, `erased` | events with that outcome (§7.4) |
| `checkpoints`, `unanchored` | §7.6 |
| `authenticated`, `unauthenticated` | §7.8. **`authenticated` + `unauthenticated` = `entries`** |
| `checkpoint_authenticated`, `record_authenticated` | §7.8. Each ≤ `authenticated`. **They may overlap**, so they need not sum to `authenticated`; `authenticated` = the size of their union |
| `record_signatures_present` | entries carrying a `record_signature` member, **whether or not record trust was given**: so a reader can see a signing sink's bundle was checked without record trust (sink-format §9.4) |

Also `opened` + `committed` + `erased` ≤ `events`. The difference is events
with a problem, or malformed ones.

### 9.3 Keys and order

`chains` is an object keyed by `chain_id`. A chain whose id is invalid, or whose
id is duplicated (§8), is keyed `#<i>`, its 0-based position in the bundle's
`chains` array. Nothing else in the result depends on array order.
Implementations compare the parsed structure, never the bytes.

### 9.4 Evolution

The result's members, the trust values, the verdicts, the erasure states and
the problem codes are a **closed set** in `aleutian.proof.bundle-result.v1`.
Adding any of them is a new `result` id. A consumer MUST refuse a `result` id it
does not know, rather than guess.

## 10. Human-readable output

Free-form, but it MUST:
- say the verdict as `OK`, `FAILED` or `UNAUTHENTICATED`;
- state both trust dimensions;
- give each failing chain's problem codes;
- point to §1's limits, at least in one line.

On **every output channel**, including standard error, error messages and
stack traces (a JSON parser's error message can quote the input), it MUST NOT
print any member value from the bundle except a valid chain id: no content,
nonces, invalid ids, entry ids or malformed values. Indexes and codes only.

## 11. Command line

- SDKs: `aleutian-verify verify-proof-bundle <bundle.json> [--checkpoint-key F]… [--record-key F]… [--json]`.
  The verb is deliberately distinct from the SDKs' existing `verify` command,
  which checks platform bundles that carry their own trust manifest: the
  opposite of §6.
- proof: `proof sink verify-bundle <bundle.json> [--key F]… [--record-trust F]… [--json]`,
  the same flag names as `proof sink verify` (`--key` is checkpoint trust).

Without `--json`, the output is §10's; with it, exactly the §9 JSON on
standard output.

| Exit | Meaning |
|---|---|
| 0 | `ok` |
| 1 | `failed` |
| 2 | usage: bad arguments; a missing or unreadable bundle file or key file; an invalid key file |
| 3 | an unreadable bundle (§9.1) |
| 4 | `unauthenticated` |
| 5 | an internal error in the verifier: never a verdict on the bundle |

## 12. Problem codes (the complete v1 list)

| Code | Level | Meaning |
|---|---|---|
| `duplicate-chain` | bundle | a chain id occurs more than once |
| `invalid-chain-id` | chain | not a sink chain id |
| `field-shape` | entry | a member outside its §4.3 shape |
| `duplicate-entry-id` | entry | an entry id repeats within the chain |
| `first-entry` | entry | entry 0 is not sequence 0 with an empty previous hash |
| `sequence` | entry | not one more than the previous entry's sequence |
| `link` | entry | `previous_hash` is not the previous entry's stored chain hash |
| `chain-hash` | entry | the chain hash does not recompute |
| `entry-type` | entry | neither `sink.event` nor `sink.erasure` |
| `erasure-invalid` | entry | a `sink.erasure` without the erasure hash, or the erasure hash under another label |
| `after-erasure` | entry | an entry after the chain's last erasure |
| `erased-event-disclosed` | entry | content disclosed for an event before the erasure |
| `modified` | entry | a disclosed event's commitment does not open |
| `checkpoint-malformed` | checkpoint | not a §3/§4.4 v6 anchor, or over 1 MiB |
| `checkpoint-subject` | checkpoint | `subject` is not the chain id |
| `checkpoint-sequence` | checkpoint | does not link to the previous checkpoint, or does not grow |
| `checkpoint-overreach` | checkpoint | covers more entries than the bundle holds |
| `checkpoint-binding` | checkpoint | its range or anchor chain hash does not match the entries |
| `checkpoint-unknown-key` | checkpoint | signed by a key not trusted for checkpoints |
| `checkpoint-bad-signature` | checkpoint | the signature is malformed or does not verify |
| `unsigned` | entry | record trust given, no record signature |
| `malformed-signature` | entry | a record signature out of shape |
| `unknown-key` | entry | a record signature by a key not trusted for records |
| `bad-signature` | entry | the record signature does not verify over the entry as stored |

## 13. Versions

v1 means chain hash v3, v6 anchors, the `record.v1` envelope and ML-DSA-65,
and nothing else. Any other chain, anchor, record or algorithm version is a new
bundle `format`, never a negotiation inside v1.

## 14. Differences from folder verification (sink-format §6)

| Folder | Bundle | Why |
|---|---|---|
| Index accountability, leftover rows, removed chains | not checked | a bundle carries no index or secret rows |
| A missing content row is a problem (MISSING) | an undisclosed event is `committed`, not a problem | disclosure is the exporter's choice (B5) |
| Erasure decided by label and hash | by hash, whatever the label; a relabelled erasure is `erasure-invalid` | the label is the attacker's to choose |
| Checkpoint series: first problem stops it | the same | |
| A checkpoint key is always required | checkpoints are checked structurally without one (steps a–e), and counted; their signatures are not, and nothing is authenticated by them | a bundle may be checked under record trust alone |
| Events after the last erasure are judged like any event | `after-erasure` | the sink never writes after an erasure (U3) |
| `erased` means content and nonce are absent from the folder | `erased` means not disclosed in the bundle | a bundle cannot show absence elsewhere (§1) |
| Checkpoint files are parsed leniently (Go's case folding, last duplicate key wins) | checkpoint text is held to §3 and §4.4 (exact names, no duplicates) | one grammar for every implementation |
| An entry of another chain format, or a timestamp outside years 0001–9999, is judged in the folder | `proof sink export` refuses to export it (unrepresentable) | a bundle verifier could only call it a hash mismatch or a shape problem |
| Prose problems, one link break reported | fixed codes, every occurrence counted, `first` index | cross-language comparison (B4) |
| No `unauthenticated` state | `unauthenticated` (exit 4) | a bundle travels; provenance must come from trusted keys (U1) |

## 15. Conformance

An implementation conforms when it reproduces every case of
`fixtures/testdata/bundle_v1_vectors.json`. That file is computed independently
from this document, and **MUST** contain at least:
- fixed key seeds, with their public keys and key ids, and valid checkpoint and
  record signatures made with them (deterministic ML-DSA-65);
- an ML-DSA signature made with a non-empty context, and one made with
  HashML-DSA: both MUST fail (they catch pre-standard libraries);
- one case per problem code, and one per unreadable reason;
- `ok`, `unauthenticated` and `failed` bundles, each trust combination, and
  each erasure state;
- a relabelled erasure, an append after an erasure, and a disclosure of an
  erased event;
- every §3 grammar case: case-variant names, escaped duplicate names, numbers
  out of grammar, lone surrogates, depth 8 (accepted) and 9 (refused);
- every value-shape case: uppercase hex, non-canonical base64, and impossible
  timestamps (`02-30`, second `60`, year `0000`), in entries and in checkpoint
  text;
- bundles with **several** unreadable reasons at once, to pin §9.1's
  precedence;
- an empty bundle (`unauthenticated`), a tail-truncated chain, and a swapped
  inner entry id under checkpoint-only trust (`ok`, as §1 says);
- a bundle exported by `proof sink export` from a real sink.

The result compared is §9's structure: trust dimensions, verdicts, erasure
states, counts, and problem codes with their counts and `first` indexes.
