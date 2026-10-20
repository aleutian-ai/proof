# Conformance

**What every implementation of the formats must pass, and which ones do.**

The vectors in [`fixtures/testdata/`](../fixtures/testdata) are the contract
(docs/decisions.md D18). Each is written by a Python script from the
specifications, never by an implementation under test, and
[`fixtures/MANIFEST.json`](../fixtures/MANIFEST.json) records each file's
SHA-256. An implementation vendors the files with `scripts/sync-vectors.sh
--write <dir>`, checks them with `--check`, and states in its README the
SHA-256 of the `MANIFEST.json` it last passed. `scripts/release-check.sh --sdk
<dir>` fails a release when an SDK states another set.

**Vector set of this tree:** `MANIFEST.json` SHA-256
`304583d41eca4e74e2fb19cd799f499e663d60d0366bb70f4f712db903264d3c`. It is
v0.5.0's set (`62b96a47373c1cf41b21af29ac23b9760eee205b00933d26769efcee09b5c662`)
plus `xwing_spec_vectors.json`; no other file changed.

## What each file pins

| File | Spec | Frozen | What an implementation must do |
|---|---|---|---|
| `chain_v4_vectors.json` | format-spec §2.0, §2.5, §5.0 | | reproduce every leaf and chain hash; refuse every `reject` case |
| `anchor_v7_canonical_vectors.json` | format-spec §9 | | reproduce canonical bytes and chain hashes; verify every signature with the v7 context; refuse every `reject` text (some are bytes that are not UTF-8, given as `text_base64`) |
| `verify_verdict_v4_vectors.json` | format-spec §2.0, §2.5, §5.0, §5.5, §9.7 | | the same verdict, first break, counts and number of breaks for every chain; the same reading or refusal of every entries file; the same outcome for every v7 bind |
| `bundle_v2_vectors.json` | bundle-format §16 | | the same §9 result for every bundle |
| `record_v2_vectors.json` | sink-format §9.1 | | reproduce every envelope; refuse every `reject` case; the stated validity of every signature |
| `chain_v3_vectors.json` | format-spec §2.1 | ✓ | as for v4 |
| `chain_vectors.json` | format-spec §2.3 | ✓ | reproduce every v2 chain hash |
| `anchor_v6_canonical_vectors.json` | format-spec §9.2 | ✓ | reproduce canonical bytes |
| `anchor_v4_canonical_vectors.json` | format-spec §9.2 | ✓ | reproduce canonical bytes (v1, v3, v4) |
| `anchor_chain_hash_vectors.json` | format-spec §9.4 | ✓ | reproduce every v1–v6 anchor chain hash |
| `verify_verdict_vectors.json` | format-spec §4, §5.5, §9.4, §9.8 | ✓ | as for v4, for v2/v3 chains and v6 anchors |
| `bundle_v1_vectors.json` | bundle-format §1–§15 | ✓ | as for v2 |
| `record_v1_vectors.json` | sink-format §9.1 | ✓ | as for v2 |
| `keyid_vectors.json` | format-spec §9.6 | | reproduce every key id |
| `commitment_vectors.json` | format-spec §8 | | reproduce every commitment; refuse every `reject` case |
| `merkle_golden.json` | format-spec §7 | | reproduce roots, inclusion and consistency proofs |
| `v3_golden_capture_request.json` | format-spec §6 | | reproduce the canonical bytes and content hash |
| `xwing_spec_vectors.json` | draft-connolly-cfrg-xwing-kem | | not ours: the specification's own vectors. Recompute their published SHAKE128 checksum (`checksum_shake128`, over the vectors rendered in the spec's `test-vectors.txt` layout), derive `pk` from `sk`, and decapsulate `ct` to `ss` |

Frozen files describe formats that are verified forever and never written
(format-spec §2.6, bundle-format §16): their cases will never change.

## Who passes what

| File | Go (this module) | Python SDK | JavaScript SDK |
|---|---|---|---|
| `chain_v4_vectors.json` | ✓ | ✓ | ✓ |
| `anchor_v7_canonical_vectors.json` | ✓ | ✓ | ✓ |
| `verify_verdict_v4_vectors.json` | ✓ | ✓ | ✓ |
| `bundle_v2_vectors.json` | ✓ | ✓ | ✓ |
| `record_v2_vectors.json` | ✓ | ✓ | ✓ |
| every frozen file, and the rest | ✓ | ✓ | ✓ |

Each column is this release's vector set, in full: the Python SDK
(`sdk/verification-python`, 1,844 tests) and the JavaScript SDK
(`sdk/verification-js`, 1,652 tests) were written from the specifications,
without reading this module's Go code, and state the set's digest in their
READMEs. Writing them found five places where the specification's wording
was looser than its vectors (how §5.5 counts an entry broken at step 2, and
which value limit a bundle with an unknown `format` gets); the text was
corrected, two vectors were added to pin the first, and all three
implementations agree on both.

An independent reader, given only the specifications, reproduced every case of
the first three files with 0 disagreements before the Go implementation was
written (2026-10-16). The bundle v2 vectors were written the same way; the Go
verifier passed all of them unchanged.

The v4 verdict vectors' `breaks` come from a walk of §5.5 written in the
vectors' own script from the spec's text, which also checks every
hand-written verdict against itself. The pre-tag review of v0.5.0
(2026-10-17) found five places where the implementations or the text
disagreed on what a walk reports after a break, how an entry after a
malformed chain hash is linked, and what a reader refuses before any check
(text that is not UTF-8, lone surrogate escapes, `null`, `-0`); the text was
settled, the vectors pin each, and all three implementations agree.

## What the shared set does not cover

Merkle roots and inclusion proofs are pinned only as golden values. An anchor
*series* is pinned only through the verdict vectors' binds (a series needs
signatures). The hosted platform's `{"entries": [...]}` wrapper and camelCase
member names are read only by the SDKs.
