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

**Vector set of this release:** `MANIFEST.json` SHA-256
`5da46887eb03877df823bf5f8a8c50ec06572e9e1db40163081b4774f314a10d`.

## What each file pins

| File | Spec | Frozen | What an implementation must do |
|---|---|---|---|
| `chain_v4_vectors.json` | format-spec §2.0, §2.5, §5.0 | | reproduce every leaf and chain hash; refuse every `reject` case |
| `anchor_v7_canonical_vectors.json` | format-spec §9 | | reproduce canonical bytes and chain hashes; verify every signature with the v7 context; refuse every `reject` text |
| `verify_verdict_v4_vectors.json` | format-spec §2.0, §2.5, §5.0, §5.5, §9.7 | | the same verdict, first break and counts for every chain; the same outcome for every v7 bind |
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
(`sdk/verification-python`, 1,783 tests) and the JavaScript SDK
(`sdk/verification-js`, 1,599 tests) were written from the specifications,
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

## What the shared set does not cover

Merkle roots and inclusion proofs are pinned only as golden values. An anchor
*series* is pinned only through the verdict vectors' binds (a series needs
signatures). The hosted platform's `{"entries": [...]}` wrapper and camelCase
member names are read only by the SDKs.
