# proof: review round 2

Second pass over `github.com/aleutian-ai/proof` at `6a77fa3`, 2026-10-11. Numbering continues from `proof-review-fixes.md` (items 1-33).

**Buckets covered:** format versions and identity · sink evidentiary claims · fuzzing and differential tests · conformance vectors, releases and supply chain · MCP server run live · scale and parallel writers.

**Status tags**

- `REPRODUCED`: demonstrated by a test, a fuzz crasher, or the running binary.
- `LIVE`: reproduced against the running MCP server over stdio (built from the `cmd/proof-mcp/v0.3.1` code against library `v0.3.0`, with only the `go` directive lowered to 1.24).
- `READ`: verified by reading the code.
- `PINNED`: the behaviour is deliberate (a comment, decision record or vector says so). Listed as a design risk, not a bug.
- `SUSPECTED`: reasoned, not demonstrated.

**Not covered:** bbolt file-byte fuzzing, `xwing`/`mlkem` decapsulation fuzzing, the sink commit/erase state machines under fuzz, in-process goroutine stress of the linker, disk-full and kill-mid-commit behaviour, and the Python/JS SDKs (not in this repo).

---

## Corrections to round 1

Your reviewer's objections were checked against the code and are right.

| Item | Correction |
|---|---|
| 23 keywrap | Withdrawn as a code finding. `keywrap.go:26,70` already say the key is public and the check is corruption-only; the validation order is marked "security-critical — do not reorder" (`:135`). Only `doc.go`'s word "authenticates" was wrong. Do not reorder. |
| 25 canonical JSON | U+2028/2029 escaping and integers above 2^53 are pinned by vectors and intended. What remains: the stale comment, duplicate keys, `-0`; the last two need the Python and JS ports to change in step. |
| 17 verify-bundle | Finding stands; the suggested fix was wrong. The sink export is a single `bundle.json` (`aleutian.proof.bundle.v1`); package `bundle` verifies a directory against a manifest and is unrelated. The verifier must be written against `docs/bundle-format.md`. See 52. |
| 28 CI | Ignore the GitHub workflow suggestion (it conflicts with your standing rule). The underlying need is running tests on Linux; a local script in a Linux container covers it. Copy the repo into the container's own filesystem, since a mounted macOS folder may not reuse inodes the way ext4 does (finding 10 depends on that). |
| 6 MCP paths | Narrowed after running it; see below. |

## Verdicts on round-1 items that were unverified

| Item | Verdict | Detail |
|---|---|---|
| 6 MCP path root | `LIVE`, narrower than written | Absolute paths and symlinks are accepted with no root check, and the error text distinguishes missing / not a regular file / unparseable, so it is an existence-and-type oracle. Error text is otherwise sanitized: `verify_chain` returns only "line 1 is not a valid entry". One small content leak: `verify_anchor` with `anchor_path=/etc/passwd` returns `invalid character 'r' looking for beginning of value`, the file's first byte. The "returns names of unlisted files" claim for `verify_bundle` was not reproduced. |
| 7 `proven` text on a broken chain | `LIVE` | A tampered chain returns `"verdict":"BROKEN"` with three `hash_mismatch` breaks and `"proven":"Nothing was edited by anyone unable to also rewrite every entry after it."` in the same object. |
| 8 `key_trust` chosen by caller | `LIVE` | The same key and anchor return `trust: self`, `provided` or `platform` (with "a third party attests to this chain") according to the argument alone. |
| 27 key parse errors | `LIVE`, sound | A non-key file named as `public_key_path` returns "no PEM block" with no file content. |
| 13 anchor binding | `REPRODUCED` | All four parts hold. `Bound=true, Outcome=bound` is returned with a signature error (`verify/anchor.go:282-285`); `BindTenantMismatch` is dead code; `verified_through=999999` with `entry_count=10` verifies; `previous_anchor_id` is unchecked (see 39). Fix note: the existing comment wants bind and signature kept distinguishable, so add a `signature_invalid` outcome with `Bound=false` instead of zeroing the result. Put `0 < verified_through <= entry_count` in `ValidateVersionInvariants`, after checking historical v4 anchors. |
| 19 checkpoint fsync | `READ` + consequences `REPRODUCED` | `writeNew` (`sink/folder.go:143-158`) has no `Sync`, and a new `anchors/<chain>/` directory is never synced. With a zero-length `0002.json`: Verify fails the chain, Checkpoint refuses it permanently, and Export emits `""` as a checkpoint (`export.go:549-553`). The only recovery is deleting the file by hand. Power loss itself was not simulated. Also unsynced: keygen and `sink init` key files (`keygen.go:175,180`). |
| 24 keyfile | Mostly `PINNED` | The ML-DSA both-form and ML-KEM skips are documented (`consistency.go:32-47`) and enforced by `deps_test.go:44-47`. Real remainder is item 61. |
| 20 MCP resource bounds | Not rerun | Still `READ`. |

---

## New findings: fix first

### 34. A forged mid-chain erasure destroys checkpointed evidence and Verify passes
`REPRODUCED` · `sink/verify.go:720-730`, `:1185-1191` · `sink/commit.go` (`resolvePair`, ~L290)

- **Problem:** the erasure record is keyless. Verify takes the last entry holding the erasure hash anywhere in the chain and counts everything before it as lawfully erased. `resolvePair` checks only the tail for an erasure.
- **Attack (write access to `evidence.db` and `.secrets` only, no key, no index edit):** append a forged `sink.erasure` entry plus one filler event with a valid commitment, then delete the earlier content and nonce rows.
- **Observed:** Verify reports `OK`, `Index: live`, `Erased: 3`, no problems. The writer keeps committing and the next Checkpoint signs over it.
- **Context:** `bundle-format.md` §14 pins the folder verifier's leniency on the premise that "the sink never writes after an erasure"; the folder verifier never enforces that premise.
- **Fix:**
  - [ ] In `verifyChain`, make any entry after a genuine erasure a problem.
  - [ ] Make an erasure on a chain with a live index row a problem wherever it sits.
  - [ ] Have `resolvePair` scan for any erasure, not only the tail.

### 35. `Checkpoint` signs state it has not verified
`REPRODUCED` · `sink/checkpoint.go` ~L95-140

- **Problem:** before signing, it runs only the hash walk and the existing series check: no content, index or record-signature checks, and nothing remembered outside the folder.
- **Observed:**
  - A forged tail erasure with its index row removed verifies as `erased-unanchored` (pinned as possibly forged in `sink-format.md` §6). After a routine checkpoint the chain reads `erased` with `Checkpoints: 2`. The documented advice to checkpoint after erasing is the step that launders it.
  - After `rm -r anchors/<chain>`, Checkpoint writes a fresh `0001.json` over whatever the chain now holds, and Verify passes.
- **Fix:**
  - [ ] Run the full per-chain verify inside Checkpoint; refuse or flag `erased-unanchored` chains the caller did not just erase.
  - [ ] Have `EraseSubject` return or sign its erasure entry ids.
  - [ ] Keep a high-water mark (chain → last checkpoint number and hash) outside the folder, or accept it as input, and refuse a series that restarts.

### 36. Poisoning `.sources` silently suppresses future records
`REPRODUCED` · `sink/commit.go` (`dropDuplicates`, ~L350-362) · `sink/paging.go` (`openPage`)

- **Attack:** write rows mapping predictable future sources to any existing `(entry id, seq)`.
- **Observed:** `Commit` returns `Committed=true, Duplicate=true`, nil error, for brand-new content. Nothing is appended, a queue consumer acks, and Verify stays `OK`.
- **Fix:**
  - [ ] Store a digest of the content hash (or an HMAC) in the position row and compare on dedup.
  - [ ] Add a Verify step: every source row points at an existing entry, at most one source per entry.

### 37. `merkle.VerifyInclusion` never returns for `tree_size > 2^62`
`REPRODUCED` (fuzz crasher) and `LIVE` · `merkle/merkle.go:157` · `cmd/proof-mcp/main.go:483`

- **Problem:** `k<<1` overflows to 0 and the loop spins.
- **Live result:** one `verify_inclusion` call with `tree_size = 2^62 + 5` and a one-element proof never answers, and the process holds a CPU core at 99.5% indefinitely. The server keeps answering other calls, so each such call costs one core until restart.
- **Fix:**
  - [ ] Reject `treeSize > 1<<62` (or bound the loop on bit length).
  - [ ] Bound `tree_size` and proof length in the MCP tool schema.

### 38. `anchor/build` will sign a mid-chain segment as if it were the whole chain
`REPRODUCED` · `anchor/build/build.go:203-265`

- **Problem:** `FromWalker` accepts a walker started with `Options.PreviousHash`. For entries 5..9 it emitted `entry_count=5, start=e5`; `Walker.VerifyAnchor` then returns `Bound=true` with third-party wording. Spec §9.1 defines `entry_count` as counted from the chain's first entry.
- **Also:** `Previous` is unchecked. A 3-entry anchor for one subject chained onto a 20-entry anchor of another subject, and verified.
- **Fix:**
  - [ ] Refuse a walker with non-empty `PreviousHash`.
  - [ ] Require `previous.Subject == subject` and `previous.EntryCount < count`.

### 39. No anchor-series rules outside `sink`
`REPRODUCED` · enforced only at `sink/verify.go:1083-1100`

- **Accepted by `verify.VerifyAnchor`, `proof verify --anchor` and the MCP tool:** a genesis anchor with a non-seed `previous_anchor_id`; a second anchor claiming the seed id while hashed onto anchor 1; `created_at_ms = -5` and going backwards.
- The limitation is noted at `verify/anchor.go:135-137`, but no exported function does the walk.
- **Fix:**
  - [ ] Export the series check from `verify` (for example `VerifyAnchorSeries`) and have `sink` call it.

### 40. `proof commit` accepts a tombstone-shaped entry and the chain is then permanently `BROKEN`
`REPRODUCED` with the built binary · `linker/order.go:45`

- **Input:** `entry_id:"tomb_…"`, `entry_type:"tombstone"` with an ordinary content hash. The linker checks only id, `ingested_at` and duplicates.
- **Result:** `proof verify` reports `BROKEN invalid_tombstone` from then on.
- **Fix:**
  - [ ] Reject reserved tombstone ids and types on the append path.

---

## New findings: next tier

### 41. Anchor JSON parsing is laxer than the signed form
`REPRODUCED` · `anchor/subject_json.go:121` (`UnmarshalJSON`) · `cmd/proof/main.go:346,359`

- All verify with `Bound=true, sig=true`: a v6 anchor spelled with `company_id`; unknown unsigned fields (`root_hash`, `tree_size`, `revoked`); case-variant keys (`"VERSION"`, `"ENTRY_COUNT":8`); duplicate keys, last wins (`{"entry_count":1,"entry_count":8}`).
- `anchor/anchor.go:122-125` explains that v5 fields were removed because an unread field is one a caller can set and believe was signed. The parser re-admits that.
- Case and duplicate handling probably differ in the Python and JS verifiers (not tested).
- [ ] `DisallowUnknownFields`, exact-case matching, duplicate-key rejection, and require the subject key that matches `version`. Entry files load the same lenient way.

### 42. The tombstone branch runs before the format dispatch
`REPRODUCED` · `verify/verify.go:338-348` · extends finding 1

- A tombstone with `format_version: 99`, or a v3 tombstone carrying `run_id`/`sequence_num`, returns `INTACT`.
- [ ] Validate version and field misuse before the tombstone return.

### 43. Sink export discloses content without checking it opens its commitment
`REPRODUCED` · `sink/export.go:647-660`

- Tampered content exports with `Disclosed: 3` and no error. The doc comment says a damaged event fails the export.
- [ ] Run `commitment.Verify` before disclosing.

### 44. Side files without buckets abort Verify instead of producing a finding
`REPRODUCED` (library); CLI exit code `READ`

- An empty-but-valid bbolt `.secrets` or `.subjects` makes Verify return an error, which the CLI maps to exit 3, not a tamper verdict.
- `PINNED` (`signatures.go:113-118`, `sink-format.md` §9.2): an empty `.signatures` makes a signing sink look unsigned and Verify is OK; only `--record-trust` notices. Worth a louder warning.
- [ ] Report a missing bucket as a problem with exit 1.

### 45. Timestamps and ids the linker accepts but the rest of the system cannot carry
`REPRODUCED` · `chainformat/chain_hash.go:296-304` · linker

- Chain-hash functions panic (`index out of range [-1]`) on a year with 11 or more digits, e.g. `time.Unix(1<<60,0)`. Library only.
- The linker accepts years outside 0-9999; export writes `10000-…` or `-0183-…`, verify says `invalid_timestamp`, re-import stores year 0001. Extends finding 26.
- The linker accepts entry ids that are not valid UTF-8; export rewrites them to U+FFFD, so export → import → export is not byte-identical.
- [ ] Validate year range and UTF-8 on the append path; return an error instead of panicking.

### 46. Signature base64 is malleable
`REPRODUCED` · `anchor/verify.go:263`

- A signature with CR/LF inside the base64 still verifies. Spec §9.5 says standard base64 with padding.
- [ ] `base64.StdEncoding.Strict()` and reject CR/LF.

### 47. Key id is a free label on the verify side
`REPRODUCED`; partly `PINNED` (anchor-model "two namespaces")

- `NewKeyRing` accepts `""` and mislabelled ids; `VerifySignature` accepts an empty `signing_key_id` that `SignCanonical` refuses. The CLI registers the supplied key under whatever id the anchor claims (`cmd/proof/verify_anchor.go:234`).
- Spec §9.1 says "32 lowercase hex"; anchor-model §6a says assigned labels are legal.
- [ ] Reject the empty id; reconcile the two documents.

### 48. `bundle.VerifyDir` accepts one file under several spellings
`REPRODUCED` · `bundle/verify.go:152`

- `a.txt`, `./a.txt`, `x/../a.txt`, `a.txt/` give 1 file, 4 rows, `FilesChecked=4`, `Intact`.
- [ ] Key on the cleaned path and reject aliases.

### 49. v2 `global_seq`: the two anchor verifiers disagree
`REPRODUCED` · `verify/anchor.go` (`walkForHead`)

- With one edited v2 `global_seq`, `verify.VerifyAnchor` says bound and `Walker.VerifyAnchor` says `chain_broken`. That v2 does not authenticate `global_seq` is documented (`format-spec.md:101`); the API disagreement is not.
- [ ] Make `walkForHead` apply the same sequence-gap rule.

### 50. A keyless bind is reported as `INTACT_ANCHORED`
`PINNED` · `verify/verify.go:74-80` ("Binding is the bar, not the signature")

- The constant's doc says truncation is ruled out, which an attacker-minted unsigned anchor does not provide.
- [ ] Consider a distinct verdict string for unsigned binds. No behaviour change requested otherwise.

### 51. The plain-store CLI holds everything in memory
`REPRODUCED` (measured, Linux/amd64, bbolt on ext4)

| Operation | 100k entries | 1M entries |
|---|---|---|
| `commit` | 2.4 s, 413 MB | 21.1 s, 3,978 MB |
| `export --jsonl` | 1.0 s, 240 MB | 10.8 s, 2,331 MB |
| `verify` (JSONL) | 0.7 s, 146 MB | 9.0 s, 1,389 MB |

- Time is linear; memory is roughly 1.4-4 KB per entry. The 1M-entry database is 1,467 MB on disk.
- A streaming `verify.Walker` exists but `proof verify` does not use it for input.
- [ ] Stream `verify` and `export`; batch `commit`; document the practical limit meanwhile.

### 61. keyfile accepts leading bytes and PEM headers
`REPRODUCED` · `keyfile/private.go`, `keyfile/public.go:105-110`

- Arbitrary text before the PEM block is accepted (only trailing bytes are checked). A block with `Proc-Type: 4,ENCRYPTED` parses.
- [ ] Reject leading bytes and any PEM header; use a constant-time compare for `z`.

---

## The evidence for correctness

### 52. No Go test judges the 114 bundle cases
`REPRODUCED` · `sink/bundle_vectors_test.go:19-25`

- The test checks keys and signature validity with circl and says itself that it does not judge expected results. Go has no `bundle.v1` verifier at all, so sections §3, §5 (verifier side), §7-§10 of `bundle-format.md` are unimplemented in Go. README:579 "all three held to the same conformance vectors" is untrue for bundles.
- [ ] Write the Go bundle verifier and run every case through it (this also closes 17), or state that Go is producer-only.

### 53. "Expected outputs are data, never regenerated by an implementation" is false for several files
`REPRODUCED` · README:432, `format-spec.md` §10

- `merkle_golden.json` and `v3_golden_capture_request.json` are written by the Go code under test via `UPDATE_GOLDEN=1` (`merkle/golden_test.go:126`, `chainformat/capture_v3_test.go:237`).
- `anchor_chain_hash_vectors.json` says "GENERATED BY THE PRODUCER"; `chain_vectors.json` came from the JS verifier.
- `commitment_vectors.json` is attributed to `independent-vectors.py`, but no script at any commit writes it.
- `REGRESSION_SIGNATURE` is labelled not independent because "Python has no ML-DSA"; dilithium-py reproduces it byte for byte.
- The stored values themselves are all correct: an independent Python computation from the spec text reproduced them.
- [ ] Move these files into the Python scripts, drop the `UPDATE_GOLDEN` write paths, correct the two doc claims.

### 54. Two of the three v2 vectors are refused by the checked API
`REPRODUCED` · `fixtures/testdata/chain_vectors.json`

- They use 64-hex `content_hash`; `chainformat.ComputeChainHash` requires 128. The test passes only because it calls `ComputeChainHashUnchecked`.
- [ ] Replace with 128-hex inputs computed in Python.

### 55. The commitment reject vectors do not test nonce length
`REPRODUCED` by computation

- For the 0/31/33-byte nonce cases the stored commitment is not the hash of that nonce, so an implementation with no length check also fails verification and passes the vector.
- [ ] Store the commitment a non-checking implementation would compute, so only refusal passes.

### 56. Vector coverage holes line up with the round-1 verifier findings
`READ`

- No chain-level verdict vectors: tombstone in chain, `format_version` dispatch, v2 run grouping, first-entry `global_seq`.
- Merkle: inclusion for n=13 only, 10 consistency pairs, no negative cases, no frontier encoding.
- Leaf: 3 ASCII vectors with the legacy `company_id` key; nothing for NFC or the size caps.
- Anchors: no v5 or invariant rejects; no standalone signed anchor. Key ids: no ML-KEM.
- [ ] Add verdict vectors for each of findings 1-3, 11, 12, 41, 42 as they are fixed.

### 57. The manifest detects drift, not tampering
`READ`

- Both Python scripts rewrite a vector and its `MANIFEST.json` entry in one run. Tags are annotated but unsigned and no commits are signed.
- `sync-vectors.sh` needs `shasum`, which minimal images lack.
- [ ] Sign tags; publish the manifest digest in release notes; fall back to `sha256sum`.

---

## Releases and supply chain

### 58. What `go install …@latest` gives a user today

`@latest` resolves to library `v0.3.0` and `cmd/proof-mcp/v0.3.1`, not HEAD.

| Round-1 finding | In v0.3.0? |
|---|---|
| 1 tombstone forgery | yes (`REPRODUCED`) |
| 2 unauthenticated id/type/timestamp | yes (`REPRODUCED`) |
| 3 no field-format validation | yes (`REPRODUCED`) |
| 4 bbolt crash, exit 2 | yes (`REPRODUCED`) |
| 5 `forget` | yes (success on missing entry `REPRODUCED`; residue `READ`) |
| 9 tracked binary | yes |
| 10 sink tests on Linux | no (no `sink` package at the tag) |
| 11 consistency size check | yes (`REPRODUCED`) |
| 12 frontier level bound | yes (`REPRODUCED`) |

- `cmd/proof-mcp` at `v0.3.1` is byte-identical to HEAD, so findings 6-8 and 37 are what users install.
- `v0.3.0` builds and passes its own tests.
- `proof sink …` verbs appear in `sink/README.md`, the example READMEs and `docs/`; none work with `@latest`.
- proof-mcp built and passed its tests under Go 1.24.7 with only the `go` line lowered, so the "requires Go 1.25" statement may be stricter than necessary (`SUSPECTED`; local dependency copies were used).

### 59. Binaries carry no checkable version; images are unsigned; licence notices are missing
`REPRODUCED` / `READ`

- No `proof version` or `--version` (exit 2). `.dockerignore` excludes `.git`, so the image binary reports `(devel)`.
- `publish-image.sh` uses one `VERSION` for both images though the modules are tagged separately; nothing signs or attests the image.
- The container copies only `/LICENSE`. circl, `x/*`, oauth2, uritemplate and the Go runtime are BSD-3; bbolt, segmentio and jsonschema-go are MIT. All require their notice in binary redistributions.
- [ ] Add a `version` verb reading `debug.ReadBuildInfo`; pass `-ldflags -X` in the Dockerfile.
- [ ] Generate a third-party licences bundle and copy it into both images before the first push.
- [ ] Sign images.

### 60. The tracked `/proof-mcp` binary embeds local build details
`REPRODUCED` (`go version -m`) · adds to finding 9

- go1.25.6, `vcs.modified=true` at `16b4315`, `CGO_ENABLED=1`, no `-trimpath`. It embeds `/Users/jin/GolandProjects/proof` and `/Users/jin/go/pkg/mod`. It is a dirty-tree build from 2026-09-21 that predates the v0.3.x MCP code.

### 62. Dependency posture
Advisory knowledge here is from memory; the vulnerability database was not reachable.

- `x/crypto v0.30.0` is below the fixes for two `ssh` advisories (fixed in 0.31.0 and 0.35.0). `ssh` is not imported (`REPRODUCED` with `go list -deps`), so `govulncheck` would be clean, but module-level scanners will flag every consumer. Bump it if a newer release still declares go 1.24.
- No advisories known for the imported packages of circl 1.6.3, bbolt 1.4.3, x/text 0.21.0, x/sys 0.30.0. go-sdk v1.7.0's status could not be confirmed.
- `deps_test.go` runs `go list -deps` without `-test` and skips the root package, so test-only imports are unenforced. The README table holds for non-test code.
- The Dockerfile's `golang:1.25` digest freezes the stdlib patch level with nothing to bump it; `container-check.sh:39` uses the unpinned tag.

### 63. Spec and code disagree in places
`READ`

- `anchor-model.md` §3 describes signature-first verification and quotes an error string that exists nowhere in the repo; it also refers to "V≥5 … root_hash". It appears to describe the platform verifier, not this one. The code binds first and checks the signature last.
- `format-spec.md` §9.4 (first anchor's `previous_anchor_id` is the seed id) is enforced only by `sink`.
- `Options.PreviousHash` and a tombstone's stored `chain_hash` are never shape-checked.
- Minor: `examples/integrations/opencode-ollama/run.sh` lacks an SPDX header; `bundle-vectors.py` does not pin dilithium-py; `keyfile/testdata/README.md` has no Sources row for `keygen_xwing_*`.

---

## Checked and found sound in round 2

- **Version downgrade:** relabelling a v3 entry as v2 or absent gives `hash_mismatch` (distinct domain prefixes); unknown versions give `unknown_format`. No v2 preimage verifies as v3.
- **Anchor version replay:** a v6 signature relabelled as any other version fails; `version` is in the signed bytes of every layout.
- **Cross-protocol reuse:** record envelopes start with `aleutian.proof.record.v1\0` and anchors with `{`, so the two cannot collide under a shared key.
- **Key ids:** no id repeated across the seven algorithms; `KeyRing` rejects wrong-length keys and unknown trust strings.
- **Record envelope:** binds chain id, entry id, type, sequence, previous hash, timestamp, content hash and key id; no cross-chain, cross-position or type replay.
- **Record trust:** with `--record-trust`, unsigned, stripped, malformed, unknown-key and bad signatures are each reported.
- **Sink checkpoint series:** rejects forks, gaps, regressions and wrong predecessors.
- **Sink erasure mechanics:** entries are never rewritten; every link still recomputes and prior checkpoints still bind. The sink has no tombstone-style unverified link.
- **Verifier mutation property (fuzzed, ~870k execs):** outside the known holes, no single-field edit, delete, duplicate, swap, truncation or edit-then-relink of a signed chain passed `Chain` plus `VerifyAnchor`.
- **Signatures (fuzzed):** no bit flip in an ML-DSA signature, key or message verified; no cross-parameter-set verification.
- **Parsers (fuzzed, 23 targets):** no panic, hang or unbounded allocation beyond items 37 and 45. Canonical JSON is idempotent; keyfile and keywrap round trips are byte-stable.
- **Parallel writers:** eight concurrent `proof commit` processes on one chain (500 entries each) all exited 0; the 4,000 entries exported and verified `INTACT`.
- **Vectors:** both Python scripts reproduce their files and `MANIFEST.json` byte for byte; all 11 manifest digests match; mutating an expected value fails the consuming Go test for 10 of 11 files (the eleventh is item 52).
- **Reproducible build:** the Dockerfile's flags give identical hashes from two different paths.
- **Secrets in history:** none. All private-key fixtures are RFC or draft seeds guarded by a provenance test.

## Suggested order for round 2

1. 37 and 40: one-line guards.
2. 34, 35, 36: the sink can currently be made to sign over forged state.
3. 38, 39, 41, 42 together with round-1 items 1-3 and 13: this is one piece of work on what the anchor verifier enforces.
4. 52: the Go bundle verifier, which also closes 17 and gives the 114 vectors something to fail against.
5. 53-57, then cut a release so `@latest` stops shipping the round-1 P0 items (58).

## Where the reproductions are

Delivered alongside this file. They were written by the review passes and have not been tidied; read each before adding it to the repo.

- `anchor_format_repro_test.go`: items 13, 24, 38, 39, 41, 42, 46, 47. Declares its own package (`zzfmt`); put it in a new directory. It logs and does not assert.
- `sink_repro_zz2_test.go`, `sink_repro_zz3_test.go`: items 19, 34, 35, 36, 43, 44. They are in package `sink` and use unexported helpers, so place them in `sink/` and run `go test -run TestZZ_ ./sink`.
- `fuzz-harnesses.tgz`: unpack at the repo root. Contains `fuzzreview/` (findings tests, five kept crashers, run scripts) and a `zz_fuzz_test.go` per package. Covers items 37, 40, 41, 45, 46, 48, 49. Each `TestF*` fails while its finding is present, so they double as regression tests once fixed.
