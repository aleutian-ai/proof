# proof: review findings and required changes

Review of `github.com/aleutian-ai/proof` at commit `6a77fa3` (14 commits past `v0.3.0`), 2026-10-10.

**How to read the status tags**

- `REPRODUCED`: demonstrated with a test or the built binary on Linux/amd64, Go 1.24.7.
- `READ`: verified by reading the code; not executed. Everything in `cmd/proof-mcp` is `READ` because that module could not be built in the review environment.
- `SUSPECTED`: reasoned from the code; confirm before fixing.

Line numbers are from `6a77fa3` and may have moved. A companion file, `review_repro_test.go`, reproduces findings 1, 2, 3, 11, 12, 18, 23, 25 and 26. Drop it into a new package directory in the main module (it declares `package zzreview`) and run `go test -v`. It logs the bad behavior rather than asserting, so it passes today; turn each log line into an assertion as the matching fix lands. The sink, CLI and noncestore reproductions (4, 5, 14-17, 21, 22) were run by hand and are not in the file.

---

## P0: breaks a claim the project makes

### 1. A tombstone is an unverified link, so history can be forged under a valid signed anchor
`REPRODUCED` · `verify/verify.go` (`Walker.Add`, tombstone branch, ~L337-347) · `verify/anchor.go` (`walkForHead`, ~L307)

- **Problem:** a tombstone's stored `chain_hash` is adopted without any check, and `entry_id` / `entry_type` are in no hash. Someone with store write access can rewrite entries `0..k-1`, mark entry `k` as a tombstone that keeps its original `chain_hash`, and everything after still links.
- **Observed:** `verify.Chain` returns `INTACT`; `VerifyAnchor` and `Walker.VerifyAnchor` return `bound=true, sig=true` at `platform` trust, with the text "the chain matches this anchor, and a third party attests to this chain".
- **Worse in `walkForHead`:** it treats any entry whose content hash starts with `TOMBSTONE:` as a tombstone, with no type, id or format check. Tombstoning only the last entry lets every other entry be replaced.
- **Docs affected:** the "edits one entry" and "inserts a forged entry" rows in `docs/verification-model.md`; D6 in `docs/decisions.md` records the hash retention but not this consequence.
- **Fix (format change, next version):** keep a tombstone link-verifiable. Two options:
  - `chain_hash = H(prev ‖ link_digest)`, with the tombstone retaining `link_digest`; or
  - retain a salted `content_hash` and erase only the nonce (the sink's `forget` path already works this way).
- **Interim fix (no format change):**
  - [ ] Use one tombstone predicate everywhere (`chainformat.IsTombstone` with type, id and format), including `walkForHead`.
  - [ ] Surface the tombstone count in `BindResult` and downgrade the `Proven` text when it is above zero.
  - [ ] Correct the threat-model table and D6 to state the limitation.

### 2. `entry_id`, `entry_type` and the timestamp string are unauthenticated
`REPRODUCED` · `chainformat/chain_hash*.go`, `verify/verify.go`

- **Observed:** swapping the ids of two middle entries, changing `entry_type`, and rewriting a timestamp as an equivalent instant in another offset (`…+05:30`) all leave the chain `INTACT` and the anchor bound.
- **Why it matters:** `entry_type` decides tombstone status, which feeds finding 1.
- **Fix:**
  - [ ] Bind `entry_id` and `entry_type` into the next format version's preimage.
  - [ ] Require the canonical timestamp string: re-format the parsed time and compare to the stored string.

### 3. The verifier does not validate field formats
`REPRODUCED` · `verify/verify.go` (uses the `*Unchecked` hash functions)

- **Observed:** a v3 entry with `content_hash="not|a|hash"` and `global_seq=-7` returns `INTACT`. The first entry's `global_seq` is never required to be 0.
- **Fix:**
  - [ ] Call `ValidateChainHashInputs*` in the walker and report a break on failure.
  - [ ] Decide and enforce the rule for the first entry's `global_seq` (0 for a whole chain; explicit for a segment).

### 4. Corrupt or crafted bbolt files crash the process, with exit 2
`REPRODUCED` · `cmd/proof/main.go:54` (no `recover`) · `store/bolt/bolt.go` `Open` · `sink/files.go` `openStore`

- **Observed:**
  - `truncate -s 100000 evidence.db` gives `SIGSEGV` (mmap fault).
  - Overwriting pages of `evidence.db`, `.secrets` or `.signatures` gives `panic: assertion failed: Page expected…`.
  - `proof export` on a corrupted db gives `panic: invalid freelist page`.
- **Impact:** all exit 2, so tampering looks like a usage error. A service embedding `sink.Verify` is killed outright.
- **Fix:**
  - [ ] `debug.SetPanicOnFault(true)` plus `recover` at the `Verify` / `Export` / `Checkpoint` boundaries and in `run()`.
  - [ ] Map the recovered panic to a "corrupt" problem with exit 1 (or 3), never 2.
  - [ ] Add tests with truncated and page-scrambled files.

### 5. `proof forget` leaves the nonce on disk
`REPRODUCED` · `internal/noncestore/noncestore.go:153` · `cmd/proof/disclose.go:136`

- **Observed:** with 500 nonces, delete one and close; the 32 bytes are still in the `.nonces` file (bbolt free page). README says forget "makes it unopenable from this machine".
- **Also observed:** a nonexistent entry or chain prints "forgot the nonce", exit 0. A typo'd `--db` creates a fresh `typo.db.nonces` and reports success.
- **Fix:**
  - [ ] Compact and rename after delete, reusing the sink's `compactFile` approach.
  - [ ] Return not-found for a missing entry or chain, with a non-zero exit.
  - [ ] Open the nonce store without create on `forget` and `disclose`.

### 6. MCP server: no path root, despite the comment saying there is one
`READ` · `cmd/proof-mcp/main.go:31`, `:516-518`, `:885-889`

- **Problem:**
  - `main.go:31` claims "Paths are resolved and checked against a root". There is no root flag or check.
  - `loadEntries` only rejects the substring `..` (which also rejects legitimate names like `a..b.json`). Absolute paths are accepted and `os.Stat` follows symlinks.
  - `loadAnchor`, `loadKeyRing` and `verify_bundle` skip even the `..` check. `readCapped` uses `Lstat`, so the loaders disagree about symlinks.
- **Impact:** a prompt-injected model can probe any file the user can read and learn existence, type and exact size from `readCapped` errors. `verify_bundle` on any directory with a `manifest.json` returns names of unlisted files and confirms guessed digests.
- **Fix:**
  - [ ] Add `--root` (default cwd), enforced with `os.Root` or `EvalSymlinks` plus a prefix check.
  - [ ] Route every tool through one loader.
  - [ ] Stop returning file size and type in errors for paths outside the root.

### 7. MCP `verify_chain` returns the `proven` text regardless of verdict
`READ` · `cmd/proof-mcp/main.go:266` · test at `main_test.go:255`

- **Problem:** "Nothing was edited…" is set unconditionally, including when the verdict is broken. The test only checks the field is non-empty.
- **Fix:**
  - [ ] Make `Proven` depend on the verdict (empty or a "nothing proven" string when broken).
  - [ ] Add a test for the broken case that asserts the text.

### 8. MCP `key_trust` is asserted by the model
`READ` · `cmd/proof-mcp/main.go:571`

- **Problem:** `verify_anchor` takes `platform` / `provided` / `self` from the tool caller and echoes it as `trust` and `trust_establishes`. An injected model can upgrade any key to `platform`.
- **Fix:**
  - [ ] Bind key path and trust level at launch, for example `--trusted-key platform=path`.
  - [ ] Report `provided` (at most) for any key supplied through a tool call.

### 9. A 9 MB Mach-O arm64 binary is tracked at the repo root
`READ` · `/proof-mcp`, added in `69ea55f`, present in tags `v0.2.0` and `v0.3.0`

- **Problem:** `.gitignore:47` ignores only `/cmd/proof-mcp/proof-mcp`. `.dockerignore` does not exclude it, so `COPY . .` pulls it into the build context.
- **Fix:**
  - [ ] `git rm proof-mcp`.
  - [ ] Add `/proof-mcp` to `.gitignore` and `.dockerignore`.
  - [ ] Decide whether to rewrite history. Note the published module zips for `v0.2.0` / `v0.3.0` are immutable on the Go proxy either way.

---

## P1: correctness and safety

### 10. Two sink tests fail on Linux
`REPRODUCED` · `sink/erase_subject_test.go:280` · `sink/erase_recovery_test.go:214`

- **Problem:** `TestEraseSubject_RewritesTheIndex` and `TestErasureRecovery_StateMachine` use `os.SameFile` to detect a rewrite. `EraseSubject` compacts the subject index twice (`sink/erase.go:302` and `:327`); on ext4 the second temp file reuses the original inode, so the file looks unchanged. The production code is correct.
- **Fix:**
  - [ ] Detect the rewrite through the existing `compact` hook on `Sink` (count calls per path) instead of inode identity.

### 11. `merkle.VerifyConsistency` omits the final size check from RFC 9162 §2.1.4.2
`REPRODUCED` · `merkle/consistency.go` (end of `VerifyConsistency`)

- **Observed:** the proof for (m=2, n=3) with the size-2 root verifies as m=1; 1,261 wrong-size acceptances for n ≤ 40.
- **Fix:**
  - [ ] Require `lastNode == 0` after the loop.
  - [ ] Add an exhaustive wrong-size test for small n.

### 12. `merkle.UnmarshalFrontier` has an unbounded level index
`REPRODUCED` · `merkle/frontier.go`

- **Observed:** `"0|50000000:<hash>"` allocates about 1.2 GB with no error. `"1|0:h|64:h"` is accepted because `1<<64 == 0` defeats the size check, and yields a bogus root.
- **Fix:**
  - [ ] Reject `lvl >= 63`, and reject levels inconsistent with the stated size.

### 13. Anchor binding leaves three things unchecked
`SUSPECTED` · `verify/anchor.go` (`bindWithHead`)

- **Problem:**
  - No expected-subject parameter; the hash is recomputed from the anchor's own `a.Subject`. `BindTenantMismatch` is declared but never produced.
  - `verified_through` is signed but never compared to anything.
  - `previous_anchor_id` is not tied to `previousAnchorHash`.
  - `VerifyAnchor` returns `res.Bound=true` alongside a signature error.
- **Fix:**
  - [ ] Take an expected subject and produce `BindTenantMismatch`.
  - [ ] Check `verified_through` against the entry count.
  - [ ] Zero the result when the signature fails.

### 14. A crash mid-commit leaves the sink failing verify until the subject is erased
`REPRODUCED` · `sink/commit.go:538` (secrets written before the append), `:454` (new entry id per attempt) · `sink/verify.go:873`

- **Observed:** panic in the appender after `sec.putAll`, then retry the same record with the same `Source`. The retry commits under a new entry id; the old content and nonce rows stay. `Verify` then reports "stored content or nonce … matches no entry", exit 1, permanently.
- **Docs affected:** `docs/sink-format.md:459` says a re-commit "reuses or replaces" this state; that holds for source positions only.
- **Fix:**
  - [ ] Have commit sweep the chain's unmatched rows under the lock, or add a repair verb.
  - [ ] Correct the doc sentence.

### 15. `proof sink commit` cannot be retried safely
`REPRODUCED` · `cmd/proof/sink.go:208-220`

- **Observed:** the CLI never sets `Record.Source`, so piping the same file twice doubles the entries. 1000 good lines followed by one bad line commits the 1000, then exits 3; a retry duplicates them.
- **Fix:**
  - [ ] Add `--source-field` (or derive a source from file name plus line number).
  - [ ] Or validate the whole stream before the first batch.

### 16. `sink init` signing-mode trap
`REPRODUCED` · `cmd/proof/sink_init.go` (`:195` for the wording)

- **Observed:** init generates a record key and prints "next: commit … --record-key", but creates nothing in the folder. One first commit without the flag makes the sink unsigned for good; later `--record-key` is refused with exit 2.
- **Fix:**
  - [ ] Have init create the signatures file in signing mode.
  - [ ] Reword `:195`, which calls the sink folder something "you share" although it holds `.secrets` and `.subjects`.

### 17. Bundles cannot be verified from the CLI
`REPRODUCED` · `docs/bundle-format.md:542`

- **Observed:** `proof sink verify-bundle` is documented; the binary answers `unknown verb`. `proof verify bundle.json` prints `BROKEN — first break at entry 0`, exit 1, which is a false tamper verdict. `{}` and `null` also give `BROKEN` rather than a parse error.
- **Fix:**
  - [ ] Implement `proof sink verify-bundle` (the library has `bundle.VerifyDir`).
  - [ ] Make `proof verify` reject input that is not an entries array with a parse error and exit 2 or 3.

### 18. `bundle.VerifyDir` edge cases
`REPRODUCED` · `bundle/`

- `VerifyDir(emptyDir, nil, "", 0)` returns `Intact=true`.
- Only the final path component is `Lstat`ed, so a symlinked intermediate directory is followed and a file outside the bundle is hashed.
- **Fix:**
  - [ ] Refuse an empty manifest.
  - [ ] Open through `os.Root`, or check every path component.

### 19. Checkpoint files are not fsynced
`READ` (missing sync) / `SUSPECTED` (power-loss outcome) · `sink/folder.go:143` (`writeNew`)

- **Problem:** write and close only. Power loss after "checkpoint signed" can leave an empty `000N.json`; Verify then fails that chain and Checkpoint refuses to add to it.
- **Fix:**
  - [ ] Sync the file, then the directory, as `compactFile` already does.

### 20. MCP resource bounds are partial
`READ` · `cmd/proof-mcp/main.go`, `commit.go:123`

- `loadEntries` checks size, then calls `os.ReadFile` separately: racy, wrong for files reporting size 0, and makes several copies of up to 64 MiB.
- `verify_bundle` has no cap on `len(m.Files)` (`main.go:693-697`).
- `commit` allows 100 × 64 KiB per call with no rate, total or database-size quota; with `--chains '*'` the chain count is also unbounded.
- `verify_inclusion` accepts an unbounded proof array.
- **Fix:**
  - [ ] Open once and read through `io.LimitReader`.
  - [ ] Cap manifest file count and proof length.
  - [ ] Add `--max-db-bytes` or a per-session quota.

### 21. keygen file handling
`REPRODUCED` · `cmd/proof/keygen.go:145`, `:175`, `:375`

- `--force` over an existing 0644 file leaves the private key 0644 while printing "(0600 …)".
- A dangling symlink at the private-key path is followed, because `os.Stat` treats it as absent.
- `SUSPECTED`: the 1Password read-back at `:375` checks only the fingerprint text field it just wrote, not the attached key.
- **Fix:**
  - [ ] Write to a temp file with `O_EXCL|O_NOFOLLOW`, `Chmod` 0600, then rename.
  - [ ] Read back and fingerprint the attached key itself.

---

## P2: lower severity

### 22. Plain-store CLI exit codes and side effects
`REPRODUCED` · `cmd/proof/main.go:185`, `:383` · `cmd/proof/import.go:97`

- [ ] `export` on a typo'd `--db` creates the db, prints `[]`, exits 0. Open without create.
- [ ] `export` of an unknown chain writes an empty file, exits 0. Return an error.
- [ ] Every `Open` runs a write transaction (lease reset), so export and anchor fail on read-only media. Add a read-only open.
- [ ] `commit` with a 64-hex content hash exits 3; should be 2.
- [ ] `verify` with a missing `--anchor` or `--key` file exits 2; should be 3.
- [ ] Exit 4 (busy) is in the usage text but not the README.
- [ ] `anchor --out` and `export --out` overwrite silently.
- [ ] `import --previous-hash` verifies with the hash but stores the first row's `PreviousHash` as `""`, and does not check adjacency to existing entries.
- [ ] Plain `commit` reads stdin unbounded and accepts duplicate `entry_id`s.
- [ ] `rm -r anchors/` then `sink verify` gives "all chains verify", exit 0. Add `--require-checkpoint`.
- [ ] Subjects are passed on argv for `erase` and `export`; offer stdin or a file.

### 23. keywrap "MAC" uses a public constant key
`REPRODUCED` · `keywrap/keywrap.go` (`macKey`), `keywrap/doc.go`

- It is a checksum, but the doc says it "authenticates" the record.
- `ErrLegacyRSAVersion` is unreachable for real v1 blobs because size and MAC checks run first.
- [ ] Rename to checksum in code and docs.
- [ ] Check the version byte before size and MAC.

### 24. keyfile consistency checks are partial
`SUSPECTED` · `keyfile/consistency.go`

- [ ] ML-DSA "both" form: check seed against the expanded key.
- [ ] ML-KEM: check `dk_PKE`; ML-KEM-512 skips derivation.
- [ ] Use `subtle.ConstantTimeCompare` for the secret `z`.
- [ ] Reject PEM headers and PKCS#8 attributes instead of ignoring them.

### 25. Canonical JSON edge cases
`REPRODUCED` · `canonical/json.go`

- [ ] U+2028/U+2029 are emitted as ` ` although the comment says that escaping is suppressed. Make code and comment agree, and pin it with a vector.
- [ ] Duplicate keys in a `json.RawMessage` collapse silently (last wins). Reject.
- [ ] `-0` and integers above 2^53 pass. Reject or document.
- [ ] Key order is UTF-8 bytes, which differs from JS UTF-16 order for astral characters. Document it and add a cross-language vector.

### 26. Smaller core items
- [ ] `REPRODUCED` · `chainformat/chain_hash.go`: `appendIntPadded` renders negative years as `0000`, so year -5 and year 0 hash the same. Reject years outside 0-9999.
- [ ] `READ`: ML-DSA signs with an empty context and `SignCanonical` accepts any `{…}` JSON, so a key reused across protocols has no domain separation. Add a context string in the next anchor version.
- [ ] `READ`: `SignAnchor` does not reject a preset `SigningKeyID` that differs from the signer's.

### 27. The "no key material" test is weaker than the docs say
`READ` · `cmd/proof-mcp` (`TestNoKeyMaterialTools`, `TestToolsAreTheExpectedSet`), `main.go:854`

- The name test is a substring denylist; `open_envelope` or `export_nonce` would pass. The real guard is the exact allowlist test.
- [ ] Describe the allowlist as the guard in README and package doc.
- [ ] `SUSPECTED`: confirm `keyfile.ParsePublicKey` errors never contain file contents, since `loadKeyRing` embeds them for a model-chosen path.

---

## Release, docs and repo hygiene

### 28. No CI or standard scaffolding
`READ`

- [ ] Add a workflow that runs `go vet` and `go test -race` on both modules with `GOWORK=off`, on Linux and macOS.
- [ ] Add the vector sync check (`scripts/sync-vectors.sh --check`) and `scripts/container-check.sh` to CI.
- [ ] Add `SECURITY.md` (disclosure address and policy), `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`.
- [ ] Add issue and PR templates, and a CI badge.

### 29. Release state has drifted
`READ`

- [ ] Cut a release matching HEAD: about 290 lines of "Unreleased" changelog, including breaking removals and the whole sink feature.
- [ ] `README.md:105` "published tag lands with v0.2.0" and `:125` "Nothing has been pushed to a registry yet": update or publish.
- [ ] `README.md:562-566` describes v0.2.0 as current.
- [ ] `README.md:570-572` says v3/v6 are "written down only in the Go source", but `docs/format-spec.md` and `docs/bundle-format.md` exist.
- [ ] The documentation table (`README.md:639-645`) omits `bundle-format.md` and `sink-format.md`.
- [ ] "475 tests" is stale (about 879 `func Test` declarations).
- [ ] The four integration examples pin a pseudo-version of `a7e7eab`; pin a tag.
- [ ] Their `run.sh` says "build (from this working tree)", but without a `go.work` the build uses the pinned commit.
- [ ] `publish-image.sh` tags both images with one version although the modules version independently; it has `--skip-checks` and no signing or SBOM.
- [ ] Server version "0.3.1" is hard-coded at `cmd/proof-mcp/main.go:81`.

### 30. Internal references in public material
`READ`

- [ ] Ticket ids: `_72a`-`_72e` in `docs/bundle-format.md:3-9,638,645`; `aleutianchain_16/32b/40` in `docs/decisions.md`; `_32b` in `CHANGELOG.md:571`; `aleutianchain_54/55` in `cmd/proof-mcp/main.go`.
- [ ] Dangling paths to a private repo: `docs/AleutianChain/*.md` cited in `deps_test.go:36,213`, `sink/erase.go:28`, `sink/paging.go:17`, `sink/subjects.go:28`, `sink/record_signing.go:156`, `cmd/proof/sink_init.go:18`; `sdk/verification-go` is cited too.
- [ ] Opaque test file names such as `sink/review74c_test.go`: rename by behavior.
- [ ] Commit subjects going forward: describe the change ("massive updates to the sink", "added int_05" tell a contributor nothing).

### 31. First-run experience
`REPRODUCED` (the README "whole loop" was run as written)

- [ ] `commit` needs `timestamp`, `ingested_at` and a 128-hex SHA-512 `content_hash`; the README shows no input example. Add one.
- [ ] The first error a new user hits is a raw Go time-parse message. Wrap it.
- [ ] The quickstart verifies an `entries.json` the reader does not have. Ship a `testdata/demo` chain.
- [ ] Put a five-line "commit, export, verify, tamper, verify" demo at the top; move `ComputeChainHashV3` and the v2/v3 history down.
- [ ] The anchored verify output prints `INTACT, ANCHORED`, which differs from the README sample.

### 32. Examples
`READ`

- [ ] `recordkey.go` is copy-pasted across kafka, nats, redis and otel; share it.
- [ ] The opencode Containerfile runs an unpinned `curl … | bash` as root on a tag-pinned Alpine image; pin by digest and checksum.
- [ ] `opencode.json` lists an odd model name, `ornith-1.5:35b`; confirm it is intended.
- [ ] Demo brokers run without TLS or auth; say so in each README.

### 33. Outside the repo
- [ ] aleutian.ai does not mention or link `proof`; it points to the AleutianFOSS org. Link the verifier from the product page.
- [ ] The site says EU AI Act Articles 12 and 19 have been in force since 2 August 2026. The Digital Omnibus on AI (in force 27 July 2026) moved the Annex III high-risk rules to 2 December 2027. Confirm the wording with counsel.

---

## Suggested order

1. Findings 9 and 10, plus CI (28): small, and CI protects everything after.
2. Interim fixes for 1-3, then 4 and 5.
3. MCP findings 6-8 and 20.
4. Sink and CLI findings 14-19, 21, 22.
5. Format change for 1 and 2 as a new chain version, with new conformance vectors for Go, Python and JavaScript.
6. Docs and release (29-31), then cut the release.

## Checked and found sound

Do not spend time re-auditing these unless a fix touches them.

- **Merkle:** leaf/node prefixes hold; inclusion proofs for all n ≤ 40 showed zero wrong-index acceptances; frontier root equals the recursive root; truncated and extended consistency proofs are rejected.
- **X-Wing:** combiner order, label bytes, SHAKE256 expansion, key and ciphertext ordering and all-zero DH handling match the draft; official vectors are in the tests.
- **Capture leaf v3:** length-prefixed fields, NFC, control-byte rejection, anchored regexes, size caps.
- **Commitment:** fixed 115-byte preimage, constant-time compare, no caller-supplied nonce.
- **Anchor canonicalisation:** per-version structs, v5 refusal, `|` rejection in the anchor chain hash, signature and key lengths checked, signer self-verifies its output.
- **SPKI/PKCS#8:** trailing bytes, algorithm parameters, embedded public keys and expanded-only keys are rejected.
- **Sink locking:** `evidence.db`'s flock works as a folder lock; six parallel CLI commits all landed and verified; race detector clean apart from finding 10.
- **Sink erasure:** after erase, no subject string remained in any live file.
- **Sink symlink handling:** `O_NOFOLLOW`, `os.Root` and stat-after-open throughout.
- **Bundle export:** bounded sizes, temp file plus link, never overwrites, 0600.
- **Error redaction:** no subject or chain id leaked in any message seen.
- **No panic was reached from untrusted input in the core packages** (the bbolt panics in finding 4 are in the storage layer).
