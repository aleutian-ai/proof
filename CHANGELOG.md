# Changelog

All notable changes to `github.com/aleutian-ai/proof`. Versions follow
[semantic versioning](https://semver.org); while the major version is 0, a
minor or patch release may contain a source-incompatible change, and every such
change is called out here.

## Unreleased

> **Release order (required).** Tag `proof` first. `cmd/proof-mcp` imports
> packages that do not exist in `v0.2.0`, so it builds only in the workspace until
> its `go.mod` is bumped to the new `proof` tag and `GOWORK=off go build ./...`
> passes. Only then tag `cmd/proof-mcp`. See the note in `cmd/proof-mcp/go.mod`.

### Changed

- **CLI: `proof append` is now `proof commit`.** *(Breaking; no alias.)* proof's
  vocabulary is commit → anchor → verify → disclose, and the CLI verb was the one
  place still saying `append`. Same input, same behaviour; the output's
  `appended` count is now `committed`. `proof import` keeps
  its name, because it carries an existing chain verbatim rather than committing
  new evidence. The library's `linker.Append` is unchanged: at the storage layer,
  "append" is the accurate word.

- **MCP `compute_chain_hash` handles chain hash v3.** It previously knew only
  v2, so it could not reproduce any entry `proof commit` writes. Given v2 inputs
  for a v3 entry, it returned a wrong hash with no error.
  *(Breaking schema change. No users.)*
  - `format_version` is **required**: 2 or 3, with no default.
  - v3 takes `global_seq`, and it is required. Non-empty `run_id` or non-zero
    `sequence_num` is refused under v3.
  - v2 requires `sequence_num` and refuses `global_seq`.
  - `global_seq` and `sequence_num` are **decimal strings**. The MCP SDK
    decodes arguments via `map[string]any`, which turns JSON numbers into
    `float64`: `9007199254740993` was hashed as `9007199254740992`.
  - The result now includes the `format_version` that was used, and the
    matching preimage.

### Removed

- **Anchor v5 is WITHDRAWN.** It had a canonical form, a validation rule, tests
  and a golden vector — and no producer, in any repository, ever emitted one. Its
  own verifier refused it, on the grounds that committing to a Merkle root no
  implementation can check asserts a guarantee nobody can test. Python and JS
  never implemented it at all; they went straight from v4 to v6.

  What changed:

  - `Canonicalize` and `ValidateVersionInvariants` refuse v5 **by name**, wrapping
    `ErrVerificationUnsupported`. Previously v5 canonicalized and was refused only
    at `VerifySignature`, so this package would hand back bytes for a version it
    would not accept — bytes a caller could sign, producing an anchor that was
    permanently unverifiable.
  - `MerkleVersion` → **`WithdrawnVersion`**. *(source-incompatible)* The old name
    read as a floor and was twice written `>= MerkleVersion`, which refused v6 and
    every version after it. The name went with the capability.
  - `Anchor.RootHash` and `Anchor.TreeSize` are **removed**. *(source-incompatible)*
    Only v5's canonical form ever read them; a field no canonical form reads is a
    field a caller can set and believe was signed. v6's runtime check rejecting
    them is gone too — the compiler does it now.
  - The v5 refusal now lives in **one** place instead of three. The duplicate
    checks in `SignAnchor` and `VerifySignature` were dead once v5 lost its
    canonical form, and two places refusing the same thing is how one drifts.

  The number 5 is reserved and will not be reused. Renumbering v6 down to 5 was
  considered and rejected: a reserved gap costs one number and guarantees that any
  artifact declaring v5 is refused by name rather than silently reinterpreted.

  `merkle/` is untouched — Merkle trees, inclusion and consistency proofs are
  unaffected. What was withdrawn is an *anchor version* that committed to a root,
  not the tree machinery. The MCP `verify_inclusion` tool still works.

  **Not changed outside this module:** the hosted platform has its own
  `storage.MerkleAnchorVersion = 5` and its own anchor types, still referenced by
  `internal/chainlinker/merkle_proof.go`. That is a separate type system. If the
  monorepo re-export lands, that file is what needs attention.

### Added

- **MCP `commit`: the first tool that writes.** Registered only with `--db`,
  which requires `--chains` (the chains agents may write, or `'*'`). The agent
  sends `content` (salted commitment; the nonce is kept in a local sidecar file,
  `<db>.nonces`, and never returned) or a pre-computed `content_hash`. Entry ids,
  timestamps (taken under the file lock) and positions are server-assigned;
  hash-bound fields cannot be supplied; entry types are server-set
  (`mcp.salted` / `mcp.digest` + optional label). At most 100 entries and 64 KiB
  each, enforced in the input schema and again in bytes. Batches are atomic;
  refused calls leave the database byte-identical; parallel calls queue instead
  of failing. Every other tool is marked read-only, and a test pins that exactly
  one tool writes. The SDK has no message-size limit, so the caps bound what is
  written, not what is decoded.
- **`proof disclose` and `proof forget`.** Prove one salted entry to a third
  party (refuses to emit a disclosure that does not verify), or erase its nonce
  so it can never be opened again. Forget says plainly which copies it cannot
  reach.
- **`linker.ErrHeadStateStale`.** When entries are durably written but the saved
  head record is not, `Append` now returns the populated `Result` together with
  this error, and `proof commit` reports success with a warning. Previously the
  result was dropped, inviting a retry that committed the same evidence twice.
- **`commitment`: salted commitments for content committed unencrypted.**
  `SHA-512("aleutian.commit.v1:" ‖ nonce ‖ SHA-512(content))` with a fresh
  32-byte nonce per item. A plain hash of low-entropy content can be guessed; this
  cannot without the nonce. Disclosing one item reveals that item's content only.
  The content is hashed first so the construction cannot be length-extended into
  a false "I committed first" claim. `Salted` and `Verify` (constant-time); the
  deterministic core is unexported so nonces cannot be fixed or derived. No format
  change: the result is an ordinary `content_hash`. Specified in
  `docs/format-spec.md` §8. Vectors in `fixtures/testdata/commitment_vectors.json`
  (10 reproduce + 6 must-reject, incl. multi-block content) were computed with
  Python's `hashlib`, independently of the Go code.
- **`examples/encrypted-artifact`**: `proof` composed with encryption it does not
  own — circl HPKE (X-Wing) and 1Password, ciphertext in a plain folder, commit,
  anchor, verify, decrypt.

- **A conformance contract, and three implementations held to it.**
  `fixtures/MANIFEST.json` records every vector's SHA-256; `fixtures.LoadManifest`
  serves it; `scripts/sync-vectors.sh` vendors and verifies copies in other
  repositories. Go, Python and JavaScript now reproduce chain hash v3 and anchor
  v6 independently, checked against the same data.

  The expected outputs are DATA — never regenerated by an implementation during
  a run. A vector edited to make one implementation pass fails the other two,
  which is the difference between a conformance suite and a mirror.

### Fixed

- **A crashed writer no longer locks its chain forever.** The bolt store saved a
  per-chain lease in the file and nothing cleared it, so a process killed
  mid-append — routine for MCP servers — left that chain permanently "busy".
  `Open` now clears stored leases: it holds bbolt's exclusive file lock, so no
  other writer can be alive. Safe because the next append reads the tail from
  the stored entries, never from saved state.

- **MCP `verify_anchor` could not read the keys `proof keygen` writes.**
  `loadKeyRing` capped the read at `anchor.PublicKeySize+1` (1953) and expected
  RAW key bytes; `proof keygen` writes PEM, at 2726 bytes. Every key the tool
  itself produces was refused — and refused with *"cannot read the public key
  file at that path"*, when the path was correct.

  It now parses through `keyfile.ParsePublicKey`, the same function the CLI's
  `proof verify --key` uses, so the two surfaces cannot disagree about what a key
  file is. Wrong-algorithm keys are refused by algorithm, naming what was supplied
  and what is needed. `key_trust` is validated before any I/O, so a bad argument
  is no longer reported as a file problem.

  Nothing caught this because `anchoredFixture` wrote raw bytes: the test invented
  an encoding and then confirmed the server agreed with the invention.

- **Every file-read failure blamed the path.** `readCapped` collapsed four
  distinguishable causes — missing, not a regular file, over the limit, read error
  — into one message that named the path. Three of them are not about the path, so
  a correct path was reported as the fault.

  Failures are now distinguishable, with `errNotRegular` and `errTooLarge`
  sentinels, the underlying error wrapped rather than dropped, both sizes reported
  when a file is too large, and `describeMode` naming what a non-regular file
  actually is. `loadAnchor` had the identical shape and got the same treatment.
  Messages carry paths and sizes, never file contents — these reach a model
  provider.

- **Two of four copies of `chain_vectors.json` were FABRICATED.**
  `sdk/verification-go/testdata/` and `sdk/verification-python/tests/fixtures/`
  held 64-character placeholder hashes ending `…0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d`
  — sequential nibbles at SHA-256 length, left over from before the SHA-512
  upgrade. Neither was referenced by any test, so nothing was passing on invented
  data, but either was one wiring-up away from becoming "the shared vector".
  Deleted. `anchor_chain_hash_vectors.json` existed only here, so no SDK checked
  it at all; it is now vendored.
- **`fixtures` had no tests.** The package serving the byte contract to three
  languages was itself unverified. The manifest is now checked against the files
  in both directions — a vector absent from the manifest would be invisible to
  every other implementation.

- **`proof verify` could PANIC while describing a broken chain.** `printResult`
  sliced `Expected[:32]` and `Actual[:32]` behind a check on `Expected` alone,
  so a break carrying one side and not the other — or a value shorter than 32
  characters — crashed the verb on the one path it exists for. Shipped in
  v0.2.0. Found by a test written for something else.
- **Every verb HUNG on a database another process had open.**
  `store/bolt.Open` passed no `Timeout`, so bbolt waited on its exclusive file
  lock forever: no output, no error, no exit code, and nothing to suggest a lock
  was the cause. It now waits `bolt.DefaultLockTimeout` (5s) and returns
  `bolt.ErrLocked`, which the CLI maps to exit `4` — making that exit code
  reachable from a second process for the first time. `bolt.WithLockTimeout(0)`
  restores the old wait-forever behaviour for a caller that wants it.

## v0.2.0 — 2026-09-25

The first release to carry the whole loop: originate entries, anchor them,
and verify the result — all from a terminal, and all independently checkable.

Documented as v0.2.0 on 2026-09-21 but never tagged, so this absorbs that
section rather than skipping a version nobody could have fetched.

### Added

- **Chain hash v3 (`aleutian.chain.v3:`), and it is now the default.** v2 bound
  `run_id` and a batch-local `sequence_num`, so the same entries in the same
  order hashed differently depending on how they were grouped into `Append`
  calls — a chain depended on the API calls that produced it and could not be
  rebuilt from its own entries. v3 binds `global_seq` instead, which v2 never
  hashed at all, and is batch-independent. See `docs/decisions.md` D15.
- `chainformat.ComputeChainHashV3`, `ComputeChainHashV3Unchecked`,
  `ValidateChainHashInputsV3`, `ChainHashPrefixV3`, `NormalizeFormatVersion`,
  and the `FormatV2`/`FormatV3` constants.
- `linker.WithFormatV2()`, for producing bytes an older verifier accepts.
- `verify.BreakUnknownFormat` and `verify.BreakFormatFieldMisuse`.
- **Anchor v6: `company_id` is now `subject`.** An open-source chaining tool has
  no business asking for a customer identifier. A subject is any non-empty
  string naming the namespace the chain is about; it stays in the signed bytes
  so an anchor cannot be replayed onto another chain. v6 uses v4's layout — NOT
  v5's, which commits to a Merkle root nothing can verify — and requires a
  non-empty subject. `anchor.SubjectVersion` names the version.
- **`proof append` and `proof import` — the terminal loop closes.**
  `append` mints positions through the linker and REFUSES input carrying
  `chain_hash`, `global_seq`, `run_id`, `sequence_num` or `previous_hash`,
  naming the field and the line: silently recomputing a value someone supplied
  is how they come to believe it was preserved. `import` verifies first, refuses
  an occupied sequence range, and stores verbatim — `export → import → export`
  is byte-identical for v2 and v3 alike. It bypasses the linker on purpose,
  since re-linking would renumber from the target's tail and v3 binds
  `global_seq`.
- **`verify.Options.PreviousHash`** lets a SEGMENT be verified. Entries taken
  from the middle of a chain link from their predecessor, so checking them
  against an empty previous hash reported a break on the first entry of a
  perfectly good segment. `store.Reader.Predecessor` has always existed to
  supply this; the verifier never had the parameter. Additive — the zero value
  is the previous behaviour.
- **`proof verify --anchor` — the CLI can now check anchors, not only produce
  them.** Three claims from one verb, and they are not the same:
  no flags checks linkage, `--anchor` binds the chain to an anchor, and
  `--anchor --key` verifies the signature too. An anchor that does not describe
  the chain exits `1`, the same as a broken chain, because it is one. The
  verdict is promoted to `INTACT_ANCHORED` and `anchor_checked` set — a field
  and a verdict the result type has always carried and nothing had ever set.
- **`proof verify` accepts flags after the filename.** Go's flag package stops
  at the first positional, so `proof verify entries.json --anchor a.json` — the
  natural form — previously failed with a confusing complaint about the number
  of files.
- **`proof anchor` — the CLI verb.** Reads a chain from a database, verifies it,
  signs an anchor over it and writes JSON. Refuses a broken chain with exit code
  `1`, the same code `proof verify` uses, so a script treats the verdict
  identically whichever verb found it. `--subject` is required with no default,
  and its refusal explains that the value can never be erased. `--previous`
  chains from an existing anchor and the summary then prints the predecessor's
  chain hash, which a verifier needs and cannot recover from the new anchor.
  The anchor goes to stdout and the human summary to stderr, so
  `proof anchor … > a.json` yields a clean file. Never an MCP tool: it takes a
  private key.
- **`anchor/build` — producing anchors, having first checked the chain.**
  `build.Anchor(ctx, Input)` runs `verify.Chain` over the entries and REFUSES to
  produce anything if the linkage is broken, so `verified_through` is never
  asserted without being established. An anchor claiming it over a broken chain
  would be a lie its own signature then authenticates, which is worse than no
  anchor because the signature invites a reader to believe it.

  It is a separate package because a producer genuinely depends on both halves
  and neither half should depend on it — `anchor` (format) cannot import
  `verify` (checking) without a cycle, so a builder living in `anchor` could
  never run the verifier. Injecting one would let a caller pass a stub that
  always answers "intact".

  Produces **v6**, mints `anchor_<uuidv4>` from `crypto/rand` with no new
  dependency, recomputes the anchor chain hash rather than copying the tip, and
  refuses to return an anchor this module's own verifier would reject.
- **Anchor signing.** `anchor.MLDSA65Signer` signs with an in-memory ML-DSA-65
  key; `anchor.ContextSigner` is the seam for Cloud KMS, an HSM, a PKCS#11 token
  or a keychain, so this module never touches a credential itself. ML-DSA-65
  only — `VerifySignature` is hardcoded to its sizes and the anchor format has no
  algorithm identifier yet, so a 44 or 87 signer would produce anchors this very
  package rejects. That waits on `_32b`.
- **`crypto.Signer` compatibility at both boundaries, but not in the interface.**
  `*anchor.MLDSA65Signer` IS a `crypto.Signer` — a compile-time assertion
  enforces it — so it drops into x509 signing, go-tuf, sigstore or your own code
  with no adapter. `anchor.FromCryptoSigner` adapts any `crypto.Signer` inbound;
  it is an explicit call because that wrapper cannot honour a context, and
  silently losing cancellation on a KMS round trip is miserable to diagnose.
  `anchor.ContextSigner` itself is deliberately narrower than `crypto.Signer`:
  nothing here calls `Sign`, so embedding it would oblige every KMS or PKCS#11
  implementer to write a method whose `rand` and `opts` are meaningless for
  ML-DSA. See `docs/decisions.md` D16.
- **`anchor.SignAnchor` is the entry point, and it is one call on purpose.**
  `signing_key_id` is INSIDE the signed bytes, so populating it after
  canonicalizing signs one set of bytes and publishes another — an anchor that
  fails verification permanently, with a diagnostic indistinguishable from
  forgery. This project has shipped that bug before. `SignAnchor` stamps the key
  id, validates version invariants, refuses v5, canonicalizes, signs and
  verifies, so the order cannot be got wrong. See `docs/decisions.md` D17.
- **Every signature is verified before it is returned.** `crypto.Signer`'s byte
  slice means a *digest* for RSA and ECDSA but the *whole message* for Ed25519
  and ML-DSA, and the interface cannot distinguish them. A third-party signer
  written with RSA habits returns a structurally perfect 3309-byte signature
  over `SHA-256(canonical)`; every length and format check passes and the anchor
  verifies nowhere. Unconditional, with no flag to disable it. It also catches a
  wrong-algorithm signer, a truncated signature, a faulted signature, and a KMS
  that rotated keys between `Public()` and `Sign()`. It establishes consistency,
  NOT authenticity — a substituted signer passes.
- `anchor.KeyIDOf` derives a signer's key id and public key in one place, with a
  single `Public()` call. The id matches `proof keygen`'s output, so no operator
  copies hex by hand. `SignAnchor` keeps a caller-set id instead, for KMS and
  registry keys whose ids are assigned labels rather than content-derived hex.
- `anchor.SignCanonical` remains as the lower-level primitive for callers who
  must control canonicalization. It refuses an empty `signing_key_id`.
- `proof keygen` — generates X-Wing, ML-KEM-768/1024 and ML-DSA-44/65/87 key
  pairs in the standard PKCS#8 seed form, self-tests every key BEFORE writing
  it, writes `0600`, never prints a private key under any flag, supports
  `--slot dual` for an independent hot/cold pair, and can store the pair in
  1Password with `--op-vault`.
- A container image: a static binary on `scratch`, non-root, no shell, 3.5 MB.
  `podman build -t proof .`; `--target proof-mcp` for the MCP server.

### Fixed

- **The MCP key-material guard did not cover signing.** `TestNoKeyMaterialTools`
  matched on `keygen`, `decrypt`, `unwrap` and similar, so a hypothetical
  `sign_anchor` tool would have passed it while carrying a private key across
  the boundary to a model provider. Only `TestToolsAreTheExpectedSet` would have
  caught that, and it is about surface stability rather than key safety.
  `sign`, `signer` and `signature_over` are now forbidden too.
- **`verify.BindAnchor` could only check the FIRST anchor in a chain.** It
  defaulted the predecessor to the genesis sentinel, so every anchor after the
  first — which is every anchor a real producer emits, since they chain from
  `prevAnchor.ChainHash` — came back as `head_mismatch`. That reads as tamper
  evidence, which is the worst possible way to be wrong: it sends someone
  hunting an attacker who does not exist. `verify.VerifyAnchor` inherited the
  same fault.
- **The anchor binder recomputed every entry as chain hash v2**, so from the
  moment v3 became the default no v3 chain could be bound to its anchor —
  reported as "linkage breaks at entry 0". `verify.Chain` learned about v3 and
  this path did not. Both now share one dispatch, so they cannot drift again.
- **An entry the build cannot recompute is no longer reported as a break.** An
  unknown format version, or a v3 entry carrying v2's `run_id`/`sequence_num`,
  is an error naming the problem rather than a claim that the chain was
  tampered with.
- **A version guard silently refused every future anchor version.**
  `anchor.VerifySignature` read `if a.Version >= MerkleVersion`, which was
  written to exclude v5 (canonicalized but never cross-language validated) and
  excluded everything above it too. It is now an exact test for v5, so v6 and
  later versions verify.

### Removed

- **The `kdf` package, which never contained any code.** It shipped in v0.1.0 as
  a `doc.go` describing domain-separated key derivation that was never written,
  so `go doc` and pkg.go.dev presented an API that did not exist. Nothing could
  import it usefully — it declared nothing — so removing it cannot break a build.
  Domain separation happens at the sites that need it: `chainformat`
  (`aleutian.chain.v2:` / `v3:`), `anchor`, `keyfile` (`proof.keyid.v1:`) and
  `xwing`.

### Changed

- **BREAKING: `verify.BindAnchor` and `verify.VerifyAnchor` take the previous
  anchor's chain hash.** An anchor commits to its predecessor's hash and names
  that predecessor only by id, so the hash cannot be recovered from the anchor
  being checked — a verifier that assumed it could check only genesis anchors.
  Genesis callers pass `anchor.SeedAnchorHash` explicitly:

  ```go
  verify.BindAnchor(a, entries, anchor.SeedAnchorHash)   // first anchor
  verify.BindAnchor(a, entries, prev.ChainHash)          // every one after
  ```

  A `BindAnchorChained` companion was built first, to avoid changing a published
  signature. That was the wrong call and was reverted before release: the
  justification assumed callers that do not exist — no importers on pkg.go.dev,
  none in the monorepo, none in the SDKs — and it left the discoverable name as
  the one that reports tampering on correct input. One function, no wrong
  default.
- The MCP `verify_anchor` tool gained `previous_anchor_hash`, and reports
  `assumed_genesis` when it is omitted, so a head mismatch is traceable to the
  missing input rather than read as an attack.
- `store.Entry` and `verify.Entry` gained `FormatVersion`. **Zero means v2**,
  so existing databases and exports are read exactly as before — no migration,
  and a v2 export is byte-identical to what the previous release produced.
- The linker no longer mints a run id for v3 entries, and `Result.RunID` is
  empty for them.
- **`chainformat.CaptureRequestV3.CompanyID` is now `Subject`, and no longer has
  to look like an Aleutian tenant id.** It was validated against
  `^comp_[0-9A-HJKMNP-TV-Z]{26}$` — a private platform's identity scheme — so an
  adopter had to mint one to describe their own data. Any non-empty string
  within the existing field rules now works. **No content hash changed**: the
  canonical form encodes values positionally and never writes a key name,
  verified against the pre-rename implementation.
- `anchor.Anchor.CompanyID` is now `Subject`. Its JSON key follows the anchor's
  VERSION (`company_id` for v3–v5, `subject` for v6), since the key is inside
  the signed bytes. Both spellings are accepted on read; two different values
  under the two spellings is an error, not a precedence rule.

### Compatibility

- **v2 chains stay verifiable forever.** They are not rewritten, not
  reinterpreted, and the released v0.1.0 verifier still reads them — asserted
  by `scripts/container-check.sh`, which verifies a v2 chain with the published
  binary on every run.
- **Anchors v3, v4 and v5 are unchanged, byte for byte.** Their canonical form
  still says `company_id`, they still verify, and v3–v5 still do not require a
  non-empty subject. No anchor is rewritten or reinterpreted.
- **No SDK implements anchor v6.** Do not emit v6 anchors to a consumer that has
  not been taught them; a verifier released before this change reports an
  unsupported version.
- A **v3** chain is NOT readable by a verifier released before this change,
  including the published Python and JS SDKs. A v3 entry names its format, so
  such a verifier reports a break rather than a wrong verdict.


### Security

Key-material hardening in `xwing`, written up on 2026-09-21 and released here.

- **`xwing`: secrets redact under every `fmt` verb except `%p`, and under
  `log/slog`.** `PrivateKey` and `SharedSecret` previously redacted only `%v`,
  `%+v`, `%#v`, and `%s`; `%d` printed the private key seed or the shared
  secret. Both types now implement `fmt.Formatter` and `slog.LogValuer`.
  **`%p` still prints the raw bytes** — `fmt` handles it before any method can
  intervene — so never use `%p` on key material.
- **`xwing`: secrets refuse serialization.** `json.Marshal`, `MarshalText`
  (used by JSON map keys, `encoding/xml`, and many config encoders), and
  `encoding/gob` now return an error for `PrivateKey` and `SharedSecret`
  instead of emitting the raw bytes. An error, not a placeholder, so an
  accidental serialization fails at the first test rather than shipping.
- **`xwing`: the sentinel errors can no longer be turned into a silent
  success.** `ErrInvalidPublicKey`, `ErrInvalidPrivateKey`, and
  `ErrInvalidCiphertext` were package variables; any code in the process could
  set one to `nil`, after which `Encapsulate` on an invalid key returned an
  all-zero shared secret and a nil error. They are now constants.

### Not covered — by design, documented

- `encoding/binary` and other reflection-based encoders serialize the raw
  bytes; they consult no marshaling interface a type could use to refuse.
- An unexported struct field of either type prints raw under `fmt`.

### Source-incompatible changes

There are **two** in this release, and while the major version is 0 a minor bump
is the conventional signal for exactly that. The larger one —
`verify.BindAnchor` and `verify.VerifyAnchor` gaining a `previousAnchorHash`
parameter — is described under **Changed** above. The other:

- The three `xwing.ErrInvalid*` sentinels changed from `var` to `const`, of an
  unexported type. `errors.Is(err, xwing.ErrInvalidPublicKey)` and
  `err == xwing.ErrInvalidPublicKey` work exactly as before. Code that
  **assigned to** a sentinel or **took its address** no longer compiles — which
  is the point.

### Verification

- **`xwing` is now tested against the specification's official test vectors**
  (`xwing/testdata/xwing_spec_vectors.json`), authenticated on every run by
  re-rendering them in the specification's text format and checking the
  checksum published for `spec/test-vectors.txt`. Earlier releases were tested
  only against self-generated vectors, which cannot detect a deviation from the
  specification that the implementation itself makes.
- **Differential test against an independent implementation** (Cloudflare
  circl's `kem/xwing`), in both directions, covering encapsulation — which the
  official vectors cannot, because `crypto/mlkem` offers no derandomized
  encapsulation. circl is a test-only dependency and is not compiled into any
  package a user imports.

### Documentation

- `xwing` package docs: corrected — X25519 comes from `crypto/ecdh`, not
  `golang.org/x/crypto`; added conformance, secret-handling, and limitations
  sections (unwipeable copies inside `crypto/ecdh` and `crypto/mlkem`; the
  unexported-struct-field printing limit; no operation under
  `GODEBUG=fips140=only`).
- README and `docs/decisions.md`: the FIPS 140-3 statement no longer implies
  a difference from recent `golang.org/x/crypto`, which wraps the same
  standard-library primitives; and states that X-Wing carries no FIPS approval
  claim, since X25519 is not an approved key-establishment scheme.
- README lists the `linker` package, which shipped in v0.1.0 but was missing
  from the package table.

### Unchanged

X-Wing output is byte-identical to v0.1.0: same keys, ciphertexts, shared
secrets, and key IDs.

## v0.1.0 — 2026-09-21

Initial release: chain format, verifier, anchors, bundles, storage
(bbolt + memory), linker, CLI, and MCP server.
