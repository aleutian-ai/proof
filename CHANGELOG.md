# Changelog

All notable changes to `github.com/aleutian-ai/proof`. Versions follow
[semantic versioning](https://semver.org); while the major version is 0, a
minor or patch release may contain a source-incompatible change, and every such
change is called out here.

## Unreleased

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

## v0.2.0 — 2026-09-21

### Security

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

### Source-incompatible change

This is why the release is v0.2.0 rather than a patch: while the major version
is 0, a minor bump is the conventional signal for a source-incompatible change.


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
