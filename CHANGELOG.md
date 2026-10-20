# Changelog

All notable changes to `github.com/aleutian-ai/proof`. Versions follow
[semantic versioning](https://semver.org); while the major version is 0, a
minor or patch release may contain a source-incompatible change, and every such
change is called out here. What is promised to stay stable, and what is not,
is in [STABILITY.md](STABILITY.md).

## Unreleased

### Added

- `STABILITY.md`: format versions and the Go API are versioned separately. Every
  format version a release has written stays verifiable by every later
  release. It also lists the v1.0 criteria.
- `CONTRIBUTING.md`: contributions are signed off under the Developer
  Certificate of Origin, with no CLA. A format change starts as a
  specification change.
- `docs/release.md`: the release order across the Go proxy, ghcr.io, PyPI and
  npm, and which steps are one-way.
- `scripts/tag-check.sh`: checks a release's tags rather than the working tree.
  Both tags must exist, the proof-mcp tag must require the same library
  version, and each tagged tree must build with `GOWORK=off
  GOFLAGS=-mod=readonly`. With `--proxy`, it also installs both binaries by
  exact version in a clean container and verifies the demo chain.
- decisions D24: no container image is published for now. The README shows how
  to build one from a release tag, or put `proof` in an image of your own. When
  images are published, they go to `ghcr.io/aleutian-ai/proof` and `/proof-mcp`.

## v0.5.0 — 2026-10-18

Chain format v4, anchor v7 and bundle v2, which close
by construction the holes two external reviews found in v3 and v6. The formats
are specified in `docs/format-spec.md`, `docs/bundle-format.md` and
`docs/sink-format.md`, and their conformance vectors are written in Python from
that text (`scripts/v4-vectors.py`, `verdict-vectors.py`, `bundle-vectors.py`).

### Formats

- **Chain format v4** (format-spec §2.0). Each entry links through a salted
  leaf hash over its id, type and content hash. Erasure removes the salt and
  those fields and keeps the leaf hash, so an erased entry is recomputed like
  any other: rewriting the entries before it breaks the chain, and `entry_id`
  and `entry_type` are hashed. A chain's first entry is at `global_seq` 0. v4
  has no tombstones.
- **v2 and v3 are frozen** (§2.6): verified forever, never rewritten. A v2 or
  v3 chain is continued in v4 from its next entry; a v2 or v3 entry after a v4
  entry is `format_field_misuse`. There is no migration tool, by design.
- **Anchor v7** (§9): the range by `start_seq`/`end_seq` (strings), so erasure
  never breaks an anchor; `previous_anchor_hash` signed in; `verified_through`
  removed; signed with the ML-DSA context `aleutian.proof.anchor.v7`.
- **Sink record envelope v2** (sink-format §9.1), signed with the context
  `aleutian.proof.record.v2`, also binds the entry's leaf hash.
- **Export bundle v2** (bundle-format §16): v4 entries, v7 checkpoints,
  record.v2 signatures. Under checkpoint trust, inner entry ids and types are
  now authenticated. v1 is frozen and still verified.
- Three bundle v1 vectors changed their example of a wrong `format` (it was
  the now-valid v2 string; bundle-format §15 note 3). The frozen vector files'
  comments say they are frozen. No expected value of a frozen file changed.

### Breaking changes

- `verify.BindAnchor`, `verify.VerifyAnchor`, `Walker.BindAnchor` and
  `Walker.VerifyAnchor` take a `verify.Expect{Subject, PreviousAnchorHash}`
  instead of the previous anchor hash. A subject that differs is
  `BindTenantMismatch`; with none given, `BindResult.SubjectChecked` is false
  and `NotProven` says so.
- `linker` writes v4 by default; `linker.WithFormatV3` (deprecated) and
  `WithFormatV2` write the frozen formats, and refuse to append after a v4
  entry (`ErrFormatRegression`). `Input.Salt` lets a writer layered on the
  linker supply the salt it minted; `WithSaltFunc` is for tests.
- `anchor/build` produces v7 anchors only.
- `anchor.ContextStringSigner` (new) signs with an ML-DSA context; a v7 anchor
  needs one. `anchor.SignerOpts` carries the context through `crypto.Signer`.
  `mldsa.SignWithContext` and `VerifyWithContext` are new.
- `sink.RecordSigner.SignRecord` takes the ML-DSA context string.
- `sink.Sink.Checkpoint` requires `TrackHeads` (or, by name, `UntrackedHeads`):
  a checkpoint series is only as complete as a record kept outside the folder
  shows (`ErrHeadsRequired`). `FileHeads` refuses a missing file
  (`ErrHeadsFileMissing`); `NewFileHeads` starts one, once.
- The sink writes v4 chains, v7 checkpoints, record.v2 signatures and bundle
  v2 exports. A sink folder from before v0.5.0 (v3 chains) is not continued:
  export it with v0.4.x first (sink-format §10).
- `bundle.VerifyDir` takes an `*os.Root` opened by the caller.
- `safebolt.LockFile` (internal) takes `exclusive bool`.

### CLI

- `proof commit` writes v4 and requires `entry_type`; `--format 3` and
  `--format 2` replace `--format-v2` and print a deprecation warning.
- New `proof erase --db --chain --seq`: erases a v4 entry in place, forgets its
  nonce, and rewrites the database and nonce files.
- `proof verify --anchor` takes `--subject`, required for a v7 anchor.
- `proof sink checkpoint` and `proof sink erase --key` require `--heads FILE`,
  and `--first` to start it.
- `proof verify` reports erased v4 entries separately from v2/v3 tombstones.

### MCP

- `verify_anchor` takes an optional `subject` and reports `subject_checked`.
- `compute_chain_hash` takes `format_version` 4 (from id, type, content hash
  and salt, or an erased entry's leaf hash) and returns `leaf_hash`.
- `verify_bundle` reads the bundle through an `os.Root` opened inside `--root`.
- The tool names and schemas are pinned in `testdata/tools_list.golden.json`.

### Security

- An erasure with no record signature in a sink that signs its records is a
  problem (`erasure-unsigned`): the forged tail erasure of review round 2.
- The bolt store's writers hold a lock file (`<db>.lock`) as well as bbolt's
  lock, so `bolt.CompactFile`'s rename cannot lose a concurrent write.
- The bbolt read-through check refuses a file that already failed in this
  process without reading it again, so a long-lived server cannot be made to
  abandon a handle (and its memory map) on every call.

### Platforms

- Linux and macOS. The module builds on other platforms, and the operations
  that open a store return an error saying the platform is unsupported
  (`internal/osfile`).

### From the pre-tag review (items 74 to 87)

An external review of `1452f03` found the construction sound and asked for
these before the tag. Format rules, now in the specs and pinned by vectors:

- **A reader never repairs text** (format-spec §2.0, §9.8). An entries file or
  anchor that is not valid UTF-8, or whose JSON escapes a lone surrogate, is
  refused: `encoding/json` read both as U+FFFD, a second spelling of an id
  that hashes the same, where the Python verifier refused the file. No member
  of an entry or a v7 anchor is `null`, and no number is `-0` (§5.5).
- **A v7 anchor's** `anchor_id` and `previous_anchor_id` are non-empty, and
  its string members are valid UTF-8 (§9.3). An invalid `subject` made an
  anchor that verified in memory and never from its file.
- **One break per entry** (§5.0, §5.5). A leaf mismatch is the entry's only
  break; a timestamp in another spelling is `invalid_timestamp` and the walk
  goes on from the stored hash (Go recomputed it and reported a mismatch there
  and after, also for v3); a tombstone reports its first failing check; an
  entry after a malformed `chain_hash` is checked through step 7 and not
  linked; a malformed supplied predecessor is the first entry's step-7 break.
  The verdict vectors now count every case's breaks.
- **Claim 6 restated** (§5.0): an erased leaf hash denies correlation to
  someone holding the original entry only once every copy of the entry is
  gone, exports and bundles included; `erased: true` on the wire says the
  export withholds the fields.

Implementation:

- `proof erase` forgets the nonce, then erases, then always rewrites the
  database, so an interrupted run is finished by running it again (it once
  left the salt in free pages, or a nonce under an id nothing held). It
  refuses a symlinked `--db`. `bolt.Store.Erase`'s contract says the same.
- `proof verify --anchor` binds a v7 anchor to a chain that has grown since
  (`Walker.WatchTip`, new); it reported `height_mismatch`.
- The failed-file cache of the store check reads a file again once its size,
  mtime or ctime changes, so a database restored from backup is not refused
  until restart. Compaction writes in 64 MiB transactions (4.7 GB to erase one
  entry of a million, now 1.2 GB).
- MCP `verify_chain` and `verify_anchor` report `erased_found` and that an
  erasure is not authenticated by the chain; they could not show a v4
  erasure. Stale v3 wording fixed.
- `linker`: a supplied `Salt` needs `ExpectChainHash`, and no batch repeats a
  salt.
- `exportbundle` hashes an `entry_type` of any length as stored.
- The sink refuses a checkpoint that is not v7; `anchor/build` refuses a
  successor that does not grow or goes back in time; `SignCanonical` signs
  only an anchor's exact canonical form; a `HeadsFile` that started a record
  refuses it once deleted; `erasure-unsigned` counts a malformed row, or one
  under a key the folder never had, as absent; an erased v4 entry with a
  tombstone field is `format_field_misuse`.
- A shared lock opens its lock file read-only, so `proof disclose` works on
  read-only media; a lock file that is not a regular file is refused.

## v0.4.1 — 2026-10-15

A patch for defects found in a review of v0.4.0. No new features and no format
change.

### Security

- **The strict entry decoder accepted a second spelling of a member through
  Unicode folding.** It refused a name whose lower case matched a known member,
  then decoded the whole object with `encoding/json`, which also folds Unicode:
  `{"timestamp": A, "timeſtamp": B}` (U+017F) was accepted and the entry
  carried B. A name that folds to one of the format's without being it is now
  refused, and every field is filled from its exact member name only. This
  reached `proof verify` and the MCP server's `verify_chain`.
- **Compacting the nonce file could drop a nonce written during the copy.**
  The rewrite held bbolt's lock on the original file and released it before
  renaming the copy over it; a writer arriving in between wrote into the file
  the rename discarded, and that entry could never be disclosed. The nonce file
  now has a separate lock file (`<nonce file>.lock`) that every open takes and
  the rewrite holds until after the rename. The two callers that ship (`proof
  forget` and the MCP `commit`) already serialized on the evidence database's
  lock, so neither could reach the window; any other caller could.

### Fixed

- `verify.VerifyAnchor` and `Walker.VerifyAnchor` return an error for a nil key
  source, including a nil `*anchor.KeyRing`; they panicked.
- `TestExportAndVerify_MemoryDoesNotGrowWithTheChain` failed about one run in
  four on Linux: its bound sat inside the streaming plateau's own variation. It
  is now a fifth of the data, which still fails any verb that holds the chain.

### Changed

- **`.review/` is no longer in the repository.** v0.4.0 shipped the external
  review's findings and reproduction tests in its module zip; that zip cannot
  be changed. The folder is now ignored.
- `fixtures/MANIFEST.json` records that two vector files were corrected in
  v0.4.0, and that the v2 values the JavaScript verifier once produced are gone.
- New `SECURITY.md`: how to report a vulnerability (GitHub private reporting,
  or security@aleutian.ai), and what is in scope.
- README: "Keeping keys in 1Password", from a run against a real vault.

## v0.4.0 — 2026-10-13

### Security

Fixes from an external review of `6a77fa3` (2026-10-10).

- **The anchor binder had its own tombstone rule.** `verify.BindAnchor` and
  `verify.VerifyAnchor` took any entry whose content hash began `TOMBSTONE:` as
  erased and adopted its stored chain hash, without looking at its type or id.
  Marking only the last entry that way let every other entry be replaced under
  a valid signed anchor. Binding now runs the same walk as `verify.Chain`, where
  an entry is a tombstone by `entry_type` and the `tomb_` id prefix
  (format-spec §5).
- **A real tombstone still leaves the entries before it unbound, and the result
  now says so.** *(Limitation, not fixed: it needs a new chain format version.)*
  A tombstone's chain hash is taken as stored, so whoever can write the store
  can replace everything before one, or before an entry they turn into one
  (`entry_type` and `entry_id` are in no hash). `verify.Result` gains
  `LastTombstone`; `verify.BindResult` gains `Tombstones` and `EntriesNotBound`,
  and its `Proven` / `NotProven` text names the entries an anchor does not bind;
  `proof verify` prints the same. See verification-model.md, "What a tombstone
  leaves unverified", and decisions.md D6.
- **The verifier checks field shapes.** *(Breaking.)* A chain or content hash
  that is not a digest, a negative sequence number or a v2 entry with no run id
  is a break, new type `invalid_field`, even when the entry hashes to its stored
  chain hash. The first `global_seq` is not constrained: proof's linker starts
  at 0 and the hosted platform's at 1.
- **A stored timestamp has one spelling.** *(Breaking.)* It must be exactly
  `YYYY-MM-DDTHH:MM:SS.ffffffZ` (new constant `verify.TimestampLayout`). Another
  offset, no fraction or more than six digits is `invalid_timestamp`: each
  hashed the same as the canonical form, so the string could be changed without
  a break.
- **`verify.VerifyAnchor` returns nothing bound beside a signature error.** It
  returned `Bound=true` with the error.
- **`merkle.VerifyConsistency` makes RFC 9162 §2.1.4.2's final size check.** A
  proof for (m, n) also verified for some smaller old sizes against the same
  old root: 1,261 wrong-size acceptances for n ≤ 40, now 0.
- **`merkle.UnmarshalFrontier` bounds the level index.** `0|50000000:<hash>`
  allocated about 1.2 GB, and level 64 passed the size check because `1<<64` is
  0 in Go. A level must be a set bit of the size.
- **`bundle.VerifyDir` follows no symlinked directory and refuses an empty
  manifest.** *(Breaking: an empty manifest is `ErrEmptyManifest`, it was
  `Intact=true`.)* Only the last path component was checked, so `sub/secret`
  with `sub` a symlink had a file outside the bundle hashed. Files are now
  opened through an `os.Root` with every component checked.
- **`chainformat.ComputeChainHash` and `ComputeChainHashV3` refuse a year
  outside 0000-9999.** A negative year was written as `0000`, so year -5 and
  year 0 hashed alike. New `chainformat.ValidateTimestamp`.
- **A damaged store file is an error, on every path.** No operation on a
  truncated or overwritten store file panics or hangs, the ones that write
  included. Every bbolt-backed store (`store/bolt`, the sink's files, the nonce
  store) returns an error wrapping `ErrCorrupt` (`bolt.ErrCorrupt`,
  `sink.ErrCorrupt`, one value); a handle that failed inside the storage layer
  is abandoned rather than closed, with its lock released and its memory map
  left until the process exits. Files are read through once before a process
  first writes to them (`bolt.WithoutCheck`, `sink.WithoutIntegrityCheck`,
  `--skip-check`; about 0.1 s per GiB in cache), and every open first checks
  the sizes and counts in the meta pages and freelist header against the
  file's length. A panic in caller-supplied code (a signer, a key source, a
  callback) is not reported as damage: it is re-raised to the caller after the
  transaction rolls back. `proof sink verify` exits 1 on
  a damaged file and every other verb 3; they exited 2, the usage-error code,
  from the Go runtime. *(Not covered: a file deliberately crafted beyond the
  meta pages and freelist header. Pages that point back at each other are
  followed without end.)*
- **Sink: a reused source with different content is refused.** *(Breaking.)*
  A record whose `Source` is already committed with different content, or whose
  committed content is missing, gets the new `sink.ErrSourceConflict` and
  nothing in the call is committed. It was reported `Committed, Duplicate` and
  dropped, so rows written into `.sources` made new records vanish. Verify now
  checks the sources file: a position that points at no entry, or an entry with
  more than one, is a problem. *(Not closed: a source pointed at an entry that
  already holds the same bytes still reads as a duplicate.)*
- **Sink: `Checkpoint` does not sign over an erasure it cannot confirm.**
  *(Breaking.)* A chain that ends with an erasure no checkpoint covers is
  signed only when the caller confirms it (`sink.ConfirmErasures`, with the
  results the erase call returned: a chain is confirmed only when it ends with
  the entry that call made on that chain), its record signature verifies
  (`sink.CheckpointRecordTrust`), or the operator names the chain and vouches
  for it (`sink.ConfirmErasedChains`). On an unsigned sink, `proof sink erase`
  followed by `proof sink checkpoint` no longer covers the erasure: use
  `proof sink erase --key K` (or `--resume --key K`), which checkpoints the
  erased chains in the same run; for an erasure that missed that, `proof sink
  checkpoint --confirm-erased-chain <chain id>`. On a signing sink, `proof
  sink checkpoint --record-trust PUB`. An erase run does not vouch for an
  erasure entry it found already on a chain (`EraseResult.Relinked`). A forged
  erasure stays `erased-unanchored`. *(Not closed: someone who can write the
  subject index can mark a chain as an interrupted erasure, and the next erase
  run completes and checkpoints it; and an operator who vouches for an erasure
  they did not make signs the forgery.)*
- **Sink: checkpoint series heads.** New `sink.CheckpointHeads`,
  `sink.FileHeads`, `sink.TrackHeads`, `sink.WithCheckpointHeads` and `--heads
  FILE` on `proof sink checkpoint`, `verify` and `erase`: with the heads kept
  outside the folder, a series that is shorter than it was, or was restarted,
  is a failure and is not extended. Off unless asked for.
- **`proof sink init` puts the sink in signing mode.** *(Breaking.)* It creates
  the folder and the signatures file (`sink.RequireRecordSigning`), so a first
  commit without `--record-key` is refused instead of making the sink unsigned
  for good. It refuses a sink that already holds unsigned records.
- **`proof sink repair`** and `(*Sink).Repair`: removes content, nonce, source
  and record signature rows that match no entry (what a commit that crashed
  before its append leaves, and Verify reported forever). It prints counts. It
  leaves a chain alone when a checkpoint, a recorded head (`--heads`) or, for
  a chain with no entries, a record signature says the chain held more, when
  its erasure is pending, or when it cannot be read. *(Not closed: on a chain
  no checkpoint covers, entries removed from the end look like a crashed
  commit, and repair deletes their content.)*
- **`proof sink commit --source-field F` / `--source-prefix P`**: with either,
  committing the same input again commits nothing new. The CLI never set a
  source, so a retry duplicated every entry.
- **`proof sink verify --require-checkpoint`** makes a chain with no verified
  checkpoint a failure; `--subject-file FILE|-` on `proof sink erase` and
  `export` keeps a subject off the command line.
- **`proof export` and `proof anchor` only read.** *(Breaking: exit codes.)*
  The database is opened read-only. A `--db` that names nothing is exit 3 and
  creates nothing (it was created, and export printed `[]` and exited 0). A
  chain with no entries is exit 3, not an empty file.
- **`--out` does not overwrite.** *(Breaking.)* `export --out` and `anchor
  --out` refuse an existing file or symlink (exit 2) unless `--force` is given;
  the file is written beside its destination and renamed.
- **Exit codes.** *(Breaking.)* `commit` with a content hash that is not 128
  lowercase hex is exit 2 (was 3). `verify` with a missing or unusable
  `--anchor`, `--previous` or `--key` file is exit 3 (was 2).
- **`proof commit` bounds its input and refuses repeated entry ids.**
  *(Breaking.)* A line over 1 MiB or stdin over 1 GiB is refused. An
  `entry_id` given twice, or already on the chain, refuses the whole commit.
  The check reads the chain, so a commit's time grows with the chain's length.
  A bad timestamp is reported by field name, without Go's parse error or the
  value.
- **`proof import --previous-hash` is stored, and an import must continue the
  chain.** *(Breaking.)* Into a chain that has entries, the import must start
  at the tail's `global_seq` + 1 and link from the tail's chain hash.
- **`verify`, `export` and `anchor` no longer hold the chain in memory.** New
  `verify.EntryReader`, `verify.Walker.BindAnchor`, `verify.MaxEntryLineBytes`.
  One million entries: verify 1.7 GB to 10 MB, export 3.0 GB to 11 MB, commit
  4.0 GB to 0.7 GB. *(Breaking: a JSONL entries line over 1 MiB is refused.)*
- **A result that is not bound says nothing was proven.** Every outcome of an
  anchor bind carried the wording of a successful one, so `proof verify`
  printed "the chain in front of you is the one this anchor committed to"
  under "ANCHOR DOES NOT DESCRIBE THIS CHAIN".
- **keygen file handling.** Keys are written to a new temp file (`O_EXCL`,
  `O_NOFOLLOW`), synced and renamed. `--force` over a 0644 file leaves the
  private key 0600; a symlink at a key path is never written through.
- **The 1Password read-back checks the stored keys.** `--op-vault` (keygen and
  `sink init`) fetches both attached key files by item id and fingerprints
  them; it compared the fingerprint text field it had just written. Tested
  against a fake vault, not a real one.
- **keyfile accepts one PEM block and nothing else.** *(Breaking for such
  files.)* Bytes before the block, PEM headers (including `Proc-Type:
  4,ENCRYPTED`) and PKCS#8 attributes are refused. The platform keygen labels
  keep their `Name` header. The ML-KEM secret `z` is compared in constant time.
- **`bundle.VerifyDir`: one file, one path.** *(Breaking for such manifests.)*
  A path not in clean form, or not the file's name on disk, is `unsafe_path`; a
  path listed twice is the new `duplicate_path`.
- **The linker refuses what nothing else can carry.** *(Breaking.)* An entry id
  that is not valid UTF-8, and a timestamp whose UTC year is outside 0000 to
  9999. The unchecked chain-hash functions no longer panic on a year of 11 or
  more digits.
- **A Merkle tree size above 2^62 no longer loops forever.** The split
  computation doubled past the integer range, so `merkle.VerifyInclusion` and
  `VerifyConsistency` never returned for such a size. The MCP
  `verify_inclusion` tool takes the size from its caller: one call pinned a CPU
  core. That tool also refuses a proof of more than 63 nodes.
- **Anchors are parsed strictly.** *(Breaking.)* Only the member names an
  anchor has, spelled exactly, each once; the subject under the name its
  version uses. An anchor with unknown members, upper-case member names, a
  repeated member or a v6 `company_id` parsed and verified with `Bound=true`.
- **Anchor rules that were signed and never checked.** *(Breaking.)*
  `verified_through` above `entry_count`, `entry_count` below 1 and a negative
  `created_at_ms` are refused (v4, v6). A signature with a line break in its
  base64, an anchor with no `signing_key_id` and a key ring entry under the
  empty id are refused. `previous_anchor_id` and the predecessor hash must
  agree about whether an anchor is the first: new outcome
  `predecessor_mismatch`.
- **An anchor is never built over, or bound to, a mid-chain segment.**
  `build.FromWalker` and `Walker.VerifyAnchor` refuse a walker that started
  from a predecessor hash (new `Walker.Segment`). A walker over entries 5..9
  produced `entry_count=5` and verified as an anchor over a five-entry chain.
  `build` also refuses a previous anchor for another subject or one that covers
  more entries than the chain.
- **`verify.Series` and `verify.VerifyAnchorSeries`.** The rules that make
  several anchors a series (same subject, seed then predecessor ids, rising
  counts, time not going back) were enforced by the sink alone. They are now
  exported, and the sink uses them.
- **`verify.DecodeEntries`; `proof verify` on a file that is not entries is
  exit 3.** *(Breaking.)* An export bundle, `{}` or `null` was read as one
  entry with empty fields and reported `BROKEN`. Entries with a repeated member
  or one spelled in another case are refused. The MCP server uses the same
  decoder.
- **`proof sink verify-bundle` and package `exportbundle`: the Go reference
  verifier for export bundles** (`docs/bundle-format.md` rev 3.2).
  `proof sink verify-bundle <bundle.json> [--key F]… [--record-trust F]… [--json]`
  verifies a bundle without the sink. Exit 0 ok · 1 failed · 2 usage or a bad
  bundle or key file · 3 unreadable bundle · 4 unauthenticated · 5 internal
  error. Its output says it is the writer's own implementation, not an
  independent one. It was documented and did not exist; `proof verify
  bundle.json` printed a false `BROKEN`. Written from the specification, not
  from folder verification: a strict one-pass reader in place of
  `encoding/json`, every §5 limit enforced while reading, and no import of
  `sink`, so a recipient does not compile in bbolt. It reproduces all 114 cases
  of `bundle_v1_vectors.json` as whole results, which no Go test judged before.
- **proof-mcp reads files only inside `--root`.** *(Breaking.)* New launch
  flag `--root DIR`, default the working directory. Relative paths are relative
  to it, absolute paths must be under it, and a symbolic link that leaves it is
  refused. A path outside it gets one fixed error whatever is there. Any path
  on the machine was accepted before, and the error text said whether it
  existed and what it was. Errors no longer carry anything from the JSON or key
  parser: `verify_anchor` on a non-JSON file returned the file's first byte.
- **proof-mcp: what a key establishes is set at launch, never by a tool
  call.** *(Breaking.)* `verify_anchor` no longer takes `key_trust`; a call
  that sends it is rejected. A key named in a call is always `provided`. New
  repeatable flag `--trusted-key LEVEL=PATH` (`platform` or `self`) binds a key
  to a level. The argument alone used to turn any key into "a third party
  attests to this chain".
- **proof-mcp: `verify_chain` proves nothing about a broken chain.**
  *(Breaking.)* `proven` said "Nothing was edited…" beside `"verdict":"BROKEN"`.
  With an erased entry, `proven` covers only the entries after the last one.
  New output fields `last_tombstone` (`verify_chain`), `tombstones` and
  `entries_not_bound` (`verify_anchor`).
- **proof-mcp: bounds.** Files are opened once and read through a hard byte
  limit; `verify_bundle` refuses a manifest of more than 10,000 files;
  `verify_inclusion` declares its bounds in its schema; new flag
  `--max-db-bytes N` (default 1 GiB, 0 for none) refuses `commit` once the
  database reaches it. A stray positional argument now fails the launch.
- **The linker refuses entries shaped like erased ones.** *(Breaking.)* An
  input with entry type `tombstone`, an id starting `tomb_` or a `TOMBSTONE:`
  content hash is refused by `linker.Append` and `AppendChains`, so by
  `proof commit` too. One with the type and id and an ordinary content hash was
  appended, and the chain then verified as `BROKEN` (`invalid_tombstone`) for
  good. A tombstone replaces an entry in the store; it is never appended.
- **Sink: an entry after an erasure record is a verification problem.** An
  erasure record is keyless. Someone with write access to `evidence.db` and
  `.secrets` could append one, add an ordinary event after it and delete the
  content before it; `Verify` counted from the last erasure and reported the
  destroyed evidence as lawfully erased, with no problem. An erasure anywhere
  but the end of a chain now fails, and so does any erasure on a chain the
  subject index still binds.
- **Sink: `Checkpoint` signs nothing that does not verify.** It ran the hash
  walk and the existing series check only, so it signed over content that had
  been modified or deleted and over the forged erasure above. It now runs the
  whole per-chain verification first and reports a failing chain in
  `Checkpointed.Problem`. *(Not fixed, needs a design decision: a forged
  erasure at the end of a chain with its index row removed still verifies and
  is then covered by a checkpoint; and a deleted `anchors/<chain>/` is silently
  restarted at `0001.json`. Both are now stated in sink-format.md §6.)*
- **Sink: export checks disclosed content against its commitment.** Modified
  content was exported and counted as disclosed; it is now
  `ErrExportUnrepresentable`.
- **Sink: a secrets file or subject index without its buckets is
  `ErrCorrupt`.** `proof sink verify` exits 1; it was a plain error, exit 3.
- **Sink: checkpoint files are synced.** The file, its directory and a newly
  made `anchors/<chain>/` are fsynced before `Checkpoint` reports success. A
  power loss could leave an empty `000N.json`, which fails Verify and blocks
  every later checkpoint of that chain.
- **`proof forget` takes the nonce out of the nonce file.** *(Breaking: exit
  codes.)* It deleted the key and left the 32 bytes in a bbolt free page. It
  now rewrites the file after the delete, under the evidence database's lock. A
  missing entry, chain or database is exit 3 and creates nothing; each printed
  "forgot the nonce" and exited 0, and a mistyped `--db` created an empty
  database and nonce file. `proof disclose` creates nothing either.

### Conformance vectors

- **Every vector file but one is now written by a Python script from the
  spec.** New `scripts/spec-vectors.py` writes `chain_vectors.json`,
  `v3_golden_capture_request.json`, `merkle_golden.json`,
  `commitment_vectors.json` and `anchor_chain_hash_vectors.json`. Two of these
  were written by Go tests under `UPDATE_GOLDEN=1`; those write paths are
  removed. Before it became their writer the script reproduced three of the
  files byte for byte and every value in the other two.
  `anchor_v4_canonical_vectors.json` is still written by no script.
- **`chain_vectors.json` changed.** *(Vector change: re-vendor.)* Two of its
  three cases carried 64-character content hashes, which the format refuses
  and which passed only because the Go test called the unchecked function.
- **`commitment_vectors.json` changed.** *(Vector change: re-vendor.)* The
  three wrong-length-nonce reject cases stored a commitment unrelated to their
  nonce, so an implementation with no length check also passed. They now store
  what the formula gives for that nonce; only a refusal passes.
- `scripts/sync-vectors.sh` falls back to `sha256sum` where `shasum` is absent.

### Release and supply chain

- **Images carry third-party licence notices.**
  `scripts/third-party-licenses.sh` writes
  `licenses/proof/THIRD_PARTY_LICENSES` and
  `licenses/proof-mcp/THIRD_PARTY_LICENSES` from the modules each binary
  links; the image build fails if a binary links a module its file does not
  name.
- **`proof-mcp` reports the version it was built as.** It was the constant
  "0.3.1".
- **`golang.org/x/crypto` v0.30.0 → v0.48.0**, with `x/sys` v0.41.0 and
  `x/text` v0.34.0: the last releases that declare `go 1.24.0`. v0.30.0 was
  below the fixes for two advisories in `x/crypto/ssh`, which nothing here
  imports.
- **`deps_test.go` checks test-only imports and the root package.**
- `scripts/release-check.sh` also regenerates the `spec-vectors.py` files,
  checks the licence files are current, and runs the crypto packages on
  linux/amd64 under emulation (reported SKIPPED where that cannot run).

### Documentation and examples

- **`docs/anchor-model.md` §3 described another verifier.** It is rewritten for
  this one: the bind is computed first, the signature is checked last.
- README: a five-line demo at the top, an input example for `proof commit`, and
  a demo chain under `testdata/demo/` that the quickstart verifies.
- Internal ticket ids and private-repository paths removed from `docs/`.
- Each integration example's README says its demo broker runs without TLS or
  authentication and is not a deployment recipe. The opencode example's model
  name is `ornith-1.5:9b`.

### Added

- **Verifier verdict vectors** (`fixtures/testdata/verify_verdict_vectors.json`,
  `fixtures.VerifyVerdictVectors`). 77 cases written by
  `scripts/verdict-vectors.py` from `docs/format-spec.md` alone: what a
  verifier concludes about whole chains, entries files, anchor text and keyless
  binds, where the other vectors pin single hashes. Each is a valid chain with
  one stated defect. Go, the Python SDK and the JavaScript SDK each pass all 77.
  They include the tombstone limitation as a pinned case: a tampered chain that
  verifies, with the count a verifier must report.
- **`proof version`** (and `--version`): the release and commit a binary was
  built from. The image build passes the release in, since its build context
  has no `.git`.
- **`scripts/release-check.sh`**: the gate before a tag. gofmt, `go vet` and the
  tests for both modules; the vectors regenerated byte for byte from their
  scripts; vendored vector copies against the manifest; then `go vet` and
  `go test -race` on Linux in a container, with the tree copied into the
  container's own filesystem.
- **README: "Known limitations of the current formats"**, seven items, stated
  as holes and not as caveats.

### Fixed

- **Two sink tests failed on Linux.** `TestEraseSubject_RewritesTheIndex` and
  `TestErasureRecovery_StateMachine` detected a rewrite by inode. An erasure
  compacts the subject index twice, and on ext4 the second copy can get the
  inode the first freed. They count compactions now.
- **`/proof-mcp` is ignored** by `.gitignore` and `.dockerignore`. A 9 MB
  binary of that name is tracked at the repo root; remove it with `git rm`.
- Comments and docs that disagreed with the code: `canonical` said U+2028 and
  U+2029 are written raw (they are escaped, and a vector pins it); `keywrap`
  said its checksum authenticates a record (its key is public).

### Removed

- **`anchor.ValidateChainHashInputs`.** *(Breaking; no known users.)* It checked
  the hosted platform's id shapes (`comp_` + ULID, UUID entry ids), which are not
  the format's rules and would reject proof's own ids. Nothing called it. The
  format's only rule on anchor chain-hash inputs, no `|`, stays in
  `ValidateChainHashDelimiters`, which `ChainHash` applies. (`chainformat` has an
  unrelated function of the same name; it is unchanged.)
- **`store.Reader.ByID` and the entry-id index behind it.** *(Breaking; no
  known users.)* The index covered the whole file, so the same entry id in two
  chains silently re-pointed it at the second chain. Nothing in proof called
  `ByID`; only the store's own conformance tests did. It was removed rather than
  repaired. Format-spec §5.4 (an erased entry's original id must not resolve)
  now holds by construction: entries are keyed by chain and position, so there
  is no index an erased id could survive in. Bolt `Open` deletes the old
  `by_id` bucket from existing files; it is derived data, so nothing is lost.
  A new conformance test pins that equal ids in two chains stay two entries.

### Changed

- **`scripts/sync-vectors.sh` vendors and checks `MANIFEST.json` too.** An
  implementation checks its copies against the manifest beside them, so a stale
  manifest let stale copies pass that check (the monorepo SDKs' manifest was
  missing five vectors).

### Added

- **Bundle conformance vectors** (`fixtures/testdata/bundle_v1_vectors.json`,
  `fixtures.BundleV1Vectors`). 114 cases built by `scripts/bundle-vectors.py`
  from `docs/bundle-format.md` alone: each is a valid bundle with one stated
  defect, its expected result declared from that construction, never computed
  by a verifier. They cover every problem code, every unreadable reason but
  `too-large`, each trust combination and erasure state, the §3 grammar cases,
  context and HashML-DSA signatures (both must fail), and one real
  `proof sink export` (`scripts/bundlefixture`, build tag `bundlefixture`).
  Signatures are deterministic ML-DSA-65 from fixed seeds, made in Python and
  checked by `sink`'s tests with circl. Bundle-format §15 no longer requires a
  `too-large` vector (note 1): implementations test it themselves.
  Revisions 3.1 and 3.2 of the bundle format (2026-10-08) state what the two
  independent verifiers found unstated (§3 numbers in the bundle are
  `structure`; inner members of `record_signature`/`disclosed`; key-file text;
  duplicate ids on malformed entries; §7.6; §10 `UNREADABLE`), and add a §5
  limit of 15,000,000 JSON values (§9.1 position 3) so that a verifier's
  memory is bounded by the largest readable bundle. Format-spec §9.2 now lists
  the control-character escapes (Go 1.22+). Two vectors pin FIPS 204's hint
  encoding: a valid signature re-encoded with a repeated hint index must fail.
- **`proof sink export` and `sink.Export`: the export bundle**
  (`docs/bundle-format.md`, normative). Exports the chains selected by
  `--chain`, `--subject` (resolved through the secret index; never written) or
  `--all` as one JSON bundle that anyone can verify without the folder or
  proof.
  - **No content by default.** `--disclose all|<ids>` adds content and nonces;
    erased events and erasure records are never disclosed.
  - **Damage is never hidden.** Signature rows are exported exactly as stored.
    What a bundle cannot represent fails the export: a gap in the checkpoints,
    non-UTF-8 checkpoint text, or a live event to disclose whose content is
    missing.
  - Each chain is read under one lock hold, with a gap between chains, as
    `VerifyEach` does. The spec's limits are enforced.
  - `--out` is required. The file is written beside it, synced, then linked into
    place, never over an existing file, at mode 0600. Privacy warnings go to
    standard error.
- **`docs/format-spec.md` now specifies chain hash v3 and anchors.** §2 leads
  with v3 (the format `proof commit` writes); v2 is legacy, for existing chains.
  A new §9 covers anchors: the canonical form for every version (including the
  Go-style HTML escaping another language gets wrong by default), version
  invariants, the anchor chain hash, the ML-DSA-65 signature, key ids, and
  verification order.
- **Shared vectors for v3, anchor v6 and key ids**, in `fixtures/` and the
  manifest: `chain_v3_vectors.json`, `anchor_v6_canonical_vectors.json` and
  `keyid_vectors.json`. Their expected values were computed **independently in
  Python** by `scripts/independent-vectors.py`, from the spec alone. Until now,
  v3 and v6 expected values existed only as constants generated by Go and copied
  into the SDK tests.

- **`sink`: evidence per subject, erasable per subject, as a library package.**
  A folder holding one evidence file with one **opaque** chain per
  (class, subject), `<class>.<32 random hex>`, and a SECRET subject index
  (`evidence.db.subjects`), the only thing linking a subject to its chains. The
  evidence file and checkpoints never name a subject.
  - Events are committed as salted commitments. Their content and nonces are
    kept in ONE SECRET bbolt file, `evidence.db.secrets`, written durably in
    one transaction before the evidence transaction that commits them: a
    committed entry never points at content that did not reach the disk.
  - Each chain is checkpointed (ML-DSA-65) and verified on its own.
  - **Commit** returns one `Outcome{Committed, Duplicate}` per record, in
    order, naming no chain or subject; consumers acknowledge by index.
    - Each file is written once per call; every chain's entries and heads go in
      ONE transaction, which is the commit point. About 6–8 flushes per call,
      however many subjects it touches (before: ~11 per subject). Measured on
      macOS, 200 subjects per call went from ~10 s to ~0.1 s.
    - On any returned error nothing is committed and nothing new is left
      behind. It is not crash-atomic across the files: a crash can leave
      preparatory state, which is recoverable and erasable.
    - A failure in one pair's stored state is a `*PairError` naming that pair's
      records. Errors never name a chain.
    - Idempotent: a `Record.Source` (upstream position plus incarnation)
      already committed on its chain is skipped, across crashes.
  - **Erasure by subject** (`EraseSubject`, `EraseSubjectClass`,
    `ResumeErasures`) forgets the subject first, so a returning subject gets a
    new chain.
    - It then appends a genuine erasure entry to each chain. Its hash is
      domain-separated (`aleutian.sink.erasure.v1:`), and "genuine" is decided by
      that hash, never by `entry_type`.
    - It deletes content, nonces and source positions, and rewrites the secret
      files on every call, so erased content leaves the live files. A chain
      stays pending until that rewrite has succeeded.
    - It is recoverable after a crash, and fail-closed: a stuck chain is found
      before the subject is forgotten; otherwise `*ErasureIncompleteError`.
  - **Verify** cross-checks the index (`IndexState`: live, erased,
    erased-unanchored, index-only; problems: pending, unaccounted, relinked,
    malformed) and never names a subject. `ChainSubjects` is the one call that
    does.
  - Classes are public and permanent: from data only through an allowlist
    (`JSONFields.Classes`), and never equal to the subject.
  - Specified in `docs/sink-format.md`.
  - CLI `proof sink commit|checkpoint|verify|erase`:
    - `commit --class C | --class-field F --classes A,B` with `--subject-field
      F` (counts only); `verify [--show-subjects]` (marked SECRET);
      `erase --subject S [--class C] | --resume`; `checkpoint --trust`.
    - Exit codes: 0 ok · 1 a chain failed or was not checkpointed · 2 usage ·
      3 error · 4 busy.
  - Hardened through several 4-agent reviews:
    - `os.Root` for checkpoint I/O, and the bbolt files refused when they are
      not regular files;
    - bounded, type-checked reads;
    - strict checkpoint series;
    - read-only Verify;
    - the rest is recorded in the tickets.
- **`sink.WithRecordSigner`: a sink that signs every entry it writes**
  (ML-DSA-65, `docs/sink-format.md` §9), events in Commit and erasure entries
  alike, under a record key separate from the checkpoint key (recommended).
  - `sink.RecordSigner` (its own type, not `anchor.ContextSigner`) and
    `sink.MLDSA65RecordSigner`.
  - The `aleutian.proof.record.v1` envelope: eight length-prefixed fields
    including `previous_hash`, so record signatures chain; no JSON; empty
    ML-DSA context. Vectors computed independently in Python, must-refuse
    cases and a pinned signature (`fixtures/testdata/record_v1_vectors.json`).
  - Signatures are made against each entry's predicted chain hash, verified
    under the key their id names, and written durably to the shareable
    `evidence.db.signatures` before the append; a signer failure writes
    nothing (and an erasure forgets nothing).
  - The mode is fixed by a sink's first stored signatures:
    `ErrRecordSignerRequired`, `ErrSinkNotSigning`. Signing runs in parallel,
    bounded (`WithRecordSigningConcurrency`, default 16).
  - **Verify checks them** with `WithRecordTrust` (a key source separate from
    the checkpoint keys): every entry must carry a valid signature, rebuilt
    from the stored entry. Counts per kind on `ChainReport` (`Signed`,
    `Unsigned`, `MalformedSignatures`, `UnknownKeySignatures`,
    `BadSignatures`, `OrphanSignatures`), one problem line per kind.
    `Report.RecordSignatures` says `not-checked` for a signing sink verified
    without record trust: a separate dimension, never a silent pass. A signed
    erasure counts as `erased` without a checkpoint when nothing else fails.
    `UsesRecordKey` backs a CLI warning when a checkpoint key also signs
    records.
  - **`proof sink init`** makes the two keys the recommended way: a record key
    (online) and a checkpoint key (kept elsewhere; `--op-vault` puts it in
    1Password only), beside the sink folder, never inside it, and prints the
    commands to use. `--one-key` is allowed and warned about.
  - **CLI:** `proof sink commit|erase --record-key`, `proof sink verify
    --record-trust` (repeatable); a record key given or missing against the
    sink's mode exits 2 with the fix. The NATS and Redis examples sign with
    `PROOF_RECORD_KEY_FILE` (a path, never key material) and stop on a
    configuration error instead of redelivering.
- **Verify and Checkpoint no longer hold the sink for the whole run.** They
  read a page of whole chains at a time (~50 ms of work), releasing the files
  for longer than bbolt's lock retry between pages. Measured at 100k chains, a
  writer committing every 100 ms waits p99 ~95 ms during a Verify, where it
  waited the entire run before; Verify itself takes ~3× longer. New
  `Sink.VerifyEach` streams each report to a callback (peak heap 3.4 MiB at
  100k chains, against 43 MiB collected); `Verify` is unchanged for callers.
  `proof sink verify` prints each chain as it is verified, with the
  cross-chain findings after. The report is per-chain readings, not one
  snapshot (`docs/sink-format.md` §6).
- **Verify checks the stored linkage:** every entry's stored `previous_hash`
  must be the previous entry's chain hash, and a sink chain must start at
  sequence 0, so a signed record can be neither spliced in nor the front cut
  off with the (keyless) hashes recomputed. Entries not in chain format v3 are
  reported. A damaged signatures file is a reported problem, not an error.
- **Verify and erase no longer print crafted ids** found in the folder (entry
  ids, chain ids, entry types): entries are named by position, chains by
  number.
- **Erase errors name no chain** (as Commit's never did): chain ids in their
  messages are replaced, the ids stay in the results.
- **`linker.Input.ExpectChainHash`:** a caller can pin the chain hash an entry
  must get; `Append` and `AppendChains` refuse the whole call, writing nothing,
  otherwise (`linker.ErrUnexpectedChainHash`). The sink pins every entry, so a
  batch can no longer land at an unpredicted position (the branch that accepted
  that is gone).
- **Every bbolt file of a sink is opened without following a symlink**
  (`O_NOFOLLOW`, then a regular-file check on the opened handle), closing the
  window between the check by name and bbolt's open. New
  `store/bolt.WithNoFollow`.
- **`anchor.SignCanonical` refuses bytes that are not canonical JSON** (must
  start with `{`), so a key used for both checkpoints and records can never
  give a record envelope a checkpoint-path signature.
- **`store.ChainsUpdater` (optional capability) and `linker.AppendChains`.**
  - Append to several chains in ONE atomic transaction: tails, entries and
    heads together.
  - The bolt and memory stores implement it, and the conformance suite pins it.
    What its callback returns must be an append (`store.CheckAppend`: no
    overwritten history, no gap, heads that name the last entry).
  - A chain leased by `Append` is refused (`store.ErrChainLeased` →
    `linker.ErrChainBusy`).
  - `Append` and `AppendChains` hash through one shared path: for FormatV3,
    appending chains together or one at a time gives byte-identical entries
    (property-tested on both stores, plus a pinned V3 golden).
  - New: `store.Tail`, `store.CheckAppend`, `linker.ChainInputs`.
- **`verify.Walker`: `Chain`, streamed.** Feed entries one at a time (e.g. a
  page at a time from a store) and get exactly `Chain`'s result: `Chain` is now
  a `Walker` over a slice. `Walker.VerifyAnchor` binds a checkpoint when the
  walk reaches its last entry, so a whole series is verified in one pass.
  Re-walking per checkpoint was quadratic in checkpoints × entries. A test
  checks it against `VerifyAnchor` on intact, tombstoned and tampered chains.
  `build.FromWalker` builds an anchor from a walk; `build.Anchor` is
  `FromWalker` over a slice. The sink's Verify and Checkpoint now read chains a
  page at a time: memory holds one page, the checkpoint series, and the entry
  ids of the chain's stored rows.
- **`store/bolt.WithReadOnly`:** a shared lock, changes nothing, and refuses a
  file without the chain buckets rather than panicking on it.
- **`examples/integrations/nats`: NATS JetStream → proof.** A consumer commits
  `evidence.<key>` messages (key = the subject) and acknowledges each message
  only when its record's outcome is committed. `run.sh` crashes it between commit and ack against a real
  `nats-server`: all six messages are redelivered and recognised, and none is
  committed twice. It is its own module, so the NATS client stays out of proof's
  `go.mod`.
- **`examples/integrations/redis`: Redis / Valkey Streams → proof.** Redis never
  redelivers, so the consumer recovers pending entries (its own, then any idle
  past `-claim-idle`) before reading new ones. `run.sh` crashes it between
  commit and `XACK`; the six pending entries are recovered on restart,
  recognised, and none is committed twice. Positions carry a stream incarnation,
  so a deleted and recreated stream that reuses an entry id is not mistaken for
  the old one. `run.sh` proves this, and the check fails with the incarnation
  removed. Entries deleted while pending are reported as lost. It defaults to
  Valkey and is also run against Redis 8. It is its own module.
- **`examples/integrations/kafka`: Kafka → proof** (franz-go). The topic is the
  class (operator-fixed), the record key the subject. Offsets are committed only
  after the sink commit, per partition, up to the first record not committed;
  refused records (no key, a name) are logged by position and committed past.
  Positions carry Kafka's own topic id and the record's leader epoch, taken
  from the fetch response, so neither a deleted and recreated topic nor a
  truncated log (an unclean leader election) is mistaken for records already
  committed; `run.sh` proves the recreate case, and the check fails with the id
  removed. `run.sh` also signs every
  record (`proof sink init`, `PROOF_RECORD_KEY_FILE`), erases a user, and runs
  `proof sink verify` repeatedly alongside a live consumer. Run on
  `apache/kafka` and `apache/kafka-native` 4.1. It is its own module.
- **`examples/integrations/otel`: OpenTelemetry logs → proof.** An OTLP/HTTP
  receiver behind a real OTel Collector (`otlp_http` exporter), which does the
  batching, retrying and queueing. OTLP has no delivery position, so each log
  record needs a stable delivery id, `log.record.uid` (the collector's
  `transform` processor adds one when the app did not); it is the record's
  Source, and a record without one is refused. The receiver answers only after
  the sink commit: 200, with refusals in `partial_success`; 503 on a sink
  failure, so the collector retries. Configuration and contract errors stop it.
  `run.sh` drives it with `telemetrygen` through
  `opentelemetry-collector-contrib` 0.162: a crash before answering is retried
  and recognised (the check fails with the uid removed), records are signed,
  and a user is erased. It is its own module (`pdata` v1.65.0).
- **`examples/integrations/fluent-bit`: Fluent Bit → OTLP → `otel-sink`,
  configuration only.** Tags route (only `audit` lines go to proof). A random
  `log.record.uid` is added before buffering, unless the app wrote its own, so
  a retried chunk is recognised. A random id rather than `path:offset`: a
  reused file position would make a new line look committed. `run.sh` on
  Fluent Bit 5.1.3 shows the retry recognised and debug lines never sent. It
  also shows the cost: a shipper that loses its read position duplicates the
  lines it gave ids to, while app-written ids are recognised. Without the uid
  filters the run fails.
- `store/bolt.Store.Chains` lists every chain in a file, from the store itself.
  Not part of the store port.

### Changed

- **`scripts/container-check.sh` reports honestly.**
  - A failing step can no longer abort the run while reporting itself: one
    `detail` helper that cannot fail replaces five pipelines that died under
    `pipefail` when `grep` matched nothing.
  - A preflight stops with **exit 2** when podman can't pull, and names a failing
    credential helper, instead of reporting three product failures. Exit codes
    are now: 0 passed · 1 check failed · 2 environment.
  - The install-path check verifies **v3** through the released binary, as well
    as v2.
  - A new check drives **`proof-mcp` over stdio inside its shipped image**:
    `commit` is the only tool that writes, it commits, it returns no nonce, and
    the chain verifies.
  - Uncommitted changes print a warning.
- `anchor.ChainHash` and friends name the anchor field `subject`, not
  `companyID`. The value and its position are unchanged.


## v0.3.0 — 2026-09-28

> **Two tags.** The library is `v0.3.0`. The MCP server is a separate module,
> released as **`cmd/proof-mcp/v0.3.1`**, because its new `commit` tool depends on
> packages first released here (`commitment`, `internal/noncestore`).
> `cmd/proof-mcp/v0.3.0` is **retracted**: it was tagged one commit before its
> `go.mod` required `proof v0.3.0`, so it does not build. `go install
> github.com/aleutian-ai/proof/cmd/proof-mcp@latest` resolves to `v0.3.1`.
>
> **Breaking changes** (pre-1.0, no known users): `proof append` → `proof commit`;
> anchor v5 withdrawn (`MerkleVersion` → `WithdrawnVersion`, `Anchor.RootHash`
> and `Anchor.TreeSize` removed); MCP `compute_chain_hash` requires
> `format_version` and takes sequence numbers as strings; `proof-mcp --db`
> requires `--chains`.

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
