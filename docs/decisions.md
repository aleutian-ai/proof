# Design decisions

Each entry records what was decided, what was rejected, and — most usefully — the
reasoning, so a future change can tell whether the original constraint still
holds.

Several of these were **reversed** after investigation. Those are kept with their
original reasoning intact, because being able to see why a plausible answer was
wrong is worth more than a clean list.

---

## D1 · Zero dependencies in the crypto core

**Decided:** `xwing`, `keywrap` and `merkle` import nothing outside the standard
library. Enforced by `deps_test.go`, per package.

**Why:** for a library whose pitch is "audit our cryptography", every dependency
is something a reviewer must vendor, pin and diff. "There is nothing to review"
is the strongest version of that claim.

It also puts the KEM inside Go's native FIPS 140-3 module boundary, which
`x/crypto` is outside of.

**Cost:** two Go stdlib version floors. `crypto/mlkem` and `crypto/sha3` arrived
in Go 1.24, so 1.24 is a hard minimum.

**Revised once:** the original rule claimed the *whole* module would be
dependency-free. It is not — see D2.

---

## D2 · `canonical` and `chainformat` depend on `golang.org/x/text`

**Decided:** accept the dependency rather than work around it.

**Why:** `canonical` rejects non-NFC strings **fail-closed**. Unnormalised text is
the classic cause of cross-*language* divergence — Go, Python and JavaScript
would each hash different bytes for the same logical string, and a verifier in
another language would report tamper on a clean chain. NFC checking requires the
Unicode tables, which the standard library does not ship.

**Rejected:** moving NFC validation into an opt-in subpackage to keep `canonical`
dependency-free. That makes a fail-closed validator optional, which is a footgun
on a security boundary — the wrong trade for one dependency.

**Consequence:** the honest headline is *"the KEM core has zero dependencies; the
format core has one"*, not "zero dependencies" unqualified.

**Note:** all `capture.request.v3` fields are ASCII-restricted by regex, so NFC
is a no-op for that entry type today. The dependency is defence-in-depth for it,
and load-bearing for `canonical`'s arbitrary-JSON path.

---

## D3 · The Go floor stays at 1.24, by hand

**Decided:** pin `bbolt` to v1.4.3 and `x/sys` to v0.30.0.

**Why:** `bbolt@latest` (v1.5.0) requires Go 1.25.0, and `go mod tidy` **silently
rewrites the module's `go` directive** to match. That raises the toolchain floor
for every consumer — including one who imports only `xwing` and will never touch
a storage engine.

Pinning bbolt alone is insufficient: `x/sys`, pulled in transitively, forces 1.25
on its own.

**Cost:** two pins to maintain. v1.4.3 is a current stable release, not a stale
one, so the cost is low today. If either pin is bumped, expect the `go` directive
to move with it — recorded next to the allowlist in `deps_test.go`.

---

## D4 · `ComputeChainHash` validates by default

**Decided:**

```go
ComputeChainHash(...)          (string, error)   // validates, then computes
ComputeChainHashUnchecked(...) string            // raw primitive
```

**Why:** the preimage is `|`-delimited and not self-delimiting. With an
unvalidated `previous_hash`, two different entries produce the same hash — a
constructible collision, not a theoretical one (see format-spec §3).

A producer that controls its own inputs is safe by provenance. A library is not.

**Reversed:** the original plan kept `ComputeChainHash` unchecked and added
`ComputeChainHashChecked`, putting the safe function behind the longer name. That
is backwards. The safe one should be what you reach for by default; the primitive
should require typing `Unchecked`.

**Also corrected:** the delimiter reasoning was initially backwards. Exhaustive
testing showed that banning `|` in `run_id` prevents nothing on its own — the
load-bearing rule is that `previous_hash` is fixed-shape.

---

## D5 · `ComputeChainHashMs` is not shipped

**Decided:** drop the millisecond-taking convenience wrapper.

**Why:** it had **zero** production callers in either the producer or the
published SDK. Its only behavioural difference from the primary function is
silent precision loss, which surfaces later as an unverifiable chain rather than
as an error at the point of the mistake.

A new public API should not ship a footgun nobody uses.

**Reversed:** the original plan kept it "for cross-language parity, documented
harder". Counting the call sites changed the answer. The hazard outlives the
function, so it is pinned by test instead
(`TestChainHash_MillisecondTruncationChangesTheHash`).

---

## D6 · A tombstone retains the original chain hash

**Decided:** erasure replaces `content_hash` and leaves `chain_hash` untouched.
Verifiers must skip recomputation for tombstones.

**Why:** anchors sign the chain hash. Recomputing on erasure would invalidate
every anchor covering that range — meaning **exercising a right to erasure would
destroy the proof that the data ever existed.**

**Rejected:** recomputing the tombstone's hash so the row is self-consistent.
That breaks every entry after it *and* every anchor over it. It is the
obvious-looking fix and it is worse than the problem.

**Cost:** an invariant enforced by convention across every verifier rather than
by the type system. That cost was paid: three SDKs got it wrong, because the rule
was written in one implementation's comments. Now in format-spec §5, which is
what this document set exists for.

---

## D7 · `EntryV3` is a sealed interface

**Decided:** the interface has an unexported method, so only this package can
implement it.

**Why:** a verifier must never be handed an entry type it cannot understand. If
an outside package could implement `EntryV3`, it could define a body no other
verifier reproduces — producing a chain that type-checks and is unverifiable by
anyone else.

Sealing also keeps additions non-breaking: callers only hold the interface.

**Not just design tidiness** — `aleutianchain_16` requires the published SDK to
delegate to this package while keeping `CanonicalBytesV3(entry ChainEntryV3)` as
its API. Without the interface here, the SDK keeps its own dispatch, keeps its
own encoder, and the deduplication never happens.

---

## D8 · Errors are opaque about lengths

**Decided:** never echo a field's actual byte length in a validation error.

**Why:** an attacker who can submit entries and read errors otherwise learns the
exact post-NFC byte length of a rejected field — a size oracle over content they
cannot see.

Applied to per-field caps and to the total canonical-size check.

**Cost:** less diagnostic detail. Accepted; the caps are public constants, so a
legitimate caller can work out what was violated.

---

## D9 · bbolt is the default store

**Decided:** `store/bolt` over `go.etcd.io/bbolt`. **Rejected:** SQLite (owner
call) and Badger.

**Why bbolt over Badger:** the primary deployment is a short-lived subprocess
spawned and killed constantly. bbolt opens by mmap in microseconds with no
background goroutines; Badger pays LSM open cost and starts a compactor. Paying
that to append three entries and exit is the wrong trade. The chain is also
inherently single-writer, so Badger's concurrent write path is capability carried
and never used.

**Auditability**, the original argument for SQLite, is handled by a canonical
JSONL export instead — a cross-language, fixture-tested format rather than an
implementation detail of whichever embedded store shipped that year.

---

## D10 · Writes are upserts, and stale entry ids must not resolve

**Decided:** writing at an existing `(chain_id, global_seq)` replaces the entry.
If the replacement carries a different `entry_id`, the old id is removed from the
index.

**Why upsert:** erasure rewrites an entry in place. An append-only store leaves
both rows, and a verifier walks an entry that no longer exists — reporting a break
on an intact chain, one position after the real change.

**Why the id must disappear:** erasure assigns a fresh `tomb_*` id. If the
original still resolved, anyone holding it could look it up, receive the
tombstone, and confirm that *that specific entry* was erased. The tombstone's
content hash is random precisely to prevent that correlation — so a surviving id
would undo the design. **It is an anti-correlation property that has to be
enforced in the index, not only in the hash.**

Both were found by the cross-adapter integration matrix, not by the conformance
suite: the suite checked each adapter against the contract, and the contract had
not said.

---

## D11 · Every guard is mutation-tested

**Decided:** each protective test is verified by deliberately breaking what it
protects and confirming it fails.

**Why:** a guard that has never failed is not a guard. Several tests in this
repository were written against a mistaken mental model and passed regardless —
the published SDK's tombstone test built an entry that cannot occur in
production, and passed for years against a broken verifier.

**The trap, learned three times:** a mutation that does not **compile** produces
zero test failures, which reads identically to a missing guard. Assert the build
succeeded before believing a mutation result.

---

## D12 · The MCP server is a separate module

**Decided:** `cmd/proof-mcp/` has its own `go.mod`. The library module is
untouched.

**Why:** the official MCP Go SDK brings nine transitive dependencies —
jsonschema-go, segmentio/asm, segmentio/encoding, uritemplate, x/oauth2, x/sync,
x/time, golang-jwt — and requires Go 1.25.0. Adding it to the main module would
have raised the floor for everyone and put a protocol SDK into the graph of
someone who only wants to verify a chain.

```
go get github.com/aleutian-ai/proof         →  2 direct deps, Go 1.24
go install .../cmd/proof-mcp@latest         →  18 modules,     Go 1.25
```

`deps_test.go` alone would not have been enough: it confines dependencies
per-package, but the `go` directive and the module graph are module-wide.

**Rejected:** hand-rolling stdio JSON-RPC. Roughly 200 lines and zero
dependencies, but it means owning a protocol implementation that will drift as
MCP evolves, with no conformance reference. For a transport — as opposed to
cryptography — using the reference implementation is the better trade.

**Cost:** a `replace ../..` for local development, and nested modules are
slightly awkward in tooling. Acceptable for a binary.

---

## D13 · No key-material tools on the MCP surface, enforced by test

**Decided:** the MCP server has no keygen, decrypt, or unwrap tool, and
`TestNoKeyMaterialTools` fails the build if one whose name suggests key handling
is registered.

**Why:** a seed or plaintext returned in a tool result enters the model's context
and is transmitted to a model provider, where it may be logged and retained. For
a system whose central claim is that the operator never holds the customer's key,
that would quietly falsify the claim — and it is exactly the tool someone adds in
good faith because it looks useful.

**The check is on names, not behaviour**, deliberately. It is coarse, it will
occasionally be annoying, and it fails closed. Someone who genuinely needs such a
tool has to come and argue for it, which is the intended friction.

If it is ever justified: file-path in, file-path out, key material never in
JSON-RPC, and its own threat model.

**Related:** tool results carry `proven` and `not_proven` fields rather than only
a verdict. A model relaying the result will summarise it; putting the boundary in
the payload means the model must actively discard it to overclaim, instead of
having to remember to add it.

---

## D14 · The trust store is bring-your-own-key

**Decided:** `proof` ships **no embedded public keys**. Verification takes a
`KeySource`, and the caller states what their keys establish.

**Rejected:** porting the published SDK's trust store — `trust_manifest*.go`,
`trust_root_{dev,staging,prod}.go`, `manifest_freshness.go`, and Aleutian's
embedded production keys (~1,500 lines).

**Why:** two reasons, and the second is the stronger one.

*Operational:* embedding Aleutian's roots would put Aleutian's key rotation on an
OSS release cadence. Rotate a key and every user's verification breaks until they
upgrade `proof` — coupling a security operation to a package release is exactly
the failure mode a trust store is supposed to avoid.

*Positional:* a general-purpose Apache-2.0 verification library that ships one
vendor's keys is not general-purpose. Worse, it would be **asserting trust on the
verifier's behalf** — deciding, at compile time, whose attestations count. The
whole premise of an offline verifier is that the person running it does not have
to take the operator's word for anything, and a hardcoded root set quietly
reintroduces exactly that.

Aleutian's keys already ship in `sdk/verification-go`, which is already Apache-2.0
and already the right home for them.

**Consequence:** verifying an Aleutian anchor takes one extra step — build a
`KeyRing` from keys you obtained deliberately. `Example_verifyingWithYourOwnKeys`
is a compiled, executed example of that, so the recipe cannot rot.

**What this buys:** `Trust` becomes meaningful. Because the caller says where a
key came from, the result can distinguish *"a third party attests to this"* from
*"the chain's own holder attests to it"* — a distinction that is impossible if the
library decides trust for you, and which is the difference between evidence and an
assertion.

**Left open:** a thin `proof/trust` adapter offering one-line convenience for
Aleutian customers. Additive — `KeySource` means adding it later changes nothing
built here. Not built until someone asks.
