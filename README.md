# proof

**AleutianChain** — the verifiable audit chain behind [Aleutian](https://aleutian.ai),
as a standalone Go library.

An audit chain is an append-only sequence in which each entry's hash covers its
predecessor's. Any retroactive edit breaks every link after it, so tampering is
detectable **without trusting the storage layer, or the party that wrote it.**

This repository is the format and the maths — the part a third party needs in
order to check the work. It is deliberately not the service.

```go
import "github.com/aleutian-ai/proof/chainformat"

hash, err := chainformat.ComputeChainHash(previousHash, runID, seq, ts, contentHash)
```

---

## What this proves — and what it does not

Read this before anything else. "Verified" covers three different claims here,
and the difference is the whole design.

| You checked | Proven | NOT proven |
|---|---|---|
| **Linkage only**<br>`verify.Chain` | Nothing was edited by anyone unable to also rewrite every entry after it. | That this is the whole chain. |
| **\+ an anchor, no key**<br>`verify.BindAnchor` | The chain is the one that anchor committed to — including where it *started*, so **truncation is caught**. | That the anchor is genuine. |
| **\+ the anchor's signature**<br>`verify.VerifyAnchor` | The anchor was signed by the holder of a key you named. | That the anchor reached you by a path its subject could not rewrite. |

### Why linkage alone cannot see truncation

Deleting entries from the front is not an edit-with-the-rest-intact — it is
presenting a valid suffix as though it were the whole:

```
ORIGINAL   [0]→[1]→[2]→[3]→[4]→[5]
PRESENTED            [3]→[4]→[5]      internally flawless. Verifies clean.
```

Nothing inside a chain records how long it should be or where it began; the first
entry is simply the one whose previous hash is empty. Closing this needs
something *outside* the chain — an **anchor**, a signed statement that at a given
time the chain's head was `H` over a stated entry range. Truncate below that
range and the anchor no longer describes what you were handed.

### The part that is not cryptography

An anchor is only as good as **where you got it**. One read back from the same
store as the chain proves consistency, not external commitment: whoever can
rewrite the chain can re-sign the anchor. It becomes an independent witness only
when it reaches you by a path its subject cannot alter — which is a question
about delivery and key custody, not about hashes.

`proof` cannot determine that for you, so it does not pretend to. Results carry
`proven` and `not_proven` as **fields**, not footnotes.

> If you build on this, keep the three claims apart when you report results.
> Calling a locally verified chain "verified" invites a reader to believe the
> strongest one.

See [docs/verification-model.md](docs/verification-model.md) and
[docs/anchor-model.md](docs/anchor-model.md).

---

## Quickstart

```console
$ go install github.com/aleutian-ai/proof/cmd/proof@latest

$ proof verify entries.json
INTACT — 5 entries verified, 1 erased

  Proven:     nothing was edited under you.
  NOT proven: that this is the whole chain. Entries could have been
              removed from the front and the rest re-linked; detecting
              that needs an anchor, which was not checked here.
```

Exit codes are distinct on purpose: `0` ok · `1` chain broken · `2` usage ·
`3` I/O error. A script that cannot tell "the chain is broken" from "I could not
open the file" will take the wrong action on one of them.

As a library:

```console
$ go get github.com/aleutian-ai/proof
```

As an MCP server, so an agent can check a chain during a conversation:

```console
$ go install github.com/aleutian-ai/proof/cmd/proof-mcp@latest
$ claude mcp add aleutianchain -- proof-mcp
```

Seven tools: `verify_chain`, `verify_anchor`, `verify_bundle`,
`compute_chain_hash`, `canonicalize_leaf`, `verify_inclusion`,
`explain_trust_model`.

### There is no keygen or decrypt tool, and there will not be one

MCP tool results are transmitted to a model provider, where they may be logged
and retained. A seed or a plaintext returned from a tool would cross that
boundary — quietly falsifying the one claim the whole system rests on, that the
operator never holds the customer's key.

`TestNoKeyMaterialTools` fails the build if a tool whose name suggests key
handling is ever registered. The check is on *names*: coarse, occasionally
annoying, and it fails closed. Key operations belong in the human-driven CLI.

---

## Trust is yours to decide

`proof` ships **no embedded public keys**. You supply the key, and you say where
it came from:

```go
ring, _ := anchor.NewKeyRing(anchor.TrustProvided, map[string][]byte{
    "aleutian-ml-dsa-65-2026-v1": publicKey,
})
res, _ := verify.VerifyAnchor(a, entries, ring)
fmt.Println(res.Trust.Establishes())
```

| Level | Establishes |
|---|---|
| `platform` | a third party attests to this chain |
| `provided` | the holder of a key you supplied attests to this chain |
| `self` | the chain's own holder attests to it; no third party is involved |

Embedding a vendor's roots would decide, at build time, whose attestations count
— and the premise of an offline verifier is that whoever runs it need not take
anyone's word for that. It would also tie key rotation to a software release.
See [D14](docs/decisions.md).

---

## Dependencies

The cryptographic core has **none**. Not "few" — none.

```console
$ go list -deps ./xwing ./keywrap | grep -v '^github.com/aleutian-ai/proof'
(stdlib only)
```

That is checkable, and it is checked: [`deps_test.go`](deps_test.go) fails the
build if any package gains an import outside its allowlist.

| Package | External dependencies |
|---|---|
| `xwing`, `keywrap` | **none** — `crypto/mlkem`, `crypto/sha3`, `crypto/ecdh` are stdlib as of Go 1.24 |
| `merkle` | **none** |
| `bundle` | **none** |
| `canonical`, `chainformat` | `golang.org/x/text` — Unicode NFC validation needs the Unicode tables |
| `anchor`, `verify` | `github.com/cloudflare/circl` — ML-DSA-65 is not in the standard library |
| `store/bolt` | `go.etcd.io/bbolt` |
| **anywhere** | never a cloud SDK |

Being stdlib-only also places the KEM inside Go's native FIPS 140-3 module
boundary (`GODEBUG=fips140=on`), which `x/crypto` is outside of.

The `go` directive is held at **1.24.0** by hand. `bbolt` and `x/sys` are pinned
below their latest releases to keep it there — someone importing only `xwing`
should not need a newer toolchain because of a storage engine they never use.

---

## Packages

```
xwing           X-Wing hybrid KEM — ML-KEM-768 + X25519
keywrap         versioned wrapped-key wire format
canonical       deterministic JSON encoding
chainformat     leaf encoding, chain hash linkage, tombstones   ← the core
merkle          roots, inclusion proofs, consistency proofs
anchor          anchor canonical form, anchor-of-anchors hash, ML-DSA-65 verify
bundle          export-bundle manifest root + directory verification
verify          the verdicts: Chain, BindAnchor, VerifyAnchor
store           persistence port + bolt / memory adapters
fixtures        cross-language golden vectors, embedded

cmd/proof       CLI — verify · export · init
cmd/proof-mcp   MCP server (separate module: its SDK needs Go 1.25)
```

---

## Erasure

A chain that cannot forget is a chain that cannot comply. When an entry's content
is erased, the entry stays in position and its content hash is replaced by a
random tombstone value:

```
[1]→[2]→[3']→[4]→[5]     3' keeps its ORIGINAL chain_hash
          └─ content_hash replaced by 32 random bytes
```

The linkage survives, so a lawful erasure stays distinguishable from a row that
merely vanished.

**A tombstone's chain hash is not reproducible from its own fields**, and a
verifier that recomputes it will report a false break on every erased entry.
That is deliberate: anchors sign the chain hash, so recomputing on erasure would
invalidate every anchor over that range — exercising a right to erasure would
destroy the proof that the data ever existed.

> **Implementing a verifier?** Skip hash recomputation for tombstones; validate
> the format only. This rule is easy to miss and expensive to get wrong — three
> independent SDKs got it wrong the same way, because it had been written down in
> exactly one implementation's comments. It is now in
> [docs/format-spec.md](docs/format-spec.md).

---

## Status

Under active development, ahead of a first tagged release. Every capability
described above is built and tested; what remains is packaging and the
deduplication that motivated the project.

| | |
|---|---|
| ✅ built | format core · `anchor` · `bundle` · `verify` · `linker` · CLI · MCP server (7 tools) |
| ⏳ not yet | published tag · the monorepo and SDKs consuming this instead of their own copies |

**276 tests** across the library and MCP module. Every guard here has been
**mutation-tested** — the protection is deliberately broken and the test
confirmed to fail — because a guard that has never failed is not a guard. That
discipline has repeatedly caught tests which passed for the wrong reason.

---

## What is deliberately not here

This is the format, the maths, and the append path — not the service. Absent, and
staying absent:

- **tenancy, retention, key ceremony, hosted anchoring** — operational plane
- **cloud clients of any kind** — asserted by test, because a verifier an auditor
  cannot run without credentials to the thing being audited is not a verifier

The dividing line is whether a third party can check the claim for themselves. If
they can, it belongs here; if it is about *operating* the system, it does not.

**The linker was on this list until 2026-09-12.** It now ships, in `linker/`,
because a verifier alone checks a claim it cannot produce — you would need the
service to make a chain worth verifying, which is not a guarantee a third party
can exercise on their own. Sequence assignment and hash linkage are checkable
arithmetic and belong here. Watermark reconciliation, per-tenant batching, and
heartbeats stayed behind, which is the same dividing line applied more carefully.

---

## Documentation

| Document | For |
|---|---|
| [docs/format-spec.md](docs/format-spec.md) | Implementing a verifier in another language |
| [docs/verification-model.md](docs/verification-model.md) | Understanding what a verdict means |
| [docs/anchor-model.md](docs/anchor-model.md) | What an anchor proves, and what its provenance must be |
| [docs/decisions.md](docs/decisions.md) | Why the design is the way it is |
| [docs/runbook.md](docs/runbook.md) | Working on this repository |

---

## Licence

Apache 2.0. See [LICENSE](LICENSE).

The verification maths is open because a cryptographic audit trail nobody can
inspect is a claim, not a proof. The operational platform — tenancy, retention,
key ceremony, hosted anchoring — is not part of this repository.
