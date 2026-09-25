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

hash, err := chainformat.ComputeChainHashV3(previousHash, globalSeq, ts, contentHash)
```

v3 is the current format and the one to build against. v2 exists, is still
verified, and is never rewritten — it bound the *batch* an entry was written in,
so a chain depended on the API calls that produced it rather than on its own
contents. v3 binds the entry's position in the chain instead. See
[D15](docs/decisions.md).

---

## What this proves — and what it does not

Read this before anything else. "Verified" covers three different claims here,
and the difference is the whole design.

| You checked | Proven | NOT proven |
|---|---|---|
| **Linkage only**<br>`verify.Chain`<br>`proof verify e.json` | Nothing was edited by anyone unable to also rewrite every entry after it. | That this is the whole chain. |
| **\+ an anchor, no key**<br>`verify.BindAnchor`<br>`… --anchor a.json` | The chain is the one that anchor committed to — including where it *started*, so **truncation is caught**. | That the anchor is genuine. |
| **\+ the anchor's signature**<br>`verify.VerifyAnchor`<br>`… --anchor a.json --key pub.pem` | The anchor was signed by the holder of a key you named. | That the anchor reached you by a path its subject could not rewrite. |

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

Or without installing anything:

```console
$ podman build -t proof .                          # published tag lands with v0.2.0
$ podman run --rm --network=none -v "$PWD:/data:ro" \
      proof verify /data/entries.json
```

A container is the lowest-trust way to run someone else's verifier, which is
why it is a first-class path here and not an afterthought. The image is 3.5 MB:
a static binary on `scratch`, with no shell, no package manager and no libc, so
there is nothing in it to audit but the binary. `--network=none` is not a
precaution you are taking against this tool — verification is arithmetic over a
file you already have — it is a way to *check* the claim rather than believe it.

The build pins its own base image by digest, and `--target proof-mcp` builds
the MCP server the same way. A published image records the commit it was built
from in `org.opencontainers.image.revision` — passed as `--label` by
`scripts/publish-image.sh`, never as a build argument, because an `ARG`
interpolated into a `LABEL` is not part of podman's cache key and would happily
carry a previous build's commit. A plain `podman build` sets no revision label
rather than an untrue one.

Nothing has been pushed to a registry yet — `scripts/publish-image.sh` does
that, by hand, and refuses to run against a dirty working tree so an image's
revision label is never a lie.

### Anchoring a chain

```console
$ proof anchor --db chain.db --chain demo \
      --subject acct-pseudonym-7f3a \
      --key ml-dsa-65-private.pem --out anchor.json

anchored 4 entries

  anchor id   anchor_d7b286b6-6b36-45a1-83be-dbef73b2e4e9
  subject     acct-pseudonym-7f3a
  range       ent_000 … ent_003
  key id      e38207ddb2d82ffe9ff0ffda06085a36
  previous    (none — this is the first anchor in the chain)

  Proven:     these entries link, and nothing was edited under you.
  NOT proven: that this anchor is an independent witness. It becomes
              one only when it reaches a reader by a path you cannot
              rewrite. Kept beside the chain it describes, it proves
              consistency and nothing more.
```

**It verifies the chain before it will describe it**, and refuses a broken one
with exit code `1` — the same code `proof verify` uses, so a script treats "this
chain is broken" identically whichever verb found it. `verified_through` is
therefore a claim this tool established rather than one it repeated.

`--subject` is required and has no default. It is inside the signed bytes, so it
can never be erased or corrected: use a stable pseudonym or an opaque id, never
a name, an email address or a device hostname.

Pass `--previous <anchor.json>` for every anchor after the first. The output then
prints the predecessor's chain hash, because a verifier needs it and **cannot
recover it from the new anchor alone** — an anchor names its predecessor by id,
not by hash.

Without `--out` the anchor goes to stdout and the summary to stderr, so
`proof anchor … > anchor.json` gives a clean file.

Like `keygen`, this verb takes a private key and is therefore never exposed over
MCP.

Check it back with `proof verify --anchor`, below.

### The whole loop, from a terminal

```console
$ proof init   --db chain.db
$ proof append --db chain.db --chain demo  < entries.jsonl
$ proof export --db chain.db --chain demo --out e.jsonl --jsonl
$ proof anchor --db chain.db --chain demo --subject acct-7f3a \
      --key ml-dsa-65-private.pem --out a.json
$ proof verify e.jsonl --anchor a.json --key ml-dsa-65-public.pem
```

`append` **mints** positions and hashes; its input carries none. Supplying
`chain_hash`, `global_seq`, `run_id` or `sequence_num` is an error rather than
ignored — silently recomputing a field someone supplied is how they end up
believing their hashes were preserved.

`import` **carries** them. It verifies the batch, refuses to write into an
occupied sequence range, and then stores every hashed field verbatim, so
`export → import → export` is byte-identical. It deliberately does not use the
linker: re-linking would renumber from the target's tail, and v3 binds
`global_seq`, so identical entries would acquire different hashes.

Importing a *segment* needs `--previous-hash`, because its first entry links
from a predecessor rather than from nothing.

### Checking an anchor

```console
$ proof verify entries.json --anchor anchor.json --key ml-dsa-65-public.pem

INTACT — 4 entries verified

  Proven:     nothing was edited under you.
  NOT proven: that this is the whole chain — not from linkage alone.
              See the anchor result below, which is what closes it.

ANCHOR BOUND — 4 entries covered
  signature verified (provided)
  establishes: the holder of a key you supplied attests to this chain
```

This is the truncation case made concrete. Drop entries from the front, re-link
what remains, and `proof verify` alone reports **INTACT** — correctly, because
linkage genuinely cannot see it. Add `--anchor` and the same file comes back
`range_start_mismatch`, exit `1`.

`--previous <anchor.json>` is needed for any anchor that is not the first in its
chain (`--previous-hash <hex>` if you kept the hash but not the file). Omit it
and the output **says** it assumed a genesis anchor, so a mismatch points at the
missing input rather than at an imaginary attacker.

`--key-trust` decides what success means — `platform`, `provided` or `self` —
and the result always states what that establishes rather than saying "verified".

### Generating keys

```console
$ proof keygen --alg x-wing --slot dual --out-dir ./keys

X-Wing (primary)
  private  keys/x-wing-primary-private.pem   (0600 — this is the secret)
  public   keys/x-wing-primary-public.pem
  key id   4f2c…
  SHA-512  4f2c 9a11 …
  self-test passed: this key encrypted a secret to itself and recovered it
```

`--alg` takes `x-wing`, `ml-kem-768`, `ml-kem-1024`, `ml-dsa-44`, `ml-dsa-65`,
or `ml-dsa-87` — only algorithms this module can also **operate** with, because
a key nothing can use is a trap, not a key. Files are written in the standard
PKCS#8 seed form (RFC 9881 / RFC 9935), so other implementations can read them.

Three things are deliberate:

- **The key is proved before it is stored.** Generate → pairwise consistency
  test → write. A key that fails its own round trip never reaches disk, so a
  faulty generation cannot be discovered later, after data is encrypted to it.
- **`--slot dual`** mints an independent hot primary and cold backup, and
  refuses both if their fingerprints match — identical keys minted seconds
  apart mean the random source is broken.
- **The private key is never printed.** Not on stdout, not on stderr, not with
  a flag. It exists in one place: the `0600` file you asked for.

`--op-vault <vault>` additionally stores the pair in 1Password through the `op`
CLI, passing the files by reference so the secret never appears in the process
list, then reads the fingerprint back to confirm what actually landed. If that
fails, the command says so and leaves you the valid files on disk.

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

### No MCP tool touches key material, and none ever will

MCP tool results are transmitted to a model provider, where they may be logged
and retained. A seed or a plaintext returned from a tool would cross that
boundary — quietly falsifying the one claim the whole system rests on, that the
operator never holds the customer's key.

`TestNoKeyMaterialTools` fails the build if a tool whose name suggests key
handling is ever registered. The check is on *names*: coarse, occasionally
annoying, and it fails closed. Key operations belong in the human-driven CLI,
where `proof keygen` lives and no result crosses a provider boundary.

---

## Trust is yours to decide

`proof` ships **no embedded public keys**. You supply the key, and you say where
it came from:

```go
ring, _ := anchor.NewKeyRing(anchor.TrustProvided, map[string][]byte{
    "aleutian-ml-dsa-65-2026-v1": publicKey,
})
res, _ := verify.VerifyAnchor(a, entries, anchor.SeedAnchorHash, ring)
fmt.Println(res.Trust.Establishes())
```

The third argument is the **previous anchor's chain hash**. An anchor commits to
its predecessor's hash but names that predecessor only by id, so the hash cannot
be recovered from the anchor in front of you — you need the previous anchor, or
a record of its hash. Pass `anchor.SeedAnchorHash` for the first anchor in a
chain and `prev.ChainHash` for every one after it. It is a required argument
rather than a default because defaulting it made the verifier silently
genesis-only, and a correct chained anchor came back looking like tampering.

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

## Signing an anchor

`proof` verifies anchors, and now produces them. One call:

```go
s, err := anchor.NewMLDSA65Signer(seed)   // seed from `proof keygen`
if err != nil {
    return err
}
defer s.Close()

signed, err := anchor.SignAnchor(ctx, s, a)
```

`SignAnchor` stamps the key id, validates, canonicalizes, signs, **and verifies
the signature before returning it**. It is one call rather than four because
`signing_key_id` lives *inside* the signed bytes: populate it after
canonicalizing and you sign one set of bytes and publish another. The anchor
then fails verification forever, with a generic "invalid signature" and nothing
pointing at the cause. That is not hypothetical — it is a bug this project
already shipped once, and the API is now shaped so it cannot recur.

The self-verification also catches something no length check can. `crypto.Signer`
passes a `[]byte` that means a **digest** for RSA and ECDSA but the **whole
message** for Ed25519 and ML-DSA, and the interface cannot tell them apart. A
signer written with RSA habits hashes first and returns a structurally perfect
3309-byte signature over the wrong bytes.

### Your key never has to touch this module

```go
type ContextSigner interface {
    Public() crypto.PublicKey
    SignContext(ctx context.Context, msg []byte) ([]byte, error)
}
```

Cloud KMS, an HSM, a PKCS#11 token, a keychain — implement that, or wrap an
existing `crypto.Signer` with `anchor.FromCryptoSigner`. `proof` holds no
credentials and opens no connections.

`crypto.Signer` is deliberately **not** embedded in that interface: nothing here
calls it, so requiring it would oblige every KMS implementer to write a `Sign`
method whose `rand` and `opts` are meaningless for ML-DSA. The compatibility
lives where it is free instead — `*anchor.MLDSA65Signer` **is** a `crypto.Signer`
(enforced by a compile-time assertion), so it drops into x509 signing, go-tuf,
sigstore or your own code unchanged.

> **What a verified signature proves.** That it matches the key the signer
> advertises — consistency, not authenticity. A substituted signer passes. Only
> a key you obtained independently (`TrustPlatform` / `TrustProvided`) closes
> that, never a `TrustSelf` ring built from the anchor's own key.

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
| `mldsa` | `github.com/cloudflare/circl` — ML-DSA-65 is not in the standard library |
| `anchor`, `verify` | **none directly** — ML-DSA-65 reaches circl through `mldsa`, so signing and verification share one primitive |
| `store/bolt` | `go.etcd.io/bbolt` |
| **anywhere** | never a cloud SDK |

Being stdlib-only means the KEM's primitives — ML-KEM, X25519, SHA-3 — are
implemented by Go's native FIPS 140-3 module (`crypto/internal/fips140`) and
run under `GODEBUG=fips140=on`. Two precisions, so this is not over-read:
recent `x/crypto` releases wrap these same standard-library primitives, so the
gain over `x/crypto` is one fewer dependency, not different cryptography; and
X-Wing **cannot** run under `GODEBUG=fips140=only`, because the standard
library refuses X25519 in that mode. X25519 is not an approved
key-establishment scheme under SP 800-56A, so X-Wing as a whole makes no FIPS
approval claim.

The `go` directive is held at **1.24.0** by hand. `bbolt` and `x/sys` are pinned
below their latest releases to keep it there — someone importing only `xwing`
should not need a newer toolchain because of a storage engine they never use.

---

## Packages

```
chainformat     leaf encoding, chain hash linkage, tombstones   ← the core
canonical       deterministic JSON encoding
linker          sequence assignment + hash linkage — the append path
verify          the verdicts: Chain, BindAnchor, VerifyAnchor
anchor          anchor canonical form, anchor-of-anchors hash, ML-DSA-65 sign + verify
anchor/build    produce an anchor — verifies the chain before describing it
merkle          roots, inclusion proofs, consistency proofs
bundle          export-bundle manifest root + directory verification
store           persistence port + bolt / memory adapters
fixtures        cross-language golden vectors, embedded

mldsa           ML-DSA-44/65/87 sign + verify (FIPS 204)
mlkem           ML-KEM-768/1024 encapsulate + decapsulate (FIPS 203)
xwing           X-Wing hybrid KEM — ML-KEM-768 + X25519
keywrap         versioned wrapped-key wire format
keyfile         PKCS#8 / SPKI key files + key ids, for all seven algorithms

cmd/proof       CLI — init · append · export · import · anchor · verify · keygen
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

Under active development. **v0.2.0** is the first release carrying the whole
loop — originate, anchor, verify — from a terminal.

While the major version is 0, a minor release may contain a source-incompatible
change; v0.2.0 contains two, both called out in the
[changelog](CHANGELOG.md). What remains is the deduplication that motivated the
project, and a normative spec covering chain hash v3 and anchor v6 — both are
implemented and tested here but specified only in the Go source and
`docs/decisions.md`, which is the gap a second implementation would close.

| | |
|---|---|
| ✅ built | format core · `anchor` (verify, sign **and build**) · `bundle` · `verify` · `linker` · CLI · MCP server (7 tools) |
| ⏳ not yet | the monorepo and SDKs consuming this instead of their own copies |

**469 tests** across the library and MCP module. Every guard here has been
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

**Anchor *signing* crossed the same line on 2026-09-24.** Until then this module
could verify an anchor but not produce one, which capped a standalone user at the
weakest of the three claims in the table above — they could check someone else's
evidence but never generate their own. Signing is arithmetic over bytes, so it
belongs here.

What stayed behind is the part that actually makes an anchor worth anything:

| Here | Not here |
|---|---|
| computing the canonical bytes | deciding **when** to anchor |
| producing and checking the signature | **key custody** and ceremony |
| refusing to sign what cannot be verified | **delivery** to somewhere the subject cannot rewrite |

That last row is the whole game, and no amount of cryptography settles it. An
anchor read back from the same store as the chain proves consistency, not
external commitment. `proof` gives you a signed anchor; whether it reaches a
reader by a path you could not tamper with is an operational question this
module cannot answer and does not pretend to.

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
