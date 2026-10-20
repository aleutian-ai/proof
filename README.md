# proof

**An open protocol and toolkit for creating independently verifiable histories
of digital evidence.** Known inside [Aleutian](https://aleutian.ai) as
AleutianChain; this is the standalone Go library, CLI and MCP server.

You **commit** evidence to a chain as it happens, **anchor** signed checkpoints,
and anyone can later **verify** that history, without trusting you, Aleutian, or
wherever the evidence is stored. Each entry's hash covers its predecessor's, so
any retroactive edit breaks every link after it.

`proof` is the **integrity** layer, not the confidentiality layer. It commits a
fingerprint of your evidence, never the evidence itself, and it does not encrypt,
store or manage keys. Compose it with whatever you already use for those:
[`examples/encrypted-artifact`](examples/encrypted-artifact) encrypts with circl
and 1Password and commits the result. See [What proof is not](#what-proof-is-not).

```
   encrypt  →  store  →  COMMIT  →  ANCHOR  →  VERIFY  →  disclose / decrypt
   (yours)     (yours)   └──────────── proof ──────────┘   (yours)
```

## Try it

Commit five entries, export the chain, verify it, change one timestamp, verify
again. Run this from a clone of this repository, with the CLI built from that
clone on your `PATH` (`go install ./cmd/proof`):

```console
$ proof init --db demo.db && proof commit --db demo.db --chain demo < testdata/demo/input.jsonl
$ proof export --db demo.db --chain demo --out entries.json
$ proof verify entries.json
$ sed 's/T09:00:02/T09:00:03/' entries.json > tampered.json
$ proof verify tampered.json
```

What the first, third and fifth lines print:

```console
$ proof init --db demo.db && proof commit --db demo.db --chain demo < testdata/demo/input.jsonl
created demo.db
{
  "committed": 5,
  "first_seq": 0,
  "last_seq": 4,
  "head_hash": "b84501d7820a909f2325a3b4824c5d75806164e25460008022b404b322f95605fa626f2de702082b29b63b29ceafdfcb45923fa107f76a97c8f1bb135cf116c9"
}

$ proof verify entries.json
INTACT — 5 entries verified

  Proven:     nothing was edited under you.
  NOT proven: that this is the whole chain. Entries could have been
              removed from the front and the rest re-linked; detecting
              that needs an anchor, which was not checked here.

$ proof verify tampered.json
BROKEN — first break at entry 2

  [2] hash_mismatch        ent_002
       expected 49a069093fe0a722655a27d9b5e82aa8…
       actual   f8055ed3ae0b4c441ae4b9fab4cca2de…
  [3] hash_mismatch        ent_003
       expected 7896d215bc47fde9cd0532032164c0d5…
       actual   13dfaa9589640b7b43e50f2ed7d0926b…
  [4] hash_mismatch        ent_004
       expected 9e12215cf0d3c60de8db0177ac9a36fe…
       actual   b84501d7820a909f2325a3b4824c5d75…

  Note: one altered entry breaks every entry after it, so the
  count above is the blast radius. Entry 2 is the place to look.
```

Your hashes will differ from these, on every run: each entry gets a fresh
random salt when it is committed (chain format v4, below), so the same input
never produces the same chain twice. Everything else prints as shown.

The first verify exits `0` and the second exits `1`. `INTACT` is the weakest of
three claims this tool makes; the next section says what it does not cover.
[`testdata/demo/`](testdata/demo) also holds the exported chain, a signed anchor
over it, the public key that verifies the anchor, and a tampered copy, so the
[Quickstart](#quickstart) below needs no database.

---

## What this proves — and what it does not

Read this before anything else. "Verified" covers three different claims here,
and the difference is the whole design.

| You checked | Proven | NOT proven |
|---|---|---|
| **Linkage only**<br>`verify.Chain`<br>`proof verify e.json` | Nothing was edited by anyone unable to also rewrite every entry after it. | That this is the whole chain. |
| **\+ an anchor, no key**<br>`verify.BindAnchor`<br>`… --anchor a.json` | The chain is the one that anchor committed to — including where it *started*, so **truncation is caught**. | That the anchor is genuine. |
| **\+ the anchor's signature**<br>`verify.VerifyAnchor`<br>`… --anchor a.json --key pub.pem` | The anchor was signed by the holder of a key you named. | That the anchor reached you by a path its subject could not rewrite. |

### What chain format v4 closed, and what is left

v0.5.0 writes **chain format v4** and **anchor v7** (format-spec §2.0, §9).
Three holes that two external reviews found in v3 and v6 are closed by
construction, not reported around:

- **Every link is checked, erased entries included.** v4 links through a
  salted *leaf hash* over the entry's id, type and content hash. Erasure
  removes the salt and those fields and keeps the leaf hash, so an erased entry
  is recomputed like any other, and rewriting anything before it breaks the
  chain. (In v3 a tombstone's chain hash was taken on trust, and everything
  before it could be replaced under a valid signed anchor.)
- **`entry_id` and `entry_type` are hashed.** Changing either is a break.
- **Erasure does not break anchors.** v7 names its range by sequence number,
  which erasure never changes, and signs its predecessor's hash, so a verifier
  needs no second file. v7 signatures carry a context string
  (`aleutian.proof.anchor.v7`), so a key used elsewhere cannot produce one.

What is still true, and should be read before relying on a verdict:

1. **v2 and v3 chains keep their limits, for good.** Their hashes are signed
   into anchors that exist, so they are frozen (format-spec §2.6): verified
   forever, never rewritten. A v3 tombstone's chain hash is still taken as
   stored, so the entries before a chain's last tombstone are reported as not
   bound (`last_tombstone`, `entries_not_bound`), and v2 does not hash
   `global_seq`. The remedy is to **continue** such a chain: its next entry is
   v4, and from there every entry has v4's guarantee (format-spec §2.5).
   There is no migration tool, by design: a re-linked chain verifies and is not
   the one that was anchored.
2. **An erasure proves an entry existed, not who erased it.** Anyone who can
   write the store can produce the erased shape; the chain stays intact and the
   anchor stays bound. The sink authenticates its own erasures (signed in a
   signing sink, and never checkpointed unless confirmed); a bare chain does
   not ([verification-model.md](docs/verification-model.md), "Who may erase").
3. **An anchor series cannot show that it is complete.** Delete the latest
   anchors and the shorter series verifies. Keep anchors where the chain's
   writer cannot rewrite them. The sink makes the external record mandatory:
   `proof sink checkpoint` requires `--heads FILE`, a record of each series
   kept outside the folder, and refuses a series that is shorter than it, or
   restarted ([runbook.md](docs/runbook.md), "Where to keep checkpoint heads").
   It is only worth where you keep it: a writer who can also rewrite the heads
   is not stopped, and a chain removed whole, with its checkpoints, is not
   noticed through it.
4. **The sink cannot attribute an erasure in a sink that does not sign.** A
   forged erasure at the end of a chain, with its index row removed, reads
   `erased (not yet checkpointed)`, as a real one does before its checkpoint.
   `checkpoint` never signs over it unless the erase run confirmed it, its
   record signature verifies, or the operator vouches for the chain by name; in
   a sink that signs, `verify` reports it (`erasure-unsigned`). **Not closed:**
   the events it covered are gone; an operator who vouches for an erasure they
   did not make signs the forgery; and someone who can write the subject index
   can mark a chain pending, which the next erase run then completes as its
   own.
5. **Rows written into `.sources` cannot make new records vanish, mostly.** A
   record is a duplicate only if the entry its source points at holds the same
   content; otherwise `commit` refuses it (`ErrSourceConflict`). **Not
   closed:** someone who knows a future record's exact bytes can still make it
   read as a duplicate, by rewriting the stored content too, or by pointing its
   source at an entry that already holds those bytes. `proof sink repair` deletes
   rows that match no entry, and on a chain no checkpoint covers, entries
   removed from the end leave nothing that says so.
6. **An operator who controls the evidence store and every signing key the
   verifier trusts can rewrite history and produce a newly valid one.** Only
   earlier checkpoints kept or witnessed outside the operator's reach make that
   rewrite detectable.
7. **A damaged store file is an error, not a crash; a crafted one is not
   covered.** No command panics or hangs on a file that is cut short or whose
   pages were overwritten: `sink verify` exits 1 and everything else exits 3.
   Every open first checks the sizes and counts in the file's meta pages and
   freelist header against the file's length, commands that write read each
   file through before writing to it (`--skip-check` on the sink verbs skips
   that), and every call into the storage layer is guarded. **Not covered:** a
   file deliberately crafted beyond that, which can hang the process or end it.
   These files are a store's own, not an interchange format: verify someone
   else's evidence as an exported bundle, never by opening their files.
8. **Linux and macOS only.** The stores lock files with `flock` and open them
   with `O_NOFOLLOW`; on Windows the commands that open a store report that the
   platform is unsupported. Verifying an exported file needs neither.

Details: [verification-model.md](docs/verification-model.md),
[sink-format.md §6](docs/sink-format.md).

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
```

The outputs shown here are from v0.5.0. `proof version` prints what your
binary was built from; in a clone, `go install ./cmd/proof` builds the tree.

`testdata/demo/entries.json` is a five-entry chain that ships with the
repository (`scripts/make-demo.sh` wrote it):

```console
$ proof verify testdata/demo/entries.json
INTACT — 5 entries verified

  Proven:     nothing was edited under you.
  NOT proven: that this is the whole chain. Entries could have been
              removed from the front and the rest re-linked; detecting
              that needs an anchor, which was not checked here.
```

`testdata/demo/entries-tampered.json` is the same file with one entry's
timestamp changed by a second:

```console
$ proof verify testdata/demo/entries-tampered.json
BROKEN — first break at entry 2

  [2] hash_mismatch        ent_002
       expected c260239caea088429270e02dc4a2a6d4…
       actual   a7038212db08c231b279fdc468213e86…
  [3] hash_mismatch        ent_003
       expected cb9ec3e171872eac56d6edfa3d1b3670…
       actual   47a95a07cc1917a7484e21fb05d53db9…
  [4] hash_mismatch        ent_004
       expected 608c1cbf0340502bd064fc22306f164b…
       actual   ad4cb788e3311701da339ae119939aa2…

  Note: one altered entry breaks every entry after it, so the
  count above is the blast radius. Entry 2 is the place to look.
```

Exit codes are distinct on purpose: `0` ok · `1` chain broken · `2` usage ·
`3` I/O or parse error (a file that is not entries, a store too damaged to read) ·
`4` the database is busy. A script that cannot tell "the chain is broken" from "I could not
open the file" will take the wrong action on one of them.

Or without installing anything:

```console
$ podman build -t proof .
$ podman run --rm --network=none -v "$PWD:/data:ro" \
      proof verify /data/entries.json
```

A container is the lowest-trust way to run someone else's verifier, which is
why it is a first-class path here and not an afterthought. The image is 3.5 MB:
a static binary on `scratch`, with no shell, no package manager and no libc, so
there is nothing in it to audit but the binary. Beside the binary are two text
files: `/LICENSE`, and `/THIRD_PARTY_LICENSES`, the licences of the third-party
modules that binary links (`scripts/third-party-licenses.sh` generates it, and
the image build refuses a binary that links a module the file does not name). `--network=none` is not a
precaution you are taking against this tool — verification is arithmetic over a
file you already have — it is a way to *check* the claim rather than believe it.

The build pins its own base image by digest, and `--target proof-mcp` builds
the MCP server the same way. A published image records the commit it was built
from in `org.opencontainers.image.revision` — passed as `--label` by
`scripts/publish-image.sh`, never as a build argument, because an `ARG`
interpolated into a `LABEL` is not part of podman's cache key and would happily
carry a previous build's commit. A plain `podman build` sets no revision label
rather than an untrue one.

**There is no published image: build your own.** For a verifier, that is the
better way anyway, because an image you built from a tagged source needs no
trust in whoever would have pushed one. Build a release from its tag:

```console
$ git clone https://github.com/aleutian-ai/proof && cd proof
$ git checkout v0.5.0
$ podman build -t proof .
$ podman build -t proof-mcp --target proof-mcp .
```

Or put `proof` in an image of your own. The binary is static, so any base
will do:

```dockerfile
FROM docker.io/library/golang:1.25 AS proof
RUN CGO_ENABLED=0 go install github.com/aleutian-ai/proof/cmd/proof@v0.5.0

FROM your-base-image
COPY --from=proof /go/bin/proof /usr/local/bin/proof
```

`scripts/publish-image.sh` pushes images to a registry if that is ever needed
(decisions D24). It refuses a dirty working tree, so an image's revision label
is never a lie.

### Anchoring a chain

```console
$ proof anchor --db chain.db --chain demo \
      --subject acct-pseudonym-7f3a \
      --key ml-dsa-65-private.pem --out anchor.json

anchored 5 entries

  anchor id   anchor_e6540b42-60ab-4eae-afcd-aea14d927208
  subject     acct-pseudonym-7f3a
  range       global_seq 0 … 4
  key id      13c8130c3202ecb43afa55c67c885e7e
  previous    (none — this is the first anchor in the chain)

  Proven:     these entries link, and nothing was edited under you.
  NOT proven: that this anchor is an independent witness. It becomes
              one only when it reaches a reader by a path you cannot
              rewrite. Kept beside the chain it describes, it proves
              consistency and nothing more.
```

**It verifies the chain before it will describe it**, and refuses a broken one
with exit code `1` — the same code `proof verify` uses, so a script treats "this
chain is broken" identically whichever verb found it. It writes a **v7 anchor**:
its range is the entries' sequence numbers, which erasure never changes, and it
is signed with the context string `aleutian.proof.anchor.v7`.

`--subject` is required and has no default. It is inside the signed bytes, so it
can never be erased or corrected: use a stable pseudonym or an opaque id, never
a name, an email address or a device hostname.

Pass `--previous <anchor.json>` for every anchor after the first. The new anchor
then carries the predecessor's id and chain hash inside its signature, so a
verifier needs only the new anchor to bind it.

Without `--out` the anchor goes to stdout and the summary to stderr, so
`proof anchor … > anchor.json` gives a clean file.

Like `keygen`, this verb takes a private key and is therefore never exposed over
MCP.

Check it back with `proof verify --anchor`, below.

### The whole loop, from a terminal

```console
$ proof init   --db chain.db
$ proof commit --db chain.db --chain demo  < entries.jsonl
$ proof export --db chain.db --chain demo --out e.jsonl --jsonl
$ proof anchor --db chain.db --chain demo --subject acct-7f3a \
      --key ml-dsa-65-private.pem --out a.json
$ proof verify e.jsonl --anchor a.json --subject acct-7f3a --key ml-dsa-65-public.pem
```

`export` and `anchor` only read the database and never create one, and neither
overwrites an existing `--out` file unless you add `--force`. `commit` refuses
an `entry_id` the chain already holds, so running the loop a second time stops
at `commit`.

`commit` reads one JSON object per line. This is the first line of
`testdata/demo/input.jsonl`:

```console
$ head -1 testdata/demo/input.jsonl
{"entry_id":"ent_000","entry_type":"event","timestamp":"2026-10-13T09:00:00.000000Z","ingested_at":"2026-10-13T09:00:00.250000Z","content_hash":"23611b9176b397ee93edc22431170b500e97ebfac950ee90dcf5fd60a4d43da2c8cac0eaf345ddb6e65b6dbcc15175255a4110dcb385ab99a51348a8ed6f6d44"}
```

| Field | What it is |
|---|---|
| `entry_id` | your name for the entry; one id names one entry in a chain. Hashed, 1 to 256 bytes |
| `entry_type` | your label for the kind of entry. Hashed, 1 to 256 bytes |
| `timestamp` | when the event happened, RFC 3339; it is hashed |
| `ingested_at` | when you received it, RFC 3339; it orders the batch and is not stored |
| `content_hash` | the SHA-512 of the evidence, as 128 lowercase hex characters. `proof` never sees the evidence |

All five are required, and a line that lacks one or has it in another form is
refused by line number, with nothing committed. `commit` writes chain format v4
and mints each entry's salt itself; `--format 3` (or `2`) still writes the
frozen formats for one more release, with a deprecation warning. The message names the field and never repeats its value:

```console
$ echo '{"entry_id":"ent_x","entry_type":"event","timestamp":"yesterday","ingested_at":"2026-10-13T09:00:00Z","content_hash":"abc"}' | proof commit --db demo.db --chain demo
proof commit: line 1: timestamp is not an RFC 3339 time, for example 2026-01-20T12:00:01.123456Z
```

`commit` **mints** positions and hashes; its input carries none. Supplying
`chain_hash`, `global_seq`, `run_id` or `sequence_num` is an error rather than
ignored — silently recomputing a field someone supplied is how they end up
believing their hashes were preserved.

`import` **carries** them. It verifies the batch, refuses to write into an
occupied sequence range, and then stores every hashed field verbatim, so
`export → import → export` is byte-identical. It deliberately does not use the
linker: re-linking would renumber from the target's tail and mint new salts, so
identical entries would acquire different hashes.

Importing a *segment* needs `--previous-hash`, because its first entry links
from a predecessor rather than from nothing.

### Checking an anchor

The demo chain ships with an anchor over its five entries and the public key
that verifies it:

```console
$ proof verify testdata/demo/entries.json --anchor testdata/demo/anchor.json --subject demo-chain --key testdata/demo/anchor-public.pem
INTACT, ANCHORED — 5 entries

ANCHOR BOUND — 5 entries covered
  signature verified (provided)
  establishes: the holder of a key you supplied attests to this chain

  Proven:     the chain matches this anchor, and the holder of a key you supplied attests to this chain
  NOT proven: that this is the whole chain beyond the anchored range, or that the anchor reached you by a path its subject could not rewrite
```

That key came from the same directory as the chain and the anchor, which is the
case "NOT proven" describes: it shows the three files agree, and nothing about
who made them.

This is the truncation case made concrete. Drop entries from the front,
renumber and re-link what remains, and `proof verify` alone reports **INTACT** —
correctly, because linkage genuinely cannot see it. (Without renumbering, v4
catches it: a chain's first entry is at sequence 0.) Add `--anchor` and the
same file comes back `height_mismatch`, exit `1`: the anchor covers a sequence
the chain no longer has.

`--subject` is required for a v7 anchor: it is what the anchor must be about,
and without it a genuine anchor for another chain would bind. Another subject
is `tenant_mismatch`, exit `1`. A v7 anchor carries its predecessor's hash, so
`--previous <anchor.json>` (or `--previous-hash <hex>`) is optional: given, it
must match. For an older anchor it is needed for any anchor that is not the
first in its chain, and the output says when it assumed a genesis anchor.

Erasing entries does not change this. `proof erase --db chain.db --chain demo
--seq 2` removes that entry's id, type, content hash and salt and rewrites the
database file so their bytes are gone; the export still verifies and the anchor
still binds:

```console
$ proof verify after.json --anchor a.json --subject acct-pseudonym-7f3a --key ml-dsa-65-public.pem
INTACT, ANCHORED — 5 entries, 1 erased
```

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

`--op-vault <vault>` also stores the pair in 1Password: see the next section.

### Keeping keys in 1Password

`proof` can put a key in 1Password as it creates it, so the private key need
not live on disk. It does this through the 1Password CLI, `op`, and nothing
else: no 1Password SDK is compiled in.

**You need:** the `op` CLI on your `PATH`, signed in (`op whoami` prints your
account), and a vault you can write to. `proof` never handles your 1Password
credentials; `op` does.

#### Storing a key: `keygen --op-vault`

```console
$ proof keygen --alg ml-dsa-65 --out-dir ./keys --name optest --op-vault proof-test

ML-DSA-65
  private  keys/ml-dsa-65-private.pem   (0600 — this is the secret)
  public   keys/ml-dsa-65-public.pem
  …
  1Password  proof-ml-dsa-65-optest (vault proof-test) — stored keys read back and verified
```

It creates one Secure Note per key, titled `proof-<algorithm>[-<name>][-<slot>]`,
holding:

| Field | Holds |
|---|---|
| `privkey_pem` | the private key file, attached |
| `pubkey_pem` | the public key file, attached |
| `fingerprint` | the public key's SHA-512, as text |

The files are passed to `op` by path, so the private key never appears in the
process list. Then `proof` **reads both attachments back, by item id, and checks
that each is the key it just generated**: the public key's fingerprint, and the
fingerprint of the public key derived from the stored private key. It does not
trust the `fingerprint` text field it wrote itself. If the read-back fails, it
says so and leaves the key files on disk.

`keygen` keeps its files on disk either way. Delete them yourself once you are
satisfied, or use `sink init` (below), which removes the one it stores.

#### Checking it yourself

The read-back is proof checking its own work. To check independently:

```console
$ op item list --vault proof-test
ID                            TITLE                     VAULT        EDITED
3xr3xumyu4cta2bhvuok4pirry    proof-ml-dsa-65-optest    proof-test   6 minutes ago

$ diff <(op read "op://proof-test/3xr3xumyu4cta2bhvuok4pirry/pubkey_pem")  keys/ml-dsa-65-public.pem
$ diff <(op read "op://proof-test/3xr3xumyu4cta2bhvuok4pirry/privkey_pem") keys/ml-dsa-65-private.pem
```

Both `diff`s print nothing: the stored keys are the files, byte for byte. Use
the item **id** in the path rather than the title. `keygen --force` with the
same name creates a second item with the same title, and a read by title is
then ambiguous.

#### A sink whose checkpoint key lives only in 1Password: `sink init --op-vault`

A sink has two keys (see [sink/README.md](sink/README.md)): the record key signs
every commit and must be online; the checkpoint key signs checkpoints and is
best kept elsewhere. `--op-vault` stores the **checkpoint** key in 1Password and
removes its private file from disk. The record key stays on disk.

```console
$ proof sink init --dir sink --keys-dir sinkkeys --op-vault proof-test
…
ML-DSA-65 (checkpoint)
  …
  1Password  proof-ml-dsa-65-checkpoint (vault proof-test) — stored keys read back and verified
  removed  sinkkeys/ml-dsa-65-checkpoint-private.pem from disk (unlinked, not wiped: SSD and journal copies may remain)

sink now signs its records: a commit or erase without --record-key is refused.

next:
  proof sink commit     --dir sink … --record-key sinkkeys/ml-dsa-65-record-private.pem
  proof sink erase      --dir sink … --record-key sinkkeys/ml-dsa-65-record-private.pem
  proof sink checkpoint --dir sink --key <(op read op://proof-test/proof-ml-dsa-65-checkpoint/privkey_pem) --record-trust sinkkeys/ml-dsa-65-record-public.pem
  proof sink verify     --dir sink --key sinkkeys/ml-dsa-65-checkpoint-public.pem --record-trust sinkkeys/ml-dsa-65-record-public.pem

$ ls sinkkeys
ml-dsa-65-checkpoint-public.pem    ml-dsa-65-record-private.pem    ml-dsa-65-record-public.pem
```

The private file is removed only **after** the read-back succeeds, so a failed
store never costs you the key. "Unlinked, not wiped" is literal: the file is
deleted, not overwritten, and an SSD or a filesystem journal may still hold a
copy. If that matters, generate the key on a machine whose disk you control.

`sink init --op-vault` refuses to run if the vault already holds an item named
`proof-ml-dsa-65-checkpoint`, since a second would make the printed `op read`
ambiguous. Remove or rename the old one first.

#### Using the stored key

The printed `checkpoint` command reads the key straight from 1Password with
`<(op read …)`, so no copy is written to disk. That syntax needs bash or zsh, and
each command must be on one line (a line break pasted into the middle runs the
rest as a separate command). A full round trip:

```console
$ echo '{"user":"u-1","n":1}' | proof sink commit --dir sink --class events --subject-field user --record-key sinkkeys/ml-dsa-65-record-private.pem
committed 1 entry on 1 chain (0 duplicates)

$ proof sink checkpoint --dir sink --key <(op read op://proof-test/proof-ml-dsa-65-checkpoint/privkey_pem) --record-trust sinkkeys/ml-dsa-65-record-public.pem
checkpoint anchors/events.fe5cd86e5e94160eec4ff98b2fcd4b46/0001.json signed over 1 entry

$ proof sink verify --dir sink --key sinkkeys/ml-dsa-65-checkpoint-public.pem --record-trust sinkkeys/ml-dsa-65-record-public.pem
chain events.fe5cd86e5e94160eec4ff98b2fcd4b46 verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored · 1 signed
Record signatures: checked against --record-trust
all 1 chains verify
```

A commit without `--record-key` is refused (`this sink signs its records`): the
sink was put in signing mode when it was created.

#### What this does and does not protect

- **It keeps the checkpoint key off the machine that writes the sink.** Someone
  who can write the sink folder and read the record key still cannot sign a
  checkpoint.
- **It does not make 1Password part of verification.** Verifying needs only the
  public keys, which stay on disk and are meant to be handed out.
- **Anyone who can read the vault can sign checkpoints.** Who can read it is set
  in 1Password, not here.
- **The `fingerprint` text field is informational.** `proof` never trusts it;
  it checks the attached keys.

All of the above was run against a real vault with v0.4.0, including the
`diff` check and the round trip. To clean up a test vault:
`op vault delete <vault>`.

### As a library

```console
$ go get github.com/aleutian-ai/proof
```

```go
import "github.com/aleutian-ai/proof/chainformat"

salt, _ := chainformat.NewSaltV4()
leaf, err := chainformat.ComputeLeafHashV4(entryID, entryType, contentHash, salt)
hash, err := chainformat.ComputeChainHashV4(previousHash, globalSeq, ts, leaf)
```

v4 is the current format and the one to build against; `linker` mints the salt
for you. v2 and v3 are frozen: verified forever, never rewritten, and continued
in v4 from a chain's next entry. See [D19 and D22](docs/decisions.md).

### As an MCP server

An agent can check a chain during a conversation — and, if you allow it, commit
evidence of its own actions as it works:

`go install` puts the binary in `$(go env GOPATH)/bin`, which must be on your
`PATH` for the client to start it (or give the client the full path).

```console
$ go install github.com/aleutian-ai/proof/cmd/proof-mcp@latest
$ claude mcp add aleutianchain -- proof-mcp                              # read-only
$ claude mcp add aleutianchain -- proof-mcp --root ./exports \
      --trusted-key platform=./aleutian-public.pem                        # + a key you vouch for
$ claude mcp add aleutianchain -- proof-mcp --db ./evidence.db \
      --chains agent-actions,payments                                     # + commit
```

Seven read-only tools: `verify_chain`, `verify_anchor`, `verify_bundle`,
`compute_chain_hash`, `canonicalize_leaf`, `verify_inclusion`,
`explain_trust_model`. (`verify_bundle` checks a directory against a
`manifest.json`; it is not the export-bundle verifier, which is
`proof sink verify-bundle` in the CLI.)

Tools read files only inside `--root` (default: the directory the server was
started in). What a key establishes is never a tool argument: a key an agent
supplies is reported as `provided`, and only a key you bind at launch with
`--trusted-key platform=PATH` or `self=PATH` is reported at that level. With
`--db`, `--max-db-bytes` (default 1 GiB) stops commits once the database reaches
that size.

With `--db`, an eighth: **`commit`, the only tool that writes.** `--chains` is
required with it — name the chains agents may write, or `'*'` for any — so an
injected prompt cannot append to chains you did not intend, including ones you
write with the CLI. The agent sends text and picks one of those chains; the
server makes a salted commitment, **keeps the nonce in a local file beside the
database** (`evidence.db.nonces`), and returns nothing secret. Everything that
is hashed — entry id, timestamp, position, chain hash — is assigned by the
server. Entry types are server-set (`mcp.salted` or `mcp.digest`, plus an
optional label), so a verifier knows which check an entry needs. The agent can
append, never edit, reorder or remove; there is no import tool. Anchoring stays
in the CLI, because signing keys never cross MCP.

Later, whoever runs the server can prove or erase one entry:

```console
$ proof disclose --db evidence.db --chain agent-actions --entry mcp-… --content action.txt
$ proof erase    --db evidence.db --chain agent-actions --seq 7
```

`erase` removes the entry's id, type, content hash and salt, forgets its
nonce, and rewrites both files; the chain still verifies and anchors still
bind. (`proof forget` destroys only the nonce, and is what a v3 entry gets.)

`verify_anchor` takes an optional `subject`: the subject the anchor must be
for. Without it, the result's `not_proven` says the subject was not checked,
because a genuine anchor for another chain would bind too. `compute_chain_hash`
takes `format_version` 4 (from an entry's id, type, content hash and salt, or
an erased entry's leaf hash alone), 3 or 2.

**Know what crosses the model boundary.** The content an agent commits passes
through the conversation, so the model provider sees it. The server keeps the
nonce out of the transcript, but it cannot recall content that is already there.
Erasing an entry (`proof erase`) makes it unopenable from this machine; it does
not reach provider transcripts, backups, or anyone it was disclosed to. For
content you may need to erase fully, compute a salted commitment yourself and
send `content_hash`. Erasure also removes content, not the fact that an entry
existed: its timestamp and position stay on the chain.

What a committed entry proves is that it was recorded and not changed since —
not that it is true. Timestamps are the server's clock and advisory; position
(`global_seq`) is the authoritative order.

### No MCP tool touches key material, and none ever will

MCP tool results are transmitted to a model provider, where they may be logged
and retained. A seed or a plaintext returned from a tool would cross that
boundary — quietly falsifying the one claim the whole system rests on, that the
operator never holds the customer's key.

The guard is an exact allowlist: `TestToolsAreTheExpectedSet` (and its `--db`
twin) fails the build if the registered tools are anything other than the
eight listed above, so a tool that returns key material cannot be added without
editing that list and arguing for it, whatever the tool is called.
`TestNoKeyMaterialTools` is a second, coarser check on names. Key operations
belong in the human-driven CLI, where `proof keygen` lives and no result
crosses a provider boundary.

---

## Trust is yours to decide

`proof` ships **no embedded public keys**. You supply the key, and you say where
it came from:

```go
ring, _ := anchor.NewKeyRing(anchor.TrustProvided, map[string][]byte{
    "aleutian-ml-dsa-65-2026-v1": publicKey,
})
res, _ := verify.VerifyAnchor(a, entries, verify.Expect{Subject: "acct-7f3a"}, ring)
fmt.Println(res.Trust.Establishes())
```

The third argument is what **you** expect, which an anchor cannot say about
itself. `Subject` is what the anchor must be about: a genuine anchor for
another subject is `tenant_mismatch`, and with none given the result says the
subject was not checked. `PreviousAnchorHash` is the predecessor's chain hash:
optional for a v7 anchor, which signs its own (given, it must match), and
required for an older one, whose hash names its predecessor only by id (pass
`anchor.SeedAnchorHash` for the first).

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

type ContextStringSigner interface {
    ContextSigner
    SignWithContext(ctx context.Context, msg []byte, mldsaContext string) ([]byte, error)
}
```

Cloud KMS, an HSM, a PKCS#11 token, a keychain — implement those, or wrap an
existing `crypto.Signer` with `anchor.FromCryptoSigner`. A v7 anchor is signed
with the ML-DSA context string `aleutian.proof.anchor.v7`, so its signer must
be a `ContextStringSigner`; one that ignores the context produces a signature
`SignAnchor` refuses rather than returns. `proof` holds no
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

## Conformance — three implementations, one set of vectors

The same bytes must produce the same hashes and the same verdict in Go, Python
and JavaScript, or a test fails.

```
              proof/fixtures/testdata/     ← canonical, public, versioned
              proof/fixtures/MANIFEST.json ← SHA-256 of every vector
                          │
                          │  vendored + digest-checked
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
         Go            Python          JavaScript
          └─────── all must reproduce ────┘
```

**The expected outputs are data.** They are never regenerated by an
implementation during a test run, which is the difference between a conformance
suite and a mirror. A vector edited to make one implementation pass fails the
other two:

```console
$ # change one expected_hash to suit one implementation
$ pytest tests/test_conformance_vectors.py   →  1 failed
$ npm test -- conformanceVectors             →  1 failed
```

`scripts/sync-vectors.sh --check <dir>` verifies a vendored copy anywhere;
`--write` re-vendors it.

Agreement is also tested on real artifacts, not only constants: a v3 chain from
`proof commit` and a v6 anchor signed by `proof anchor` with a real ML-DSA-65
key both verify in Python and JavaScript (as of vector set v0.4.1). Those fixtures must never be
regenerated by the SDK that checks them — they are evidence precisely because
another implementation produced them.

> **All three pass every file of this release's set**, chain format v4, anchor
> v7 and bundle v2 included. The Python and JavaScript verifiers were written
> from the specifications without reading the Go code.
> [docs/conformance.md](docs/conformance.md) lists, per implementation and per
> vector file, what each passes.
>
> **What this does not yet establish.** Not under the shared set:
> Merkle roots and inclusion proofs, an anchor
> *series* (the verdict vectors need no key, and a series needs signatures),
> and the two input forms only the SDKs read (the hosted platform's
> `{"entries": [...]}` wrapper and camelCase member names).
>
> Who writes each vector file: `scripts/independent-vectors.py`,
> `scripts/spec-vectors.py`, `scripts/v4-vectors.py`,
> `scripts/verdict-vectors.py` and `scripts/bundle-vectors.py`, each computing
> its values in Python from the spec. No Go test writes one. Five files (`merkle_golden.json`,
> `v3_golden_capture_request.json`, `anchor_chain_hash_vectors.json`,
> `chain_vectors.json`, `commitment_vectors.json`) were first written by an
> implementation or by hand; `spec-vectors.py` reproduced the first three byte
> for byte and every value in the other two before it became their writer, and
> the last two were then changed on purpose (see
> [format-spec §10](docs/format-spec.md)). One file,
> `anchor_v4_canonical_vectors.json`, is still written by no script.

## Dependencies

The cryptographic core has **none**. Not "few" — none.

```console
$ go list -deps ./xwing ./keywrap | grep -v '^github.com/aleutian-ai/proof'
(stdlib only)
```

That is checkable, and it is checked: [`deps_test.go`](deps_test.go) fails the
build if any package gains an import outside its allowlist. A package's test
files are held to the same list plus a second, explicit one, so the table below
is about what a consumer compiles, and a test cannot bring in a new module
unnoticed.

| Package | External dependencies |
|---|---|
| `xwing`, `keywrap` | **none** — `crypto/mlkem`, `crypto/sha3`, `crypto/ecdh` are stdlib as of Go 1.24 |
| `merkle` | **none** |
| `bundle` | **none** |
| `exportbundle` | **none directly** — circl through `mldsa`, `golang.org/x/text` through `chainformat`; never bbolt, so verifying a bundle does not compile in the store |
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
chainformat     leaf encoding, chain hash and leaf hash v4, v2/v3 tombstones   ← the core
commitment      salted commitments for unencrypted content (format-spec §8)
canonical       deterministic JSON encoding
linker          sequence assignment + hash linkage — the append path
verify          the verdicts: Chain, BindAnchor, VerifyAnchor
anchor          anchor canonical form, anchor-of-anchors hash, ML-DSA-65 sign + verify
anchor/build    produce an anchor — verifies the chain before describing it
merkle          roots, inclusion proofs, consistency proofs
bundle          a directory checked against a manifest (unrelated to sink export bundles)
exportbundle    verifier for a sink export bundle (bundle.json), from docs/bundle-format.md
store           persistence port + bolt / memory adapters
fixtures        cross-language conformance vectors + digest manifest

mldsa           ML-DSA-44/65/87 sign + verify (FIPS 204) — anchors use ML-DSA-65
keyfile         PKCS#8 / SPKI key files + key ids, for all seven algorithms

                post-quantum KEM primitives. The chain does NOT use these; they
                are here for key files and the Aleutian platform's wrapped-key
                format. Encrypting your evidence is not their job — see above.
mlkem           ML-KEM-768/1024 encapsulate + decapsulate (FIPS 203)
xwing           X-Wing hybrid KEM — ML-KEM-768 + X25519
keywrap         versioned wrapped-key wire format

sink            one chain per key in a folder: idempotent commits, per-chain
                checkpoints, verification, erasure (docs/sink-format.md)
cmd/proof       CLI — init · commit · export · import · anchor · verify · keygen · disclose · erase · forget · sink
cmd/proof-mcp   MCP server (separate module: its SDK needs Go 1.25)

examples/       composition, not features — encrypted-artifact; integrations/nats,
                integrations/redis, integrations/kafka and integrations/otel feed a sink
                (each its own module); integrations/fluent-bit is config only
```

---

## Erasure

A chain that cannot forget is a chain that cannot comply. In chain format v4,
erasing an entry removes its id, type, content hash and salt, and keeps its
position, timestamp, **leaf hash** and chain hash:

```
[0]→[1]→[2']→[3]→[4]     2' keeps its leaf_hash and chain_hash; id, type,
          │              content hash and salt are gone
          └─ chain_hash = H(previous_hash | seq | ts | leaf_hash)  ← recomputed
```

The leaf hash is a salted commitment to the erased fields, so someone who has
the chain after the erasure and the original entry cannot match the two, and
the chain hash is recomputed from it like any other entry's: **every link is
still checked**, and anchors over the range still bind. `proof erase --db …
--chain … --seq N` does it: it forgets the entry's nonce if it had one, erases
the entry, and rewrites the files so the removed bytes are not left in free
pages, in that order, so that if it is interrupted, running it again finishes
the job. What it cannot reach: backups, snapshots, earlier exports and
bundles, a process that had the file open before the rewrite, and anyone the
entry was disclosed to. Any of those still holds the entry's `content_hash`
at its position, and needs no salt to match it.

`erased: true` in an export says the export withholds the entry's fields. An
exporter can write a live entry that way and it verifies the same, so the flag
is a statement about the file, not about the store.

An erased entry proves an entry existed at that position, not who erased it
(see the limitations above).

> **Implementing a verifier?** In v4, recompute an erased entry from its stored
> leaf hash; never skip it. In v2 and v3 the rule is the opposite: a tombstone's
> chain hash is not reproducible from its fields, so validate its format and
> carry its stored hash forward. Three independent SDKs once got the v3 rule
> wrong the same way, because it had been written down in exactly one
> implementation's comments. Both are in [docs/format-spec.md](docs/format-spec.md) §5.

---

## Status

Under active development. The [changelog](CHANGELOG.md) is the record of what
each release contains; while the major version is 0, a minor release may
contain a source-incompatible change, and every one is called out there.
`proof version` prints what a binary was built from.

**Three implementations are held to one set of vectors.** Go (this module),
Python and JavaScript reproduce every vector file, chain format v4, anchor v7
and bundle v2 included, and give the same verdict on every verdict and bundle
vector ([docs/conformance.md](docs/conformance.md)). Runs on Linux and macOS.
The formats are specified in [docs/format-spec.md](docs/format-spec.md) and
[docs/bundle-format.md](docs/bundle-format.md); the Go code is one
implementation of them, not their definition.

| | |
|---|---|
| ✅ built | chain format v4 and anchor v7 · format core · `anchor` (verify, sign and build) · `verify` (chains, anchors, anchor series) · `linker` · `sink` (commit, checkpoint, verify, erase, export) · `exportbundle` and `proof sink verify-bundle` (bundle v1 and v2) · CLI · MCP server (7 read-only tools + `commit` with `--db`) |
| ⚠️ known limitations | [listed above](#what-chain-format-v4-closed-and-what-is-left), and not softened: read them before relying on a verdict |
| ⏳ not yet | the monorepo and SDKs consuming this instead of their own copies · the SDKs' v4/v7 releases (in the monorepo, not yet published) |

`scripts/release-check.sh` is the gate a tree passes before it is tagged:
formatting, `go vet` and the tests for both modules, the vectors regenerated
byte for byte from their scripts, and `go vet` plus `go test -race` on Linux in
a container.

---

## What proof is not

This is the format, the maths, and the commit path — not the service. Absent, and
staying absent:

- **encryption and confidentiality** — `proof` commits a fingerprint and never
  sees content. Encrypt with what you already trust (circl, age, a KMS) and commit
  the ciphertext; [`examples/encrypted-artifact`](examples/encrypted-artifact)
  shows how. Erasure then means destroying the key: the chain keeps verifying,
  the content is gone.
- **storage of the evidence itself** — a folder, S3, a database: yours to choose.
  The chain holds commitments, not payloads.

  Committing content **unencrypted**? Use `commitment.Salted`, so the public
  chain cannot be used to guess low-entropy content like `consent: yes`.
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
| [docs/bundle-format.md](docs/bundle-format.md) | The export bundle a recipient verifies without the sink |
| [docs/sink-format.md](docs/sink-format.md) | What a sink folder holds, and what its verification covers |
| [docs/verification-model.md](docs/verification-model.md) | Understanding what a verdict means |
| [docs/anchor-model.md](docs/anchor-model.md) | What an anchor proves, and what its provenance must be |
| [docs/decisions.md](docs/decisions.md) | Why the design is the way it is |
| [docs/conformance.md](docs/conformance.md) | Which implementation passes which vector file |
| [docs/runbook.md](docs/runbook.md) | Working on this repository, and where to keep checkpoint heads |
| [docs/release.md](docs/release.md) | Releasing: the order of the four channels, and which steps are one-way |
| [STABILITY.md](STABILITY.md) | What will not change under you: the format promise, and API versioning |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributing: the DCO sign-off, format changes, what a pull request needs |
| [SECURITY.md](SECURITY.md) | Reporting a vulnerability |

---

## Licence

Apache 2.0. See [LICENSE](LICENSE).

The verification maths is open because a cryptographic audit trail nobody can
inspect is a claim, not a proof. The operational platform — tenancy, retention,
key ceremony, hosted anchoring — is not part of this repository.
