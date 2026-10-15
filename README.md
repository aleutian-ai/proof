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
  "head_hash": "08a3d94e3b3f351483642273ab1e4a0318bf9e95c49a5cd0a21b16737f9bc8988996f9fe66cdfe1bd944840fbee3763541483cf176598ea58fe02bb177aa2c7b"
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
       expected 19a80aef54b57ad64b0cec0532ac72b7…
       actual   61863b5ef3be12a0c185ae1555701f9b…
  [3] hash_mismatch        ent_003
       expected fcde110bf30fe281042f969fd06691b8…
       actual   9dda32f8d174fc701ebbab239febb666…
  [4] hash_mismatch        ent_004
       expected f9840a1a41752eb581d54c4a4a9ca496…
       actual   08a3d94e3b3f351483642273ab1e4a03…

  Note: one altered entry breaks every entry after it, so the
  count above is the blast radius. Entry 2 is the place to look.
```

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

### Known limitations of the current formats

These are holes in chain format v3, anchor v6 and the sink as they are today.
The verifiers report the exposure where they can. None of them detects the
attack. Read them before relying on a verdict.

1. **An erased entry is an unverified link.** A tombstone keeps the erased
   entry's chain hash, and a verifier takes that hash as stored, because the
   content hash it was computed from is gone. So nothing links the entries
   before a tombstone to the entries after it. Anyone who can write the store
   can replace every entry before a tombstone, or before an entry they turn
   into one, and the chain still verifies as `INTACT` and still binds to a
   valid signed anchor. The result says how many entries are exposed
   (`last_tombstone`, `entries_not_bound`) and its wording covers only the
   entries after the last tombstone. A chain with no tombstone is not affected
   unless an attacker adds one, which they can (see 2).
2. **`entry_id` and `entry_type` are in no hash.** Either can be changed
   without a break. `entry_type` and the `tomb_` id prefix are what mark an
   entry as erased.
3. **Erasing the first or last entry of an anchored range breaks that
   anchor.** Erasure replaces the entry's id, and an anchor names its range by
   the first and last entry ids.
4. **An anchor series cannot show that it is complete.** Delete the latest
   anchors and the shorter series verifies. Keep anchors where the chain's
   writer cannot rewrite them. Anchors are signed with an empty ML-DSA context
   string, so a signing key must not be used for anything else.
5. **The sink cannot tell an erasure it made from one written into its
   folder, except by who checkpoints it.** An erasure record carries no key.
   Someone with write access to the folder can append one at the end of a chain
   and remove the chain's index row; it verifies as `erased-unanchored`, as a
   real erasure does before its checkpoint. Three things that followed from
   that are now closed, and each has a remainder that is not:
   - *A routine checkpoint no longer covers it.* `proof sink checkpoint` signs
     over an erasure only when the same run made it on that chain
     (`proof sink erase --key`, `erase --resume --key`), its record signature
     verifies (`checkpoint --record-trust`, on a sink that signs), or the
     operator names the chain and vouches for it
     (`checkpoint --confirm-erased-chain <chain id>`, for an erasure that
     missed its own run's checkpoint). An erase run does not vouch for an
     erasure entry it found already on a chain the index still bound to a
     subject. A forged erasure stays `erased (not yet checkpointed)`.
     **Not closed:** the events it covered are still gone and are not
     restored, and `checkpoint` reports that chain on every run until someone
     vouches for it, which the sink cannot check: an operator who vouches for
     an erasure they did not make signs the forgery. And an erase run
     completes whatever the index marks as an interrupted erasure: someone who
     can write the index can mark a chain pending, and the next erase run then
     erases it and checkpoints it as its own.
   - *A deleted checkpoint series is noticed, if its head is kept elsewhere.*
     With `--heads FILE` on `checkpoint` and `verify` (a file outside the sink
     folder), a series that is shorter than it was, or was started again, is a
     failure and is not extended. **Not closed:** without `--heads` nothing
     changed: the next checkpoint starts a new series and verification passes
     (`verify --require-checkpoint` only catches a chain left with no
     checkpoint at all). Someone who can also rewrite the heads file is not
     stopped (see 6), and a chain removed whole, with its checkpoints, is not
     noticed through it.
   - *Rows written into `.sources` no longer make new records vanish.* A record
     is a duplicate only if the entry its source points at holds the same
     content; otherwise `commit` refuses it (`ErrSourceConflict`) and nothing
     is acknowledged. `verify` reports a source position that points at no
     entry, and an entry with more than one. **Not closed:** someone who knows
     a future record's exact bytes can still make it read as a duplicate, by
     also rewriting the stored content, or by pointing its source at an entry
     that already holds those bytes (events that repeat byte for byte).

   `proof sink repair` deletes rows that match no entry, which is what a commit
   that crashed leaves, and also what removing entries leaves. It leaves a
   chain alone when a checkpoint, a recorded head (`--heads`) or, for a chain
   with no entries, a record signature says the chain held more. **Not
   closed:** on a chain no checkpoint covers, entries removed from the end
   leave nothing that says so, and repair then deletes their content.
6. **An operator who controls the evidence store and every signing key the
   verifier trusts can rewrite history and produce a newly valid one.** Only
   earlier checkpoints kept or witnessed outside the operator's reach make that
   rewrite detectable.
7. **A damaged store file is an error, not a crash; a crafted one is not
   covered.** No command panics or hangs on a file that is cut short or whose
   pages were overwritten: `sink verify` exits 1 and everything else exits 3.
   Every open first checks the sizes and counts in the file's meta pages and
   freelist header against the file's length (a freelist claiming more entries
   than the file could hold once made the process run out of memory), commands
   that write read each file through before writing to it (`--skip-check` on
   the sink verbs skips that), and every call into the storage layer is
   guarded. In a long-lived process, a file that fails inside the storage layer
   is abandoned rather than closed: its lock is released, but its memory map
   stays until the process exits. **Not covered:** a file deliberately crafted
   beyond that. Pages that point back at each other are followed without end,
   and a count or offset inside a data page is believed as written; either can
   hang the process or end it. These files are a store's own, not an
   interchange format: verify someone else's evidence as an exported bundle,
   never by opening their files.

A next format version is drafted to close 1 to 3 and tighten 4. It is not
implemented. Details: [verification-model.md](docs/verification-model.md),
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

The outputs shown here are from v0.4.1. `proof version` prints what your
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
       expected 19a80aef54b57ad64b0cec0532ac72b7…
       actual   61863b5ef3be12a0c185ae1555701f9b…
  [3] hash_mismatch        ent_003
       expected fcde110bf30fe281042f969fd06691b8…
       actual   9dda32f8d174fc701ebbab239febb666…
  [4] hash_mismatch        ent_004
       expected f9840a1a41752eb581d54c4a4a9ca496…
       actual   08a3d94e3b3f351483642273ab1e4a03…

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
$ proof commit --db chain.db --chain demo  < entries.jsonl
$ proof export --db chain.db --chain demo --out e.jsonl --jsonl
$ proof anchor --db chain.db --chain demo --subject acct-7f3a \
      --key ml-dsa-65-private.pem --out a.json
$ proof verify e.jsonl --anchor a.json --key ml-dsa-65-public.pem
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
| `entry_id` | your name for the entry; one id names one entry in a chain |
| `entry_type` | your label for the kind of entry; it is stored, and it is in no hash |
| `timestamp` | when the event happened, RFC 3339; it is hashed |
| `ingested_at` | when you received it, RFC 3339; it orders the batch and is not stored |
| `content_hash` | the SHA-512 of the evidence, as 128 lowercase hex characters. `proof` never sees the evidence |

`entry_id`, `timestamp`, `ingested_at` and `content_hash` are required, and a
line that lacks one or has it in another form is refused by line number, with
nothing committed. The message names the field and never repeats its value:

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
linker: re-linking would renumber from the target's tail, and v3 binds
`global_seq`, so identical entries would acquire different hashes.

Importing a *segment* needs `--previous-hash`, because its first entry links
from a predecessor rather than from nothing.

### Checking an anchor

The demo chain ships with an anchor over its five entries and the public key
that verifies it:

```console
$ proof verify testdata/demo/entries.json --anchor testdata/demo/anchor.json --key testdata/demo/anchor-public.pem
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

hash, err := chainformat.ComputeChainHashV3(previousHash, globalSeq, ts, contentHash)
```

v3 is the current format and the one to build against. v2 exists, is still
verified, and is never rewritten — it bound the *batch* an entry was written in,
so a chain depended on the API calls that produced it rather than on its own
contents. v3 binds the entry's position in the chain instead. See
[D15](docs/decisions.md).

### As an MCP server

An agent can check a chain during a conversation — and, if you allow it, commit
evidence of its own actions as it works:

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
`explain_trust_model`.

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
$ proof forget   --db evidence.db --chain agent-actions --entry mcp-…
```

**Know what crosses the model boundary.** The content an agent commits passes
through the conversation, so the model provider sees it. The server keeps the
nonce out of the transcript, but it cannot recall content that is already there.
Erasing an entry (`proof forget`) makes it unopenable from this machine; it does
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
key both verify in Python and JavaScript. Those fixtures must never be
regenerated by the SDK that checks them — they are evidence precisely because
another implementation produced them.

> **What this does not yet establish.** The three agree on chain hash v2/v3,
> anchor v3/v4/v6, the verifier verdict vectors and the export-bundle vectors.
> Not under the shared set: Merkle roots and inclusion proofs, an anchor
> *series* (the verdict vectors need no key, and a series needs signatures),
> and the two input forms only the SDKs read (the hosted platform's
> `{"entries": [...]}` wrapper and camelCase member names).
>
> Who writes each vector file: `scripts/independent-vectors.py`,
> `scripts/spec-vectors.py`, `scripts/verdict-vectors.py` and
> `scripts/bundle-vectors.py`, each computing its values in Python from the
> spec. No Go test writes one. Five files (`merkle_golden.json`,
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
chainformat     leaf encoding, chain hash linkage, tombstones   ← the core
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
cmd/proof       CLI — init · commit · export · import · anchor · verify · keygen · disclose · forget · sink
cmd/proof-mcp   MCP server (separate module: its SDK needs Go 1.25)

examples/       composition, not features — encrypted-artifact; integrations/nats,
                integrations/redis, integrations/kafka and integrations/otel feed a sink
                (each its own module); integrations/fluent-bit is config only
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

Under active development. The [changelog](CHANGELOG.md) is the record of what
each release contains; while the major version is 0, a minor release may
contain a source-incompatible change, and every one is called out there.
`proof version` prints what a binary was built from.

**Three implementations are held to one set of vectors.** Go (this module),
Python and JavaScript reproduce chain hash v3 and anchor v6, give the same
verdict on the verifier verdict vectors (whole chains, entries files, anchor
text, keyless binds), and give the same result on every export-bundle vector.
The formats are specified in [docs/format-spec.md](docs/format-spec.md) and
[docs/bundle-format.md](docs/bundle-format.md); the Go code is one
implementation of them, not their definition.

| | |
|---|---|
| ✅ built | format core · `anchor` (verify, sign and build) · `verify` (chains, anchors, anchor series) · `linker` · `sink` (commit, checkpoint, verify, erase, export) · `exportbundle` and `proof sink verify-bundle` · CLI · MCP server (7 read-only tools + `commit` with `--db`) |
| ⚠️ known limitations | [listed above](#known-limitations-of-the-current-formats), and not softened: read them before relying on a verdict |
| ⏳ not yet | the next chain and anchor format versions (drafted, not implemented) · the monorepo and SDKs consuming this instead of their own copies |

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
| [docs/runbook.md](docs/runbook.md) | Working on this repository |
| [SECURITY.md](SECURITY.md) | Reporting a vulnerability |

---

## Licence

Apache 2.0. See [LICENSE](LICENSE).

The verification maths is open because a cryptographic audit trail nobody can
inspect is a claim, not a proof. The operational platform — tenancy, retention,
key ceremony, hosted anchoring — is not part of this repository.
