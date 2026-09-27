# encrypted-artifact — proof composed with encryption it does not own

`proof` is the integrity layer, not the confidentiality layer. It commits,
anchors and verifies; it does not encrypt, store or manage keys. This example
shows the composition: encrypt with [circl](https://github.com/cloudflare/circl)'s
HPKE (X-Wing, post-quantum), keep private keys in 1Password, store ciphertext in
a plain folder, and commit it with `proof`.

```
   encrypt  →  store  →  COMMIT  →  ANCHOR  →  VERIFY  →  decrypt
   circl       folder    └────────── proof ──────────┘      circl
   HPKE                                                     + 1Password
```

```
  your file ──► HPKE (X-Wing public key) ──► items/<id>.sealed    ciphertext, any storage
                                                  │
                                            SHA-512 of the ciphertext
                                                  ▼
                                   proof chain (chain.db)         commitments only
                                                  │
                                   checkpoint signed with ML-DSA-65 (anchors/)
                                                  │
              verify: PUBLIC keys only ◄──────────┘
              open:   private X-Wing key, from 1Password
```

## Run it

```sh
go build ./examples/encrypted-artifact

./encrypted-artifact init       -vault Private          # private keys → 1Password, public → keys/
./encrypted-artifact commit     -vault Private a.txt b.txt
./encrypted-artifact checkpoint -vault Private
./encrypted-artifact verify                             # needs no private key
./encrypted-artifact open       -vault Private item-…   # decrypt one item to stdout
```

Flags go **before** file names. To try it without 1Password, add
`-keystore file`: private keys then go to `<dir>/secrets/`, next to the data
they protect, which is for trying the example only.

> **The 1Password path (`-keystore op`, the default) is written but has not yet
> been run end to end.** It stores each private key with `op document create`
> and reads it back with `op document get`, passing keys to `op` as temporary
> files, never as command-line arguments. The run below uses `-keystore file`.

## A real run

```
$ encrypted-artifact init
initialised data
  encryption key  X-Wing (private half in data/secrets (demo only))
  signing key     ML-DSA-65, key id 5cc8fd2adb0fee7c71fb9e64b0a28445

$ encrypted-artifact commit log1.txt log2.txt
encrypted log1.txt → items/item-9aee3509dbb24046.sealed (1182 bytes)
encrypted log2.txt → items/item-ef4c50ac85346ac1.sealed (1172 bytes)
committed 2 entries to the chain

$ encrypted-artifact checkpoint
checkpoint anchors/0001.json signed over 2 entries

$ encrypted-artifact commit log3.txt
encrypted log3.txt → items/item-70de5cfcf94df86b.sealed (1166 bytes)
committed 1 entries to the chain

$ encrypted-artifact checkpoint
checkpoint anchors/0002.json signed over 3 entries

$ encrypted-artifact verify
chain        intact, 3 entries
items        all 3 encrypted files match the chain
checkpoint   0001 signed, covers 2 entries
checkpoint   0002 signed, covers 3 entries

$ encrypted-artifact open item-70de5cfcf94df86b
user revoked consent at 14:02
```

No plaintext exists anywhere in the folder outside `secrets/`. The chain and
checkpoints are ordinary `proof` artifacts, so the `proof` CLI verifies them too:

```
$ proof export --db data/chain.db --chain artifacts --out all.json
$ proof verify all.json --anchor data/anchors/0002.json \
      --previous data/anchors/0001.json --key data/keys/mldsa65-public.pem
INTACT, ANCHORED — 3 entries
```

## What it catches

| Attack | Result |
|---|---|
| Flip one byte of an encrypted item | `verify`: item was MODIFIED · `open`: could not be decrypted |
| Swap two items' files | `verify`: MODIFIED · `open`: fails, because the item id is HPKE authenticated data |
| Delete an item | `verify`: item is MISSING, because the chain records it |
| Open with someone else's key | could not be decrypted |
| Forge a checkpoint with a different signing key | `verify`: invalid signature |

## How the proof works

Two links, each from a different layer:

```
  chain ──SHA-512──► this exact ciphertext ──AEAD tag──► this exact plaintext
  (proof)                                    (HPKE)
```

The chain proves which ciphertext was committed at which position. HPKE's
authentication tag proves the plaintext came from that ciphertext. Neither layer
needs to know about the other.

## Design notes

- **The chain commits to ciphertext, never plaintext**, so the chain and its
  checkpoints can be shared freely. HPKE output is random, so the commitment
  cannot be guessed; content committed *unencrypted* needs a salted commitment
  instead.
- **Erasure is destroying the key**, not deleting files: the ciphertext stays,
  the chain still verifies, and the content is unreadable forever. This example
  uses **one** encryption key for everything, so destroying it erases the whole
  log; per-item erasure needs per-item (or per-subject) keys.
- **Keys are standard PKCS#8 PEM** (`proof`'s `keyfile`), so the signing key
  works with `proof anchor --key` and `proof verify --key` unchanged.
- **Checkpoints are checked against the entries they covered.** Checkpoint 0001
  covered 2 entries, so it is verified against the first 2, not all 3.
