# Contributing to proof

Bug reports, questions, independent implementations and pull requests are all
welcome.

**A security issue goes through [SECURITY.md](SECURITY.md), not a public issue.**
For a verifier, a security issue includes accepting something it should
refuse, or claiming more than it checked, even when nothing crashes.

## Licensing your contribution: the DCO

`proof` is Apache-2.0. A contribution is licensed under Apache-2.0 too, as
section 5 of the licence says, and that includes its patent grant. There is
no contributor licence agreement to sign.

Instead, each commit carries a [Developer Certificate of
Origin](https://developercertificate.org/) sign-off. With it you certify that
you wrote the change, or otherwise have the right to submit it under the
project's licence:

```console
$ git commit -s
```

That adds a line with your name and email:

```
Signed-off-by: Your Name <you@example.com>
```

A pull request whose commits are not signed off cannot be merged. If you
forgot, `git commit --amend -s` fixes the last commit, and `git rebase
--signoff main` fixes all of them.

## Before you change a format

The formats (chain, anchor, bundle, sink record) are specified in
`docs/format-spec.md`, `docs/bundle-format.md` and `docs/sink-format.md`. The
Go code is one implementation of them, not their definition.

- **A change to hashed or signed bytes starts as a change to the
  specification**, in an issue, before any code. Released formats are frozen
  ([STABILITY.md](STABILITY.md)). A fix to one is a new format version, not an
  edit.
- **The conformance vectors in `fixtures/` are data written by scripts**
  (`scripts/*-vectors.py`), never edited by hand. The gate regenerates them
  and refuses any byte that differs (decisions D18).

## What a pull request needs

- **Tests for what it changes.** A new check that refuses something needs a
  test that fails when the check is removed. Every guard in this repository is
  mutation-tested this way (decisions D11; docs/runbook.md, "Mutation
  testing").
- **The gate passes:** `./scripts/release-check.sh --local`. This runs gofmt,
  vet and the tests for both modules, regenerates the vectors, and checks the
  licence files. It needs Python 3 and `pip install dilithium-py`. There is
  no CI; the gate is the same script for everyone. The full run, without
  `--local`, also tests on Linux in podman containers.
- **No new dependency in the crypto core** (decisions D1). Any dependency
  added elsewhere needs a reason in the pull request, and
  `./scripts/third-party-licenses.sh` rerun.
- **Go 1.24** stays the floor (decisions D3).
- **No overclaiming in docs or output.** "Tamper-evident", not
  "tamper-proof". A verdict says what was checked and what was not.

docs/runbook.md covers the test layers, common tasks (a store adapter, a
fixture, a change to hashed bytes) and the traps already found.

## Implementing proof in another language

That is the most useful contribution of all. Start from `docs/format-spec.md`
§11 (the checklist) and `docs/conformance.md`, and pass the vector set in
`fixtures/`. Please tell us in an issue: an implementation written from the
specification alone is the best test the specification gets.
