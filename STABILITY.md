# Stability and versioning

`proof` has two kinds of version, and they break different things:

| | Example | What a change breaks | Versioned by |
|---|---|---|---|
| **Go API** | `v0.5.0` | builds: your code no longer compiles | the module's semver tags |
| **Format** | `aleutian.chain.leaf.v4:`, anchor `"version": 7`, `aleutian.proof.bundle.v2` | stored data: chains, anchors and bundles that already exist | the version in the bytes themselves |

An API change costs you an afternoon. A format change, done badly, would
strand every chain anyone has stored. So they are versioned separately, and
the promises differ.

## The format promise

**Every format version a release of `proof` has written stays verifiable by
every later release.** New formats are added. Released ones are not changed,
and their verification is not removed.

- A released format is **frozen**. Its hashed bytes, canonical form, domain
  strings and conformance vectors never change. A weakness found in it is
  documented, not fixed in place, because its hashes are already signed into
  anchors (decisions D22). The fix is a new format version.
- A frozen chain format is **continued, not migrated**. The next entry is
  written in the new format and links from the old head (format-spec §2.5).
  There is no migration tool, because a re-linked chain is not the chain that
  was anchored.
- The vectors in `fixtures/` are part of the promise. A release whose code
  disagrees with a released vector is a bug in that release.

Today that covers chain formats v2, v3 and v4; anchor versions 1–4, 6 and 7;
and export bundles v1 and v2. Anchor version 5 was withdrawn before any
producer wrote one (CHANGELOG, v0.3.0), and it is refused by name. Its number
is never reused.

**What the promise does not cover.** A *sink folder* is an application's
working directory, not an interchange format. A sink folder written before
v0.5.0 is not continued by v0.5.0. Its contents stay verifiable through the
formats above: export it as a `bundle.v1` with v0.4.x, and v0.5.0 verifies that
bundle (sink-format §10). Should a later layout change leave older folders
behind, the change will be called out in the CHANGELOG with the way to export
them, as this one was.

## The Go API, while the major version is 0

Versions follow [semantic versioning](https://semver.org). While the major
version is 0:

- **A minor release (`v0.5.0` to `v0.6.0`) may change the API incompatibly.**
  Every such change is marked *source-incompatible* in the CHANGELOG, with what
  to do instead.
- **A patch release (`v0.4.0` to `v0.4.1`) does not change the API
  incompatibly.** It may refuse input that an earlier version wrongly accepted.
  For a verifier, that is a fix, not a break, and the CHANGELOG says so.
- Only the latest release receives fixes (SECURITY.md).
- A published tag is never moved. A broken release is fixed by the next
  version, and retracted in `go.mod` when it must not be used.
- `internal/` packages are not API.
- `cmd/proof-mcp` is a separate module with its own tag series
  (`cmd/proof-mcp/vX.Y.Z`). Each tag requires a released library version,
  normally the one with the same number (docs/release.md).

The CLI's commands, flags, exit codes and JSON output follow the same rules as
the Go API. The MCP server's tool names and schemas do too; they are pinned by
`cmd/proof-mcp/testdata/tools_list.golden.json`.

## v1.0

v1.0 will promise that the Go API does not change incompatibly within major
version 1. The format promise above already holds, and does not wait for v1.0.

v1.0 waits for these:

- [ ] The formats it ships have had an external review with no open finding
      that would need a new format version.
- [ ] At least one implementation outside this repository, beyond the two SDKs
      in the Aleutian monorepo, passes the full conformance vector set.
- [ ] The API has gone through at least one minor release with no
      source-incompatible change, and has been used by a consumer outside the
      repository.
- [ ] The Python and JavaScript SDKs are published, and track this module's
      vectors.
- [ ] The conformance vectors cover what the README lists as not yet covered:
      Merkle roots and inclusion proofs, and anchor series.

After v1.0, removing or changing anything in the API needs a new major version.
Deprecations are announced in the CHANGELOG at least one minor release before
they take effect.
