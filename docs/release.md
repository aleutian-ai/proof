# Releasing proof

A release of `proof` reaches people through four channels: the Go module
proxy, the container registry, PyPI and npm. Each one has its own tool, its
own way to fail and its own one-way door. This is the order to take them in,
why that order, and what can and cannot be undone at each step. It covers
`proof`, `proof-mcp` and the two verifier SDKs. The cross-SDK release
governance in the monorepo (`tickets/planned/sdk_release_engineering_channels_v1.md`)
still applies; this document does not restate it.

Nothing here publishes to more than one channel. Each upload is its own
command, run by a person who has just read what it will write. The scripts
check and order; they do not walk through the one-way doors for you.

## The order, and why

```
  1. gate the tree            release-check.sh                 reversible
  2. tag proof vX             CHANGELOG heading, commit, tag   reversible until pushed
  3. push the proof tag       ─────────────────────────────▶   ONE-WAY: the proxy caches it
  4. bump and tag proof-mcp   go get proof@vX, tag-check.sh    reversible until pushed
  5. push the proof-mcp tag   ─────────────────────────────▶   ONE-WAY
  6. check as an outsider     tag-check.sh vX --proxy          read-only
  7. images                   publish-image.sh vX              ONE-WAY in practice
  8. SDKs, last               publish-sdks.sh --publish …      ONE-WAY, and the number is spent
```

- **proof before proof-mcp.** `cmd/proof-mcp` is a separate module and has no
  replace directive, because `go install …@vX` refuses one. Its `go.mod`
  therefore names a published library version. That version has to be on the
  proxy before the bump can be made, so the library is tagged and pushed first.
  `cmd/proof-mcp/v0.3.0` was tagged before its bump and did not build; it had
  to be retracted. `tag-check.sh` now refuses that state.
- **The proxy before the images.** The images are built from the tagged tree.
  An image whose source cannot be fetched by version is a binary nobody can
  check.
- **The SDKs last.** They are the only step that cannot be redone in any form.
  PyPI never lets a version number be used twice, even after deletion, and npm
  blocks unpublishing after 72 hours. Everything before them can be fixed with
  a new version, without leaving a broken release under a number that is gone.

A release that stops halfway is the realistic failure: tags pushed and images
not, or Python published and JavaScript not. Finish it, or record in the
CHANGELOG which channels carry the version.

## The steps

### 1. Gate the tree (reversible)

```console
$ ./scripts/release-check.sh ../AleutianEnterprise/sdk/testdata \
      --sdk ../AleutianEnterprise/sdk/verification-python \
      --sdk ../AleutianEnterprise/sdk/verification-js
```

`--sdk` takes one directory each time it appears. A bare argument is a
vendored vector directory. Every check has to pass, including both Linux
container steps. A skipped step is a check that did not run, not a pass.

If podman stops with `error getting credentials`, a registry credential helper
(gcloud, for example) is failing, even for a docker.io pull. Fix the helper's
login, or run the gate with an empty configuration:

```console
$ mkdir -p /tmp/noauth && echo '{}' > /tmp/noauth/config.json && echo '{}' > /tmp/noauth/auth.json
$ DOCKER_CONFIG=/tmp/noauth REGISTRY_AUTH_FILE=/tmp/noauth/auth.json ./scripts/release-check.sh …
```

### 2. Tag the library (reversible until pushed)

Change `## Unreleased` in `CHANGELOG.md` to `## vX.Y.Z — YYYY-MM-DD`. Commit,
then `git tag -a vX.Y.Z -m vX.Y.Z`. A local tag can still be deleted and made
again.

### 3. Push the library tag (one-way)

`git push origin <branch> vX.Y.Z`. Once anyone fetches the version through
the proxy, the proxy and the checksum database keep that tag's bytes for good.
A published tag is never moved (SECURITY.md). A broken release is fixed by
the next version, and by a `retract` line in `go.mod` if it must not be used.

### 4. Bump and tag proof-mcp (reversible until pushed)

```console
$ go -C cmd/proof-mcp get github.com/aleutian-ai/proof@vX.Y.Z
$ go -C cmd/proof-mcp mod tidy
$ GOWORK=off go -C cmd/proof-mcp test ./...
$ git commit -am "proof-mcp: require proof vX.Y.Z"
$ git tag -a cmd/proof-mcp/vX.Y.Z -m cmd/proof-mcp/vX.Y.Z
$ ./scripts/tag-check.sh vX.Y.Z
```

`GOWORK=off` matters. The gitignored `go.work` would otherwise build against
the working tree and hide a wrong requirement. `tag-check.sh` exports each
tagged tree with `git archive` and builds it with
`GOWORK=off GOFLAGS=-mod=readonly`, because the tagged commit is what ships,
not the working tree. It also checks that the proof-mcp tag requires exactly
the library version, and that the CHANGELOG at the library tag has the
heading.

### 5. Push the proof-mcp tag (one-way)

`git push origin <branch> cmd/proof-mcp/vX.Y.Z`. This is one-way for the
same reason as step 3.

### 6. Check as an outsider (read-only)

```console
$ ./scripts/tag-check.sh vX.Y.Z --proxy
```

This runs in a clean container, with no credentials, no workspace and the
public proxy. It confirms that the proxy serves both versions. It installs
both binaries by exact version rather than `@latest`, so a bad tag fails
instead of being skipped. It checks that each binary reports that version.
It also verifies the demo chain from the tagged tree and refuses the tampered
one. If an outsider cannot do it, it did not ship.

### 7. Images (one-way in practice; not done for now)

No image is published for now (decisions D24): users build their own from the
tag. Skip this step until that changes.

Build from the library tag. A separate worktree leaves your checkout alone:

```console
$ git worktree add /tmp/proof-vX.Y.Z vX.Y.Z
$ podman login ghcr.io
$ /tmp/proof-vX.Y.Z/scripts/publish-image.sh vX.Y.Z --dry-run
$ /tmp/proof-vX.Y.Z/scripts/publish-image.sh vX.Y.Z
$ git worktree remove /tmp/proof-vX.Y.Z
```

The Dockerfile builds `proof-mcp` against the library in the same tree, so
the library tag is the right source for both images. `publish-image.sh`
refuses a dirty tree, and refuses a HEAD the version tag does not point at.
Before it pushes, it reads the revision label back off the built images, runs
`container-check.sh --quick` against them, and names every ref it is about
to write.

It writes `ghcr.io/aleutian-ai/proof:vX.Y.Z` and `proof-mcp:vX.Y.Z`, and moves
`:latest` for a release that is not a prerelease (decisions D24). A version
tag can be deleted from the registry, but anyone who pulled it by digest may
already depend on it, so treat it as published. `:latest` can be moved back.

Afterwards, pull by digest on a clean machine and verify a chain:
`podman run --rm -v "$PWD:/data:ro" ghcr.io/aleutian-ai/proof@sha256:… verify /data/entries.json`.

### 8. The SDKs, last (one-way; the number is spent)

In the monorepo, after their CHANGELOGs have their version headings:

```console
$ ./scripts/publish-sdks.sh --check
$ ./scripts/publish-sdks.sh --publish python
$ ./scripts/publish-sdks.sh --publish js
```

`--check` runs every gate and publishes nothing, including the vendored
vectors matching `fixtures/MANIFEST.json`. Each `--publish` asks before it
uploads. Afterwards, `pip install` and `npm install` the published packages in
a clean container and verify a `fixtures/` vector with each.

## What each step can undo

| Step | Undo | Cost of a mistake |
|---|---|---|
| 1 gate | nothing to undo | none |
| 2 tag locally | `git tag -d` | none |
| 3, 5 push a tag | never; publish a new version, `retract` the bad one | a version that exists forever |
| 7 images | delete the version tag; move `:latest` back | anyone who pulled it has it |
| 8 SDKs | none on PyPI; npm only within 72 hours | the version number is gone |
