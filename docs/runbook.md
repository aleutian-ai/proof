# Runbook

Working on this repository: what to run, how to change things safely, and the
mistakes that have already been made here so they need not be made again.

---

## Quick reference

```bash
go build ./... && go vet ./... && gofmt -l .     # must be clean; gofmt prints nothing
go test ./...                                    # ~497 tests
go test ./... -race                              # before touching the store

go test . -run TestLifecycle -v                  # seal → link → verify → erase → verify
go test . -run TestStoreE2E -v                   # adapter × scenario matrix
go test . -run 'Dependency|NoCloud' -v           # the dependency guard
go test ./store/... -v                           # store conformance, both adapters

go test . -fuzz FuzzCanonicalV3 -fuzztime 60s    # encoder fuzzing
```

---

## Test layers, and what each is for

Each answers something the one before it cannot. If you are deciding where a new
test belongs, this is the question to ask.

| Layer | Where | Answers |
|---|---|---|
| Unit | `<pkg>/*_test.go` | does this function work |
| Golden vectors | `chainformat`, `merkle` | do we agree with other implementations |
| Conformance | `store/storetest` | does this adapter satisfy the contract |
| Integration | `integration_test.go`, `lifecycle_test.go` | do the packages compose |
| Matrix | `integration_store_test.go` | do the adapters agree with **each other** |
| Invariants + fuzz | `invariants_test.go` | does it hold for inputs nobody wrote down |
| Adversary | `integration_test.go` | are the specific attacks detected |

**Conformance and matrix are not redundant.** Conformance checks each adapter
against the contract; the matrix checks adapters against each other, which is
what catches a contract that is *underspecified*. Two adapters can both satisfy a
loose contract and still disagree — that has happened here twice (decisions D10).

---

## Mutation testing — required for any guard

If you add a test whose job is to prevent something, **break the thing and
confirm the test fails.**

```bash
cp target.go /tmp/bak            # 1. back up
# 2. break the protection
go build ./...                   # 3. MUST still compile
go test ./...                    # 4. confirm the intended test FAILS
cp /tmp/bak target.go            # 5. restore
go test ./...                    # 6. confirm green again
```

**Step 3 is not optional.** A mutation that fails to compile produces zero test
failures, which is indistinguishable from a guard that does not exist. That trap
has been hit three times in this repository — twice by removing code that left an
import unused.

The reason this discipline exists: the published SDK's tombstone test constructed
an entry that cannot occur in production and passed for years against a broken
verifier. A test only checks what its author already believed.

---

## Common tasks

### Add a store adapter

1. Implement `store.Store` in `store/<name>/`.
2. Add `var _ store.Store = (*Store)(nil)` — a compile-time check beats a runtime
   surprise.
3. Wire the **unmodified** conformance suite:
   ```go
   func TestConformance(t *testing.T) {
       storetest.Run(t, func(t *testing.T) store.Store { return New() })
   }
   ```
4. Add it to `adapters` in `integration_store_test.go`, so every scenario runs
   against it.
5. Add its dependencies to the `deps_test.go` allowlist, **with a reason**.

If your adapter needs a weakened suite, it is not interchangeable with the others
— which is the whole property the port provides. Fix the adapter, or change the
contract deliberately and update every adapter.

**Byte-ordered stores:** encode sequence numbers as fixed-width big-endian.
Decimal sorts `"10"` before `"9"` and silently corrupts every range scan.
`RangeOrderingTorture` exists to catch exactly this.

### Add a fixture

1. Put the `.json` in `fixtures/testdata/`.
2. Add a `//go:embed` line and an accessor in `fixtures/fixtures.go`.
3. **One copy only.** No per-package `testdata/` directories.

Fixtures are embedded so a change becomes a version bump visible in a consumer's
`go.mod`, rather than a silent file edit. Non-Go verifiers read the same file
directly.

**Never regenerate a cross-language fixture from this module's own code.** That
is circular — it proves only that the encoder is deterministic. Take vectors from
an independently written implementation and confirm them against a second one.

### Change something that affects hashed bytes

Do not, unless you intend to invalidate every existing chain. If you must:

1. Establish which vectors change and why.
2. Version it — the domain prefix carries `v2` / `v3` for this reason.
3. Regenerate fixtures **and** re-bake every language port.
4. Update `docs/format-spec.md`; it is normative for other implementations.

The golden tests will fail loudly. That is the system working.

### Add a dependency

Expect `deps_test.go` to fail — that is the guard, not an obstacle. Widen the
allowlist **deliberately**, with the reason inline. Do not loosen the test.

Check whether the dependency raises the module's `go` directive:

```bash
go get <dep> && cat go.mod          # did the `go` line move?
```

`go mod tidy` rewrites it silently. See decisions D3.

---

## Release checklist

- [ ] `go build ./... && go vet ./... && gofmt -l .` clean
- [ ] `go test ./...` and `go test ./... -race` green
- [ ] `go test . -run 'Dependency|NoCloud'` green
- [ ] `go.mod` `go` directive unchanged — or the change is intended
- [ ] Fixtures unchanged, or regenerated and re-baked across all languages
- [ ] `docs/format-spec.md` matches the code if hashed bytes changed
- [ ] `README.md` status table matches what is actually built
- [ ] No overclaiming: tamper-*evident* not tamper-proof; *inside* the FIPS
      module boundary is not FIPS *certified*

---

## Known traps

**Timestamps.** Hash input. Never route one through a millisecond representation
before hashing — the failure appears later as an unverifiable chain, not as an
error where the mistake was made.

**Tombstones.** Never recompute their chain hash. Three shipped SDKs got this
wrong. See format-spec §5.

**`sequence_num` vs `global_seq`.** `sequence_num` is position within a run and
IS hashed. `global_seq` is chain-wide and is NOT. Swapping them changes every
hash.

**Merkle leaves.** Hex-decode `content_hash` before leaf-hashing. Hashing the hex
text produces roots nobody else can reproduce.

**`Range` versus the tree builders.** `merkle`'s builders take raw leaf data and
hash internally; `VerifyInclusion` takes an already-hashed leaf. Passing hashed
leaves to a builder double-hashes them, and every proof then verifies against
nothing. Found by an integration test; neither package's own tests could see it.

---

## Repository layout

```
xwing/ keywrap/           crypto core — zero external dependencies
canonical/ chainformat/   the format — x/text only
merkle/                   trees and proofs
store/                    port + storetest + bolt + memory
fixtures/                 cross-language vectors, go:embed
internal/mem/             Zeroize
deps_test.go              the dependency guard
*_test.go (root)          integration, lifecycle, invariants, matrix
docs/                     this set
```

`anchor/`, `kdf/`, `cmd/proof/` are `doc.go` stubs, not yet implemented. `kdf/`
has no consumer and should probably be deleted rather than shipped empty.
