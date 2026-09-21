// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package proof_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/fixtures"
	"github.com/aleutian-ai/proof/keywrap"
	"github.com/aleutian-ai/proof/merkle"
	"github.com/aleutian-ai/proof/xwing"
)

// End-to-end tests across package boundaries.
//
// The per-package suites prove each piece in isolation. These prove the pieces
// COMPOSE — that the bytes one package emits are the bytes the next one expects.
// That is where an integration seam actually breaks: not inside a function, but
// at the handoff, where two correct components disagree about a representation.
//
// Deliberately in package proof_test (external), so everything below goes
// through the public API only. If one of these needs an unexported helper, the
// public API is missing something a real consumer will also miss.
//
// # What is NOT covered yet
//
// Chain linkage (prev_hash) needs aleutianchain_06; persistence needs _09.._11;
// anchors need _07/_08. So these prove "verify a committed SET", not "verify a
// chain". The distinction matters and is not papered over.

// goldenVector mirrors one record of the cross-language fixture.
type goldenVector struct {
	Name                   string                       `json:"name"`
	Input                  chainformat.CaptureRequestV3 `json:"input"`
	ExpectedCanonicalHex   string                       `json:"expected_canonical_bytes_hex"`
	ExpectedContentHashHex string                       `json:"expected_content_hash_sha512_hex"`
}

type goldenFile struct {
	DomainPrefixV3 string         `json:"domain_prefix_v3"`
	EntryType      string         `json:"entry_type"`
	Vectors        []goldenVector `json:"vectors"`
}

// loadVectors returns the fixture's entries.
//
// Using the shipped golden rather than hand-built structs means these tests run
// on the same inputs every other language verifier runs on — including the ones
// chosen to be awkward (empty digests, zk mode, full PII inspection).
func loadVectors(t *testing.T) []goldenVector {
	t.Helper()
	var f goldenFile
	if err := json.Unmarshal(fixtures.CaptureRequestV3Golden(), &f); err != nil {
		t.Fatalf("decode capture golden: %v", err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("capture golden has no vectors")
	}
	if f.DomainPrefixV3 != chainformat.DomainPrefixV3 {
		t.Fatalf("fixture domain prefix %q != package constant %q", f.DomainPrefixV3, chainformat.DomainPrefixV3)
	}
	return f.Vectors
}

// contentHashes encodes every vector and returns the resulting content hashes.
func contentHashes(t *testing.T, vs []goldenVector) []string {
	t.Helper()
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		_, ch, err := chainformat.EncodeAndHashV3(v.Input)
		if err != nil {
			t.Fatalf("encode %s: %v", v.Name, err)
		}
		out = append(out, ch)
	}
	return out
}

// rawLeaves decodes content hashes to the raw bytes the tree builders expect.
//
// # The asymmetry this exists to make explicit
//
// merkle's tree builders (RootFromLeaves, InclusionProof, ConsistencyProof) take
// RAW leaf data and apply LeafHash internally. VerifyInclusion takes an
// already-hashed leaf. Passing hashed leaves to the builders double-hashes them:
// every proof is then internally consistent and verifies against nothing.
//
// Nothing in either package's own tests catches that — both are "correct", they
// simply disagree about what a "leaf" is. This helper, and leafHashAt below,
// keep the two representations from being confused at the call site.
func rawLeaves(t *testing.T, hexes []string) [][]byte {
	t.Helper()
	out := make([][]byte, 0, len(hexes))
	for _, h := range hexes {
		raw, err := hex.DecodeString(h)
		if err != nil {
			t.Fatalf("decode content hash: %v", err)
		}
		out = append(out, raw)
	}
	return out
}

// leafHashAt returns the LEAF HASH for VerifyInclusion, which — unlike the tree
// builders — expects the hash rather than the data.
func leafHashAt(raw [][]byte, i int) []byte { return merkle.LeafHash(raw[i]) }

// =============================================================================
// TIER 1A — seal a payload key and recover it across a wire boundary
// =============================================================================

// TestE2E_SealAndRecover runs the full KEM path: generate, encapsulate, frame,
// serialize, parse, decapsulate — and asserts both sides derive the same secret.
//
// The serialize/parse step is the point. Encapsulate and Decapsulate agreeing
// in memory proves the math; agreeing across MarshalBinary/UnmarshalV3 proves
// the WIRE FORMAT, which is what actually gets stored and shipped.
func TestE2E_SealAndRecover(t *testing.T) {
	t.Parallel()

	pub, priv, err := xwing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	defer priv.Zeroize()

	ct, sealSecret, err := xwing.Encapsulate(pub)
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}
	defer sealSecret.Zeroize()

	wrapped, err := keywrap.NewV3(ct, pub)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	blob, err := wrapped.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal wrapped key: %v", err)
	}
	if len(blob) != keywrap.V3Size {
		t.Fatalf("wrapped key is %d bytes, want %d", len(blob), keywrap.V3Size)
	}

	// ---- the blob crosses a wire / lands in storage ----

	parsed, err := keywrap.UnmarshalV3(blob)
	if err != nil {
		t.Fatalf("unmarshal wrapped key: %v", err)
	}

	// Routing: the recipient can tell WHICH key opens this without trial
	// decapsulation. Getting this wrong turns key rotation into brute force.
	wantKID, err := pub.KeyIDHex()
	if err != nil {
		t.Fatalf("key id: %v", err)
	}
	if got := hex.EncodeToString(parsed.KeyID[:]); got != wantKID {
		t.Errorf("wrapped key id = %s, recipient key id = %s", got, wantKID)
	}

	recovered, err := xwing.Decapsulate(
		xwing.Ciphertext{MLKEMCT: parsed.MLKEMCT, X25519EPK: parsed.X25519EPK[:]}, priv)
	if err != nil {
		t.Fatalf("decapsulate: %v", err)
	}
	defer recovered.Zeroize()

	if !bytes.Equal(sealSecret[:], recovered[:]) {
		t.Fatal("recovered shared secret differs from the sealed one")
	}
}

// TestE2E_WrongRecipientCannotRecover pins the security property that makes the
// round-trip meaningful.
//
// ML-KEM uses implicit rejection (FIPS 203 §7.3): decapsulating with the wrong
// key returns a pseudorandom secret and NO error. So "no error" must never be
// read as "correct key" — the guarantee is that the secret DIFFERS, and callers
// discover the mismatch when authenticated decryption fails.
func TestE2E_WrongRecipientCannotRecover(t *testing.T) {
	t.Parallel()

	pubA, privA, err := xwing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate A: %v", err)
	}
	defer privA.Zeroize()
	_, privB, err := xwing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate B: %v", err)
	}
	defer privB.Zeroize()

	ct, secretA, err := xwing.Encapsulate(pubA)
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}
	defer secretA.Zeroize()

	secretB, err := xwing.Decapsulate(ct, privB)
	if err != nil {
		t.Fatalf("decapsulate with wrong key returned an error; ML-KEM implicit "+
			"rejection requires success with a pseudorandom result: %v", err)
	}
	defer secretB.Zeroize()

	if bytes.Equal(secretA[:], secretB[:]) {
		t.Fatal("a different private key recovered the same shared secret")
	}
}

// =============================================================================
// TIER 1B — commit a batch of entries and prove one is a member
// =============================================================================

// TestE2E_CommitBatchAndProveMembership runs entry → canonical → content hash →
// Merkle root → inclusion proof, and verifies the proof for every position.
//
// This is the composition seam that matters: chainformat emits 128-char hex and
// merkle.RootHex consumes 128-char hex. A mismatch in that representation (raw
// vs hex, upper vs lower) would be invisible to both packages' own tests.
func TestE2E_CommitBatchAndProveMembership(t *testing.T) {
	t.Parallel()

	vectors := loadVectors(t)
	hashes := contentHashes(t, vectors)

	rootHex, err := merkle.RootHex(hashes)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	root, err := hex.DecodeString(rootHex)
	if err != nil {
		t.Fatalf("decode root: %v", err)
	}

	leaves := rawLeaves(t, hashes)
	for i, v := range vectors {
		proof, err := merkle.InclusionProof(i, leaves)
		if err != nil {
			t.Fatalf("inclusion proof for %s: %v", v.Name, err)
		}
		if !merkle.VerifyInclusion(leafHashAt(leaves, i), i, len(leaves), proof, root) {
			t.Errorf("entry %d (%s) failed its own inclusion proof", i, v.Name)
		}
	}
}

// TestE2E_FixtureIsTheContract asserts the encoder reproduces the committed
// bytes AND hash for every vector — the same assertion every language port runs.
func TestE2E_FixtureIsTheContract(t *testing.T) {
	t.Parallel()

	for _, v := range loadVectors(t) {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			canonical, contentHash, err := chainformat.EncodeAndHashV3(v.Input)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if got := hex.EncodeToString(canonical); got != v.ExpectedCanonicalHex {
				t.Errorf("canonical bytes diverge from the contract:\n want %s\n  got %s",
					v.ExpectedCanonicalHex, got)
			}
			if contentHash != v.ExpectedContentHashHex {
				t.Errorf("content hash diverges:\n want %s\n  got %s",
					v.ExpectedContentHashHex, contentHash)
			}
		})
	}
}

// =============================================================================
// TIER 4 — the adversary matrix
// =============================================================================

// TestE2E_AdversaryCannotAlterACommittedSet enumerates what someone with write
// access to storage can actually DO to a committed set, and asserts each is
// detected.
//
// # Why enumerate rather than test "tampering is detected"
//
// "We detect tampering" is not a claim until the verbs are listed. An attacker
// does not tamper in the abstract; they modify, delete, insert, reorder, swap,
// or truncate. Each is a distinct operation on the leaf set, and an
// implementation can plausibly catch some and miss others — a scheme that hashes
// leaves without binding POSITION catches modification but not reordering.
//
// Every case below re-derives the root from the mutated set and asserts it moved.
// A moved root is what makes the mutation visible to anyone holding the original.
func TestE2E_AdversaryCannotAlterACommittedSet(t *testing.T) {
	t.Parallel()

	vectors := loadVectors(t)
	if len(vectors) < 3 {
		t.Fatalf("adversary matrix needs at least 3 vectors, fixture has %d", len(vectors))
	}
	honest := contentHashes(t, vectors)
	honestRoot, err := merkle.RootHex(honest)
	if err != nil {
		t.Fatalf("honest root: %v", err)
	}

	clone := func() []string { return append([]string(nil), honest...) }

	// MODIFY is expressed through the encoder rather than by editing a hash
	// directly — it proves the field change propagates all the way to the root,
	// which is the actual claim. The rest operate on the committed set.
	modified := func(t *testing.T) []string {
		t.Helper()
		v := vectors[1].Input
		v.Model = v.Model + "-tampered"
		_, ch, err := chainformat.EncodeAndHashV3(v)
		if err != nil {
			t.Fatalf("re-encode modified entry: %v", err)
		}
		h := clone()
		h[1] = ch
		return h
	}

	cases := []struct {
		attack string
		mutate func(t *testing.T) []string
	}{
		{"modify a field in one entry", modified},
		{"delete an entry", func(*testing.T) []string {
			h := clone()
			return append(h[:1], h[2:]...)
		}},
		{"insert a forged entry", func(*testing.T) []string {
			h := clone()
			return append(h, honest[0]) // replay an existing entry as a new one
		}},
		{"reorder two entries", func(*testing.T) []string {
			h := clone()
			h[0], h[1] = h[1], h[0]
			return h
		}},
		{"truncate the set", func(*testing.T) []string {
			return clone()[:len(honest)-1]
		}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.attack, func(t *testing.T) {
			t.Parallel()
			mutatedRoot, err := merkle.RootHex(tc.mutate(t))
			if err != nil {
				t.Fatalf("root over mutated set: %v", err)
			}
			if mutatedRoot == honestRoot {
				t.Fatalf("UNDETECTED: %q produced the same root (%s) — this attack "+
					"would be invisible to anyone holding the original commitment",
					tc.attack, honestRoot)
			}
		})
	}
}

// TestE2E_StaleProofFailsAgainstNewRoot covers the case the matrix above cannot:
// an attacker who keeps a VALID proof from before the tampering.
//
// The root moving is only useful if old proofs stop verifying against the new
// root. Otherwise a verifier could be handed yesterday's proof and today's root
// and see nothing wrong.
func TestE2E_StaleProofFailsAgainstNewRoot(t *testing.T) {
	t.Parallel()

	vectors := loadVectors(t)
	honest := contentHashes(t, vectors)
	honestLeaves := rawLeaves(t, honest)

	staleProof, err := merkle.InclusionProof(1, honestLeaves)
	if err != nil {
		t.Fatalf("inclusion proof: %v", err)
	}

	tampered := vectors[1].Input
	tampered.Provider = tampered.Provider + "x"
	_, ch, err := chainformat.EncodeAndHashV3(tampered)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	mutated := append([]string(nil), honest...)
	mutated[1] = ch

	newRootHex, err := merkle.RootHex(mutated)
	if err != nil {
		t.Fatalf("mutated root: %v", err)
	}
	newRoot, err := hex.DecodeString(newRootHex)
	if err != nil {
		t.Fatalf("decode root: %v", err)
	}

	if merkle.VerifyInclusion(leafHashAt(honestLeaves, 1), 1, len(honestLeaves), staleProof, newRoot) {
		t.Fatal("a pre-tampering inclusion proof still verified against the post-tampering root")
	}
}

// jsonUnmarshalGolden decodes the embedded capture golden into v. Shared with
// the fuzz seed corpus, which has a *testing.F rather than a *testing.T.
func jsonUnmarshalGolden(v any) error {
	return json.Unmarshal(fixtures.CaptureRequestV3Golden(), v)
}
