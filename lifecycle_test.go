// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package proof_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/keywrap"
	"github.com/aleutian-ai/proof/xwing"
)

// A one-off end-to-end pass over the whole system, and a throwaway verifier.
//
// # Why the verifier here is written from the DOCS
//
// walkChain below was written from chainformat's package documentation alone —
// not by copying the producer's verifier or the SDK's. That makes it a test of
// the documentation as much as of the code: if the rules a third party needs are
// all written down, this works. If it needs something only findable by reading
// another implementation, the docs are incomplete and aleutianchain_13 would
// inherit that gap.
//
// It is deliberately ~30 lines. The real verifier (aleutianchain_13) will add
// break classification, bounded reporting, and anchor binding; none of that
// changes the linkage rule this exercises.

// walkChain re-derives every entry's chain hash and returns the index of the
// first entry that does not match, or -1 if the chain is intact.
//
// The two rules it implements both come from the package docs:
//
//  1. each entry's hash covers the previous entry's hash
//  2. a tombstone's hash is NOT recomputable — validate its format and advance
//     on the STORED value, because later entries were chained against that
func walkChain(t *testing.T, entries []linkedEntry) int {
	t.Helper()

	previousHash := ""
	for i, e := range entries {
		if chainformat.IsTombstone(e.EntryType, e.EntryID) {
			if !chainformat.ValidateTombstoneContentHash(e.ContentHash) {
				t.Errorf("entry %d: malformed tombstone content hash", i)
				return i
			}
			previousHash = e.ChainHash // rule 2
			continue
		}
		expected := chainformat.ComputeChainHashUnchecked(
			previousHash, e.RunID, e.SequenceNum, e.Timestamp, e.ContentHash)
		if expected != e.ChainHash {
			return i
		}
		previousHash = expected // rule 1
	}
	return -1
}

// linkedEntry is one row of a chain: the entry plus its linkage fields.
type linkedEntry struct {
	EntryID     string
	EntryType   string
	RunID       string
	SequenceNum int64
	Timestamp   time.Time
	ContentHash string
	ChainHash   string

	// sealedPayload is the encrypted content. Erasure destroys it; nothing else
	// in the row changes except ContentHash.
	sealedPayload []byte
}

// sealPayload encrypts plaintext under a freshly encapsulated shared secret and
// returns the wrapped key alongside the ciphertext.
//
// This mirrors the real KEM-DEM shape: X-Wing establishes the secret, and that
// secret is used directly as an AES-256-GCM key.
func sealPayload(t *testing.T, pub xwing.PublicKey, plaintext []byte) (wrapped []byte, sealed []byte) {
	t.Helper()

	ct, secret, err := xwing.Encapsulate(pub)
	if err != nil {
		t.Fatalf("encapsulate: %v", err)
	}
	defer secret.Zeroize()

	w, err := keywrap.NewV3(ct, pub)
	if err != nil {
		t.Fatalf("wrap key: %v", err)
	}
	wrapped, err = w.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal wrapped key: %v", err)
	}

	block, err := aes.NewCipher(secret[:])
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return wrapped, gcm.Seal(nonce, nonce, plaintext, nil)
}

// openPayload reverses sealPayload using the recipient's private key.
func openPayload(t *testing.T, priv xwing.PrivateKey, wrapped, sealed []byte) []byte {
	t.Helper()

	w, err := keywrap.UnmarshalV3(wrapped)
	if err != nil {
		t.Fatalf("unmarshal wrapped key: %v", err)
	}
	secret, err := xwing.Decapsulate(
		xwing.Ciphertext{MLKEMCT: w.MLKEMCT, X25519EPK: w.X25519EPK[:]}, priv)
	if err != nil {
		t.Fatalf("decapsulate: %v", err)
	}
	defer secret.Zeroize()

	block, err := aes.NewCipher(secret[:])
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	if len(sealed) < gcm.NonceSize() {
		t.Fatal("sealed payload is shorter than a nonce")
	}
	plaintext, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], nil)
	if err != nil {
		t.Fatalf("open payload: %v", err)
	}
	return plaintext
}

// TestLifecycle_SealLinkVerifyEraseVerify runs the whole system end to end.
//
//	seal ─► link ─► VERIFY (content provable) ─► ERASE ─► VERIFY (chain intact,
//	                                                              content gone)
//
// # The claim being demonstrated
//
// Before erasure, a holder of the private key can decrypt an entry's payload,
// recompute its content hash, and show it matches what the chain committed to —
// the content is provably the content the log recorded.
//
// After erasure, that comparison is impossible by construction: the payload is
// destroyed and the content hash is replaced by a random value. The chain still
// verifies. Those two facts together are the product: erasure is real, and it
// does not cost you the integrity of everything around it.
func TestLifecycle_SealLinkVerifyEraseVerify(t *testing.T) {
	t.Parallel()

	pub, priv, err := xwing.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	defer priv.Zeroize()

	const runID = "run_550e8400-e29b-41d4-a716-446655440000"
	base := time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC)
	payloads := [][]byte{
		[]byte(`{"prompt":"first interaction"}`),
		[]byte(`{"prompt":"second interaction — this one gets erased"}`),
		[]byte(`{"prompt":"third interaction"}`),
	}

	// ---- seal each payload and link the entries into a chain ----
	entries := make([]linkedEntry, 0, len(payloads))
	wrappedKeys := make([][]byte, 0, len(payloads))
	previousHash := ""

	for i, p := range payloads {
		wrapped, sealed := sealPayload(t, pub, p)
		sum := sha512.Sum512(sealed)
		contentHash := hex.EncodeToString(sum[:])

		ts := base.Add(time.Duration(i) * time.Second)
		chainHash, err := chainformat.ComputeChainHash(
			previousHash, runID, int64(i), ts, contentHash)
		if err != nil {
			t.Fatalf("entry %d: link: %v", i, err)
		}

		entries = append(entries, linkedEntry{
			EntryID: "entry_" + string(rune('1'+i)), EntryType: "request",
			RunID: runID, SequenceNum: int64(i), Timestamp: ts,
			ContentHash: contentHash, ChainHash: chainHash, sealedPayload: sealed,
		})
		wrappedKeys = append(wrappedKeys, wrapped)
		previousHash = chainHash
	}

	// ---- VERIFY, before erasure ----
	if idx := walkChain(t, entries); idx != -1 {
		t.Fatalf("freshly built chain reported a break at index %d", idx)
	}

	// Every entry's content is provably what the chain committed to.
	for i, e := range entries {
		plaintext := openPayload(t, priv, wrappedKeys[i], e.sealedPayload)
		if !bytes.Equal(plaintext, payloads[i]) {
			t.Fatalf("entry %d: decrypted payload differs from the original", i)
		}
		sum := sha512.Sum512(e.sealedPayload)
		if hex.EncodeToString(sum[:]) != e.ContentHash {
			t.Fatalf("entry %d: recomputed content hash does not match the chain", i)
		}
	}

	// ---- ERASE entry 2, the way the producer does ----
	//
	// content_hash → random tombstone value; chain_hash PRESERVED; payload gone.
	// Everything else about the row is untouched.
	tombstoneHash, err := chainformat.GenerateTombstoneContentHash()
	if err != nil {
		t.Fatalf("generate tombstone content hash: %v", err)
	}
	entries[1].EntryType = chainformat.TombstoneEntryType
	entries[1].EntryID = chainformat.TombstoneEntryIDPrefix + "550e8400-e29b-41d4-a716-446655440000"
	entries[1].ContentHash = tombstoneHash
	entries[1].sealedPayload = nil // the ciphertext is destroyed
	wrappedKeys[1] = nil           // and so is the wrapped key
	// entries[1].ChainHash deliberately NOT recomputed — that is the invariant.

	// ---- VERIFY, after erasure ----
	if idx := walkChain(t, entries); idx != -1 {
		t.Fatalf("a lawfully erased entry broke the chain at index %d — this is the "+
			"sdk_verify_01 failure mode", idx)
	}

	// The erased entry's content can no longer be shown, by construction.
	if entries[1].sealedPayload != nil {
		t.Fatal("erasure did not destroy the payload")
	}
	if !chainformat.IsTombstoneContentHash(entries[1].ContentHash) {
		t.Fatal("erased entry does not carry a tombstone content hash")
	}

	// Its neighbours are untouched and still provable.
	for _, i := range []int{0, 2} {
		plaintext := openPayload(t, priv, wrappedKeys[i], entries[i].sealedPayload)
		if !bytes.Equal(plaintext, payloads[i]) {
			t.Fatalf("entry %d: erasing a neighbour damaged this entry", i)
		}
	}
}

// TestLifecycle_TamperIsDetected is the negative control for the test above.
//
// Without it, "the chain verified after erasure" could mean the walk is simply
// permissive. This asserts the same walk rejects an actual edit.
func TestLifecycle_TamperIsDetected(t *testing.T) {
	t.Parallel()

	entries := buildTestChain(t, 4)
	entries[2].ContentHash = flipLastHexNibble(entries[2].ContentHash)

	if idx := walkChain(t, entries); idx != 2 {
		t.Fatalf("tampering with entry 2 reported a break at index %d, want 2", idx)
	}
}

// TestLifecycle_TruncationIsNOTDetected pins a documented LIMITATION.
//
// This test asserts something the system cannot do, which is unusual and
// deliberate. An attacker who deletes the front of a chain and re-links the
// remainder produces something that verifies perfectly, because nothing inside a
// chain records where it began.
//
// If this test ever starts failing, the linkage rules changed and the package
// documentation on consistency-versus-existence needs revisiting — someone may
// have added a defence, which would be good news, but the docs would then be
// wrong. Closing this gap for real requires an anchor (aleutianchain_07/_08).
func TestLifecycle_TruncationIsNOTDetected(t *testing.T) {
	t.Parallel()

	full := buildTestChain(t, 5)
	if idx := walkChain(t, full); idx != -1 {
		t.Fatalf("baseline chain broke at %d", idx)
	}

	// Discard entries 0-1 and re-link the remainder as though it were the whole.
	truncated := append([]linkedEntry(nil), full[2:]...)
	previousHash := ""
	for i := range truncated {
		truncated[i].SequenceNum = int64(i)
		truncated[i].ChainHash = chainformat.ComputeChainHashUnchecked(
			previousHash, truncated[i].RunID, int64(i),
			truncated[i].Timestamp, truncated[i].ContentHash)
		previousHash = truncated[i].ChainHash
	}

	if idx := walkChain(t, truncated); idx != -1 {
		t.Fatalf("truncation was detected at index %d — if a defence was added, the "+
			"package docs claiming this is undetectable are now wrong", idx)
	}
}

// buildTestChain returns n linked entries with deterministic content hashes.
func buildTestChain(t *testing.T, n int) []linkedEntry {
	t.Helper()

	const runID = "run_550e8400-e29b-41d4-a716-446655440000"
	base := time.Date(2026, 1, 20, 12, 0, 0, 0, time.UTC)

	entries := make([]linkedEntry, 0, n)
	previousHash := ""
	for i := 0; i < n; i++ {
		sum := sha512.Sum512([]byte{byte(i)})
		contentHash := hex.EncodeToString(sum[:])
		ts := base.Add(time.Duration(i) * time.Second)

		chainHash, err := chainformat.ComputeChainHash(previousHash, runID, int64(i), ts, contentHash)
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
		entries = append(entries, linkedEntry{
			EntryID: "entry_" + string(rune('1'+i)), EntryType: "request",
			RunID: runID, SequenceNum: int64(i), Timestamp: ts,
			ContentHash: contentHash, ChainHash: chainHash,
		})
		previousHash = chainHash
	}
	return entries
}
