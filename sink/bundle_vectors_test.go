// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/fixtures"
	"github.com/aleutian-ai/proof/keyfile"
)

// The bundle vectors' keys and signatures are made in Python (dilithium-py),
// and the Python SDK verifies with that same library. These tests check them
// with a different implementation (circl, through proof's encoders): the
// keys, every signature a case relies on being valid, and every one it
// relies on being invalid. They do NOT judge the expected results: that is
// the verifiers' job (_72d–_72f).

type bundleVectorFile struct {
	Keys map[string]struct {
		SeedHex      string `json:"seed_hex"`
		PublicKeyHex string `json:"public_key_hex"`
		PublicKeyPEM string `json:"public_key_pem"`
		KeyID        string `json:"key_id"`
	} `json:"keys"`
	Cases []struct {
		Name      string `json:"name"`
		BundleB64 string `json:"bundle_b64"`
		Trust     struct {
			CheckpointKeys []string `json:"checkpoint_keys"`
			RecordKeys     []string `json:"record_keys"`
		} `json:"trust"`
		Expected struct {
			Verdict string `json:"verdict"`
		} `json:"expected"`
		Signatures []struct {
			Kind  string `json:"kind"`
			Index int    `json:"index"`
			Valid bool   `json:"valid"`
		} `json:"signatures"`
	} `json:"cases"`
}

// vectorBundle is just enough of a bundle to find its signatures.
type vectorBundle struct {
	Chains []struct {
		ChainID string `json:"chain_id"`
		Entries []struct {
			EntryID         string `json:"entry_id"`
			EntryType       string `json:"entry_type"`
			GlobalSeq       string `json:"global_seq"`
			PreviousHash    string `json:"previous_hash"`
			Timestamp       string `json:"timestamp"`
			ContentHash     string `json:"content_hash"`
			RecordSignature *struct {
				KeyID     string `json:"key_id"`
				Signature string `json:"signature"`
			} `json:"record_signature"`
		} `json:"entries"`
		Checkpoints []string `json:"checkpoints"`
	} `json:"chains"`
}

func loadBundleVectors(t *testing.T) bundleVectorFile {
	t.Helper()
	var f bundleVectorFile
	if err := json.Unmarshal(fixtures.BundleV1Vectors(), &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// vectorPublicKeys maps key id to public key.
func vectorPublicKeys(t *testing.T, f bundleVectorFile) map[string][]byte {
	t.Helper()
	keys := map[string][]byte{}
	for _, k := range f.Keys {
		pub, err := hex.DecodeString(k.PublicKeyHex)
		if err != nil {
			t.Fatal(err)
		}
		keys[k.KeyID] = pub
	}
	return keys
}

func vectorCase(t *testing.T, f bundleVectorFile, name string) vectorBundle {
	t.Helper()
	for _, c := range f.Cases {
		if c.Name != name {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(c.BundleB64)
		if err != nil {
			t.Fatal(err)
		}
		var b vectorBundle
		if err := json.Unmarshal(raw, &b); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return b
	}
	t.Fatalf("no case %s", name)
	return vectorBundle{}
}

// recordSignatureValid reports whether entry i's record signature verifies
// (pure ML-DSA-65, empty context) under the key it names.
func recordSignatureValid(t *testing.T, keys map[string][]byte, b vectorBundle, chain, i int) bool {
	t.Helper()
	c := b.Chains[chain]
	e := c.Entries[i]
	if e.RecordSignature == nil {
		t.Fatalf("entry %d has no record signature", i)
	}
	f, err := fieldsFromStrings(map[string]string{
		"chain_id": c.ChainID, "entry_id": e.EntryID, "entry_type": e.EntryType, "global_seq": e.GlobalSeq,
		"previous_hash": e.PreviousHash, "timestamp": e.Timestamp, "content_hash": e.ContentHash,
		"signing_key_id": e.RecordSignature.KeyID,
	})
	if err != nil {
		t.Fatalf("entry %d: %v", i, err)
	}
	env, err := recordEnvelope(f)
	if err != nil {
		t.Fatalf("entry %d: %v", i, err)
	}
	sig, err := base64.StdEncoding.DecodeString(e.RecordSignature.Signature)
	if err != nil {
		t.Fatalf("entry %d: %v", i, err)
	}
	pub, ok := keys[e.RecordSignature.KeyID]
	if !ok {
		t.Fatalf("entry %d names an unknown key", i)
	}
	return verifyRecordEnvelope(pub, env, sig) == nil
}

// checkpointSignatureValid reports whether checkpoint k verifies (pure
// ML-DSA-65, empty context) over its canonical bytes, under the key it names.
func checkpointSignatureValid(t *testing.T, keys map[string][]byte, b vectorBundle, chain, k int) bool {
	t.Helper()
	a, canonical := parseVectorCheckpoint(t, b.Chains[chain].Checkpoints[k])
	pub, ok := keys[a.SigningKeyID]
	if !ok {
		t.Fatalf("checkpoint %d names an unknown key", k)
	}
	sig, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil {
		t.Fatal(err)
	}
	var p mldsa65.PublicKey
	if err := p.UnmarshalBinary(pub); err != nil {
		t.Fatal(err)
	}
	return mldsa65.Verify(&p, canonical, nil, sig)
}

func parseVectorCheckpoint(t *testing.T, text string) (anchor.Anchor, []byte) {
	t.Helper()
	var a anchor.Anchor
	if err := json.Unmarshal([]byte(text), &a); err != nil {
		t.Fatal(err)
	}
	canonical, err := anchor.Canonicalize(a)
	if err != nil {
		t.Fatal(err)
	}
	return a, canonical
}

// TestBundleVectorKeys derives each key from its seed with proof's signer and
// checks the public key, the PEM file and the key id the vectors state.
func TestBundleVectorKeys(t *testing.T) {
	f := loadBundleVectors(t)
	if len(f.Keys) != 3 {
		t.Fatalf("%d keys, want 3", len(f.Keys))
	}
	for name, k := range f.Keys {
		seed, err := hex.DecodeString(k.SeedHex)
		if err != nil {
			t.Fatal(err)
		}
		s, err := anchor.NewMLDSA65Signer(seed)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := s.Public().(*anchor.PublicKey).MarshalBinary()
		s.Close()
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(pub) != k.PublicKeyHex {
			t.Errorf("%s: public key differs from proof's derivation", name)
		}
		if s.KeyID() != k.KeyID {
			t.Errorf("%s: key id %s, proof computes %s", name, k.KeyID, s.KeyID())
		}
		alg, filePub, err := keyfile.ParsePublicKey([]byte(k.PublicKeyPEM))
		if err != nil || alg != keyfile.MLDSA65 || !bytes.Equal(filePub, pub) {
			t.Errorf("%s: the PEM is not proof's public key file for this key: %v", name, err)
		}
		want, err := keyfile.MarshalPublicKey(keyfile.MLDSA65, pub)
		if err != nil || string(want) != k.PublicKeyPEM {
			t.Errorf("%s: the PEM is not byte-identical to what proof writes", name)
		}
	}
}

// TestBundleVectorValidSignatures: in every case expected `ok` under both
// trusts, in the real export, and in the cases that append entries, every
// record and checkpoint signature verifies under circl. This also proves the
// generator's envelope and canonical bytes are proof's.
func TestBundleVectorValidSignatures(t *testing.T) {
	f := loadBundleVectors(t)
	keys := vectorPublicKeys(t, f)
	names := []string{"real_export", "after_erasure", "unauthenticated_unanchored_tail"}
	for _, c := range f.Cases {
		if c.Expected.Verdict == "ok" && len(c.Trust.CheckpointKeys) > 0 && len(c.Trust.RecordKeys) > 0 {
			names = append(names, c.Name)
		}
	}
	if len(names) < 9 {
		t.Fatalf("only %d cases to check: %v", len(names), names)
	}
	for _, name := range names {
		b := vectorCase(t, f, name)
		n := 0
		for ci, c := range b.Chains {
			for i := range c.Entries {
				if !recordSignatureValid(t, keys, b, ci, i) {
					t.Errorf("%s: chain %d entry %d: record signature does not verify", name, ci, i)
				}
				n++
			}
			for k := range c.Checkpoints {
				if !checkpointSignatureValid(t, keys, b, ci, k) {
					t.Errorf("%s: chain %d checkpoint %d: signature does not verify", name, ci, k)
				}
				n++
			}
		}
		if n < 3 {
			t.Errorf("%s: only %d signatures checked", name, n)
		}
	}
}

// TestBundleVectorStatedSignatures checks every signature a case states the
// validity of (`signatures`), in chain 0.
func TestBundleVectorStatedSignatures(t *testing.T) {
	f := loadBundleVectors(t)
	keys := vectorPublicKeys(t, f)
	stated := 0
	for _, c := range f.Cases {
		for _, s := range c.Signatures {
			stated++
			b := vectorCase(t, f, c.Name)
			var got bool
			switch s.Kind {
			case "record":
				got = recordSignatureValid(t, keys, b, 0, s.Index)
			case "checkpoint":
				got = checkpointSignatureValid(t, keys, b, 0, s.Index)
			default:
				t.Fatalf("%s: unknown kind %q", c.Name, s.Kind)
			}
			if got != s.Valid {
				t.Errorf("%s: %s %d: circl says valid=%v, the vector states %v", c.Name, s.Kind, s.Index, got, s.Valid)
			}
		}
	}
	if stated < 6 {
		t.Errorf("only %d stated signatures", stated)
	}
}

// TestBundleVectorContextSignaturesAreReal: the context-signature cases must
// fail for the right reason. Each is a genuine signature with context "proof"
// (circl verifies it so), not a corrupted one.
func TestBundleVectorContextSignaturesAreReal(t *testing.T) {
	f := loadBundleVectors(t)
	keys := vectorPublicKeys(t, f)

	b := vectorCase(t, f, "checkpoint_signed_with_context")
	a, canonical := parseVectorCheckpoint(t, b.Chains[0].Checkpoints[0])
	sig, _ := base64.StdEncoding.DecodeString(a.Signature)
	var p mldsa65.PublicKey
	if err := p.UnmarshalBinary(keys[a.SigningKeyID]); err != nil {
		t.Fatal(err)
	}
	if !mldsa65.Verify(&p, canonical, []byte("proof"), sig) {
		t.Error("checkpoint_signed_with_context: not a valid signature with context \"proof\"")
	}

	b = vectorCase(t, f, "record_signed_with_context")
	c, e := b.Chains[0], b.Chains[0].Entries[1]
	fields, err := fieldsFromStrings(map[string]string{
		"chain_id": c.ChainID, "entry_id": e.EntryID, "entry_type": e.EntryType, "global_seq": e.GlobalSeq,
		"previous_hash": e.PreviousHash, "timestamp": e.Timestamp, "content_hash": e.ContentHash,
		"signing_key_id": e.RecordSignature.KeyID,
	})
	if err != nil {
		t.Fatal(err)
	}
	env, err := recordEnvelope(fields)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ = base64.StdEncoding.DecodeString(e.RecordSignature.Signature)
	if err := p.UnmarshalBinary(keys[e.RecordSignature.KeyID]); err != nil {
		t.Fatal(err)
	}
	if !mldsa65.Verify(&p, env, []byte("proof"), sig) {
		t.Error("record_signed_with_context: not a valid signature with context \"proof\"")
	}
}
