// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/keyfile"
)

func testRecordSigner(t *testing.T, fill byte) *MLDSA65RecordSigner {
	t.Helper()
	s, err := NewMLDSA65RecordSigner(bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestSignRecord_RoundTrip: a signature verifies under the signer's key, over
// the envelope carrying the key id derived from that key.
func TestSignRecord_RoundTrip(t *testing.T) {
	s := testRecordSigner(t, 7)
	key, err := recordKeyOf(s)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := keyfile.KeyIDHex(keyfile.MLDSA65, key.pub)
	if key.id != want {
		t.Fatalf("key id %s, want the keyfile id %s", key.id, want)
	}
	f := validRecordFields()
	f.keyID = "" // signRecord fills it
	sig, err := signRecord(context.Background(), s, key, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != anchor.SignatureSize {
		t.Fatalf("signature is %d bytes", len(sig))
	}
	f.keyID = key.id
	if err := verifyRecordSignature(key.pub, f, sig); err != nil {
		t.Fatalf("does not verify: %v", err)
	}
	// Deterministic (hedging off, as for anchors): same record, same bytes.
	again, _ := signRecord(context.Background(), s, key, f)
	if !bytes.Equal(sig, again) {
		t.Fatal("signing the same record twice gave two signatures")
	}
}

// TestVerifyRecordSignature_EveryFieldIsBound: a signature for one record fails
// for the record with any one field changed: relabelled type, moved chain or
// position, changed time or commitment, another key id.
func TestVerifyRecordSignature_EveryFieldIsBound(t *testing.T) {
	s := testRecordSigner(t, 7)
	key, _ := recordKeyOf(s)
	f := validRecordFields()
	sig, err := signRecord(context.Background(), s, key, f)
	if err != nil {
		t.Fatal(err)
	}
	f.keyID = key.id
	changes := map[string]func(f *recordFields){
		"chain":        func(f *recordFields) { f.chainID = "auth.0123456789abcdef0123456789abcdef" },
		"entry id":     func(f *recordFields) { f.entryID = "sink-" + strings.Repeat("1", 32) },
		"entry type":   func(f *recordFields) { f.entryType = EntryTypeErasure },
		"sequence":     func(f *recordFields) { f.globalSeq++ },
		"previous":     func(f *recordFields) { f.prevHash = strings.Repeat("01", 64) },
		"timestamp":    func(f *recordFields) { f.timestamp = f.timestamp.Add(time.Microsecond) },
		"content hash": func(f *recordFields) { f.contentHash = strings.Repeat("cd", 64) },
		"key id":       func(f *recordFields) { f.keyID = strings.Repeat("0", 32) },
	}
	for name, change := range changes {
		g := f
		change(&g)
		if err := verifyRecordSignature(key.pub, g, sig); err == nil {
			t.Errorf("a signature verified for the record with its %s changed", name)
		}
	}
	other, _ := recordKeyOf(testRecordSigner(t, 8))
	if err := verifyRecordSignature(other.pub, f, sig); err == nil {
		t.Error("verified under another key")
	}
	if err := verifyRecordSignature(key.pub, f, sig[:len(sig)-1]); err == nil ||
		!strings.Contains(err.Error(), "3308 bytes, want 3309") {
		t.Errorf("a truncated signature: %v; want the size named", err)
	}
}

// Signers that misbehave, to show signRecord never returns what it cannot
// verify.
type fakeRecordSigner struct {
	pub  crypto.PublicKey
	sign func(msg []byte) ([]byte, error)
	n    int
}

func (f *fakeRecordSigner) Public() crypto.PublicKey { return f.pub }
func (f *fakeRecordSigner) SignRecord(_ context.Context, msg []byte) ([]byte, error) {
	f.n++
	return f.sign(msg)
}

type notMarshalable struct{}

func TestSignRecord_RefusesWhatItCannotVerify(t *testing.T) {
	real := testRecordSigner(t, 7)
	key, _ := recordKeyOf(real)
	other := testRecordSigner(t, 8)
	cases := map[string]func(msg []byte) ([]byte, error){
		"garbage of the right length": func([]byte) ([]byte, error) { return make([]byte, anchor.SignatureSize), nil },
		"wrong length":                func([]byte) ([]byte, error) { return make([]byte, 10), nil },
		"another key's signature": func(msg []byte) ([]byte, error) {
			return other.SignRecord(context.Background(), msg)
		},
		"an error": func([]byte) ([]byte, error) { return nil, errors.New("kms: quota") },
	}
	for name, sign := range cases {
		t.Run(name, func(t *testing.T) {
			f := &fakeRecordSigner{pub: real.Public(), sign: sign}
			if sig, err := signRecord(context.Background(), f, key, validRecordFields()); err == nil {
				t.Fatalf("returned an unverifiable signature (%d bytes)", len(sig))
			}
		})
	}
}

func TestRecordKeyOf_Refuses(t *testing.T) {
	cases := map[string]RecordSigner{
		"nil signer":              nil,
		"key not marshalable":     &fakeRecordSigner{pub: notMarshalable{}},
		"marshal fails":           &fakeRecordSigner{pub: failingKey{}},
		"typed nil via pointer":   (*MLDSA65RecordSigner)(nil),
		"typed nil, another type": (*fakeRecordSigner)(nil),
		"zero-value signer":       &MLDSA65RecordSigner{},
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := recordKeyOf(s); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	// A wrong-size key is named as such, before any key id is derived.
	_, err := recordKeyOf(&fakeRecordSigner{pub: mustPublicKey(t, make([]byte, 32))})
	if err == nil || !strings.Contains(err.Error(), "32 bytes, want 1952") {
		t.Fatalf("err = %v; want the size named", err)
	}
}

// mustPublicKey wraps raw bytes as a BinaryMarshaler public key.
func mustPublicKey(t *testing.T, raw []byte) crypto.PublicKey {
	t.Helper()
	return rawKey(raw)
}

type failingKey struct{}

func (failingKey) MarshalBinary() ([]byte, error) { return nil, errors.New("hsm: unavailable") }

type rawKey []byte

func (r rawKey) MarshalBinary() ([]byte, error) { return append([]byte(nil), r...), nil }

// TestSignRecord_InvalidFieldsNeverReachTheSigner: the envelope is checked
// first, so a remote signer is never asked to sign something invalid.
func TestSignRecord_InvalidFieldsNeverReachTheSigner(t *testing.T) {
	real := testRecordSigner(t, 7)
	key, _ := recordKeyOf(real)
	f := &fakeRecordSigner{pub: real.Public(), sign: func(msg []byte) ([]byte, error) {
		return real.SignRecord(context.Background(), msg)
	}}
	bad := validRecordFields()
	bad.entryType = "tombstone"
	if _, err := signRecord(context.Background(), f, key, bad); err == nil {
		t.Fatal("signed an invalid record")
	}
	if f.n != 0 {
		t.Fatal("the signer was called for an invalid record")
	}
}

// TestSignRecord_KeyChangedUnderneath: a signer whose key differs from the one
// derived at the start (a KMS rotated mid-batch) is refused: the signature
// would name a key that did not make it.
func TestSignRecord_KeyChangedUnderneath(t *testing.T) {
	a := testRecordSigner(t, 7)
	key, _ := recordKeyOf(a)
	b := testRecordSigner(t, 8)
	if _, err := signRecord(context.Background(), b, key, validRecordFields()); err == nil {
		t.Fatal("a signature by another key was accepted under the first key's id")
	}
}

func TestMLDSA65RecordSigner(t *testing.T) {
	if _, err := NewMLDSA65RecordSigner(make([]byte, 31)); err == nil {
		t.Fatal("a 31-byte seed was accepted")
	}
	s := testRecordSigner(t, 7)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.SignRecord(ctx, []byte("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context: %v", err)
	}
	//lint:ignore SA1012 a nil context must be refused, not panic
	if _, err := s.SignRecord(nil, []byte("x")); err == nil { //nolint:staticcheck
		t.Fatal("signed with a nil context")
	}
	key, _ := recordKeyOf(s)
	// A signer that ignores its context: signRecord itself must refuse nil.
	careless := &fakeRecordSigner{pub: s.Public(), sign: func(msg []byte) ([]byte, error) {
		return s.SignRecord(context.Background(), msg)
	}}
	//lint:ignore SA1012 as above
	if _, err := signRecord(nil, careless, key, validRecordFields()); err == nil { //nolint:staticcheck
		t.Fatal("signRecord accepted a nil context")
	}
	s.Close()
	if _, err := s.SignRecord(context.Background(), []byte("x")); !errors.Is(err, anchor.ErrSignerClosed) {
		t.Fatalf("after Close: %v", err)
	}
	if _, err := recordKeyOf(s); err != nil {
		t.Fatalf("the public identity should survive Close: %v", err)
	}
}

// TestRecordSignatureIsNotAnAnchorSignature: the same key signing an anchor and
// a record never produces interchangeable signatures (the domains differ).
func TestRecordSignatureIsNotAnAnchorSignature(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	as, err := anchor.NewMLDSA65Signer(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer as.Close()
	rs := testRecordSigner(t, 7)
	key, _ := recordKeyOf(rs)
	f := validRecordFields()
	f.keyID = key.id
	env, _ := recordEnvelope(f)
	if env[0] == '{' {
		t.Fatal("an envelope could be read as an anchor's canonical JSON")
	}
	anchorSig, err := as.SignContext(context.Background(), []byte(`{"subject":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyRecordSignature(key.pub, f, anchorSig); err == nil {
		t.Fatal("an anchor signature verified as a record signature")
	}
}

// TestZeroValueRecordSignerDoesNotPanic: a signer not made by the constructor
// errors instead of panicking (library code never panics).
func TestZeroValueRecordSignerDoesNotPanic(t *testing.T) {
	var z MLDSA65RecordSigner
	if z.Public() != nil {
		t.Fatal("a zero-value signer reported a key")
	}
	if _, err := z.SignRecord(context.Background(), []byte("x")); err == nil {
		t.Fatal("a zero-value signer signed")
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestVerifyRecordSignature_KeyMustBeTheNamedKey: a key other than the one the
// record names is refused before any signature check, so a key source that
// returns the wrong key can never make the report name the wrong signer.
func TestVerifyRecordSignature_KeyMustBeTheNamedKey(t *testing.T) {
	a := testRecordSigner(t, 7)
	ka, _ := recordKeyOf(a)
	kb, _ := recordKeyOf(testRecordSigner(t, 8))
	f := validRecordFields()
	sig, err := signRecord(context.Background(), a, ka, f)
	if err != nil {
		t.Fatal(err)
	}
	f.keyID = ka.id
	if err := verifyRecordSignature(kb.pub, f, sig); err == nil || !strings.Contains(err.Error(), "not the signing key") {
		t.Fatalf("err = %v; want the key mismatch named", err)
	}
}

// TestRecordSignature_Regression: the pinned deterministic signature of the
// "event" vector by the seed-0x07 key is reproduced, and verifies. Not an
// independent vector (see the fixture's comment): it pins proof's signer.
func TestRecordSignature_Regression(t *testing.T) {
	file := loadRecordVectors(t)
	reg := file.Regression
	var env []byte
	for _, v := range file.Vectors {
		if v.Name == reg.Vector {
			env, _ = hex.DecodeString(v.Hex)
		}
	}
	seed, _ := hex.DecodeString(reg.SeedHex)
	s, err := NewMLDSA65RecordSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	key, _ := recordKeyOf(s)
	if hex.EncodeToString(key.pub) != reg.PublicHex {
		t.Fatal("the seed no longer derives the pinned public key")
	}
	sig, err := s.SignRecord(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(sig) != reg.SigHex {
		t.Fatal("the signature of the pinned envelope changed")
	}
	if err := verifyRecordEnvelope(key.pub, env, sig); err != nil {
		t.Fatal(err)
	}
}
