// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"context"
	"crypto"
	"encoding"
	"errors"
	"fmt"
	"reflect"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/mldsa"
)

// RecordSigner signs sink records: one ML-DSA-65 signature per record, over
// its aleutian.proof.record.v1 envelope.
//
// # Description
//
// A type of its own rather than anchor.ContextSigner, although the shape is
// the same. The record key and the checkpoint key are different roles: the
// record key is online in the writer and used for every record, the
// checkpoint key is used rarely and can be kept elsewhere. A distinct type
// means one cannot be passed where the other is expected by accident.
//
// Where the private key lives (in memory from a key file, Cloud KMS, an HSM,
// another secret manager) is the implementation's business. This package
// provides [MLDSA65RecordSigner]; a Cloud KMS example is planned (ticket _75e).
//
// There is no KeyID method: the key id is DERIVED from Public(), so a
// signature can never name a key that did not make it.
//
// # Example
//
//	s, err := sink.NewMLDSA65RecordSigner(seed)
//	if err != nil {
//	    return err
//	}
//	defer s.Close()
//
// # Limitations
//
//   - ML-DSA-65 only.
//
// # Assumptions
//
//   - Implementations are safe for concurrent use: records are signed in
//     parallel.
//   - Public() returns a value implementing encoding.BinaryMarshaler whose
//     bytes are the raw ML-DSA-65 public key (1952 bytes).
//   - SignRecord signs its input as given, with the empty ML-DSA context: the
//     envelope already carries its domain. Never a digest of it.
//   - SignRecord honours ctx: the sink waits for every call it started, while
//     holding the sink's files, so a call that ignores cancellation holds them
//     too. Callers of the sink should pass a context with a deadline.
//   - Its errors do not quote the envelope: they may be logged, and Commit
//     redacts chain ids only where they appear as text.
//   - The returned slice may be reused by the signer: the sink copies it.
type RecordSigner interface {
	// Public returns the ML-DSA-65 public key; see the Assumptions.
	Public() crypto.PublicKey

	// SignRecord signs envelope, the whole message. It must abort if ctx is
	// cancelled before the signature is produced.
	SignRecord(ctx context.Context, envelope []byte) ([]byte, error)
}

// MLDSA65RecordSigner is a RecordSigner holding an ML-DSA-65 key in memory.
//
// # Description
//
// It wraps anchor.MLDSA65Signer, so the key handling (seed copied, zeroized on
// Close, deterministic signing) is the one already reviewed for checkpoints,
// behind the record-signing type.
//
// # Example
//
//	alg, seed, err := keyfile.ParsePrivateKey(pem)
//	s, err := sink.NewMLDSA65RecordSigner(seed)
//	defer s.Close()
//
// # Limitations
//
//   - The key is in process memory for the signer's lifetime, and each
//     signature leaves derived key material on the heap; see
//     anchor.MLDSA65Signer.
//
// # Assumptions
//
//   - Safe for concurrent use.
type MLDSA65RecordSigner struct {
	inner *anchor.MLDSA65Signer
}

// NewMLDSA65RecordSigner builds a record signer from a 32-byte ML-DSA-65 seed.
//
// # Description
//
// The seed is copied; the caller may zeroize its own buffer immediately.
//
// # Inputs
//
//   - seed: exactly 32 bytes, as keyfile.ParsePrivateKey returns for an
//     ML-DSA-65 key
//
// # Outputs
//
//   - *MLDSA65RecordSigner: ready to sign
//   - error: the seed is the wrong length, or key derivation failed
//
// # Example
//
//	s, err := sink.NewMLDSA65RecordSigner(seed)
//	if err != nil {
//	    return err
//	}
//	defer s.Close()
//
// # Limitations
//
//   - ML-DSA-65 only.
//
// # Assumptions
//
//   - seed came from a cryptographically secure source.
func NewMLDSA65RecordSigner(seed []byte) (*MLDSA65RecordSigner, error) {
	inner, err := anchor.NewMLDSA65Signer(seed)
	if err != nil {
		return nil, fmt.Errorf("sink: record signer: %w", err)
	}
	return &MLDSA65RecordSigner{inner: inner}, nil
}

// Public returns the ML-DSA-65 public key.
//
// # Description
//
// Implements [RecordSigner]. The value is an *anchor.PublicKey, whose
// MarshalBinary returns the raw key.
//
// # Outputs
//
//   - crypto.PublicKey: a copy of the key
//
// # Example
//
//	raw, err := s.Public().(encoding.BinaryMarshaler).MarshalBinary()
//
// # Limitations
//
//   - Copies on every call.
//
// # Assumptions
//
//   - None. It survives Close: the public identity is not secret.
func (s *MLDSA65RecordSigner) Public() crypto.PublicKey {
	if s == nil || s.inner == nil {
		return nil // recordKeyOf refuses it
	}
	return s.inner.Public()
}

// SignRecord signs one record envelope.
//
// # Description
//
// Implements [RecordSigner]. Signing is deterministic, with the empty ML-DSA
// context. The sink verifies every signature it is given before storing it,
// so a faulted signature never reaches the file.
//
// # Inputs
//
//   - ctx: cancelled before the call means no signature
//   - envelope: the whole aleutian.proof.record.v1 envelope
//
// # Outputs
//
//   - []byte: 3309 bytes
//   - error: ctx.Err() (wrapped), anchor.ErrSignerClosed, a zero-value
//     signer or nil ctx, or a signing failure. Not prefixed: the caller
//     (signRecord) adds the context.
//
// # Example
//
//	sig, err := s.SignRecord(ctx, envelope)
//
// # Limitations
//
//   - Cancellation is checked once; an in-memory signature cannot be
//     interrupted.
//
// # Assumptions
//
//   - envelope is already the exact bytes to sign.
func (s *MLDSA65RecordSigner) SignRecord(ctx context.Context, envelope []byte) ([]byte, error) {
	if s == nil || s.inner == nil {
		return nil, errors.New("record signer was not made by NewMLDSA65RecordSigner")
	}
	if ctx == nil {
		return nil, errors.New("record signer: a context is required")
	}
	return s.inner.SignContext(ctx, envelope)
}

// Close zeroizes the key and makes the signer refuse to sign.
//
// # Description
//
// Idempotent. The public key survives.
//
// # Outputs
//
//   - error: always nil; present for io.Closer
//
// # Example
//
//	defer s.Close()
//
// # Limitations
//
//   - Does not reach key material earlier signatures left on the heap.
//
// # Assumptions
//
//   - None.
func (s *MLDSA65RecordSigner) Close() error {
	if s == nil || s.inner == nil {
		return nil
	}
	return s.inner.Close()
}

// recordKey is a record signer's public identity, derived once per call so
// every record of the call names the same key.
type recordKey struct {
	id  string // 32 lowercase hex: keyfile.KeyIDHex(ML-DSA-65, pub)
	pub []byte // raw ML-DSA-65 public key
}

// recordKeyOf derives s's key id from its public key. Once per call: for a
// remote signer, Public may cost a round trip, or change across a rotation.
func recordKeyOf(s RecordSigner) (recordKey, error) {
	if s == nil {
		return recordKey{}, errors.New("sink: a record signer is required")
	}
	if v := reflect.ValueOf(s); v.Kind() == reflect.Pointer && v.IsNil() {
		return recordKey{}, errors.New("sink: a record signer is required (got a nil pointer)")
	}
	pk := s.Public()
	m, ok := pk.(encoding.BinaryMarshaler)
	if !ok {
		return recordKey{}, fmt.Errorf("sink: record signer's public key (%T) cannot be read as bytes", pk)
	}
	pub, err := m.MarshalBinary()
	if err != nil {
		return recordKey{}, fmt.Errorf("sink: read the record signer's public key: %w", err)
	}
	if len(pub) != anchor.PublicKeySize {
		return recordKey{}, fmt.Errorf("sink: record signer's public key is %d bytes, want %d (ML-DSA-65)",
			len(pub), anchor.PublicKeySize)
	}
	id, err := keyfile.KeyIDHex(keyfile.MLDSA65, pub)
	if err != nil {
		return recordKey{}, fmt.Errorf("sink: derive the record key id: %w", err)
	}
	return recordKey{id: id, pub: bytes.Clone(pub)}, nil
}

// signRecord signs f's envelope with s under key (key.id goes into the
// envelope; f.keyID is ignored), and returns the signature only after
// verifying it under key.pub. So a faulted signature, one by another key (a
// signer rotated underneath), or a signer's garbage is refused, never stored.
// Invalid fields are refused before the signer is called.
func signRecord(ctx context.Context, s RecordSigner, key recordKey, f recordFields) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("sink: sign record: a context is required")
	}
	f.keyID = key.id
	env, err := recordEnvelope(f)
	if err != nil {
		return nil, err
	}
	sig, err := s.SignRecord(ctx, env)
	if err != nil {
		return nil, fmt.Errorf("sink: sign record: %w", err)
	}
	// Our own copy: a signer that reuses its buffer must not change the bytes
	// after they were verified.
	sig = bytes.Clone(sig)
	if err := verifyRecordEnvelope(key.pub, env, sig); err != nil {
		return nil, fmt.Errorf("sink: the record signer returned a signature that does not verify "+
			"under its key %s: %w", key.id, err)
	}
	return sig, nil
}

// verifyRecordSignature checks sig over f's envelope under pub, and that pub is
// the key f.keyID names: a key source handing back another key than the id
// asked for can never make a report name the wrong key. The one verification
// Commit's self-check and Verify both use, so they cannot drift. Record.v1 is
// ML-DSA-65 only; nothing here reads an algorithm from the file.
func verifyRecordSignature(pub []byte, f recordFields, sig []byte) error {
	id, err := keyfile.KeyIDHex(keyfile.MLDSA65, pub)
	if err != nil {
		return fmt.Errorf("record key: %w", err)
	}
	if id != f.keyID {
		return fmt.Errorf("the key given is %s, not the signing key %s the record names", id, f.keyID)
	}
	env, err := recordEnvelope(f)
	if err != nil {
		return err
	}
	return verifyRecordEnvelope(pub, env, sig)
}

func verifyRecordEnvelope(pub, env, sig []byte) error {
	if len(sig) != anchor.SignatureSize {
		return fmt.Errorf("signature is %d bytes, want %d", len(sig), anchor.SignatureSize)
	}
	if err := mldsa.Verify(mldsa.MLDSA65, pub, env, sig); err != nil {
		return fmt.Errorf("signature does not verify: %w", err)
	}
	return nil
}
