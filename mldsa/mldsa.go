// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package mldsa signs and verifies with ML-DSA-44, ML-DSA-65, and ML-DSA-87.
//
// # Description
//
// One place for all three FIPS 204 parameter sets, so callers choose a level
// instead of importing a different package per level. Keys are handled as
// SEEDS: 32 bytes from which the signing key and public key are derived, which
// is the form [github.com/aleutian-ai/proof/keyfile] reads and writes.
//
// Signatures use an EMPTY context string — "pure" ML-DSA per FIPS 204 §5.3 —
// matching what [github.com/aleutian-ai/proof/anchor] has always verified.
//
// Signing is DETERMINISTIC: the same seed and message always produce the same
// signature. FIPS 204 permits both; deterministic removes a dependence on the
// caller's random source and makes signatures reproducible in tests and audits.
//
// # Limitations
//
//   - No context strings. Adding one later is an API addition, but signatures
//     made with a context do not verify without it, so this is a format choice.
//   - Seed residue cannot be fully eliminated. This package zeroizes every
//     buffer it owns, but circl's key objects keep their own copy of the seed
//     and the expanded key and expose no way to wipe them, so a copy survives
//     until the garbage collector reclaims it.
//   - Backed by github.com/cloudflare/circl: ML-DSA is not in Go's standard
//     library, so unlike the KEM this is outside Go's FIPS 140-3 module.
//
// # Assumptions
//
//   - Callers zeroize seeds when finished.
package mldsa

import (
	"fmt"

	"github.com/aleutian-ai/proof/internal/mem"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// sentinelError is the type of this package's sentinel errors. Constants, so
// no code can reassign one and turn a rejected signature into an accepted one.
type sentinelError string

// Error implements the error interface.
func (e sentinelError) Error() string { return string(e) }

// Errors returned by this package. Compare with errors.Is.
const (
	// ErrUnsupportedParameterSet means the ParameterSet is not one of the three
	// FIPS 204 sets.
	ErrUnsupportedParameterSet sentinelError = "mldsa: unsupported parameter set"

	// ErrInvalidKey means a seed or public key has the wrong length.
	ErrInvalidKey sentinelError = "mldsa: invalid key"

	// ErrInvalidSignature means the signature is malformed or does not verify.
	// One error covers both: distinguishing them tells an attacker which half
	// of their guess was right.
	ErrInvalidSignature sentinelError = "mldsa: invalid signature"
)

// ParameterSet selects an ML-DSA security level.
type ParameterSet int

// The three FIPS 204 parameter sets. NIST security categories 2, 3, and 5.
const (
	// MLDSA44 is NIST category 2. Used by transparency-log checkpoint
	// cosignatures (C2SP), where signature size matters most.
	MLDSA44 ParameterSet = iota + 1

	// MLDSA65 is NIST category 3 and this module's default — it matches the
	// security level of ML-KEM-768, which X-Wing uses.
	MLDSA65

	// MLDSA87 is NIST category 5, required by NSA CNSA 2.0 for national
	// security systems.
	MLDSA87
)

// String returns the standard name, such as "ML-DSA-65".
//
// # Description
//
// The name FIPS 204 uses, so it can appear in errors, logs, and key files
// without a translation table.
//
// # Inputs
//
//   - receiver: any ParameterSet, including an invalid one
//
// # Outputs
//
//   - string: the standard name, or "unknown"
//
// # Example
//
//	fmt.Println(mldsa.MLDSA65) // ML-DSA-65
//
// # Limitations
//
//   - Not a parser; there is no reverse mapping here.
//
// # Assumptions
//
//   - None.
func (s ParameterSet) String() string {
	switch s {
	case MLDSA44:
		return "ML-DSA-44"
	case MLDSA65:
		return "ML-DSA-65"
	case MLDSA87:
		return "ML-DSA-87"
	default:
		return "unknown"
	}
}

// SeedSize returns the seed length in bytes, which is 32 for every set.
//
// # Description
//
// All three parameter sets derive from a 32-byte seed, so this exists for
// symmetry with the other size accessors and to validate inputs without
// special-casing the set.
//
// # Inputs
//
//   - receiver: any ParameterSet
//
// # Outputs
//
//   - int: 32, or 0 for an unknown set — callers use 0 to detect an invalid set
//
// # Example
//
//	if len(seed) != set.SeedSize() { return ErrInvalidKey }
//
// # Limitations
//
//   - Returns 0 rather than an error; the zero is the signal.
//
// # Assumptions
//
//   - None.
func (s ParameterSet) SeedSize() int {
	switch s {
	case MLDSA44, MLDSA65, MLDSA87:
		return 32
	default:
		return 0
	}
}

// PublicKeySize returns the public key length in bytes.
//
// # Description
//
// Taken from circl's constants rather than hard-coded, so the two can never
// disagree. A test pins them to the FIPS 204 values.
//
// # Inputs
//
//   - receiver: any ParameterSet
//
// # Outputs
//
//   - int: 1312, 1952, or 2592; 0 for an unknown set
//
// # Example
//
//	pub := make([]byte, mldsa.MLDSA87.PublicKeySize())
//
// # Limitations
//
//   - Size only; says nothing about whether a key is well-formed.
//
// # Assumptions
//
//   - None.
func (s ParameterSet) PublicKeySize() int {
	switch s {
	case MLDSA44:
		return mldsa44.PublicKeySize
	case MLDSA65:
		return mldsa65.PublicKeySize
	case MLDSA87:
		return mldsa87.PublicKeySize
	default:
		return 0
	}
}

// SignatureSize returns the signature length in bytes.
//
// # Description
//
// ML-DSA signatures are fixed-length per parameter set. Useful for sizing
// buffers and for rejecting an obviously wrong signature before verifying.
//
// # Inputs
//
//   - receiver: any ParameterSet
//
// # Outputs
//
//   - int: 2420, 3309, or 4627; 0 for an unknown set
//
// # Example
//
//	if len(sig) != set.SignatureSize() { return ErrInvalidSignature }
//
// # Limitations
//
//   - Size only; a correctly sized signature can still be invalid.
//
// # Assumptions
//
//   - None.
func (s ParameterSet) SignatureSize() int {
	switch s {
	case MLDSA44:
		return mldsa44.SignatureSize
	case MLDSA65:
		return mldsa65.SignatureSize
	case MLDSA87:
		return mldsa87.SignatureSize
	default:
		return 0
	}
}

// PublicKeyFromSeed derives the public key for a seed.
//
// # Description
//
// Needed wherever a key must be identified rather than used: generating a key
// pair, computing a key id, or checking that a key file's seed matches a
// recorded public key.
//
// # Inputs
//
//   - set: the parameter set
//   - seed: exactly 32 bytes
//
// # Outputs
//
//   - []byte: the public key, set.PublicKeySize() bytes
//   - error: ErrUnsupportedParameterSet or ErrInvalidKey
//
// # Example
//
//	pub, err := mldsa.PublicKeyFromSeed(mldsa.MLDSA65, seed)
//
// # Limitations
//
//   - Derivation is not free; cache the result rather than recomputing it.
//
// # Assumptions
//
//   - seed came from a secure generator or a key file.
func PublicKeyFromSeed(set ParameterSet, seed []byte) ([]byte, error) {
	s, err := seedArray(set, seed)
	if err != nil {
		return nil, err
	}
	defer mem.Zeroize(s[:])

	switch set {
	case MLDSA44:
		pub, _ := mldsa44.NewKeyFromSeed(s)
		return pub.Bytes(), nil
	case MLDSA65:
		pub, _ := mldsa65.NewKeyFromSeed(s)
		return pub.Bytes(), nil
	case MLDSA87:
		pub, _ := mldsa87.NewKeyFromSeed(s)
		return pub.Bytes(), nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedParameterSet, int(set))
	}
}

// Sign produces a deterministic signature over msg.
//
// # Description
//
// Pure ML-DSA with an empty context string, deterministic per FIPS 204. The
// same seed and message always yield the same signature.
//
// # Inputs
//
//   - set: the parameter set
//   - seed: exactly 32 bytes
//   - msg: the message; may be empty
//
// # Outputs
//
//   - []byte: the signature, set.SignatureSize() bytes
//   - error: ErrUnsupportedParameterSet, ErrInvalidKey, or a signing failure
//
// # Example
//
//	sig, err := mldsa.Sign(mldsa.MLDSA65, seed, canonicalBytes)
//
// # Limitations
//
//   - No context string; see the package documentation.
//   - msg is signed as-is. Hashing or canonicalizing it is the caller's job.
//
// # Assumptions
//
//   - The caller has already decided what the signature is over.
func Sign(set ParameterSet, seed, msg []byte) ([]byte, error) {
	s, err := seedArray(set, seed)
	if err != nil {
		return nil, err
	}
	defer mem.Zeroize(s[:])

	sig := make([]byte, set.SignatureSize())
	switch set {
	case MLDSA44:
		_, priv := mldsa44.NewKeyFromSeed(s)
		err = mldsa44.SignTo(priv, msg, nil, false, sig)
	case MLDSA65:
		_, priv := mldsa65.NewKeyFromSeed(s)
		err = mldsa65.SignTo(priv, msg, nil, false, sig)
	case MLDSA87:
		_, priv := mldsa87.NewKeyFromSeed(s)
		err = mldsa87.SignTo(priv, msg, nil, false, sig)
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedParameterSet, int(set))
	}
	if err != nil {
		return nil, fmt.Errorf("mldsa: sign: %w", err)
	}
	return sig, nil
}

// Verify reports whether sig is a valid signature over msg under pub.
//
// # Description
//
// Returns nil when the signature verifies and ErrInvalidSignature otherwise.
// An error rather than a bool so that ignoring the result is a visible mistake
// rather than an invisible one.
//
// The parameter set comes from the CALLER, who knows which key this is — never
// from the signature or from a length. A verifier that inferred it would let an
// attacker choose the weakest set.
//
// # Inputs
//
//   - set: the parameter set the public key belongs to
//   - pub: exactly set.PublicKeySize() bytes
//   - msg: the message the signature should cover
//   - sig: the signature
//
// # Outputs
//
//   - error: nil if valid; ErrUnsupportedParameterSet, ErrInvalidKey, or
//     ErrInvalidSignature
//
// # Example
//
//	if err := mldsa.Verify(mldsa.MLDSA65, pub, msg, sig); err != nil {
//	    return err
//	}
//
// # Limitations
//
//   - A signature made under a different parameter set never verifies here,
//     by construction.
//
// # Assumptions
//
//   - pub is trusted: this says the holder of its key signed msg, nothing about
//     whether that key should be trusted.
func Verify(set ParameterSet, pub, msg, sig []byte) error {
	if set.PublicKeySize() == 0 {
		return fmt.Errorf("%w: %d", ErrUnsupportedParameterSet, int(set))
	}
	if len(pub) != set.PublicKeySize() {
		return fmt.Errorf("%w: %s public key must be %d bytes, got %d",
			ErrInvalidKey, set, set.PublicKeySize(), len(pub))
	}
	if len(sig) != set.SignatureSize() {
		return ErrInvalidSignature
	}

	var ok bool
	switch set {
	case MLDSA44:
		var p mldsa44.PublicKey
		if err := p.UnmarshalBinary(pub); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		ok = mldsa44.Verify(&p, msg, nil, sig)
	case MLDSA65:
		var p mldsa65.PublicKey
		if err := p.UnmarshalBinary(pub); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		ok = mldsa65.Verify(&p, msg, nil, sig)
	default:
		var p mldsa87.PublicKey
		if err := p.UnmarshalBinary(pub); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		ok = mldsa87.Verify(&p, msg, nil, sig)
	}
	if !ok {
		return ErrInvalidSignature
	}
	return nil
}

// seedArray validates a seed and copies it into the fixed-size array circl
// requires.
//
// # Outputs
//
//   - *[32]byte: the seed
//   - error: ErrUnsupportedParameterSet or ErrInvalidKey
func seedArray(set ParameterSet, seed []byte) (*[32]byte, error) {
	if set.SeedSize() == 0 {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedParameterSet, int(set))
	}
	if len(seed) != set.SeedSize() {
		return nil, fmt.Errorf("%w: %s seed must be %d bytes, got %d",
			ErrInvalidKey, set, set.SeedSize(), len(seed))
	}
	var out [32]byte
	copy(out[:], seed)
	return &out, nil
}
