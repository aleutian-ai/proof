// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package mlkem encapsulates and decapsulates with ML-KEM-768 and ML-KEM-1024.
//
// # Description
//
// Pure ML-KEM (FIPS 203), with no classical component. Keys are handled as
// 64-byte SEEDS — the d ‖ z form RFC 9935 recommends and
// [github.com/aleutian-ai/proof/keyfile] reads and writes.
//
// # X-Wing remains the default; this exists for CNSA 2.0
//
// [github.com/aleutian-ai/proof/xwing] pairs ML-KEM-768 with X25519 so the
// shared secret survives a break of EITHER primitive. Pure ML-KEM gives that
// hedge up: break ML-KEM and nothing is left. Prefer X-Wing.
//
// This package exists because NSA's CNSA 2.0 requires ML-KEM-1024 for national
// security systems, and X-Wing cannot satisfy it — X-Wing is fixed at
// ML-KEM-768, and X25519 is not an approved key-establishment scheme.
//
// ML-KEM-512 is absent deliberately: it is not in Go's standard library, and at
// NIST category 1 it is weaker than the signatures this module pairs with keys.
//
// # Limitations
//
//   - Encapsulation is randomised, with no derandomised variant, so NIST's
//     encapsulation test vectors cannot be run through this API.
//   - Decapsulating a ciphertext made for another key returns a DIFFERENT
//     shared secret and no error. That is ML-KEM's implicit rejection, not a
//     bug; a mismatch surfaces when the secret fails to authenticate data.
//
// # Assumptions
//
//   - Callers zeroize seeds and shared secrets when finished.
package mlkem

import (
	"crypto/mlkem"
	"fmt"
	"io"
	"log/slog"

	"github.com/aleutian-ai/proof/internal/mem"
)

// sentinelError is the type of this package's sentinel errors. Constants, so
// nothing in the process can reassign one and turn a rejected key into an
// accepted one.
type sentinelError string

// Error implements the error interface.
func (e sentinelError) Error() string { return string(e) }

// Errors returned by this package. Compare with errors.Is.
const (
	// ErrUnsupportedParameterSet means the ParameterSet is not ML-KEM-768 or
	// ML-KEM-1024.
	ErrUnsupportedParameterSet sentinelError = "mlkem: unsupported parameter set"

	// ErrInvalidKey means a seed or encapsulation key was rejected.
	ErrInvalidKey sentinelError = "mlkem: invalid key"

	// ErrInvalidCiphertext means the ciphertext has the wrong length.
	ErrInvalidCiphertext sentinelError = "mlkem: invalid ciphertext"

	// errSerializeSecret is returned by every serialization method on
	// SharedSecret.
	errSerializeSecret sentinelError = "mlkem: refusing to serialize secret key material"
)

// ParameterSet selects an ML-KEM security level.
type ParameterSet int

// The two parameter sets this package implements.
const (
	// MLKEM768 is NIST category 3 — the level X-Wing uses internally.
	MLKEM768 ParameterSet = iota + 1

	// MLKEM1024 is NIST category 5, required by NSA CNSA 2.0.
	MLKEM1024
)

// SharedSecret is a 32-byte ML-KEM shared secret, suitable as an AES-256 key.
//
// It redacts under every fmt verb except %p and refuses json, text, and gob
// serialization, matching xwing.SharedSecret. See that type for why %p cannot
// be covered.
type SharedSecret [32]byte

// Zeroize overwrites the shared secret with zeros.
//
// # Description
//
// Best-effort: call it as soon as the secret is no longer needed. Use a pointer
// receiver so the value itself is cleared, not a copy.
//
// # Example
//
//	ss, ct, err := mlkem.Encapsulate(mlkem.MLKEM1024, pub)
//	if err != nil {
//	    return err
//	}
//	defer ss.Zeroize()
//
// # Limitations
//
//   - Cannot defeat a moving garbage collector or pages already swapped out.
//
// # Assumptions
//
//   - The caller has exclusive access; not safe for concurrent use.
func (ss *SharedSecret) Zeroize() { mem.Zeroize(ss[:]) }

// String returns a redacted placeholder.
func (ss SharedSecret) String() string { return "[REDACTED SharedSecret]" }

// GoString returns a redacted placeholder.
func (ss SharedSecret) GoString() string { return "[REDACTED SharedSecret]" }

// Format implements fmt.Formatter so every verb except %p redacts; without it
// %d and %x print the secret.
func (ss SharedSecret) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "[REDACTED SharedSecret]")
}

// MarshalJSON refuses: an accidental serialization should fail, not ship.
func (ss SharedSecret) MarshalJSON() ([]byte, error) { return nil, errSerializeSecret }

// MarshalText refuses, closing the encoding.TextMarshaler path.
func (ss SharedSecret) MarshalText() ([]byte, error) { return nil, errSerializeSecret }

// GobEncode refuses, closing encoding/gob.
func (ss SharedSecret) GobEncode() ([]byte, error) { return nil, errSerializeSecret }

// LogValue implements slog.LogValuer so slog logs the placeholder rather than a
// serialization error.
func (ss SharedSecret) LogValue() slog.Value { return slog.StringValue("[REDACTED SharedSecret]") }

// String returns the standard name, such as "ML-KEM-1024".
//
// # Description
//
// The name FIPS 203 uses, for errors, logs, and key files.
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
//	fmt.Println(mlkem.MLKEM768) // ML-KEM-768
//
// # Limitations
//
//   - Not a parser.
//
// # Assumptions
//
//   - None.
func (s ParameterSet) String() string {
	switch s {
	case MLKEM768:
		return "ML-KEM-768"
	case MLKEM1024:
		return "ML-KEM-1024"
	default:
		return "unknown"
	}
}

// SeedSize returns the seed length in bytes, 64 for both sets.
//
// # Description
//
// The seed is d ‖ z, the form RFC 9935 recommends storing.
//
// # Inputs
//
//   - receiver: any ParameterSet
//
// # Outputs
//
//   - int: 64, or 0 for an unknown set
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
	case MLKEM768, MLKEM1024:
		return 64
	default:
		return 0
	}
}

// PublicKeySize returns the encapsulation key length in bytes.
//
// # Description
//
// 1184 for ML-KEM-768 and 1568 for ML-KEM-1024, per FIPS 203. A test derives a
// real key and checks these against it.
//
// # Inputs
//
//   - receiver: any ParameterSet
//
// # Outputs
//
//   - int: 1184 or 1568; 0 for an unknown set
//
// # Example
//
//	pub := make([]byte, mlkem.MLKEM1024.PublicKeySize())
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
	case MLKEM768:
		return 1184
	case MLKEM1024:
		return 1568
	default:
		return 0
	}
}

// CiphertextSize returns the ciphertext length in bytes.
//
// # Description
//
// 1088 for ML-KEM-768 and 1568 for ML-KEM-1024, per FIPS 203.
//
// # Inputs
//
//   - receiver: any ParameterSet
//
// # Outputs
//
//   - int: 1088 or 1568; 0 for an unknown set
//
// # Example
//
//	if len(ct) != set.CiphertextSize() { return ErrInvalidCiphertext }
//
// # Limitations
//
//   - Size only; a correctly sized ciphertext can still decapsulate to an
//     unrelated secret (implicit rejection).
//
// # Assumptions
//
//   - None.
func (s ParameterSet) CiphertextSize() int {
	switch s {
	case MLKEM768:
		return 1088
	case MLKEM1024:
		return 1568
	default:
		return 0
	}
}

// PublicKeyFromSeed derives the encapsulation key for a seed.
//
// # Description
//
// Needed wherever a key must be identified rather than used: generating a key
// pair, computing a key id, or checking a key file against a recorded public
// key.
//
// # Inputs
//
//   - set: the parameter set
//   - seed: exactly 64 bytes, d ‖ z
//
// # Outputs
//
//   - []byte: the encapsulation key, set.PublicKeySize() bytes
//   - error: ErrUnsupportedParameterSet or ErrInvalidKey
//
// # Example
//
//	pub, err := mlkem.PublicKeyFromSeed(mlkem.MLKEM1024, seed)
//
// # Limitations
//
//   - Derivation is not free; cache the result.
//
// # Assumptions
//
//   - seed came from a secure generator or a key file.
func PublicKeyFromSeed(set ParameterSet, seed []byte) ([]byte, error) {
	if err := checkSeed(set, seed); err != nil {
		return nil, err
	}
	switch set {
	case MLKEM768:
		dk, err := mlkem.NewDecapsulationKey768(seed)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		return dk.EncapsulationKey().Bytes(), nil
	case MLKEM1024:
		dk, err := mlkem.NewDecapsulationKey1024(seed)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		return dk.EncapsulationKey().Bytes(), nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedParameterSet, int(set))
	}
}

// Encapsulate generates a shared secret and the ciphertext carrying it.
//
// # Description
//
// Randomised, drawing from crypto/rand. Send the ciphertext to the holder of
// the matching decapsulation key; keep the shared secret.
//
// # Inputs
//
//   - set: the parameter set the public key belongs to
//   - pub: exactly set.PublicKeySize() bytes
//
// # Outputs
//
//   - []byte: the ciphertext, set.CiphertextSize() bytes
//   - SharedSecret: the secret; call Zeroize when done
//   - error: ErrUnsupportedParameterSet or ErrInvalidKey
//
// # Example
//
//	ct, ss, err := mlkem.Encapsulate(mlkem.MLKEM1024, pub)
//	if err != nil {
//	    return err
//	}
//	defer ss.Zeroize()
//
// # Limitations
//
//   - No derandomised variant, so NIST's encapsulation vectors cannot be run
//     through this function.
//
// # Assumptions
//
//   - pub is the intended recipient's key; ML-KEM does not authenticate it.
func Encapsulate(set ParameterSet, pub []byte) ([]byte, SharedSecret, error) {
	var ss SharedSecret
	if set.PublicKeySize() == 0 {
		return nil, ss, fmt.Errorf("%w: %d", ErrUnsupportedParameterSet, int(set))
	}
	if len(pub) != set.PublicKeySize() {
		return nil, ss, fmt.Errorf("%w: %s public key must be %d bytes, got %d",
			ErrInvalidKey, set, set.PublicKeySize(), len(pub))
	}

	var shared, ct []byte
	switch set {
	case MLKEM768:
		ek, err := mlkem.NewEncapsulationKey768(pub)
		if err != nil {
			return nil, ss, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		shared, ct = ek.Encapsulate()
	case MLKEM1024:
		ek, err := mlkem.NewEncapsulationKey1024(pub)
		if err != nil {
			return nil, ss, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		shared, ct = ek.Encapsulate()
	default:
		return nil, ss, fmt.Errorf("%w: %d", ErrUnsupportedParameterSet, int(set))
	}
	defer mem.Zeroize(shared)
	copy(ss[:], shared)
	return ct, ss, nil
}

// Decapsulate recovers the shared secret from a ciphertext.
//
// # Description
//
// A ciphertext made for a DIFFERENT key does not produce an error: ML-KEM's
// implicit rejection returns an unrelated secret instead. The mismatch surfaces
// when that secret fails to authenticate data, never as a distinguishable error
// here.
//
// # Inputs
//
//   - set: the parameter set the key belongs to
//   - seed: exactly 64 bytes
//   - ct: exactly set.CiphertextSize() bytes
//
// # Outputs
//
//   - SharedSecret: the secret; call Zeroize when done
//   - error: ErrUnsupportedParameterSet, ErrInvalidKey, or ErrInvalidCiphertext
//
// # Example
//
//	ss, err := mlkem.Decapsulate(mlkem.MLKEM1024, seed, ct)
//
// # Limitations
//
//   - Cannot distinguish a wrong key from a corrupted ciphertext, by design.
//
// # Assumptions
//
//   - The caller authenticates whatever the shared secret protects.
func Decapsulate(set ParameterSet, seed, ct []byte) (SharedSecret, error) {
	var ss SharedSecret
	if err := checkSeed(set, seed); err != nil {
		return ss, err
	}
	if len(ct) != set.CiphertextSize() {
		return ss, fmt.Errorf("%w: %s ciphertext must be %d bytes, got %d",
			ErrInvalidCiphertext, set, set.CiphertextSize(), len(ct))
	}

	var shared []byte
	var err error
	switch set {
	case MLKEM768:
		var dk *mlkem.DecapsulationKey768
		if dk, err = mlkem.NewDecapsulationKey768(seed); err != nil {
			return ss, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		shared, err = dk.Decapsulate(ct)
	case MLKEM1024:
		var dk *mlkem.DecapsulationKey1024
		if dk, err = mlkem.NewDecapsulationKey1024(seed); err != nil {
			return ss, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		shared, err = dk.Decapsulate(ct)
	default:
		return ss, fmt.Errorf("%w: %d", ErrUnsupportedParameterSet, int(set))
	}
	if err != nil {
		return ss, fmt.Errorf("%w: %v", ErrInvalidCiphertext, err)
	}
	defer mem.Zeroize(shared)
	copy(ss[:], shared)
	return ss, nil
}

// checkSeed validates the parameter set and seed length.
//
// # Outputs
//
//   - error: ErrUnsupportedParameterSet or ErrInvalidKey
func checkSeed(set ParameterSet, seed []byte) error {
	if set.SeedSize() == 0 {
		return fmt.Errorf("%w: %d", ErrUnsupportedParameterSet, int(set))
	}
	if len(seed) != set.SeedSize() {
		return fmt.Errorf("%w: %s seed must be %d bytes, got %d",
			ErrInvalidKey, set, set.SeedSize(), len(seed))
	}
	return nil
}
