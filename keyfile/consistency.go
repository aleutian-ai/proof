// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package keyfile

import (
	"bytes"
	"crypto/mlkem"
	"crypto/sha3"
	"fmt"
)

// CheckConsistency verifies a "both"-form private key's seed against its
// expanded key.
//
// # Description
//
// RFC 9935 §6: "When receiving a private key that contains both the seed and
// the expandedKey, the recipient SHOULD perform a seed consistency check" and,
// if the check is done and they disagree, "MUST reject the private key as
// malformed". [ParsePrivateKey] calls this for every both-form key.
//
// What is verified, for ML-KEM, from the expanded decapsulation key's layout
// (FIPS 203: dk = dk_PKE ‖ ek ‖ H(ek) ‖ z):
//
//	z            must equal the second half of the seed (the seed is d ‖ z)
//	H(ek)        must equal SHA3-256 of the embedded encapsulation key
//	ek           must equal the encapsulation key derived from the seed —
//	             ML-KEM-768 and ML-KEM-1024 only, since crypto/mlkem
//	             implements those two
//
// Not verified: dk_PKE, the secret vector, which cannot be derived without an
// ML-KEM implementation this package deliberately does not carry. That is
// safe here because only the SEED is ever returned and used; the expanded half
// is discarded after this check.
//
// Known gap, stated precisely: for ML-KEM-512 an expanded key that belongs to a
// DIFFERENT key pair yet is internally consistent — its z matching the seed and
// its embedded H(ek) matching its embedded ek — passes these checks. RFC 9935
// C.4.1 example 1 is exactly such a key, and this package accepts it. Only
// re-deriving ek from the seed detects it, which the standard library supports
// for ML-KEM-768 and ML-KEM-1024 but not 512. The same damage IS rejected for
// those two sets.
//
// ML-DSA is not checked at all: deriving its expanded key requires an ML-DSA
// implementation, which would pull a dependency into a package whose value is
// having none. The seed is still the only thing used.
//
// # Inputs
//
//   - alg: the key's algorithm
//   - seed: the seed half, already length-checked
//   - expanded: the expanded half, already length-checked
//
// # Outputs
//
//   - error: ErrInconsistentKey if a check fails; nil if all checks pass or
//     none apply to this algorithm
//
// # Example
//
//	if err := keyfile.CheckConsistency(alg, seed, expanded); err != nil {
//	    return err
//	}
//
// # Limitations
//
//   - Partial for ML-KEM-512 (no derivation available) and absent for ML-DSA;
//     see above for why that is sound.
//
// # Assumptions
//
//   - Lengths were validated by the caller.
func CheckConsistency(alg Algorithm, seed, expanded []byte) error {
	info, ok := algorithms[alg]
	if !ok || info.mlkemK == 0 {
		return nil // ML-DSA and X-Wing: nothing this package can check
	}
	if len(seed) != info.seedSize || len(expanded) != info.expandedSize {
		return fmt.Errorf("%w: wrong field sizes", ErrMalformed)
	}

	// FIPS 203 layout of the expanded decapsulation key.
	dkPKELen := 384 * info.mlkemK
	ekLen := 384*info.mlkemK + 32
	ek := expanded[dkPKELen : dkPKELen+ekLen]
	hek := expanded[dkPKELen+ekLen : dkPKELen+ekLen+32]
	z := expanded[len(expanded)-32:]

	if !bytes.Equal(z, seed[32:]) {
		return fmt.Errorf("%w: %s implicit rejection secret z differs from the seed", ErrInconsistentKey, info.name)
	}
	if got := sha3.Sum256(ek); !bytes.Equal(got[:], hek) {
		return fmt.Errorf("%w: %s embedded public key hash does not match the embedded public key",
			ErrInconsistentKey, info.name)
	}

	derived, err := deriveMLKEMPublic(alg, seed)
	if err != nil {
		return err
	}
	if derived == nil {
		return nil // ML-KEM-512: no derivation available here
	}
	if !bytes.Equal(derived, ek) {
		return fmt.Errorf("%w: %s public key derived from the seed does not match the expanded key",
			ErrInconsistentKey, info.name)
	}
	return nil
}

// deriveMLKEMPublic derives the encapsulation key from a seed, for the ML-KEM
// parameter sets the standard library implements.
//
// # Outputs
//
//   - []byte: the encapsulation key, or nil when this package cannot derive it
//     (ML-KEM-512)
//   - error: ErrInconsistentKey if the seed is rejected by crypto/mlkem
func deriveMLKEMPublic(alg Algorithm, seed []byte) ([]byte, error) {
	switch alg {
	case MLKEM768:
		dk, err := mlkem.NewDecapsulationKey768(seed)
		if err != nil {
			return nil, fmt.Errorf("%w: seed rejected: %v", ErrInconsistentKey, err)
		}
		return dk.EncapsulationKey().Bytes(), nil
	case MLKEM1024:
		dk, err := mlkem.NewDecapsulationKey1024(seed)
		if err != nil {
			return nil, fmt.Errorf("%w: seed rejected: %v", ErrInconsistentKey, err)
		}
		return dk.EncapsulationKey().Bytes(), nil
	default:
		return nil, nil
	}
}
