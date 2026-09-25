// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package xwing

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha3"
	"fmt"
	"io"
	"log/slog"

	"github.com/aleutian-ai/proof/internal/mem"
)

// label is the 6-byte XWING domain separator per IETF draft-connolly-cfrg-xwing-kem §5.3.
// ASCII: concat("\./", "/^\") — the X-Wing emoticon \././^\
// Hex: 5c 2e 2f 2f 5e 5c
// This value is fixed by the specification — do not modify.
var label = []byte{0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c}

// sentinelError is the type of this package's sentinel errors.
//
// It exists so the sentinels can be CONSTANTS. A sentinel declared as
// `var ErrX = errors.New(...)` can be reassigned by any package in the process,
// including to nil — and every function here returns a sentinel on invalid
// input, so a nil sentinel would turn "invalid key" into a success: Encapsulate
// would return a zero ciphertext, an all-zero shared secret, and a nil error.
// A constant cannot be reassigned and cannot be nil, so these functions fail
// closed unconditionally.
//
// The type is unexported, which keeps it out of the API surface; it does NOT
// stop a caller building an equal value from a string of that type. What the
// constants guarantee is narrower and is the one that matters: the sentinels
// themselves cannot be reassigned or set to nil. It is a comparable string type,
// so errors.Is matches both a bare sentinel and one wrapped with %w.
type sentinelError string

// Error implements the error interface.
func (e sentinelError) Error() string { return string(e) }

// Sentinel errors returned by XWING functions on invalid input.
//
// ErrInvalidPublicKey is returned when an PublicKey has wrong field lengths.
// ErrInvalidPrivateKey is returned when a private key seed has wrong length.
// ErrInvalidCiphertext is returned when an Ciphertext has wrong field lengths.
//
// These are constants, not variables — see sentinelError. Compare with
// errors.Is, or with == against an unwrapped error.
const (
	ErrInvalidPublicKey  sentinelError = "xwing: invalid public key"
	ErrInvalidPrivateKey sentinelError = "xwing: invalid private key"
	ErrInvalidCiphertext sentinelError = "xwing: invalid ciphertext"
)

func init() {
	if mlkem.CiphertextSize768 != 1088 {
		panic("xwing: mlkem.CiphertextSize768 changed; expected 1088")
	}
	if mlkem.EncapsulationKeySize768 != 1184 {
		panic("xwing: mlkem.EncapsulationKeySize768 changed; expected 1184")
	}
	if mlkem.SharedKeySize != 32 {
		panic("xwing: mlkem.SharedKeySize changed; expected 32")
	}
	if mlkem.SeedSize != 64 {
		panic("xwing: mlkem.SeedSize changed; expected 64")
	}
}

// basepointMul derives the X25519 public key for a 32-byte scalar.
//
// Scalar clamping per RFC 7748 §5 is applied by crypto/ecdh, matching the
// clamping x/crypto/curve25519 applied before it.
//
// # Outputs
//
//   - []byte: 32-byte X25519 public key
//   - error: wrapped, if the scalar is rejected (e.g. all zero). Never panics.
func basepointMul(scalar []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		return nil, fmt.Errorf("xwing: x25519 scalar: %w", err)
	}
	return priv.PublicKey().Bytes(), nil
}

// dh performs X25519 Diffie-Hellman, returning 32 ZERO BYTES when peer is a
// low-order point rather than failing.
//
// # Description
//
// This is REQUIRED by draft-connolly-cfrg-xwing-kem §4.2 and is not a
// convenience: ML-KEM-768 supplies independent post-quantum security, so the
// combined secret stays safe even when the X25519 half degenerates. An
// implementation that rejects low-order points is not X-Wing — it would refuse
// ciphertexts a conforming peer can legitimately produce.
//
// crypto/ecdh reports the all-zero result as an error, so the substitution is
// deliberate here. Peer length is validated by every caller before this runs, so
// a low-order point is the only reachable error. Do NOT add a reject-zero check.
//
// # Outputs
//
//   - []byte: 32-byte shared secret, or 32 zero bytes for a low-order peer
//   - error: only for a rejected local scalar; never for the peer point
func dh(scalar, peer []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(scalar)
	if err != nil {
		return nil, fmt.Errorf("xwing: x25519 scalar: %w", err)
	}
	// NewPublicKey only length-checks an X25519 point, so this branch is
	// defensive — callers validate the 32-byte length before calling. Substitute
	// rather than fail so a future stricter parser cannot break §4.2 conformance.
	pub, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return make([]byte, 32), nil
	}
	// THIS is where §4.2 is enforced: crypto/ecdh reports a low-order peer as
	// "bad X25519 remote ECDH input: low order point". Verified by mutation test —
	// removing this substitution fails TestEncapsulateLowOrderX25519PointDoesNotFail
	// and TestDecapsulateLowOrderCiphertextDoesNotFail.
	shared, err := priv.ECDH(pub)
	if err != nil {
		return make([]byte, 32), nil
	}
	return shared, nil
}

// PublicKey is the XWING recipient public key.
//
// The canonical binary encoding (MarshalBinary) is MLKEMPub ‖ X25519Pub = 1216 bytes.
// This matches the spec wire order: pk = concat(pk_M, pk_X).
// MLKEMPub is 1184 bytes (mlkem.EncapsulationKeySize768); X25519Pub is 32 bytes.
// Store and transmit only the canonical form; reconstruct with UnmarshalPublicKey.
type PublicKey struct {
	X25519Pub []byte // 32 bytes — X25519 recipient public key (pk_X)
	MLKEMPub  []byte // 1184 bytes — ML-KEM-768 encapsulation key (pk_M)
}

// PrivateKey is the XWING private key.
//
// The canonical form is a single 32-byte seed. Key material is derived via
// expandDecapsulationKey (SHAKE256 expansion to 96 bytes) at use time, per
// IETF draft-connolly-cfrg-xwing-kem §5.2.
//
// Callers MUST defer priv.Zeroize() immediately after obtaining this value.
type PrivateKey struct {
	Seed [32]byte // 32-byte master seed — SHAKE256-expanded to derive ML-KEM seed + X25519 scalar
}

// Ciphertext holds both components of the XWING encapsulation output.
//
// Total size: 1120 bytes. Wire format (spec): ct = concat(ct_M, ct_X).
// MLKEMCT is 1088 bytes (mlkem.CiphertextSize768, ct_M in the spec);
// X25519EPK is 32 bytes (the X25519 ephemeral public key, ct_X in the spec).
type Ciphertext struct {
	MLKEMCT   []byte // 1088 bytes — ML-KEM-768 ciphertext (ct_M); first in wire format
	X25519EPK []byte // 32 bytes — X25519 ephemeral public key (ct_X); second in wire format
}

// SharedSecret is the 32-byte XWING shared secret output.
//
// Fixed-size array prevents slice aliasing and accidental truncation.
// This value is used directly as an AES-256-GCM key.
// Callers MUST call Zeroize after all cryptographic use is complete.
type SharedSecret [32]byte

// MarshalBinary returns the canonical 1216-byte XWING public key encoding.
//
// # Description
//
// Concatenates MLKEMPub (1184 bytes) and X25519Pub (32 bytes) in spec wire order:
// pk = concat(pk_M, pk_X). This canonical form is used for storage in Secret
// Manager and for the the caller WrappedKeyV3 wire format.
// Reconstruct with UnmarshalPublicKey.
//
// # Inputs
//
//   - receiver: PublicKey produced by GenerateKeyPair, PublicKey, or UnmarshalPublicKey
//
// # Outputs
//
//   - []byte: 1216-byte canonical encoding (MLKEMPub ‖ X25519Pub)
//   - error: ErrInvalidPublicKey if MLKEMPub is not 1184 bytes or X25519Pub is not 32 bytes
//
// # Example
//
//	pub, _, err := GenerateKeyPair()
//	if err != nil {
//	    return err
//	}
//	encoded, err := pub.MarshalBinary()
//	if err != nil {
//	    return err
//	}
//	// Store encoded (1216 bytes) in a key store.
//
// # Limitations
//
//   - Allocates a new 1216-byte slice on every call; does not pool.
//
// # Assumptions
//
//   - pub was produced by GenerateKeyPair, PublicKey, or UnmarshalPublicKey
func (pub PublicKey) MarshalBinary() ([]byte, error) {
	if len(pub.MLKEMPub) != mlkem.EncapsulationKeySize768 || len(pub.X25519Pub) != 32 {
		return nil, ErrInvalidPublicKey
	}
	out := make([]byte, 0, 1216)
	out = append(out, pub.MLKEMPub...)  // pk_M first (1184 bytes)
	out = append(out, pub.X25519Pub...) // pk_X second (32 bytes)
	return out, nil
}

// UnmarshalPublicKey parses a 1216-byte canonical XWING public key encoding.
//
// # Description
//
// Splits the canonical form pk = concat(pk_M, pk_X) into struct fields. The first
// 1184 bytes become MLKEMPub; the last 32 bytes become X25519Pub. The returned
// slices are independent copies of data — callers may freely modify data after
// unmarshaling.
//
// # Inputs
//
//   - data: Exactly 1216 bytes in canonical form (output of MarshalBinary)
//
// # Outputs
//
//   - PublicKey: Populated key with independent copies of pk_M and pk_X
//   - error: ErrInvalidPublicKey if len(data) != 1216
//
// # Example
//
//	pub, err := UnmarshalPublicKey(storedBytes)
//	if err != nil {
//	    return err
//	}
//
// # Limitations
//
//   - Allocates 1216 bytes for the copies.
//
// # Assumptions
//
//   - data is the output of PublicKey.MarshalBinary, not an arbitrary byte slice
func UnmarshalPublicKey(data []byte) (PublicKey, error) {
	if len(data) != 1216 {
		return PublicKey{}, ErrInvalidPublicKey
	}
	mlkemPub := make([]byte, mlkem.EncapsulationKeySize768)
	x25519Pub := make([]byte, 32)
	copy(mlkemPub, data[:1184])  // pk_M is first 1184 bytes
	copy(x25519Pub, data[1184:]) // pk_X is last 32 bytes
	return PublicKey{
		MLKEMPub:  mlkemPub,
		X25519Pub: x25519Pub,
	}, nil
}

// NewPrivateKey constructs an PrivateKey from a 32-byte seed slice.
//
// # Description
//
// Copies the seed into the fixed-size Seed field. The seed is the canonical
// XWING private key per IETF draft-connolly-cfrg-xwing-kem §5.2.
//
// # Inputs
//
//   - seed: Exactly 32 bytes — the XWING decapsulation key seed
//
// # Outputs
//
//   - PrivateKey: Key with Seed populated
//   - error: ErrInvalidPrivateKey if len(seed) != 32
//
// # Example
//
//	priv, err := NewPrivateKey(seedBytes)
//	if err != nil {
//	    return err
//	}
//	defer priv.Zeroize()
//
// # Limitations
//
//   - Any 32 bytes is a valid seed; there is no structural validation beyond length.
//
// # Assumptions
//
//   - seed was produced by GenerateKeyPair or loaded from a secure key store
func NewPrivateKey(seed []byte) (PrivateKey, error) {
	if len(seed) != 32 {
		return PrivateKey{}, ErrInvalidPrivateKey
	}
	var priv PrivateKey
	copy(priv.Seed[:], seed)
	return priv, nil
}

// expandDecapsulationKey expands a 32-byte seed via SHAKE256 to derive
// the ML-KEM-768 seed (d‖z, 64 bytes) and X25519 private scalar (32 bytes).
//
// Per IETF draft-connolly-cfrg-xwing-kem §5.2:
//
//	expanded = SHAKE256(sk, 96)
//	mlkem_d  = expanded[0:32]
//	mlkem_z  = expanded[32:64]
//	x25519   = expanded[64:96]
//
// Callers MUST defer Zeroize on the returned arrays.
func expandDecapsulationKey(seed [32]byte) (mlkemSeed [64]byte, x25519Priv [32]byte) {
	h := sha3.NewSHAKE256()
	h.Write(seed[:])
	var expanded [96]byte
	_, _ = h.Read(expanded[:])
	copy(mlkemSeed[:], expanded[:64])
	copy(x25519Priv[:], expanded[64:96])
	mem.Zeroize(expanded[:])
	return
}

// GenerateKeyPair generates a new XWING key pair from cryptographically
// secure random bytes.
//
// # Description
//
// Generates a 32-byte random seed, then derives the full key pair via SHAKE256
// expansion per IETF draft-connolly-cfrg-xwing-kem §5.2:
//  1. Generate 32 random bytes as the private key seed.
//  2. Expand via SHAKE256 to 96 bytes: ML-KEM seed (d‖z, 64B) + X25519 scalar (32B).
//  3. Derive ML-KEM-768 public key from seed.
//  4. Derive X25519 public key from scalar × basepoint.
//
// # Outputs
//
//   - PublicKey: Recipient public key (1216 bytes canonical: MLKEMPub ‖ X25519Pub)
//   - PrivateKey: Private key (32-byte seed)
//   - error: Non-nil if crypto/rand is unavailable or ML-KEM key generation fails
//
// # Example
//
//	pub, priv, err := GenerateKeyPair()
//	if err != nil {
//	    return err
//	}
//	defer priv.Zeroize()
//
// # Limitations
//
//   - Entropy source is crypto/rand; there is no seeded deterministic variant for
//     production use. KAT testing uses a test-file-only helper.
//
// # Assumptions
//
//   - crypto/rand.Reader is available and returns cryptographically secure bytes
func GenerateKeyPair() (PublicKey, PrivateKey, error) {
	var seed [32]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return PublicKey{}, PrivateKey{}, fmt.Errorf("xwing: generate seed: %w", err)
	}
	priv := PrivateKey{Seed: seed}
	mem.Zeroize(seed[:]) // priv.Seed has its own copy (value type)

	pub, err := priv.PublicKey()
	if err != nil {
		priv.Zeroize()
		return PublicKey{}, PrivateKey{}, err
	}
	return pub, priv, nil
}

// PublicKey derives the XWING public key from the private key seed.
//
// # Description
//
// Expands the 32-byte seed via SHAKE256, then derives both the ML-KEM-768
// encapsulation key and the X25519 public key. Expanded material is zeroized
// after use.
//
// # Outputs
//
//   - PublicKey: The corresponding public key
//   - error: Non-nil if ML-KEM key reconstruction fails
//
// # Example
//
//	pub, err := priv.PublicKey()
//	if err != nil {
//	    return err
//	}
//
// # Limitations
//
//   - Performs SHAKE256 expansion + ML-KEM key reconstruction on every call.
//     Cache the result if called multiple times.
//
// # Assumptions
//
//   - priv was produced by GenerateKeyPair or NewPrivateKey
func (priv *PrivateKey) PublicKey() (PublicKey, error) {
	mlkemSeed, x25519Priv := expandDecapsulationKey(priv.Seed)
	defer mem.Zeroize(mlkemSeed[:])
	defer mem.Zeroize(x25519Priv[:])

	x25519Pub, err := basepointMul(x25519Priv[:])
	if err != nil {
		return PublicKey{}, fmt.Errorf("xwing: derive x25519 public key: %w", err)
	}
	dk, err := mlkem.NewDecapsulationKey768(mlkemSeed[:])
	if err != nil {
		return PublicKey{}, fmt.Errorf("xwing: reconstruct mlkem key: %w", err)
	}
	return PublicKey{
		MLKEMPub:  dk.EncapsulationKey().Bytes(),
		X25519Pub: x25519Pub,
	}, nil
}

// Encapsulate generates a shared secret and its encapsulation for the given
// recipient public key.
//
// # Description
//
// Implements XWING encapsulation per IETF draft-connolly-cfrg-xwing-kem §5.4:
//  1. Generate a fresh 32-byte ephemeral X25519 scalar from crypto/rand.
//  2. Derive ephemeral public key (ct_X): X25519(eph, basepoint).
//  3. Compute X25519 DH shared component (ss_X): X25519(eph, pk_X).
//  4. Encapsulate with ML-KEM-768: (ss_M, ct_M) = ek.Encapsulate().
//  5. Combine: ss = SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel).
//
// The returned SharedSecret is used directly as an AES-256-GCM key.
// Callers MUST defer ss.Zeroize() immediately after this call returns.
//
// X25519 low-order point inputs (which produce an all-zero ss_X) do NOT cause an
// error. Per §4.2 of the XWING draft, security holds regardless because ML-KEM-768
// provides independent post-quantum security. Do not add a reject-zero check.
//
// # Inputs
//
//   - pub: XWING recipient public key; X25519Pub must be 32 bytes, MLKEMPub must be 1184 bytes
//
// # Outputs
//
//   - Ciphertext: Encapsulation output (1120 bytes: MLKEMCT ‖ X25519EPK)
//   - SharedSecret: 32-byte shared secret; use as AES-256-GCM key then Zeroize
//   - error: ErrInvalidPublicKey if field lengths are wrong; wrapped error on entropy failure
//
// # Example
//
//	ct, ss, err := Encapsulate(pub)
//	if err != nil {
//	    return err
//	}
//	defer ss.Zeroize()
//
// # Limitations
//
//   - The ephemeral key is generated from crypto/rand and cannot be injected externally.
//     KAT testing uses the unexported encapsulateWithEphemeral helper.
//
// # Assumptions
//
//   - pub was produced by GenerateKeyPair, PublicKey, or UnmarshalPublicKey
//   - crypto/rand.Reader is available
func Encapsulate(pub PublicKey) (Ciphertext, SharedSecret, error) {
	var ephPriv [32]byte
	if _, err := io.ReadFull(rand.Reader, ephPriv[:]); err != nil {
		return Ciphertext{}, SharedSecret{}, fmt.Errorf("xwing: generate ephemeral key: %w", err)
	}
	ct, ss, err := encapsulateWithEphemeral(pub, ephPriv)
	mem.Zeroize(ephPriv[:])
	return ct, ss, err
}

// Decapsulate recovers the shared secret from an XWING ciphertext using the
// recipient private key.
//
// # Description
//
// Implements XWING decapsulation per IETF draft-connolly-cfrg-xwing-kem §5.5:
//  1. Expand 32-byte seed via SHAKE256 to derive (sk_M, sk_X, pk_X).
//  2. Compute X25519 DH: ss_X = X25519(sk_X, ct_X).
//  3. Decapsulate ML-KEM-768: ss_M = dk.Decapsulate(ct_M).
//  4. Combine: ss = SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel).
//
// pk_X is derived from the seed at call time and is never stored separately.
//
// ML-KEM-768 uses implicit rejection (FIPS 203 §7.3): Decapsulate with a wrong private
// key returns a pseudorandom value with no error. A wrong-key decapsulation therefore
// produces a different SharedSecret silently — callers cannot distinguish wrong-key from
// correct-key by inspecting the error. Authentication is verified at the AES-GCM tag
// level by the caller.
//
// # Inputs
//
//   - ct: XWING ciphertext from Encapsulate; MLKEMCT must be 1088 bytes, X25519EPK must be 32 bytes
//   - priv: XWING private key (32-byte seed)
//
// # Outputs
//
//   - SharedSecret: 32-byte value; matches encapsulator's SharedSecret iff keys correspond
//   - error: ErrInvalidCiphertext if field lengths are wrong;
//     wrapped error on ML-KEM key reconstruction failure;
//     NO error is returned if the wrong private key is used (implicit rejection)
//
// # Example
//
//	ss, err := Decapsulate(ct, priv)
//	if err != nil {
//	    return err
//	}
//	defer ss.Zeroize()
//
// # Limitations
//
//   - Wrong-key decapsulation is silent: ss is pseudorandom, error is nil
//   - Callers must verify at AES-GCM authentication tag level
//   - ML-KEM expanded decapsulation key (~2400 bytes) is allocated in heap and not
//     explicitly zeroized — Go's crypto/mlkem does not expose a zeroization method.
//     This is a known limitation; the expanded key persists until GC reclaims the pages.
//
// # Assumptions
//
//   - ct was produced by Encapsulate for the public key corresponding to priv
//   - priv was produced by GenerateKeyPair or NewPrivateKey
func Decapsulate(ct Ciphertext, priv PrivateKey) (SharedSecret, error) {
	if len(ct.MLKEMCT) != mlkem.CiphertextSize768 || len(ct.X25519EPK) != 32 {
		return SharedSecret{}, ErrInvalidCiphertext
	}

	mlkemSeed, x25519Priv := expandDecapsulationKey(priv.Seed)
	defer mem.Zeroize(mlkemSeed[:])
	defer mem.Zeroize(x25519Priv[:])

	// X25519 DH — dh() implements the spec §4.2 low-order rule.
	ssX, err := dh(x25519Priv[:], ct.X25519EPK)
	if err != nil {
		return SharedSecret{}, err
	}
	defer mem.Zeroize(ssX)

	// Derive pk_X from private scalar (never stored in PrivateKey)
	pkX, err := basepointMul(x25519Priv[:])
	if err != nil {
		return SharedSecret{}, fmt.Errorf("xwing: derive x25519 public key: %w", err)
	}

	// ML-KEM-768 decapsulate — implicit rejection: wrong key → pseudorandom ss, no error.
	// Note: the expanded dk (~2400 bytes) is not explicitly zeroized; crypto/mlkem does
	// not expose a zeroization method. This is documented in Limitations above.
	dk, err := mlkem.NewDecapsulationKey768(mlkemSeed[:])
	if err != nil {
		return SharedSecret{}, fmt.Errorf("xwing: reconstruct mlkem decapsulation key: %w", err)
	}
	ssM, err := dk.Decapsulate(ct.MLKEMCT)
	if err != nil {
		// Defensive: only reachable if MLKEMCT length is wrong, but we validated above.
		return SharedSecret{}, fmt.Errorf("xwing: mlkem decapsulate: %w", err)
	}
	defer mem.Zeroize(ssM)

	return combine(ssM, ssX, ct.X25519EPK, pkX), nil
}

// Zeroize overwrites the private key seed with zeros.
//
// # Description
//
// Zeroes all 32 bytes of the Seed field, narrowing the window during which
// private key material is accessible in process memory after use.
//
// # Inputs
//
//   - receiver: *PrivateKey to zeroize
//
// # Outputs
//
//   - None.
//
// # Example
//
//	_, priv, err := GenerateKeyPair()
//	if err != nil {
//	    return err
//	}
//	defer priv.Zeroize()
//	// ... use priv ...
//
// # Limitations
//
//   - Go does not support mlock(2) without cgo; pages may be swapped before Zeroize is called.
//   - Defense-in-depth only; not a cryptographic guarantee.
//
// # Assumptions
//
//   - Caller has exclusive access to priv (not safe for concurrent use)
func (priv *PrivateKey) Zeroize() {
	mem.Zeroize(priv.Seed[:])
}

// String returns a redacted placeholder to prevent accidental logging of key material.
func (priv PrivateKey) String() string { return "[REDACTED PrivateKey]" }

// GoString returns a redacted placeholder to prevent accidental logging of key material.
func (priv PrivateKey) GoString() string { return "[REDACTED PrivateKey]" }

// errSerializeSecret is returned by every serialization method on a secret type.
const errSerializeSecret sentinelError = "xwing: refusing to serialize secret key material"

// Format implements fmt.Formatter so that every verb EXCEPT %p redacts.
//
// String and GoString alone cover %v, %+v, %#v, and %s, but not %d, %x, %X, or
// %q, which print the underlying bytes: %d on a PrivateKey printed the seed.
// Format intercepts those verbs before fmt looks at the value's representation.
//
// Limitation: %p. fmt handles %p before consulting a Formatter, treats it as a
// bad verb for a non-pointer value, and prints that value with method calls
// disabled — so `%p` on a PrivateKey prints the seed, and no method can stop
// it. go vet does not flag it. Never use %p on key material.
//
// Limitation: fmt prints an UNEXPORTED struct field by reflection without
// calling any of its methods, so `struct{ k PrivateKey }` printed with %v still
// shows raw bytes. No method on this type can prevent that; do not store key
// material in unexported fields of values that get logged.
func (priv PrivateKey) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, "[REDACTED PrivateKey]") }

// MarshalJSON refuses: a private key must never be serialized by accident.
//
// An error rather than a redacted placeholder, deliberately. A struct that
// embeds a private key and reaches json.Marshal is a bug; a placeholder would let
// it ship with silent data loss, an error makes it fail at the first test.
func (priv PrivateKey) MarshalJSON() ([]byte, error) { return nil, errSerializeSecret }

// MarshalText refuses, closing the encoding.TextMarshaler path (used by
// encoding/json for map keys, encoding/xml, and many config encoders).
func (priv PrivateKey) MarshalText() ([]byte, error) { return nil, errSerializeSecret }

// GobEncode refuses, closing encoding/gob — which would otherwise serialize the
// exported Seed field by reflection.
func (priv PrivateKey) GobEncode() ([]byte, error) { return nil, errSerializeSecret }

// LogValue implements slog.LogValuer. Without it, slog's handlers fall through
// to MarshalText, which refuses, and log the refusal as an error string; with
// it, slog logs the same placeholder as fmt.
func (priv PrivateKey) LogValue() slog.Value { return slog.StringValue("[REDACTED PrivateKey]") }

// Zeroize overwrites the shared secret with zeros.
//
// # Description
//
// Zeroes all 32 bytes of the SharedSecret array, narrowing the window during which
// the AES-256-GCM key is in process memory. Must be called after the shared secret
// has been used to seal or open an AES-GCM ciphertext after use.
//
// # Inputs
//
//   - receiver: *SharedSecret to zeroize
//
// # Outputs
//
//   - None.
//
// # Example
//
//	ct, ss, err := Encapsulate(pub)
//	if err != nil {
//	    return err
//	}
//	defer ss.Zeroize()
//	// ... use ss as AES-256-GCM key ...
//
// # Limitations
//
//   - SharedSecret is a value type ([32]byte). Call Zeroize on the original variable,
//     not on a copy. `defer ss.Zeroize()` works correctly if ss is addressable.
//
// # Assumptions
//
//   - Caller has exclusive access to ss (not safe for concurrent use)
func (ss *SharedSecret) Zeroize() {
	mem.Zeroize(ss[:])
}

// String returns a redacted placeholder to prevent accidental logging of key material.
func (ss SharedSecret) String() string { return "[REDACTED SharedSecret]" }

// GoString returns a redacted placeholder to prevent accidental logging of key material.
func (ss SharedSecret) GoString() string { return "[REDACTED SharedSecret]" }

// Format implements fmt.Formatter so that every verb except %p redacts,
// including %d and %x, which would otherwise print the secret. See
// PrivateKey.Format for the %p and unexported-field limitations, which apply
// here too.
func (ss SharedSecret) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "[REDACTED SharedSecret]")
}

// MarshalJSON refuses; see PrivateKey.MarshalJSON for why this is an error.
func (ss SharedSecret) MarshalJSON() ([]byte, error) { return nil, errSerializeSecret }

// MarshalText refuses, closing the encoding.TextMarshaler path.
func (ss SharedSecret) MarshalText() ([]byte, error) { return nil, errSerializeSecret }

// GobEncode refuses, closing encoding/gob.
func (ss SharedSecret) GobEncode() ([]byte, error) { return nil, errSerializeSecret }

// LogValue implements slog.LogValuer; see PrivateKey.LogValue.
func (ss SharedSecret) LogValue() slog.Value { return slog.StringValue("[REDACTED SharedSecret]") }

// combine computes the XWING shared secret via the combiner hash.
//
// Per IETF draft-connolly-cfrg-xwing-kem §5.4 (draft-06, label LAST):
//
//	SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)
//
// Field order is fixed by the spec. Do not reorder.
// All inputs must be exactly the specified lengths; panics on violation (unexported,
// defense-in-depth for callers within this package).
func combine(ssM, ssX, ctX, pkX []byte) SharedSecret {
	if len(ssM) != 32 || len(ssX) != 32 || len(ctX) != 32 || len(pkX) != 32 {
		panic("xwing: combine called with wrong-length inputs")
	}
	h := sha3.New256()
	h.Write(ssM)
	h.Write(ssX)
	h.Write(ctX)
	h.Write(pkX)
	h.Write(label) // label LAST per draft-06
	var ss SharedSecret
	h.Sum(ss[:0])
	return ss
}

// encapsulateWithEphemeral runs XWING encapsulation with a caller-supplied
// ephemeral X25519 private scalar instead of generating one from crypto/rand.
//
// This is the core encapsulation implementation. Production callers use Encapsulate
// which generates ephPriv randomly. This function is unexported and used only by
// Encapsulate and KAT tests in xwing_test.go.
func encapsulateWithEphemeral(pub PublicKey, ephPriv [32]byte) (Ciphertext, SharedSecret, error) {
	if len(pub.MLKEMPub) != mlkem.EncapsulationKeySize768 || len(pub.X25519Pub) != 32 {
		return Ciphertext{}, SharedSecret{}, ErrInvalidPublicKey
	}

	x25519EPK, err := basepointMul(ephPriv[:])
	if err != nil {
		return Ciphertext{}, SharedSecret{}, fmt.Errorf("xwing: derive ephemeral public key: %w", err)
	}

	// X25519 DH — dh() implements the spec §4.2 low-order rule.
	ssX, err := dh(ephPriv[:], pub.X25519Pub)
	if err != nil {
		return Ciphertext{}, SharedSecret{}, err
	}
	defer mem.Zeroize(ssX)

	ek, err := mlkem.NewEncapsulationKey768(pub.MLKEMPub)
	if err != nil {
		return Ciphertext{}, SharedSecret{}, fmt.Errorf("xwing: parse mlkem public key: %w", err)
	}
	ssM, mlkemCT := ek.Encapsulate()
	defer mem.Zeroize(ssM)

	ct := Ciphertext{MLKEMCT: mlkemCT, X25519EPK: x25519EPK}
	ss := combine(ssM, ssX, x25519EPK, pub.X25519Pub)

	// Zeroize ephemeral private scalar (the copy in this stack frame).
	mem.Zeroize(ephPriv[:])

	return ct, ss, nil
}
