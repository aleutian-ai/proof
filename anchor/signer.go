// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"context"
	"crypto"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"

	"github.com/aleutian-ai/proof/internal/mem"
	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/mldsa"
)

// Errors returned by the signing path. Compare with errors.Is.
var (
	// ErrSignerClosed means Close has been called and the seed is gone.
	ErrSignerClosed = errors.New("anchor: signer is closed")

	// ErrPreHashed means a caller asked for a signature over a digest. ML-DSA
	// signs the message and hashes internally (FIPS 204 §5.3); signing a digest
	// produces a signature over the wrong bytes that is structurally perfect.
	//
	// A courtesy, not the control: it can only fire on this package's own
	// signer. The control for a signer this package did not write is
	// ErrSignerProducedBadSignature.
	ErrPreHashed = errors.New("anchor: ML-DSA signs the message, not a digest")

	// ErrSignerProducedBadSignature means a signer returned a signature that
	// does not verify under its own public key. See SignCanonical.
	ErrSignerProducedBadSignature = errors.New("anchor: signer produced a signature that does not verify under its own public key")

	// ErrKeyIDMissing means canonical bytes carry an empty signing_key_id.
	// Signing them produces an anchor that can never verify: signing_key_id is
	// INSIDE the signed form, so populating it afterwards changes the bytes.
	ErrKeyIDMissing = errors.New("anchor: canonical bytes carry an empty signing_key_id")
)

// ContextSigner produces anchor signatures and honours a context.
//
// # Description
//
// The extension point for producing anchors. Cloud KMS, an HSM, a PKCS#11
// token, a keychain or 1Password all belong on the caller's side of this
// interface; this package ships exactly one implementation, the in-memory
// [MLDSA65Signer], and never reaches for a credential of any kind.
//
// Sign through [SignAnchor]. It is the only entry point that cannot be used in
// the wrong order — see its documentation for why that matters.
//
// # Compatibility with crypto.Signer
//
// Deliberately NOT embedded here. Nothing in this package calls a
// crypto.Signer's Sign method, so embedding it would oblige every KMS or
// PKCS#11 implementer to write one whose rand and opts are meaningless for
// ML-DSA and which would never be invoked.
//
// The equivalence is real, and lives where it costs nothing:
//
//   - OUTBOUND — [MLDSA65Signer] IS a crypto.Signer, enforced by a compile-time
//     assertion in this file, so it drops into anything expecting one: x509
//     certificate signing, go-tuf, sigstore, your own code.
//   - INBOUND — [FromCryptoSigner] adapts any crypto.Signer. That wrapper
//     CANNOT honour a context, so it is an explicit call rather than a silent
//     assertion: a KMS call that hangs while the caller's timeout does nothing
//     is a miserable thing to diagnose, and accepting that belongs where a
//     reader can see it.
//
// # Why there is no KeyID method
//
// The key id is DERIVED from Public() by [KeyIDOf], so it names the key that
// actually holds the private half. A KeyID method would let a rotating KMS
// report one id and sign with another, producing an anchor recording a key that
// did not sign it — unverifiable, with nothing pointing at why.
//
// # Example
//
//	// The in-memory signer, or any implementation of this interface.
//	var s anchor.ContextSigner = mySigner
//	signed, err := anchor.SignAnchor(ctx, s, a)
//
// # Limitations
//
//   - ML-DSA-65 only. [VerifySignature] is hardcoded to its sizes and the
//     anchor format carries no algorithm identifier yet.
//   - Releasing key material is not part of this interface. An implementation
//     holding a key in memory should also implement io.Closer; consumers should
//     attempt that assertion.
//
// # Assumptions
//
//   - Implementations are safe for concurrent use.
//   - Public() returns a value implementing encoding.BinaryMarshaler whose
//     bytes are the raw ML-DSA-65 public key, exactly [PublicKeySize] long.
//     This is a REQUIREMENT, checked at run time by [KeyIDOf]; both this
//     package's [PublicKey] and circl's satisfy it.
type ContextSigner interface {
	// Public returns the public key. See the Assumptions above: its bytes must
	// be reachable through encoding.BinaryMarshaler.
	Public() crypto.PublicKey

	// SignContext signs msg, which is the WHOLE MESSAGE and never a digest.
	// It must abort if ctx is cancelled before the signature is produced.
	SignContext(ctx context.Context, msg []byte) ([]byte, error)
}

// PublicKey is a raw ML-DSA-65 public key returned by Public.
//
// # Description
//
// A type of this package's own rather than circl's, so no caller has to import
// circl to read a key out of a signer. The bytes come out through
// [PublicKey.MarshalBinary], the stdlib encoding.BinaryMarshaler interface —
// the same route a circl key offers, so code handling either works unchanged.
//
// # Example
//
//	pk := signer.Public().(*anchor.PublicKey)
//	raw, err := pk.MarshalBinary()
//
// # Limitations
//
//   - Equal compares only against another *PublicKey. A circl key holding
//     identical bytes compares false.
//
// # Assumptions
//
//   - Immutable after construction; every accessor returns a copy.
type PublicKey struct {
	raw []byte
}

// MarshalBinary returns a copy of the raw public key bytes.
//
// # Description
//
// Implements encoding.BinaryMarshaler. This is the route [KeyIDOf] uses to get
// bytes out of ANY signer's Public(), which is why it matters that circl
// implements the same interface.
//
// # Outputs
//
//   - []byte: PublicKeySize bytes, a fresh copy
//   - error: if the receiver is nil
//
// # Example
//
//	b, err := pk.MarshalBinary()
//
// # Limitations
//
//   - Copies on every call.
//
// # Assumptions
//
//   - None.
func (p *PublicKey) MarshalBinary() ([]byte, error) {
	if p == nil {
		return nil, errors.New("anchor: nil public key")
	}
	cp := make([]byte, len(p.raw))
	copy(cp, p.raw)
	return cp, nil
}

// Equal reports whether x is the same public key.
//
// # Description
//
// Part of the crypto.PublicKey convention; callers compare keys without
// reaching for the bytes. A public key is not secret, so this does not need to
// be constant time.
//
// # Inputs
//
//   - x: the key to compare against; any type, and a mismatch is false. A
//     typed-nil *PublicKey is a mismatch, not a panic.
//
// # Outputs
//
//   - bool: true when x is a non-nil *PublicKey holding identical bytes
//
// # Example
//
//	if a.Equal(b) { … }
//
// # Limitations
//
//   - Does not compare against circl's key type.
//
// # Assumptions
//
//   - None.
func (p *PublicKey) Equal(x crypto.PublicKey) bool {
	o, ok := x.(*PublicKey)
	if !ok || p == nil || o == nil || len(o.raw) != len(p.raw) {
		return false
	}
	for i := range p.raw {
		if p.raw[i] != o.raw[i] {
			return false
		}
	}
	return true
}

// MLDSA65Signer signs anchors with an in-memory ML-DSA-65 key.
//
// # Description
//
// The only signer this module ships. ML-DSA-65 ONLY: [VerifySignature] is
// hardcoded to ML-DSA-65 sizes and there is no algorithm identifier in the
// anchor format yet, so a 44 or 87 signer would produce anchors this very
// package reports as invalid. Those become reachable once `_32b` adds the
// identifier.
//
// # Example
//
//	s, err := anchor.NewMLDSA65Signer(seed)
//	if err != nil {
//	    return err
//	}
//	defer s.Close()
//	signed, err := anchor.SignAnchor(ctx, s, a)
//
// # Thread Safety
//
// Safe for concurrent use. Close may race with a signature; the loser gets
// ErrSignerClosed rather than a torn read of the seed.
//
// # Limitations
//
//   - Close zeroizes the LONG-LIVED copy of the seed. It cannot promise the key
//     is gone from process memory, and the residue GROWS WITH USE: every
//     signature re-derives a full multi-kilobyte expanded private key inside
//     the mldsa package, which is left to the garbage collector unwiped. After
//     n signatures there may be up to n such copies on the heap, and Close
//     reaches none of them. Close narrows one window; it does not close them
//     all. A caller whose threat model includes heap inspection, core dumps or
//     swap should treat the key as recoverable for the process's lifetime.
//   - Signing is deterministic (FIPS 204 hedged variant disabled), which is the
//     strongest setting for differential fault analysis. [SignAnchor] verifies
//     every signature before returning it, so a faulted signature never
//     escapes; calling Sign directly as a bare crypto.Signer has no such check.
//
// # Assumptions
//
//   - The caller obtained the seed from a trustworthy source. This type does
//     not and cannot judge that.
type MLDSA65Signer struct {
	mu     sync.RWMutex
	seed   []byte
	closed bool

	// pub and keyID are derived once at construction and never change, so they
	// survive Close — a caller can still publish the key it signed with.
	pub   []byte
	keyID string
}

// Compile-time proof of the outbound drop-in equivalence. If either assertion
// stops holding the build fails, rather than the documentation quietly becoming
// false.
var (
	_ crypto.Signer = (*MLDSA65Signer)(nil)
	_ ContextSigner = (*MLDSA65Signer)(nil)
	_ io.Closer     = (*MLDSA65Signer)(nil)
)

// NewMLDSA65Signer builds an in-memory signer from a 32-byte seed.
//
// # Description
//
// Derives the public key and key id once, so every signature this signer
// produces reports the same identity, and so [Close] can drop the seed without
// making the signer unable to say which key it used.
//
// The seed is COPIED. A caller may zeroize its own buffer immediately, which is
// what a caller reading a key file should do.
//
// # Inputs
//
//   - seed: exactly 32 bytes (mldsa.MLDSA65.SeedSize())
//
// # Outputs
//
//   - *MLDSA65Signer: ready to sign
//   - error: if seed is the wrong length, or key derivation fails
//
// # Example
//
//	alg, seed, err := keyfile.ParsePrivateKey(pem)
//	if err != nil {
//	    return err
//	}
//	s, err := anchor.NewMLDSA65Signer(seed)
//	if err != nil {
//	    return err
//	}
//	defer s.Close()
//
// # Limitations
//
//   - ML-DSA-65 only; see the type documentation.
//
// # Assumptions
//
//   - seed came from a cryptographically secure source.
func NewMLDSA65Signer(seed []byte) (*MLDSA65Signer, error) {
	if want := mldsa.MLDSA65.SeedSize(); len(seed) != want {
		// Length only — never echo seed bytes into an error.
		return nil, fmt.Errorf("anchor: seed is %d bytes, want %d (ML-DSA-65)", len(seed), want)
	}

	pub, err := mldsa.PublicKeyFromSeed(mldsa.MLDSA65, seed)
	if err != nil {
		return nil, fmt.Errorf("anchor: derive public key: %w", err)
	}
	if len(pub) != PublicKeySize {
		// Cannot happen with a correct mldsa package; asserted because a
		// wrong-sized key here would fail much later, as an unverifiable anchor.
		return nil, fmt.Errorf("anchor: derived public key is %d bytes, want %d", len(pub), PublicKeySize)
	}

	keyID, err := keyfile.KeyIDHex(keyfile.MLDSA65, pub)
	if err != nil {
		return nil, fmt.Errorf("anchor: derive key id: %w", err)
	}

	cp := make([]byte, len(seed))
	copy(cp, seed)
	return &MLDSA65Signer{seed: cp, pub: pub, keyID: keyID}, nil
}

// KeyID returns the key id this signer's key produces.
//
// # Description
//
// A cached convenience on the concrete type. [KeyIDOf] computes the same value
// for any signer and is what [SignAnchor] uses; this is the fast path for code
// that already holds the concrete type.
//
// It equals keyfile.KeyIDHex(keyfile.MLDSA65, pub), which is the id `proof
// keygen` prints, so an operator never copies hex by hand.
//
// # Outputs
//
//   - string: 32 lowercase hex characters
//
// # Example
//
//	fmt.Println("signing with", s.KeyID())
//
// # Limitations
//
//   - Survives Close, deliberately: the public identity is not secret.
//
// # Assumptions
//
//   - None.
func (s *MLDSA65Signer) KeyID() string { return s.keyID }

// Public returns the ML-DSA-65 public key.
//
// # Description
//
// Implements crypto.Signer and [ContextSigner]. The returned value is a
// *PublicKey, which satisfies encoding.BinaryMarshaler — the route [KeyIDOf]
// uses to derive the key id.
//
// # Outputs
//
//   - crypto.PublicKey: a *PublicKey holding a copy of the key bytes
//
// # Example
//
//	b, err := s.Public().(*anchor.PublicKey).MarshalBinary()
//
// # Limitations
//
//   - Copies on every call.
//
// # Assumptions
//
//   - None.
func (s *MLDSA65Signer) Public() crypto.PublicKey {
	cp := make([]byte, len(s.pub))
	copy(cp, s.pub)
	return &PublicKey{raw: cp}
}

// Sign signs msg, which must be the whole message and never a digest.
//
// # Description
//
// Implements crypto.Signer, so this signer drops into code expecting one. For
// producing anchors use [SignAnchor] instead: it verifies what it produced,
// and this method does not.
//
// rand is IGNORED: signing here is deterministic (FIPS 204 §5.3, hedged variant
// disabled), so there is no randomness for a caller to supply. A caller passing
// entropy expecting a hedged signature does not get one.
//
// opts must report crypto.Hash(0) — pass nil or crypto.Hash(0). A non-zero hash
// means the caller pre-hashed, which for ML-DSA produces a structurally perfect
// signature over the wrong bytes; refusing is the only chance to catch it.
//
// # Inputs
//
//   - rand: ignored
//   - msg: the message to sign; for an anchor, its canonical bytes
//   - opts: nil, or anything reporting crypto.Hash(0)
//
// # Outputs
//
//   - []byte: SignatureSize bytes
//   - error: ErrPreHashed, ErrSignerClosed, or a signing failure
//
// # Example
//
//	sig, err := s.Sign(nil, canonical, crypto.Hash(0))
//
// # Limitations
//
//   - Takes no context; use SignContext where cancellation matters.
//   - Does NOT verify what it produced. Direct use therefore bypasses the fault
//     and pre-hashing protections described on [SignAnchor].
//   - Re-derives the expanded private key on every call and leaves it for the
//     garbage collector unwiped; see the type's Limitations.
//
// # Assumptions
//
//   - msg is already canonical. This type does not canonicalize anything.
func (s *MLDSA65Signer) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != crypto.Hash(0) {
		return nil, fmt.Errorf("%w (got %s)", ErrPreHashed, opts.HashFunc())
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrSignerClosed
	}

	sig, err := mldsa.Sign(mldsa.MLDSA65, s.seed, msg)
	if err != nil {
		return nil, fmt.Errorf("anchor: sign: %w", err)
	}
	return sig, nil
}

// SignContext signs msg, aborting if ctx is already cancelled.
//
// # Description
//
// Implements [ContextSigner]. Signing in memory does not block, so the context
// is checked once up front rather than woven through: there is no point during
// an in-process ML-DSA signature at which cancellation could take effect. A KMS
// implementation has real work to cancel and should honour ctx throughout.
//
// # Inputs
//
//   - ctx: cancelled before the call means no signature is produced
//   - msg: the whole message; for an anchor, its canonical bytes
//
// # Outputs
//
//   - []byte: SignatureSize bytes
//   - error: ctx.Err(), ErrSignerClosed, or a signing failure
//
// # Example
//
//	sig, err := s.SignContext(ctx, canonical)
//
// # Limitations
//
//   - Cancellation is checked once; it cannot interrupt a signature in flight.
//   - Does NOT verify what it produced; see [SignAnchor].
//
// # Assumptions
//
//   - msg is already canonical.
func (s *MLDSA65Signer) SignContext(ctx context.Context, msg []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("anchor: context: %w", err)
	}
	return s.Sign(nil, msg, crypto.Hash(0))
}

// Close zeroizes the seed and makes the signer refuse to sign.
//
// # Description
//
// Idempotent. The public key and key id survive, so a caller can still publish
// the identity it signed with after dropping the private half.
//
// # Outputs
//
//   - error: always nil; present so *MLDSA65Signer satisfies io.Closer
//
// # Example
//
//	defer s.Close()
//
// # Limitations
//
//   - Zeroizes only the seed this type holds. It does NOT reach the expanded
//     private keys each signature left on the heap; see the type's Limitations.
//
// # Assumptions
//
//   - None.
func (s *MLDSA65Signer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	mem.Zeroize(s.seed)
	s.seed = nil
	s.closed = true
	return nil
}

// cryptoSignerAdapter carries a plain crypto.Signer across the ContextSigner
// boundary, dropping cancellation.
//
// The field is named and unexported rather than embedded, so the adapter
// satisfies ContextSigner and nothing else: an embedded crypto.Signer would
// re-expose Sign with arbitrary SignerOpts and let a caller route straight past
// the adapter.
type cryptoSignerAdapter struct {
	inner crypto.Signer
}

// Public implements ContextSigner by forwarding to the wrapped signer.
func (a cryptoSignerAdapter) Public() crypto.PublicKey { return a.inner.Public() }

// SignContext signs msg, IGNORING ctx. See FromCryptoSigner.
//
// crypto/rand.Reader is passed rather than nil: implementations that ignore it
// are unaffected, while stdlib ECDSA dereferences it and several HSM and
// PKCS#11 wrappers read from it. Handing nil into code this package did not
// write would turn a foreign signer's correct behaviour into a panic inside a
// library.
func (a cryptoSignerAdapter) SignContext(_ context.Context, msg []byte) ([]byte, error) {
	return a.inner.Sign(cryptorand.Reader, msg, crypto.Hash(0))
}

// FromCryptoSigner adapts any crypto.Signer to ContextSigner, giving up cancellation.
//
// # Description
//
// The inbound half of this package's compatibility with crypto.Signer: a Cloud
// KMS, PKCS#11, HSM or keychain signer someone else wrote plugs in here with no
// adapter of their own.
//
// **The returned signer IGNORES the context.** A plain crypto.Signer has no way
// to accept one, so there is nothing to forward. That is why this is an explicit
// call rather than a type assertion hidden inside this package — a KMS call that
// hangs while the caller's timeout does nothing is a miserable thing to
// diagnose, and the decision to accept that belongs where a reader can see it.
//
// Prefer implementing [ContextSigner] directly if the signer can honour a context.
//
// # Inputs
//
//   - s: any crypto.Signer, and not a typed nil. Must sign the MESSAGE rather
//     than a digest, and must be ML-DSA-65 — neither can be checked here, but
//     [SignAnchor] catches both.
//
// # Outputs
//
//   - ContextSigner: wrapping s, with SignContext discarding its context
//   - error: if s is nil, including a typed nil such as (*myKMSSigner)(nil)
//
// # Example
//
//	cs, err := anchor.FromCryptoSigner(kmsSigner) // cancellation is given up here
//	if err != nil {
//	    return err
//	}
//	signed, err := anchor.SignAnchor(ctx, cs, a)
//
// # Limitations
//
//   - Cancellation is lost, by construction.
//   - Does not adapt algorithms. A non-ML-DSA-65 signer is refused by
//     [KeyIDOf] on public key length, not here.
//
// # Assumptions
//
//   - s is safe for concurrent use, as crypto.Signer implementations should be.
func FromCryptoSigner(s crypto.Signer) (ContextSigner, error) {
	if isNil(s) {
		return nil, errors.New("anchor: crypto.Signer is required (and must not be a typed nil)")
	}
	return cryptoSignerAdapter{inner: s}, nil
}

// isNil reports whether v is nil, including a non-nil interface holding a nil
// pointer.
//
// A plain `== nil` misses `var p *myKMSSigner; FromCryptoSigner(p)`, which is
// the shape a failed initialisation actually takes. Without this the nil
// surfaces much later, as a panic inside this package pointing at the wrong
// code.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return rv.IsNil()
	default:
		return false
	}
}
