// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package xwing implements the X-Wing hybrid post-quantum KEM.
//
// # Description
//
// X-Wing combines ML-KEM-768 with X25519 so that the shared secret stays secure
// as long as EITHER primitive holds. That hedges the two live risks at once: a
// cryptanalytic break of the young lattice scheme, and a future quantum
// adversary against the classical one.
//
// Every primitive comes from the standard library: ML-KEM from crypto/mlkem,
// X25519 from crypto/ecdh, SHA3-256 and SHAKE256 from crypto/sha3. This package
// deliberately does NOT depend on github.com/cloudflare/circl — in this module
// that dependency belongs to [github.com/aleutian-ai/proof/mldsa], because
// ML-DSA is not in the standard library. Keeping the split lets a caller vendor
// the KEM alone, with no external dependency at all.
//
// # Conformance
//
// Checked against the specification's official test vectors
// (testdata/xwing_spec_vectors.json, authenticated by the checksum published
// for spec/test-vectors.txt) and differentially against an independent
// implementation, circl's kem/xwing, in both directions.
//
// # Secret handling
//
// PrivateKey and SharedSecret redact under every fmt verb except %p (via
// fmt.Formatter, so %d and %x included) and under log/slog (via LogValuer), and
// REFUSE json, text, and gob serialization with an error rather than emitting a
// placeholder — an accidental serialization should
// fail loudly, not ship with silent data loss. The sentinel errors are
// constants, so invalid input can never be turned into a silent success.
//
// # Limitations
//
//   - Key serialization is not here. On-disk key formats live in
//     [github.com/aleutian-ai/proof/keyfile], which writes X-Wing keys in the
//     standard PKCS#8 seed form so other implementations can read them.
//   - Some copies of key material cannot be wiped. crypto/ecdh.PrivateKey keeps
//     its own copy of the X25519 scalar and mlkem.DecapsulationKey holds the
//     expanded ML-KEM key; neither exposes a way to clear it, so those copies
//     live until the garbage collector reclaims them. The package zeroizes
//     every buffer it owns (the expanded seed, both derived scalars/seeds, both
//     component shared secrets, the ephemeral key).
//   - %p prints the raw bytes. fmt handles %p before consulting a Formatter and
//     prints the value with method calls disabled; go vet does not flag it.
//     Never use %p on key material.
//   - encoding/binary (Write, Append, Encode) serializes both types' raw bytes:
//     it works by reflection and consults no marshaling interface, so no
//     method can refuse it. The same applies to any reflection-based encoder
//     that ignores json.Marshaler, encoding.TextMarshaler, and gob.GobEncoder.
//   - An UNEXPORTED struct field of type PrivateKey or SharedSecret is printed
//     by fmt through reflection, without calling any method, so it prints raw
//     bytes. No method can prevent this. Do not keep key material in unexported
//     fields of values that are logged or formatted.
//   - X-Wing cannot run under GODEBUG=fips140=only: crypto/ecdh refuses X25519
//     in that mode. X25519 is not an approved key-establishment scheme under
//     SP 800-56A, so X-Wing as a whole carries no FIPS approval claim.
//
// # Assumptions
//
//   - Secret material is zeroized by the caller when no longer needed; the
//     Zeroize methods are best-effort and cannot defeat a moving GC.
package xwing
