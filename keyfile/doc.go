// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package keyfile reads and writes post-quantum key files in the standard
// formats, so keys produced here are readable by other tools.
//
// # Description
//
// Private keys are PKCS#8 (RFC 5958 OneAsymmetricKey) under the PEM label
// "PRIVATE KEY"; public keys are SubjectPublicKeyInfo under "PUBLIC KEY". The
// algorithm is identified by its object identifier inside the file, never
// guessed from a length:
//
//	ML-KEM-512/768/1024   RFC 9935   2.16.840.1.101.3.4.4.{1,2,3}
//	ML-DSA-44/65/87       RFC 9881   2.16.840.1.101.3.4.3.{17,18,19}
//	X-Wing                draft-connolly-cfrg-xwing-kem-10
//	                                 1.3.6.1.4.1.62253.25722
//
// # Seeds only
//
// RFC 9935 and RFC 9881 define three private-key forms — seed, expandedKey,
// and both — and RECOMMEND the seed. This package writes the seed form and
// nothing else, and it rejects an expandedKey-only file: expansion is one-way,
// so no seed can be recovered from it, and every API in this module takes a
// seed. A "both" file is accepted and its seed used; see [CheckConsistency] for
// what is verified.
//
// # Encoding only
//
// This package parses and serialises. It does not generate keys, derive public
// keys from private ones, or perform cryptography beyond the hash used by the
// ML-KEM consistency check. That keeps it dependency-free: reading an X-Wing
// key never compiles in an ML-DSA implementation.
//
// # Limitations
//
//   - Encryption at rest is out of scope. A private key file written here is
//     plaintext; protecting it is the caller's job.
//   - An AlgorithmIdentifier carrying parameters is rejected; all the
//     algorithms above require them to be absent.
//   - A OneAsymmetricKey carrying an embedded public key is rejected rather
//     than trusted, since this package cannot check it against the seed.
//   - Legacy "ALEUTIAN HYBRID KEM" files are READ for compatibility and never
//     written.
//
// # Assumptions
//
//   - Callers zeroize seeds when finished; the seed returned by
//     [ParsePrivateKey] is a fresh copy the caller owns.
//
// # Producing key files
//
// This package encodes and parses; it does not generate. `proof keygen` is the
// generator — it creates X-Wing, ML-KEM-768/1024 and ML-DSA-44/65/87 pairs,
// self-tests every key before writing it, writes the private half 0600, and
// never prints it. Its output is exactly what [ParsePrivateKey] reads, and the
// key id it displays is [KeyIDHex], which is the same id an anchor signed with
// that key will carry.
package keyfile
