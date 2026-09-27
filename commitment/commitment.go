// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package commitment makes salted commitments to content that is committed to a
// chain unencrypted.
//
// # Description
//
// A chain entry's content_hash is public. When it is a plain SHA-512 of
// low-entropy content, anyone holding the chain can guess the content: hash
// "consent: yes" and "consent: no" and see which matches. A salted commitment
// closes that:
//
//	commitment = SHA-512("aleutian.commit.v1:" ‖ nonce ‖ SHA-512(content))
//
// with a fresh 32-byte random nonce per item. The commitment goes on the chain;
// the content and its nonce stay with you. To DISCLOSE one item, reveal its
// content and nonce: anyone recomputes the commitment and compares. The other
// items' contents stay hidden, though the disclosed content becomes tied to its
// entry's timestamp and position.
//
// To ERASE one, destroy its content and nonce. Once EVERY copy of the nonce is
// gone — including backups, and anyone it was disclosed to — the commitment can
// no longer be opened or tied to the content, and the chain still verifies. If a
// copy survives anywhere, the item is pseudonymised, not erased. This also
// assumes the entry's own metadata (entry id, type) carries no identifiers.
//
// The result is 128 lowercase hex characters, usable directly as a chain
// entry's content_hash. The chain format does not change.
//
// # Why the content is hashed first
//
// SHA-512(domain ‖ nonce ‖ content) would be length-extendable: from a public
// commitment, anyone could compute a second commitment without knowing the
// nonce, publish it, and — once the first item is disclosed — open it to that
// content plus appended bytes, falsely claiming to have committed first. Hashing
// the content first makes the outer input a fixed 115 bytes, which cannot be
// extended into another valid opening.
//
// # Plain hash or commitment?
//
// Nothing in a content_hash says which it is, and the two are not
// distinguishable from the chain. A verifier must learn from outside the chain
// — the entry type, or the disclosure itself — whether an entry is a salted
// commitment or a plain SHA-512.
//
// # When not to use it
//
// Content encrypted with RANDOMIZED encryption (a fresh nonce or IV per item,
// as HPKE does) does not need this: identical plaintexts give different
// ciphertexts, so there is nothing to guess. Commit the ciphertext's plain
// SHA-512 (see examples/encrypted-artifact). Deterministic encryption, such as
// AES-SIV with a fixed nonce or keys derived from the content, gives equal
// ciphertexts for equal plaintexts and leaks equality — use a salted
// commitment there too.
//
// # Why not an HMAC
//
// A keyed hash (HMAC with one secret) also stops guessing, but proving a single
// item would mean revealing the key, which exposes every other item to the same
// guessing. A per-item nonce discloses exactly one item. Chain verification needs
// no secret in either case — it never recomputes a commitment from content.
package commitment

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// Domain separates these commitments from the protocol's other prefixed
	// hashes (chain hash v2/v3, anchor chain hash): none is a prefix of another.
	// It does NOT distinguish a commitment from a plain SHA-512 content hash —
	// see the package doc, "Plain hash or commitment?".
	Domain = "aleutian.commit.v1:"

	// NonceSize is the nonce length in bytes. It is FIXED, and the content is
	// hashed to a fixed 64 bytes, so the outer input is always exactly
	// len(Domain) + NonceSize + 64 = 115 bytes: unambiguous, and not
	// length-extendable into another valid opening.
	NonceSize = 32
)

// ErrNonceSize is returned when a nonce is not exactly NonceSize bytes.
var ErrNonceSize = errors.New("commitment: nonce must be exactly 32 bytes")

// Salted commits to content with a fresh random nonce.
//
// # Description
//
// Draws a NonceSize nonce from crypto/rand and returns the commitment and the
// nonce. This is the only way to create a commitment: nonces are never derived
// or reused. Keep the nonce with the content — without it, the content can
// never be shown to match the commitment.
//
// # Inputs
//
//   - content: the bytes to commit to. May be empty.
//
// # Outputs
//
//   - string: the commitment, 128 lowercase hex characters, usable as a chain
//     entry's content_hash
//   - []byte: the nonce, NonceSize bytes. The caller owns it.
//   - error: only if the system random source fails
//
// # Example
//
//	c, nonce, err := commitment.Salted([]byte(`{"consent":"yes"}`))
//	if err != nil {
//	    return err
//	}
//	// commit c to the chain; store the content and nonce privately
//
// # Limitations
//
//   - Hides content only while the nonce stays private. Disclosing the nonce
//     discloses the content to anyone who can guess it.
//   - NEVER reuse a nonce across items. Disclosing one item would expose the
//     other to guessing, and identical content under one nonce gives identical,
//     linkable commitments. Salted always draws a fresh one.
//
// # Assumptions
//
//   - crypto/rand is a sound source of randomness.
func Salted(content []byte) (string, []byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, fmt.Errorf("commitment: draw nonce: %w", err)
	}
	c, err := compute(nonce, content)
	if err != nil {
		return "", nil, err
	}
	return c, nonce, nil
}

// Verify reports whether a disclosed nonce and content open a commitment.
//
// # Description
//
// Recomputes the commitment and compares it in constant time. This is what a
// third party runs when an item is disclosed: it needs the commitment (from the
// chain), the nonce and the content, and no secret.
//
// # Inputs
//
//   - commitment: the value from the chain entry's content_hash
//   - nonce: the disclosed nonce
//   - content: the disclosed content
//
// # Outputs
//
//   - bool: true only if the nonce is the right size and the commitment matches
//
// # Example
//
//	if !commitment.Verify(entry.ContentHash, nonce, content) {
//	    return errors.New("disclosed content does not match the chain")
//	}
//
// # Limitations
//
//   - Proves the content matches the commitment. Whether that commitment is
//     really on the chain, unaltered, is the chain's job: verify it too.
//   - Assumes the entry IS a salted commitment; see the package doc.
//
// # Assumptions
//
//   - commitment is compared exactly; an uppercase-hex commitment never matches.
func Verify(commitment string, nonce, content []byte) bool {
	want, err := compute(nonce, content)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(commitment)) == 1
}

// compute is the deterministic core. Unexported on purpose: exposing a
// "commit with this nonce" function invites fixed or derived nonces, which
// quietly recreate the single-secret scheme this package exists to avoid.
func compute(nonce, content []byte) (string, error) {
	if len(nonce) != NonceSize {
		return "", ErrNonceSize
	}
	inner := sha512.Sum512(content)
	h := sha512.New()
	h.Write([]byte(Domain))
	h.Write(nonce)
	h.Write(inner[:])
	return hex.EncodeToString(h.Sum(nil)), nil
}
