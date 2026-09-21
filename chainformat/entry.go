// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package chainformat

// entryV3SealTag makes EntryV3 a sealed interface.
//
// Only types in this package can satisfy EntryV3, because sealEntryV3 takes an
// unexported parameter type that no other package can name.
type entryV3SealTag struct{}

// EntryV3 is a v3 chain entry: something that knows its own canonical byte form.
//
// # Description
//
// The v3 chain carries several entry kinds — capture requests today, subject-
// access-request lifecycle events in the verification SDK — that share one
// header and one encoder but differ in body. EntryV3 is that contract.
//
// # Why the interface is sealed
//
// A verifier must never be handed an entry type it does not understand. If an
// outside package could implement EntryV3, it could define a body the verifier
// cannot reproduce, and a chain containing it would be unverifiable by anyone
// else — while still type-checking. Sealing keeps the set of entry kinds closed
// and versioned, which is what makes "any conforming verifier reproduces these
// bytes" a claim rather than a hope.
//
// It also keeps the door open: adding an entry kind here is additive and does
// not break callers, because callers only ever hold the interface.
//
// # Assumptions
//
//   - Implementations validate before they encode. CanonicalV3 calls validateV3
//     first and refuses to emit bytes for an entry that failed it, so no
//     implementation may rely on the encoder to reject malformed input.
type EntryV3 interface {
	// EntryTypeV3 returns the entry-type tag written into the canonical header.
	EntryTypeV3() string

	// validateV3 runs every header and body check against the same post-NFC
	// bytes the encoder will emit.
	validateV3() error

	// encodeCanonicalV3 appends this entry's canonical bytes to enc.
	encodeCanonicalV3(enc *v3Encoder)

	// sealEntryV3 prevents implementations outside this package.
	sealEntryV3(entryV3SealTag)
}

// EntryTypeV3 returns the capture-request entry-type tag.
func (e CaptureRequestV3) EntryTypeV3() string { return EntryTypeCaptureRequestV3 }

func (e CaptureRequestV3) sealEntryV3(entryV3SealTag) {}

// Compile-time proof that CaptureRequestV3 satisfies the contract.
var _ EntryV3 = CaptureRequestV3{}
