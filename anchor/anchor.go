// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package anchor

// EntryRange identifies the first and last chain entries an anchor covers.
//
// # Description
//
// Both bounds are inclusive. The range is part of the signed canonical form, so
// an anchor commits to WHICH entries it speaks for — this is what makes
// truncation detectable: remove entries below StartEntryID and the anchor no
// longer describes the chain in front of you.
//
// # Assumptions
//
//   - Entry IDs contain no '|' (see ValidateChainHashDelimiters)
type EntryRange struct {
	StartEntryID string `json:"start_entry_id"`
	EndEntryID   string `json:"end_entry_id"`
}

// Anchor is a signed statement that a chain had a particular head at a
// particular point in its history.
//
// # Description
//
// Field-compatible with the published verification SDK's Anchor, deliberately:
// the SDK's shape is already exercised by cross-language fixtures, so matching
// it means anchors serialized by either can be read by the other. This type
// carries no storage-engine tags and no cloud dependency.
//
// Not every field participates in every version's canonical form. See
// Canonicalize — VerifiedThrough is absent before v4, and RootHash/TreeSize
// before v5.
//
// # Limitations
//
//   - Signature is EXCLUDED from the canonical form; it is what the canonical
//     bytes are signed with, so it cannot sign itself.
//   - An anchor is exactly as trustworthy as the key that signed it, and as the
//     copy you obtained it from. An anchor read back from the same store as the
//     chain proves consistency, not external commitment.
//
// # Assumptions
//
//   - Version is the declared format version and is INSIDE the signed bytes.
//     Verifiers dispatch on it and never infer the version from which fields
//     happen to be populated.
type Anchor struct {
	// Version is the declared canonical-form version. 3, 4, 5 and 6 are
	// defined. v6 is the one to produce; v5 canonicalizes but is refused by
	// VerifySignature, and v3/v4 spell the subject "company_id" on the wire.
	Version int `json:"version"`

	// AnchorID uniquely identifies this anchor.
	AnchorID string `json:"anchor_id"`

	// Subject is the namespace this anchor belongs to: whatever the chain is
	// ABOUT. Any non-empty string — a hostname, a project, an opaque id.
	//
	// It is in the signed bytes by design: an anchor that did not commit to its
	// subject could be replayed onto another chain. Nothing here authenticates
	// it, so it separates namespaces rather than proving one.
	//
	// NOT ERASABLE. MUST NOT CARRY PERSONAL DATA. Being inside the signed bytes
	// means this value cannot be removed, redacted or corrected afterwards:
	// changing it invalidates the signature, and via ChainHash and
	// PreviousAnchorID it invalidates every anchor that follows. Anchors are
	// meant to be handed to third parties and escrowed. A name, an email
	// address, a username or a device hostname placed here is therefore a
	// permanent, published, undeletable record of a person — which is a
	// straightforward conflict with a right to erasure, inherited by anyone who
	// adopts this library without thinking about it.
	//
	// Use a stable pseudonym or an opaque identifier. If the natural subject is
	// personal, hash it with a secret salt you keep separately, so the anchor
	// commits to the pseudonym and the mapping stays erasable.
	//
	// WIRE KEY BY VERSION. v3–v5 spell it "company_id"; v6 spells it "subject".
	// The key is INSIDE the signed bytes, which is why the rename needed a
	// version (see SubjectVersion) rather than being a refactor. Marshalling
	// emits the key that matches Version; unmarshalling accepts either.
	//
	// Until 2026-09-23 this was CompanyID, named for a private platform's
	// tenant. A tenant id is still a perfectly good subject.
	Subject string `json:"-"`

	// ChainHash binds this anchor to its covered segment AND to the previous
	// anchor. It is NOT the tip entry's chain hash — it is the output of
	// ChainHash, which uses a distinct SHA-512 domain separator. Verifiers must
	// RECOMPUTE it, never byte-compare it against the tip.
	ChainHash string `json:"chain_hash"`

	// Range is the inclusive span of entries this anchor covers.
	Range EntryRange `json:"range"`

	// EntryCount is the chain height this anchor attests to.
	EntryCount int64 `json:"entry_count"`

	// Signature is the base64-encoded ML-DSA-65 signature (3309 bytes decoded).
	// Excluded from the canonical form.
	Signature string `json:"signature"`

	// SigningKeyID identifies the key that signed this anchor. It is inside the
	// canonical form: an anchor that did not commit to its own key could be
	// re-attributed to a different one.
	SigningKeyID string `json:"signing_key_id"`

	// CreatedAtMs is the anchor's creation time in milliseconds since the Unix
	// epoch, UTC.
	CreatedAtMs int64 `json:"created_at_ms"`

	// PreviousAnchorID is the preceding anchor's id, or the seed sentinel
	// (SeedAnchorID) for the first anchor in a chain.
	PreviousAnchorID string `json:"previous_anchor_id"`

	// VerifiedThrough (v4+) is a signed claim that the range up to this height
	// was verified clean at signing time. Zero for v3.
	VerifiedThrough int64 `json:"verified_through,omitempty"`

	// RootHash (v5+) is the Merkle root the anchor commits to. Empty before v5.
	//
	// A v5 anchor with an empty RootHash is MALFORMED, not merely old: Version is
	// inside the signed bytes, so it is a valid signature over invalid content.
	RootHash string `json:"root_hash,omitempty"`

	// TreeSize (v5+) is the leaf count of the committed Merkle tree.
	TreeSize int64 `json:"tree_size,omitempty"`
}
