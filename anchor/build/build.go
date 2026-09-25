// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

// Package build produces anchors, having first checked the chain they describe.
//
// # Description
//
// An anchor is a signed claim about a chain. This package exists so the claim
// cannot be made without being established: [Anchor] runs the chain verifier
// over the entries and refuses to produce anything if the linkage is broken.
//
// It is a separate package because a producer genuinely depends on both halves,
// and neither half should depend on it:
//
//	anchor          the FORMAT     — canonical bytes, hashes, signing
//	verify          the CHECKING   — imports anchor
//	anchor/build    the PRODUCER   — imports both
//
// `anchor` cannot import `verify` (that is a cycle), so a builder living in
// `anchor` could never run the verifier. Injecting one instead would let a
// caller supply a stub that always answers "intact", which would return
// verified_through to being a convention rather than a guarantee — the exact
// failure this package is shaped to prevent.
//
// # Limitations
//
//   - Produces v6 anchors only. v5 commits to a Merkle root nothing can verify,
//     and v3/v4 spell the subject "company_id" on the wire.
//   - Establishes that the chain it was HANDED is intact. It cannot know whether
//     that chain is complete, or whether the entries are true.
//
// # Assumptions
//
//   - Entries arrive in ascending global_seq order, as every exporter in this
//     module produces them.
package build

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/verify"
)

// Errors returned by this package. Compare with errors.Is.
var (
	// ErrChainBroken means the entries do not verify, so no anchor was produced.
	// An anchor over a broken chain would attest to a chain that does not exist.
	ErrChainBroken = errors.New("build: refusing to anchor a broken chain")

	// ErrNoEntries means there was nothing to anchor.
	ErrNoEntries = errors.New("build: at least one entry is required")
)

// Input is everything needed to produce an anchor.
//
// # Description
//
// Deliberately small. Anything this package can derive, it derives — the head
// hash, the entry range, the count and the anchor id all come from the entries
// rather than from the caller, because every one of them is a field a caller
// could get subtly wrong in a way the signature would then authenticate.
//
// # Assumptions
//
//   - Entries are the complete, ordered range this anchor should cover.
type Input struct {
	// Subject names the namespace this chain is about. Required.
	//
	// It is inside the signed bytes, so an anchor cannot be replayed onto
	// another chain — and so it can never be erased or corrected afterwards.
	// Use a stable pseudonym or an opaque id, NEVER a name, an email address or
	// anything else identifying a person. See anchor.Anchor.Subject.
	Subject string

	// Entries are the chain to anchor, ascending by global_seq.
	Entries []verify.Entry

	// Previous is the anchor this one follows, or nil for the first anchor in a
	// chain. When nil, the genesis sentinels are used.
	//
	// A pointer rather than a bool-plus-hash so that a caller who has the
	// previous anchor cannot accidentally pass the wrong field of it.
	Previous *anchor.Anchor

	// CreatedAt stamps the anchor. Zero means time.Now().UTC().
	//
	// Overridable so a test can pin it; an anchor's time is descriptive, and the
	// chain's linkage is the authority on ordering.
	CreatedAt time.Time
}

// Anchor verifies a chain and produces an unsigned anchor over it.
//
// # Description
//
// In order, and the order matters:
//
//  1. Validate the input.
//  2. Run [verify.Chain] over the entries. A broken chain stops here.
//  3. Take the head from the LAST entry, and the range from the first and last.
//  4. Recompute the anchor chain hash from the predecessor, subject, range and
//     head — never copied from the tip.
//  5. Assemble a v6 anchor with verified_through set to what step 2 established.
//
// The result is UNSIGNED. Sign it with [anchor.SignAnchor], which stamps the key
// id and verifies its own output.
//
// # Why step 2 cannot be skipped or supplied
//
// `verified_through` is a claim that the range was checked clean at the moment
// of signing. An anchor that asserts it without checking is a lie its own
// signature then authenticates — which is worse than no anchor, because the
// signature invites a reader to believe it. So the verification happens here,
// with no parameter to override it and no interface to substitute.
//
// # Inputs
//
//   - ctx: honoured between steps; verification itself does not block
//   - in: see [Input]
//
// # Outputs
//
//   - anchor.Anchor: a v6 anchor, unsigned
//   - error: ErrNoEntries, ErrChainBroken, ctx.Err(), or a validation failure
//
// # Example
//
//	a, err := build.Anchor(ctx, build.Input{
//	    Subject:  "my-project",
//	    Entries:  entries,
//	    Previous: prev, // nil for the first anchor
//	})
//	if err != nil {
//	    return err
//	}
//	signed, err := anchor.SignAnchor(ctx, signer, a)
//
// # Limitations
//
//   - Verifies LINKAGE, not truth. It establishes that nothing was edited under
//     you, not that the entries describe what really happened.
//   - Does not check that the entries are the whole chain. An anchor over a
//     truncated range is a valid anchor over that range.
//   - Produces v6 only.
//
// # Assumptions
//
//   - The caller decided which entries belong in this anchor.
func Anchor(ctx context.Context, in Input) (anchor.Anchor, error) {
	if err := ctx.Err(); err != nil {
		return anchor.Anchor{}, fmt.Errorf("build: %w", err)
	}
	if len(in.Entries) == 0 {
		return anchor.Anchor{}, ErrNoEntries
	}
	if in.Subject == "" {
		return anchor.Anchor{}, errors.New("build: a subject is required; it is the " +
			"replay protection, and a v6 anchor without one is invalid")
	}

	// 2. Establish the claim BEFORE making it.
	res, err := verify.Chain(in.Entries, verify.Options{MaxBreaks: 1})
	if err != nil {
		return anchor.Anchor{}, fmt.Errorf("build: verifying the chain: %w", err)
	}
	if res.Verdict == verify.VerdictBroken {
		detail := "unknown"
		if len(res.Breaks) > 0 {
			detail = fmt.Sprintf("%s at entry %d", res.Breaks[0].Type, res.Breaks[0].Position)
		}
		return anchor.Anchor{}, fmt.Errorf("%w: %s. An anchor over a broken chain would "+
			"attest to a chain that does not exist, and its signature would make that "+
			"claim look authoritative", ErrChainBroken, detail)
	}

	first, last := in.Entries[0], in.Entries[len(in.Entries)-1]

	// 3/4. The head is the last entry's chain hash — verified above, so it is
	// the head of a chain that actually links. The anchor hash is RECOMPUTED
	// from what the anchor commits to, never copied from the tip.
	previousAnchorHash, previousAnchorID := anchor.SeedAnchorHash, anchor.SeedAnchorID
	if in.Previous != nil {
		previousAnchorHash = in.Previous.ChainHash
		previousAnchorID = in.Previous.AnchorID
	}

	chainHash, err := anchor.ChainHash(
		previousAnchorHash, in.Subject, first.EntryID, last.EntryID, last.ChainHash)
	if err != nil {
		return anchor.Anchor{}, fmt.Errorf("build: anchor chain hash: %w", err)
	}

	anchorID, err := newAnchorID()
	if err != nil {
		return anchor.Anchor{}, fmt.Errorf("build: %w", err)
	}

	createdAt := in.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}

	out := anchor.Anchor{
		Version:    anchor.SubjectVersion,
		AnchorID:   anchorID,
		Subject:    in.Subject,
		ChainHash:  chainHash,
		Range:      anchor.EntryRange{StartEntryID: first.EntryID, EndEntryID: last.EntryID},
		EntryCount: int64(len(in.Entries)),
		// Asserted ONLY because step 2 established it.
		VerifiedThrough:  int64(res.EntriesVerified),
		PreviousAnchorID: previousAnchorID,
		CreatedAtMs:      createdAt.UnixMilli(),
	}

	// Refuse to hand back something this module's own verifier would reject.
	// Cheap, and it turns a format mistake into an error here rather than an
	// unverifiable artefact discovered at audit time.
	if err := anchor.ValidateVersionInvariants(out); err != nil {
		return anchor.Anchor{}, fmt.Errorf("build: produced an invalid anchor: %w", err)
	}
	return out, nil
}

// newAnchorID mints an anchor id: "anchor_" followed by a random UUIDv4.
//
// # Description
//
// The shape matches [anchor.SeedAnchorID], so the sentinel and a real id are
// the same kind of value and a reader cannot tell them apart by format alone —
// only by value, which is the point of a sentinel.
//
// Formatted by hand from crypto/rand rather than pulled from a UUID library:
// this module holds a near-zero-dependency line, and a dependency would buy
// string formatting and nothing else.
//
// # Outputs
//
//   - string: "anchor_" + a RFC 4122 version 4 UUID
//   - error: only if the system random source fails
//
// # Example
//
//	id, err := newAnchorID() // anchor_3f2b1c4d-...
//
// # Limitations
//
//   - Randomness only; it encodes no time and sorts meaninglessly.
//
// # Assumptions
//
//   - crypto/rand is available. On failure this returns an error rather than
//     falling back to anything weaker, because a predictable anchor id would be
//     a predictable name for a record someone may want to suppress.
func newAnchorID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random bytes for the anchor id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant

	h := hex.EncodeToString(b[:])
	return "anchor_" + h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}
