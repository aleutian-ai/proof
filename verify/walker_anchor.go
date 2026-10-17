// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"fmt"

	"github.com/aleutian-ai/proof/anchor"
)

// BindAnchor checks the entries walked so far against an anchor WITHOUT
// verifying the signature: [BindAnchor], for a chain that was streamed.
//
// # Description
//
// BindAnchor takes every entry in a slice. A caller that fed a Walker one
// entry at a time has no slice, and the walker already holds what binding
// needs: the first and last entries, the count, and the breaks. The result is
// the one BindAnchor returns for the same entries, because both bind through
// the same code. It is the keyless claim; [Walker.VerifyAnchor] adds the
// signature.
//
// # Inputs
//
//   - a: the anchor; it must end at the last entry walked (v7: end_seq is the
//     last entry's global_seq; v1 to v6: it covers exactly Count() entries)
//   - expect: what the caller expects; see [Expect]
//
// # Outputs
//
//   - BindResult: as BindAnchor's. SignatureVerified is always false.
//   - error: ErrNoEntries, a malformed anchor or expected predecessor, or a walk
//     that started from a predecessor hash
//
// # Example
//
//	w := verify.NewWalker(verify.Options{MaxBreaks: 1})
//	for _, e := range page { // a page at a time, from a file or a store
//	    w.Add(e)
//	}
//	res, err := w.BindAnchor(a, verify.Expect{Subject: "orders"})
//
// # Limitations
//
//   - As [BindAnchor]'s.
//   - A walker made with a negative Options.MaxBreaks keeps no breaks, so an
//     entry of an unknown format is reported as a broken chain, not an error.
//
// # Assumptions
//
//   - Every entry of the chain, and nothing else, has been added.
func (w *Walker) BindAnchor(a anchor.Anchor, expect Expect) (BindResult, error) {
	if w.Count() == 0 {
		return BindResult{}, ErrNoEntries
	}
	if err := validateExpect(a, expect); err != nil {
		return BindResult{}, err
	}
	if err := anchor.ValidateVersionInvariants(a); err != nil {
		return BindResult{}, fmt.Errorf("verify: malformed anchor: %w", err)
	}
	return w.bind(a, expect)
}
