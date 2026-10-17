// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"fmt"

	"github.com/aleutian-ai/proof/anchor"
)

// Series checks a chain's anchors as a series, in one walk of the chain.
//
// # Description
//
// [VerifyAnchor] checks one anchor against the predecessor hash the caller
// hands it. It cannot check what makes several anchors a series, because those
// rules are about the anchors' relation to each other:
//
//   - every anchor is for the expected subject;
//   - the first names the seed anchor as its predecessor and is hashed onto the
//     seed hash; each later one names the anchor before it, by id, and is hashed
//     onto that anchor's chain hash;
//   - each covers more entries than the one before;
//   - created_at_ms never goes backwards;
//   - each binds to the chain's prefix of exactly its length and its signature
//     verifies.
//
// Without them a genesis anchor naming some other predecessor, a second anchor
// claiming to be the first, and an anchor for another subject each verified on
// their own.
//
// Feed the chain to a [Walker] and call [Series.Reached] after every Add; call
// [Series.Finish] when the chain ends. The first problem stops the series: a
// later anchor cannot be judged against a predecessor that did not verify.
//
// # Thread Safety
//
// Not safe for concurrent use.
type Series struct {
	// Label names the n-th anchor (from 1) in problems. nil means "anchor n".
	Label func(n int) string

	subject   string
	anchors   []anchor.Anchor
	keys      anchor.KeySource
	next      int
	prevHash  string
	prevID    string
	prevMs    int64
	covered   int64
	verified  int
	problems  []string
	stopped   bool
	unchecked bool
}

// NewSeries starts a series check.
//
// # Description
//
// The rules that need no chain (subject, predecessor id, growth, time) are
// checked for each anchor as the series reaches it, the first one immediately.
//
// # Inputs
//
//   - subject: the subject every anchor must be for
//   - anchors: the series, oldest first
//   - keys: the keys the anchors may be signed with; must not be nil
//
// # Outputs
//
//   - *Series: to feed with Reached and Finish
//
// # Example
//
//	s := verify.NewSeries(subject, anchors, keys)
//	w := verify.NewWalker(verify.Options{})
//	for _, e := range entries {
//	    w.Add(e)
//	    s.Reached(w)
//	}
//	s.Finish(w.Count())
//	if len(s.Problems()) > 0 { ... }
//
// # Limitations
//
//   - It cannot know that the series is complete: a series whose last anchors
//     were deleted verifies. Keep anchors where the chain's writer cannot
//     rewrite them.
//
// # Assumptions
//
//   - anchors are in the order they were made.
func NewSeries(subject string, anchors []anchor.Anchor, keys anchor.KeySource) *Series {
	s := &Series{subject: subject, anchors: anchors, keys: keys,
		prevHash: anchor.SeedAnchorHash, prevID: anchor.SeedAnchorID}
	s.unchecked = true
	return s
}

func (s *Series) label(n int) string {
	if s.Label != nil {
		return s.Label(n)
	}
	return fmt.Sprintf("anchor %d", n)
}

func (s *Series) fail(format string, args ...any) {
	s.problems = append(s.problems, fmt.Sprintf(format, args...))
	s.stopped = true
}

// checkNext checks the next anchor's place in the series, before the walk
// reaches the entries it covers.
func (s *Series) checkNext() {
	s.unchecked = false
	if s.stopped || s.next >= len(s.anchors) {
		return
	}
	a, n := s.anchors[s.next], s.next+1
	switch {
	case a.Subject != s.subject:
		s.fail("%s is for another chain", s.label(n))
	case a.PreviousAnchorID != s.prevID && n == 1:
		s.fail("%s is the first and does not name the seed anchor as its predecessor", s.label(n))
	case a.PreviousAnchorID != s.prevID:
		s.fail("%s does not name %s as its predecessor", s.label(n), s.label(n-1))
	case a.EntryCount <= s.covered:
		s.fail("%s covers %d entries, no more than %s did: a series must grow",
			s.label(n), a.EntryCount, s.label(n-1))
	case a.CreatedAtMs < s.prevMs:
		s.fail("%s was created before %s: a series does not go back in time", s.label(n), s.label(n-1))
	}
}

// Reached tells the series how far the walk has got. Call it after every
// Walker.Add: when the walk is exactly as long as the next anchor's
// entry_count, that anchor is bound to the walk and its signature verified.
func (s *Series) Reached(w *Walker) {
	if s.unchecked {
		s.checkNext()
	}
	if s.stopped || s.next >= len(s.anchors) || int64(w.Count()) != s.anchors[s.next].EntryCount {
		return
	}
	a, n := s.anchors[s.next], s.next+1
	br, err := w.VerifyAnchor(a, Expect{Subject: s.subject, PreviousAnchorHash: s.prevHash}, s.keys)
	switch {
	case err != nil:
		s.fail("%s: %v", s.label(n), err)
		return
	case !br.Bound || !br.SignatureVerified:
		s.fail("%s does NOT verify: %s", s.label(n), br.Detail)
		return
	}
	s.verified++
	s.covered = a.EntryCount
	s.prevHash, s.prevID, s.prevMs = a.ChainHash, a.AnchorID, a.CreatedAtMs
	s.next++
	s.checkNext()
}

// Finish ends the series check: total is the chain's length. An anchor the
// walk never reached claims more entries than the chain has.
func (s *Series) Finish(total int) {
	if s.unchecked {
		s.checkNext()
	}
	if !s.stopped && s.next < len(s.anchors) {
		s.fail("%s claims %d entries; the chain has %d",
			s.label(s.next+1), s.anchors[s.next].EntryCount, total)
	}
}

// Problems is what is wrong with the series so far: empty, or the first
// problem found.
func (s *Series) Problems() []string { return append([]string(nil), s.problems...) }

// Verified is how many anchors verified, and Covered how many entries the last
// of them covers.
func (s *Series) Verified() int  { return s.verified }
func (s *Series) Covered() int64 { return s.covered }

// VerifyAnchorSeries checks a whole chain against its series of anchors.
//
// # Description
//
// The convenience form of [Series] for a chain held in memory: it walks the
// entries once, binding each anchor as the walk reaches the end of the prefix
// it covers.
//
// # Inputs
//
//   - subject: the subject every anchor must be for
//   - entries: the whole chain, ascending
//   - anchors: its anchors, oldest first; at least one
//   - keys: the keys the anchors may be signed with; must not be nil
//
// # Outputs
//
//   - Result: the chain's own verdict, as [Chain] returns it
//   - []string: the series' problems; empty when every anchor verified
//   - error: ErrNoEntries, no anchors, or no key source
//
// # Example
//
//	res, problems, err := verify.VerifyAnchorSeries(subject, entries, anchors, keys)
//	if err != nil {
//	    return err
//	}
//	if res.Verdict == verify.VerdictBroken || len(problems) > 0 { ... }
//
// # Limitations
//
//   - As [NewSeries]'s.
//
// # Assumptions
//
//   - entries are ordered ascending by sequence, as exported.
func VerifyAnchorSeries(subject string, entries []Entry, anchors []anchor.Anchor,
	keys anchor.KeySource) (Result, []string, error) {
	if len(entries) == 0 {
		return Result{}, nil, ErrNoEntries
	}
	if len(anchors) == 0 {
		return Result{}, nil, fmt.Errorf("verify: no anchors to check")
	}
	if keys == nil {
		return Result{}, nil, fmt.Errorf("verify: a key source is required")
	}
	s := NewSeries(subject, anchors, keys)
	w := NewWalker(Options{})
	for _, e := range entries {
		w.Add(e)
		s.Reached(w)
	}
	s.Finish(w.Count())
	return w.Result(), s.Problems(), nil
}
