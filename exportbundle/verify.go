// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package exportbundle

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/chainformat"
	"github.com/aleutian-ai/proof/commitment"
	"github.com/aleutian-ai/proof/mldsa"
)

// The problem codes of bundle-format §12: the complete v1 list.
const (
	CodeDuplicateChain         = "duplicate-chain"
	CodeInvalidChainID         = "invalid-chain-id"
	CodeFieldShape             = "field-shape"
	CodeDuplicateEntryID       = "duplicate-entry-id"
	CodeFirstEntry             = "first-entry"
	CodeSequence               = "sequence"
	CodeLink                   = "link"
	CodeChainHash              = "chain-hash"
	CodeEntryType              = "entry-type"
	CodeErasureInvalid         = "erasure-invalid"
	CodeAfterErasure           = "after-erasure"
	CodeErasedEventDisclosed   = "erased-event-disclosed"
	CodeModified               = "modified"
	CodeCheckpointMalformed    = "checkpoint-malformed"
	CodeCheckpointSubject      = "checkpoint-subject"
	CodeCheckpointSequence     = "checkpoint-sequence"
	CodeCheckpointOverreach    = "checkpoint-overreach"
	CodeCheckpointBinding      = "checkpoint-binding"
	CodeCheckpointUnknownKey   = "checkpoint-unknown-key"
	CodeCheckpointBadSignature = "checkpoint-bad-signature"
	CodeUnsigned               = "unsigned"
	CodeMalformedSignature     = "malformed-signature"
	CodeUnknownKey             = "unknown-key"
	CodeBadSignature           = "bad-signature"
)

// The fixed strings the checks hash or compare (sink-format §2, §4.1, §9.1;
// format-spec §9.4).
const (
	typeEvent      = "sink.event"
	typeErasure    = "sink.erasure"
	erasureDomain  = "aleutian.sink.erasure.v1:"
	erasureRecord  = `{"erased":"every earlier event on this chain","through_global_seq":"%s"}`
	recordDomain   = "aleutian.proof.record.v1"
	recordDomainV2 = "aleutian.proof.record.v2" // also its ML-DSA context (sink-format §9.1)
	seedAnchorID   = "anchor_00000000-0000-0000-0000-000000000000"
	seedAnchorHash = "03443d96d3b369839f63f98b712463efba04c00551822743108d60c5f291627859ff0b7dc29f99e3c847b07b0b18bb385426c744847c1b070563f8dd07271f27"
)

// What an entry was found to be, as bits of entryState.flags.
const (
	flagWellFormed uint8 = 1 << iota
	flagEvent
	flagErasure
	flagDisclosedBad
	flagHoldsErasure
	flagGenuineErasure
	flagRecordAuthenticated
)

var (
	chainIDPattern   = regexp.MustCompile(`\A[a-z0-9][a-z0-9_-]{0,30}\.[0-9a-f]{32}\z`)
	globalSeqPattern = regexp.MustCompile(`\A(?:0|[1-9][0-9]{0,18})\z`)
	timestampPattern = regexp.MustCompile(`\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z\z`)
)

// entryState is what the checks learn about one entry.
type entryState struct {
	seq   int64
	flags uint8
}

// tally counts a chain's or a bundle's problems by code.
type tally struct {
	problems []Problem
}

// verifier holds the two trusted key sets, by computed key id.
type verifier struct {
	checkpointKeys map[string][]byte
	recordKeys     map[string][]byte
	v2             bool // the bundle is aleutian.proof.bundle.v2 (§16)
}

// Verify checks a bundle against bundle-format.md and returns the result of
// its §9.
//
// # Description
//
// Reads the bundle strictly (§3, §4), within the limits of §5; an unreadable
// bundle returns a Result with Readable false and its one reason. Otherwise
// every chain is checked on its own (§7), then the bundle (§8). No signature
// is verified before the whole bundle has been read and found within every
// limit.
//
// # Inputs
//
//   - bundle: the bundle's bytes
//   - trust: the keys the caller trusts for checkpoints and for record
//     signatures. An empty set means that dimension is not checked.
//
// # Outputs
//
//   - Result: the structured result. Its Verdict is a statement about the
//     bundle under these keys.
//   - error: an internal failure of the verifier, never a verdict on the
//     bundle. It carries no value from the bundle.
//
// # Example
//
//	data, err := exportbundle.ReadBundleFile(path, exportbundle.DefaultLimits().BundleBytes)
//	if err != nil {
//	    return err
//	}
//	res, err := exportbundle.Verify(data, exportbundle.Trust{Checkpoint: keys})
//	if err != nil {
//	    return err
//	}
//	fmt.Println(res.Verdict)
//
// # Limitations
//
//   - The limits of bundle-format §1 hold for every verdict: a bundle cannot
//     show that it is complete, that erased content is gone, or anything
//     against a writer who holds every trusted key.
//   - This is the bundle writer's own implementation.
//   - Memory: the bundle, plus its entries as strings (at most the bundle's
//     size again, and bounded by the entry limit).
//
// # Assumptions
//
//   - The keys came from outside the bundle. A bundle never adds a key.
func Verify(bundle []byte, trust Trust) (Result, error) {
	return VerifyWithLimits(bundle, trust, DefaultLimits())
}

// VerifyWithLimits is Verify with limits other than those of §5.
//
// # Description
//
// A conformant verifier applies exactly the limits of §5: this exists so that
// the limits, and their place in §9.1's precedence, can be tested without a
// 256 MiB input.
//
// # Inputs
//
//   - bundle, trust: as Verify
//   - limits: the limits to apply. A zero field means its §5 value.
//
// # Outputs
//
// As Verify.
//
// # Example
//
//	res, err := exportbundle.VerifyWithLimits(data, trust, exportbundle.Limits{Entries: 10})
//
// # Limitations
//
//   - As Verify. A result under other limits is not a conformant result.
//
// # Assumptions
//
//   - As Verify.
func VerifyWithLimits(bundle []byte, trust Trust, limits Limits) (Result, error) {
	v := verifier{checkpointKeys: keySet(trust.Checkpoint), recordKeys: keySet(trust.Record)}
	res := Result{
		CheckpointTrust: trustValue(len(v.checkpointKeys) > 0),
		RecordTrust:     trustValue(len(v.recordKeys) > 0),
	}
	chains, version, reason := readBundle(bundle, limits.withDefaults())
	if reason != "" {
		res.Reason = reason
		return res, nil
	}
	v.v2 = version == 2
	res.Readable = true

	// §8: every copy of a duplicated id is keyed by position, and checked.
	copies := make(map[string]int, len(chains))
	var bundleProblems tally
	for i := range chains {
		copies[chains[i].id]++
		if copies[chains[i].id] > 1 {
			bundleProblems.add(CodeDuplicateChain, i)
		}
	}
	res.BundleProblems = bundleProblems.sorted()
	res.Chains = make([]ChainResult, len(chains))
	res.Verdict = VerdictOK
	if len(chains) == 0 {
		// An empty export must never read as a pass (§9.2).
		res.Verdict = VerdictUnauthenticated
	}
	for i := range chains {
		c := &chains[i]
		cr, valid, err := v.checkChain(c)
		if err != nil {
			return Result{}, fmt.Errorf("chain at position %d: %w", i, err)
		}
		cr.Key = c.id
		if !valid || copies[c.id] > 1 {
			cr.Key = "#" + strconv.Itoa(i)
		}
		res.Chains[i] = cr
		res.Verdict = worse(res.Verdict, cr.Verdict)
		// The entries are not needed again.
		c.entries, c.checkpoints = nil, nil
	}
	if len(res.BundleProblems) > 0 {
		res.Verdict = VerdictFailed
	}
	return res, nil
}

// checkChain runs §7 on one chain. valid reports whether its chain id is a
// sink chain id.
func (v *verifier) checkChain(c *rawChain) (cr ChainResult, valid bool, err error) {
	var problems tally
	entries := c.entries
	n := len(entries)
	counts := Counts{Entries: n}
	valid = chainIDPattern.MatchString(c.id)
	if !valid {
		problems.addNoIndex(CodeInvalidChainID)
	}

	// §7.1 to §7.3 in one pass: shapes, repeated ids, links, the chain hash,
	// and which entries hold the erasure hash.
	state := make([]entryState, n)
	ids := make(map[string]struct{}, n)
	firstMalformed := n
	lastErasure := -1
	for i := range entries {
		e := &entries[i]
		s := &state[i]
		switch e.entryType {
		case typeEvent:
			s.flags |= flagEvent
			counts.Events++
		case typeErasure:
			s.flags |= flagErasure
		}
		if e.sig != nil {
			counts.RecordSignaturesPresent++
		}
		seq, ts, wellFormed := entryShape(e, v.v2)
		disclosedBad := e.disclosed != nil && (s.flags&flagEvent == 0 || !disclosedShape(e.disclosed))
		if disclosedBad {
			s.flags |= flagDisclosedBad
		}
		if !wellFormed || disclosedBad {
			problems.add(CodeFieldShape, i)
		}
		if _, repeat := ids[e.entryID]; repeat {
			problems.add(CodeDuplicateEntryID, i)
		} else if wellFormed {
			ids[e.entryID] = struct{}{}
		}
		if !wellFormed {
			// Not hashed, linked, classified or authenticated (§7.1).
			firstMalformed = min(firstMalformed, i)
			continue
		}
		s.seq = seq
		s.flags |= flagWellFormed
		switch {
		case i == 0:
			if e.globalSeq != "0" || e.previousHash != "" {
				problems.add(CodeFirstEntry, i)
			}
		case state[i-1].flags&flagWellFormed != 0:
			prev := &entries[i-1]
			if state[i-1].seq == math.MaxInt64 || seq != state[i-1].seq+1 {
				problems.add(CodeSequence, i)
			}
			if e.previousHash != prev.chainHash {
				problems.add(CodeLink, i)
			}
			if e.contentHash == erasureHash(prev.globalSeq) {
				s.flags |= flagHoldsErasure
				lastErasure = i
			}
		}
		if !v.chainHashRecomputes(e, seq, ts) {
			problems.add(CodeChainHash, i)
		}
	}

	// §7.4: the first matching row decides each well-formed entry.
	for i := range entries {
		e := &entries[i]
		s := &state[i]
		f := s.flags
		if f&flagWellFormed == 0 {
			continue
		}
		switch {
		case lastErasure >= 0 && i > lastErasure:
			problems.add(CodeAfterErasure, i)
		case f&flagDisclosedBad != 0:
			// Its field-shape is its outcome (§7.1).
		case f&flagHoldsErasure != 0 && f&flagErasure != 0:
			s.flags |= flagGenuineErasure
			counts.Erasures++
		case f&flagHoldsErasure != 0, f&flagErasure != 0:
			problems.add(CodeErasureInvalid, i)
		case f&flagEvent == 0:
			problems.add(CodeEntryType, i)
		case lastErasure >= 0 && e.disclosed == nil:
			counts.Erased++
		case lastErasure >= 0:
			problems.add(CodeErasedEventDisclosed, i)
		case e.disclosed == nil:
			counts.Committed++
		case opens(e):
			counts.Opened++
		default:
			problems.add(CodeModified, i)
		}
	}

	covered, err := v.checkCheckpoints(c, valid, firstMalformed, &problems, &counts)
	if err != nil {
		return ChainResult{}, valid, err
	}
	counts.Unanchored = n - covered

	if len(v.recordKeys) > 0 {
		for i := range entries {
			if code := v.checkRecordSignature(c.id, valid, &entries[i], state[i]); code != "" {
				problems.add(code, i)
				continue
			}
			state[i].flags |= flagRecordAuthenticated
		}
	}

	// §7.8. A covered entry is well-formed: step e required it.
	checkpointTrust := len(v.checkpointKeys) > 0
	for i := range state {
		byCheckpoint := checkpointTrust && i < covered && state[i].flags&flagWellFormed != 0
		byRecord := state[i].flags&flagRecordAuthenticated != 0
		if byCheckpoint {
			counts.CheckpointAuthenticated++
		}
		if byRecord {
			counts.RecordAuthenticated++
		}
		if byCheckpoint || byRecord {
			counts.Authenticated++
		}
	}
	counts.Unauthenticated = n - counts.Authenticated

	cr = ChainResult{Erasure: ErasureNone, Counts: counts, Problems: problems.sorted()}
	if lastErasure >= 0 && state[lastErasure].flags&flagGenuineErasure != 0 {
		cr.Erasure = ErasureRecorded
		if len(cr.Problems) == 0 {
			switch {
			case checkpointTrust && lastErasure < covered:
				cr.Erasure = ErasureAnchored
			case state[lastErasure].flags&flagRecordAuthenticated != 0:
				cr.Erasure = ErasureSigned
			}
		}
	}
	switch {
	case len(cr.Problems) > 0:
		cr.Verdict = VerdictFailed
	case counts.Unauthenticated > 0:
		cr.Verdict = VerdictUnauthenticated
	default:
		cr.Verdict = VerdictOK
	}
	return cr, valid, nil
}

// checkCheckpoints runs §7.6 and returns how many entries the last passing
// checkpoint covers. The first failing step of any checkpoint is its one
// problem and ends the series. Step e asks whether a prefix is all
// well-formed by comparing with the first malformed index, found once, so the
// series costs one step per checkpoint whatever the chain's length.
func (v *verifier) checkCheckpoints(c *rawChain, valid bool, firstMalformed int, problems *tally, counts *Counts) (int, error) {
	n := uint64(len(c.entries))
	previousID, previousHash, previousCount := seedAnchorID, seedAnchorHash, uint64(0)
	covered := 0
	for k, text := range c.checkpoints {
		code, ck, err := v.checkCheckpoint(c, text, valid, firstMalformed, n, previousID, previousHash, previousCount)
		if err != nil {
			return 0, fmt.Errorf("checkpoint %d: %w", k, err)
		}
		if code != "" {
			problems.add(code, k)
			break
		}
		counts.Checkpoints++
		covered = int(ck.entryCount)
		previousID, previousHash, previousCount = ck.anchorID, ck.chainHash, ck.entryCount
	}
	return covered, nil
}

// checkCheckpoint runs steps a to g of §7.6 on one checkpoint and returns the
// code of the first step that fails, or "".
func (v *verifier) checkCheckpoint(c *rawChain, text []byte, valid bool, firstMalformed int, n uint64,
	previousID, previousHash string, previousCount uint64) (string, checkpoint, error) {
	ck, ok := parseCheckpoint(text, map[bool]int{false: 1, true: 2}[v.v2])
	switch {
	case !ok:
		return CodeCheckpointMalformed, ck, nil
	case !valid || ck.subject != c.id:
		return CodeCheckpointSubject, ck, nil
	case ck.previousAnchorID != previousID || ck.entryCount <= previousCount,
		ck.v7 && ck.previousAnchorHash != previousHash:
		return CodeCheckpointSequence, ck, nil
	case ck.entryCount > n:
		return CodeCheckpointOverreach, ck, nil
	}
	count := int(ck.entryCount)
	tip := &c.entries[count-1]
	var want string
	if ck.v7 {
		// §16: the range is 0 … entry_count−1 by sequence (shape-checked in
		// step a), and the tip is that entry.
		if count > firstMalformed {
			return CodeCheckpointBinding, ck, nil
		}
		want = anchor.ChainHashV7(previousHash, c.id, 0, int64(ck.entryCount)-1, tip.chainHash)
	} else {
		if count > firstMalformed || ck.rangeStart != c.entries[0].entryID || ck.rangeEnd != tip.entryID {
			return CodeCheckpointBinding, ck, nil
		}
		var err error
		if want, err = anchor.ChainHash(previousHash, c.id, ck.rangeStart, ck.rangeEnd, tip.chainHash); err != nil {
			// Unreachable: every input was checked to hold no delimiter.
			return "", ck, fmt.Errorf("anchor chain hash refused checked inputs")
		}
	}
	if want != ck.chainHash {
		return CodeCheckpointBinding, ck, nil
	}
	if len(v.checkpointKeys) == 0 {
		return "", ck, nil
	}
	key, known := v.checkpointKeys[ck.signingKeyID]
	if !known {
		return CodeCheckpointUnknownKey, ck, nil
	}
	a := anchor.Anchor{
		Version:          int(ck.version),
		AnchorID:         ck.anchorID,
		Subject:          ck.subject,
		ChainHash:        ck.chainHash,
		Range:            anchor.EntryRange{StartEntryID: ck.rangeStart, EndEntryID: ck.rangeEnd},
		EntryCount:       int64(ck.entryCount),
		SigningKeyID:     ck.signingKeyID,
		CreatedAtMs:      int64(ck.createdAtMs),
		PreviousAnchorID: ck.previousAnchorID,
		VerifiedThrough:  int64(ck.verifiedThrough),
	}
	if ck.v7 {
		a.Range = anchor.EntryRange{StartSeq: 0, EndSeq: int64(ck.entryCount) - 1}
		a.PreviousAnchorHash = ck.previousAnchorHash
	}
	canonical, err := anchor.Canonicalize(a)
	if err != nil {
		// Unreachable: step a admits version 6 (v1) or 7 (v2) only.
		return "", ck, fmt.Errorf("anchor canonical form refused a version %d checkpoint", ck.version)
	}
	if mldsa.VerifyWithContext(mldsa.MLDSA65, key, canonical, ck.signature,
		[]byte(anchor.SigningContext(int(ck.version)))) != nil {
		return CodeCheckpointBadSignature, ck, nil
	}
	return "", ck, nil
}

// checkRecordSignature runs §7.7 on one entry and returns the problem of the
// first matching row, or "" when the entry is record-authenticated.
func (v *verifier) checkRecordSignature(chainID string, valid bool, e *rawEntry, s entryState) string {
	if e.sig == nil {
		return CodeUnsigned
	}
	keyID, signatureText := e.sig.a, e.sig.b
	signature, ok := decodeCanonicalBase64(signatureText)
	if !hex32Pattern.MatchString(keyID) || !ok || len(signature) != signatureSize {
		return CodeMalformedSignature
	}
	key, known := v.recordKeys[keyID]
	if !known {
		return CodeUnknownKey
	}
	// No envelope can be built: reported without verifying.
	if s.flags&flagWellFormed == 0 || !valid || s.flags&(flagEvent|flagErasure) == 0 ||
		(e.previousHash == "") != (e.globalSeq == "0") {
		return CodeBadSignature
	}
	env, ctx := recordEnvelope(chainID, e, keyID, v.v2)
	if mldsa.VerifyWithContext(mldsa.MLDSA65, key, env, signature, ctx) != nil {
		return CodeBadSignature
	}
	return ""
}

// add counts one occurrence of a code at an index.
func (t *tally) add(code string, index int) {
	for i := range t.problems {
		p := &t.problems[i]
		if p.Code == code {
			p.Count++
			if p.First != nil && index < *p.First {
				*p.First = index
			}
			return
		}
	}
	t.problems = append(t.problems, Problem{Code: code, Count: 1, First: &index})
}

// addNoIndex counts one occurrence of a code that has no index.
func (t *tally) addNoIndex(code string) {
	t.problems = append(t.problems, Problem{Code: code, Count: 1})
}

// sorted returns the problems sorted by code in byte order (§9.2).
func (t *tally) sorted() []Problem {
	sort.Slice(t.problems, func(i, j int) bool { return t.problems[i].Code < t.problems[j].Code })
	return t.problems
}

// keySet indexes keys by computed id. A key given twice counts once.
func keySet(keys []PublicKey) map[string][]byte {
	set := make(map[string][]byte, len(keys))
	for _, k := range keys {
		if k.id != "" {
			set[k.id] = k.raw
		}
	}
	return set
}

// trustValue is a trust dimension's value in the result.
func trustValue(checked bool) string {
	if checked {
		return TrustChecked
	}
	return TrustNotChecked
}

// worse returns the verdict that takes precedence: failed, then
// unauthenticated, then ok (§1).
func worse(a, b string) string {
	switch {
	case a == VerdictFailed || b == VerdictFailed:
		return VerdictFailed
	case a == VerdictUnauthenticated || b == VerdictUnauthenticated:
		return VerdictUnauthenticated
	}
	return VerdictOK
}

// entryShape checks the six members that make an entry well-formed (§7.1
// step 3) against §4.3, and returns the sequence and the instant they spell.
func entryShape(e *rawEntry, v2 bool) (seq int64, ts time.Time, ok bool) {
	ts, tsOK := parseTimestamp(e.timestamp)
	seq, seqOK := parseGlobalSeq(e.globalSeq)
	ok = tsOK && seqOK &&
		entryIDPattern.MatchString(e.entryID) &&
		(e.previousHash == "" || hex128Pattern.MatchString(e.previousHash)) &&
		hex128Pattern.MatchString(e.contentHash) &&
		hex128Pattern.MatchString(e.chainHash) &&
		(!v2 || hex64Pattern.MatchString(e.salt) && hex128Pattern.MatchString(e.leafHash))
	return seq, ts, ok
}

// chainHashRecomputes is §7.2 step 3: v1, chain hash v3; v2 (§16), the leaf
// hash v4 over the stored id, type, content hash and salt, then chain hash v4
// over the stored leaf hash.
func (v *verifier) chainHashRecomputes(e *rawEntry, seq int64, ts time.Time) bool {
	if !v.v2 {
		return chainformat.ComputeChainHashV3Unchecked(e.previousHash, seq, ts, e.contentHash) == e.chainHash
	}
	return chainformat.ComputeLeafHashV4Unchecked(e.entryID, e.entryType, e.contentHash, e.salt) == e.leafHash &&
		chainformat.ComputeChainHashV4Unchecked(e.previousHash, seq, ts, e.leafHash) == e.chainHash
}

// parseGlobalSeq reads a `global_seq`: base-10, no sign, no leading zeros,
// at most 2^63-1.
func parseGlobalSeq(s string) (int64, bool) {
	if !globalSeqPattern.MatchString(s) {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

// parseTimestamp reads a `timestamp`: exactly YYYY-MM-DDTHH:MM:SS.ffffffZ,
// and a real UTC instant in the years 0001 to 9999.
func parseTimestamp(s string) (time.Time, bool) {
	if !timestampPattern.MatchString(s) {
		return time.Time{}, false
	}
	// The pattern guarantees digits at each of these positions.
	num := func(from, to int) int {
		n, _ := strconv.Atoi(s[from:to])
		return n
	}
	year, month, day := num(0, 4), num(5, 7), num(8, 10)
	hour, minute, second, micro := num(11, 13), num(14, 16), num(17, 19), num(20, 26)
	if year < 1 || month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59 {
		return time.Time{}, false
	}
	t := time.Date(year, time.Month(month), day, hour, minute, second, micro*1000, time.UTC)
	// A day past the month's end rolls into the next month.
	if t.Day() != day {
		return time.Time{}, false
	}
	return t, true
}

// disclosedShape checks a `disclosed` against §4.3: canonical base64 of 1 to
// 65,536 bytes, and a nonce of 64 lowercase hex.
func disclosedShape(d *rawPair) bool {
	if !hex64Pattern.MatchString(d.b) || len(d.a) == 0 || len(d.a) > maxContent {
		return false
	}
	content, ok := decodeCanonicalBase64(d.a)
	return ok && len(content) >= 1 && len(content) <= 65536
}

// opens reports whether a disclosed event's content and nonce open its
// commitment (format-spec §8). The disclosure has passed disclosedShape.
func opens(e *rawEntry) bool {
	content, ok := decodeCanonicalBase64(e.disclosed.a)
	if !ok {
		return false
	}
	nonce, err := hex.DecodeString(e.disclosed.b)
	if err != nil {
		return false
	}
	return commitment.Verify(e.contentHash, nonce, content)
}

// erasureHash is the content hash of a genuine erasure entry whose
// predecessor has the stored sequence previousSeq (sink-format §2, §4.1).
func erasureHash(previousSeq string) string {
	sum := sha512.Sum512([]byte(erasureDomain + fmt.Sprintf(erasureRecord, previousSeq)))
	return hex.EncodeToString(sum[:])
}

// recordEnvelope builds the bytes a record signature covers (sink-format
// §9.1), from the entry's strings as stored.
func recordEnvelope(chainID string, e *rawEntry, keyID string, v2 bool) (env, mldsaContext []byte) {
	domain := recordDomain
	values := []string{chainID, e.entryID, e.entryType, e.globalSeq, e.previousHash, e.timestamp, e.contentHash, keyID}
	if v2 {
		domain, mldsaContext = recordDomainV2, []byte(recordDomainV2)
		values = append(values, e.leafHash)
	}
	out := append([]byte(domain), 0)
	for i, v := range values {
		out = append(out, byte(i+1))
		out = binary.BigEndian.AppendUint32(out, uint32(len(v)))
		out = append(out, v...)
	}
	return out, mldsaContext
}
