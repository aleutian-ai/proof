// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package exportbundle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ResultID is the `result` member of every result (bundle-format §9). The
// members, values and codes of a result are a closed set under this id.
const ResultID = "aleutian.proof.bundle-result.v1"

// The verdicts of a chain and of a bundle (§1).
const (
	VerdictOK              = "ok"
	VerdictUnauthenticated = "unauthenticated"
	VerdictFailed          = "failed"
)

// The values of a trust dimension (§6, §9.2).
const (
	TrustChecked    = "checked"
	TrustNotChecked = "not_checked"
)

// The erasure states of a chain (§7.9).
const (
	ErasureNone     = "none"
	ErasureRecorded = "recorded"
	ErasureAnchored = "anchored"
	ErasureSigned   = "signed"
)

// The exit codes of bundle-format §11.
const (
	ExitOK              = 0
	ExitFailed          = 1
	ExitUsage           = 2
	ExitUnreadable      = 3
	ExitUnauthenticated = 4
	ExitInternal        = 5
)

// Result is the structured result of bundle-format §9. Its JSON form is
// exactly §9.1's for an unreadable bundle and §9.2's for a readable one.
type Result struct {
	// Readable is false when the bundle could not be read; Reason says why.
	Readable bool
	// Reason is the §9.1 reason code of an unreadable bundle.
	Reason string
	// CheckpointTrust and RecordTrust are "checked" or "not_checked". They
	// are set for an unreadable bundle too, for the human-readable output;
	// the §9.1 JSON has no trust members.
	CheckpointTrust string
	RecordTrust     string
	// Verdict is "ok", "unauthenticated" or "failed".
	Verdict string
	// BundleProblems are the bundle-level problems (§8), sorted by code.
	BundleProblems []Problem
	// Chains holds one result per chain, in the bundle's order.
	Chains []ChainResult
}

// ChainResult is one chain's part of a result.
type ChainResult struct {
	// Key is the chain's key in the result's `chains` object: its chain id,
	// or "#<position>" when the id is invalid or duplicated (§9.3).
	Key string `json:"-"`
	// Verdict is "ok", "unauthenticated" or "failed" (§7.10).
	Verdict string `json:"verdict"`
	// Erasure is the chain's erasure state (§7.9).
	Erasure string `json:"erasure"`
	// Counts are the counts of §9.2.
	Counts Counts `json:"counts"`
	// Problems are the chain's problems, sorted by code.
	Problems []Problem `json:"problems"`
}

// Counts are a chain's counts (§9.2), in the order the specification lists
// them. Every count is present in the JSON, zero or not.
type Counts struct {
	Entries                 int `json:"entries"`
	Events                  int `json:"events"`
	Erasures                int `json:"erasures"`
	Opened                  int `json:"opened"`
	Committed               int `json:"committed"`
	Erased                  int `json:"erased"`
	Checkpoints             int `json:"checkpoints"`
	Unanchored              int `json:"unanchored"`
	Authenticated           int `json:"authenticated"`
	Unauthenticated         int `json:"unauthenticated"`
	CheckpointAuthenticated int `json:"checkpoint_authenticated"`
	RecordAuthenticated     int `json:"record_authenticated"`
	RecordSignaturesPresent int `json:"record_signatures_present"`
}

// Problem is one problem code, how often it occurred, and the lowest index it
// occurred at. First is nil for `invalid-chain-id`, which has no index.
type Problem struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
	First *int   `json:"first"`
}

// MarshalJSON writes the result exactly as bundle-format §9 defines it.
//
// # Description
//
// An unreadable bundle is `result`, `readable` and `reason`, and nothing else.
// A readable one is the members of §9.2 in the specification's order, with
// `chains` an object keyed as §9.3 says, in the bundle's order.
//
// # Inputs
//
// None.
//
// # Outputs
//
//   - []byte: compact JSON
//   - error: only if encoding a member fails
//
// # Example
//
//	out, err := json.MarshalIndent(result, "", "  ")
//
// # Limitations
//
//   - The result is pseudonymous personal data: it is keyed by chain id
//     (bundle-format §2).
//
// # Assumptions
//
//   - The Result came from Verify, so every key is a valid chain id or
//     "#<position>".
func (r Result) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(`{"result":"` + ResultID + `","readable":`)
	if !r.Readable {
		b.WriteString(`false,"reason":`)
		if err := writeJSON(&b, r.Reason); err != nil {
			return nil, err
		}
		b.WriteByte('}')
		return b.Bytes(), nil
	}
	b.WriteString(`true`)
	for _, m := range []struct{ name, value string }{
		{"checkpoint_trust", r.CheckpointTrust}, {"record_trust", r.RecordTrust}, {"verdict", r.Verdict},
	} {
		b.WriteString(`,"` + m.name + `":`)
		if err := writeJSON(&b, m.value); err != nil {
			return nil, err
		}
	}
	b.WriteString(`,"bundle_problems":`)
	if err := writeJSON(&b, problemList(r.BundleProblems)); err != nil {
		return nil, err
	}
	b.WriteString(`,"chains":{`)
	for i, c := range r.Chains {
		if i > 0 {
			b.WriteByte(',')
		}
		if err := writeJSON(&b, c.Key); err != nil {
			return nil, err
		}
		b.WriteByte(':')
		c.Problems = problemList(c.Problems)
		if err := writeJSON(&b, c); err != nil {
			return nil, err
		}
	}
	b.WriteString(`}}`)
	return b.Bytes(), nil
}

// ExitCode returns the process exit code bundle-format §11 gives this result.
//
// # Description
//
// 0 for `ok`, 1 for `failed`, 4 for `unauthenticated`, 3 for an unreadable
// bundle. Usage errors (2) and internal errors (5) are not results.
//
// # Inputs
//
// None.
//
// # Outputs
//
//   - int: the exit code; ExitInternal for a Result with no known verdict
//
// # Example
//
//	os.Exit(result.ExitCode())
//
// # Limitations
//
//   - Exit 0 means `ok` under the keys the verifier supplied, within the
//     limits of bundle-format §1.
//
// # Assumptions
//
//   - The Result came from Verify.
func (r Result) ExitCode() int {
	if !r.Readable {
		return ExitUnreadable
	}
	switch r.Verdict {
	case VerdictOK:
		return ExitOK
	case VerdictFailed:
		return ExitFailed
	case VerdictUnauthenticated:
		return ExitUnauthenticated
	}
	return ExitInternal
}

// WriteText writes the human-readable output of bundle-format §10.
//
// # Description
//
// States that this is the writer's own implementation, the verdict as OK,
// FAILED, UNAUTHENTICATED or UNREADABLE with its reason, both trust
// dimensions, each chain with its counts and problem codes, and the limits of
// §1. It prints no value from the bundle except a valid chain id: indexes and
// codes only.
//
// # Inputs
//
//   - w: where to write
//
// # Outputs
//
//   - error: the first write error
//
// # Example
//
//	err := result.WriteText(os.Stdout)
//
// # Limitations
//
//   - One line per chain: a bundle of 100,000 chains prints 100,000 lines.
//   - A valid chain id is pseudonymous personal data (bundle-format §2).
//
// # Assumptions
//
//   - The Result came from Verify.
func (r Result) WriteText(w io.Writer) error {
	var b strings.Builder
	b.WriteString("proof sink verify-bundle: the bundle writer's own implementation (the reference verifier, not an independent one)\n")
	if !r.Readable {
		fmt.Fprintf(&b, "UNREADABLE: %s\n", r.Reason)
		fmt.Fprintf(&b, "checkpoint keys: %s; record keys: %s. Nothing in the bundle was checked.\n",
			given(r.CheckpointTrust), given(r.RecordTrust))
		b.WriteString(limitsText)
		_, err := io.WriteString(w, b.String())
		return err
	}
	fmt.Fprintf(&b, "verdict: %s\n", strings.ToUpper(r.Verdict))
	fmt.Fprintf(&b, "checkpoint trust: %s; record trust: %s\n", trustText(r.CheckpointTrust), trustText(r.RecordTrust))
	switch {
	case len(r.Chains) == 0:
		b.WriteString("the bundle holds no chains: it proves nothing\n")
	case r.Verdict == VerdictUnauthenticated:
		b.WriteString("no problem found, but at least one entry is not authenticated by a key you gave: " +
			"the evidence is internally consistent, and its provenance is not established\n")
	}
	if len(r.BundleProblems) > 0 {
		fmt.Fprintf(&b, "bundle problems: %s\n", problemText(r.BundleProblems, "chain"))
	}
	for _, c := range r.Chains {
		n := c.Counts
		fmt.Fprintf(&b, "chain %s: %s, erasure %s; %d entries (%d events: %d opened, %d committed, %d erased; %d erasures); "+
			"%d checkpoints, %d entries unanchored; %d authenticated (%d by checkpoint, %d by record signature), "+
			"%d unauthenticated; %d record signatures present\n",
			c.Key, strings.ToUpper(c.Verdict), c.Erasure, n.Entries, n.Events, n.Opened, n.Committed, n.Erased, n.Erasures,
			n.Checkpoints, n.Unanchored, n.Authenticated, n.CheckpointAuthenticated, n.RecordAuthenticated,
			n.Unauthenticated, n.RecordSignaturesPresent)
		if len(c.Problems) > 0 {
			fmt.Fprintf(&b, "  problems: %s\n", problemText(c.Problems, "index"))
		}
	}
	b.WriteString(limitsText)
	_, err := io.WriteString(w, b.String())
	return err
}

// limitsText is §1's "does not prove", which every verifier must state.
const limitsText = `Limits (docs/bundle-format.md §1). Even an OK bundle does not show:
  - that it holds every chain, or that a chain is complete to its end: an exporter can leave a
    chain out, or cut one back to an earlier checkpoint, dropping later entries and an erasure;
  - that erased content is gone from anywhere: an erasure was recorded, nothing more;
  - that a timestamp is true time, or which sink a chain came from;
  - anything against a writer who controls the evidence store and every key you trust;
  - anything after the export: a bundle is a historical artifact, and a later erasure does not reach it.
  Under checkpoint trust alone, the ids and types of the entries inside a checkpoint's range are labels, not evidence.
`

// problemList returns a list that encodes as `[]`, never `null`.
func problemList(p []Problem) []Problem {
	if p == nil {
		return []Problem{}
	}
	return p
}

// writeJSON appends v's JSON, without the newline an Encoder adds.
func writeJSON(b *bytes.Buffer, v interface{}) error {
	out, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	b.Write(out)
	return nil
}

// trustText words a trust dimension for a reader.
func trustText(v string) string {
	if v == TrustChecked {
		return "checked"
	}
	return "not checked (no key given)"
}

// given words a key set for an unreadable bundle, whose result has no trust
// members.
func given(v string) string {
	if v == TrustChecked {
		return "given"
	}
	return "none given"
}

// problemText lists problems as codes, counts and first indexes.
func problemText(ps []Problem, unit string) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		if p.First == nil {
			parts[i] = fmt.Sprintf("%s (count %d)", p.Code, p.Count)
			continue
		}
		parts[i] = fmt.Sprintf("%s (count %d, first at %s %d)", p.Code, p.Count, unit, *p.First)
	}
	return strings.Join(parts, ", ")
}
