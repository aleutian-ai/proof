// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/aleutian-ai/proof/exportbundle"
)

// ---------------------------------------------------------------------------
// verify_export_bundle
//
// A sink export bundle (docs/bundle-format.md) is what a sink's operator hands
// someone outside: an auditor, a regulator, a data subject. This tool checks
// one for an agent working on their side.
//
// The keys it trusts are set at launch (--bundle-checkpoint-key,
// --bundle-record-trust), never in a call: a bundle verifies OK under whatever
// key its own author supplies, so a key a model names would prove nothing.
// With no key bound, every consistent bundle is "unauthenticated".
// ---------------------------------------------------------------------------

// bundleKeyFlag collects a repeatable PATH flag of export-bundle public keys.
// Each file is read when the flag is parsed, so a bad one fails the launch.
type bundleKeyFlag struct {
	keys []exportbundle.PublicKey
}

// String implements flag.Value.
func (f *bundleKeyFlag) String() string {
	return fmt.Sprintf("%d key(s)", len(f.keys))
}

// Set implements flag.Value. The path is the human's choice, so it is not held
// to --root, and the error may name it: it goes to stderr at launch.
func (f *bundleKeyFlag) Set(path string) error {
	k, err := exportbundle.ReadPublicKeyFile(path)
	if err != nil {
		return err
	}
	f.keys = append(f.keys, k)
	return nil
}

type verifyExportBundleIn struct {
	Path string `json:"path" jsonschema:"path to a sink export bundle (bundle.json), inside the directory this server was started with"`
}

type exportBundleChain struct {
	// Position is the chain's place in the bundle. Chain ids are pseudonymous
	// personal data (bundle-format §2), so they are not put in a model's context.
	Position int                    `json:"position"`
	Verdict  string                 `json:"verdict"`
	Erasure  string                 `json:"erasure"`
	Counts   exportbundle.Counts    `json:"counts"`
	Problems []exportbundle.Problem `json:"problems"`
}

type verifyExportBundleOut struct {
	// Verdict is ok, unauthenticated, failed, or unreadable (then Reason says why).
	Verdict         string                 `json:"verdict"`
	Reason          string                 `json:"reason,omitempty"`
	CheckpointTrust string                 `json:"checkpoint_trust"`
	RecordTrust     string                 `json:"record_trust"`
	BundleProblems  []exportbundle.Problem `json:"bundle_problems"`
	Chains          []exportBundleChain    `json:"chains"`

	Proven    string `json:"proven"`
	NotProven string `json:"not_proven"`
}

// exportBundleNotProven is bundle-format §1's "does not prove", which every
// verifier must state, whatever the verdict.
const exportBundleNotProven = "Even an OK bundle does not show: that it holds every chain, or that a " +
	"chain is complete to its end (an exporter can leave a chain out, or cut one back to an earlier " +
	"checkpoint); that erased content is gone from anywhere; that a timestamp is true time, or which " +
	"sink a chain came from; anything against a writer who controls the evidence store and every key " +
	"trusted here; anything after the export. Under checkpoint trust alone, the ids and types of the " +
	"entries inside a checkpoint's range are labels, not evidence. That a record's content is TRUE " +
	"(that a model's output was right, say) is never shown: only that it is what was committed. " +
	"This is the bundle writer's own implementation, not an independent verifier."

func (c serverConfig) verifyExportBundle(ctx context.Context, req *mcp.CallToolRequest, in verifyExportBundleIn) (
	*mcp.CallToolResult, verifyExportBundleOut, error) {

	if in.Path == "" {
		return nil, verifyExportBundleOut{}, fmt.Errorf("path is required")
	}
	data, err := c.root.read(in.Path, int64(exportbundle.DefaultLimits().BundleBytes))
	if err != nil {
		return nil, verifyExportBundleOut{}, err
	}
	res, err := exportbundle.Verify(data, c.bundleTrust)
	if err != nil {
		return nil, verifyExportBundleOut{}, fmt.Errorf("internal error: no verdict was reached")
	}

	out := verifyExportBundleOut{
		Verdict:         res.Verdict,
		CheckpointTrust: res.CheckpointTrust,
		RecordTrust:     res.RecordTrust,
		BundleProblems:  nonNilProblems(res.BundleProblems),
		Chains:          []exportBundleChain{},
		NotProven:       exportBundleNotProven,
	}
	if !res.Readable {
		out.Verdict, out.Reason = "unreadable", res.Reason
		out.Proven = "Nothing: the bundle could not be read, so nothing in it was checked."
		return nil, out, nil
	}
	for i, ch := range res.Chains {
		out.Chains = append(out.Chains, exportBundleChain{
			Position: i, Verdict: ch.Verdict, Erasure: ch.Erasure,
			Counts: ch.Counts, Problems: nonNilProblems(ch.Problems),
		})
	}
	switch {
	case len(res.Chains) == 0:
		out.Proven = "Nothing: the bundle holds no chains."
	case res.Verdict == exportbundle.VerdictOK:
		out.Proven = "Every chain links, every disclosed record matches what was committed, and every " +
			"entry is authenticated by a key this server was started with: covered by a checkpoint " +
			"signed by a trusted checkpoint key, or carrying a record signature by a trusted record key."
	case res.Verdict == exportbundle.VerdictUnauthenticated:
		out.Proven = "No problem was found, but at least one entry is not authenticated by a key this " +
			"server was started with: the bundle is internally consistent, and its provenance is not " +
			"established. Whoever made it could have made it consistent."
	default:
		out.Proven = "Nothing about the chains with problems: the bundle does not verify. Each problem " +
			"code names what failed and the first index it failed at."
	}
	if len(c.bundleTrust.Checkpoint) == 0 && len(c.bundleTrust.Record) == 0 {
		out.NotProven += " Note: this server was started with no bundle key " +
			"(--bundle-checkpoint-key, --bundle-record-trust), so no bundle can verify OK here."
	}
	return nil, out, nil
}

// nonNilProblems returns a list that encodes as [], never null.
func nonNilProblems(p []exportbundle.Problem) []exportbundle.Problem {
	if p == nil {
		return []exportbundle.Problem{}
	}
	return p
}
