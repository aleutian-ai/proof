// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/verify"
)

// anchorOptions are the anchor-related flags of `proof verify`.
//
// Grouped in a struct so the three claims the CLI can make stay visible as
// three, rather than dissolving into a handful of loose booleans:
//
//	(none)             linkage only        — nothing was edited
//	--anchor           + bind              — …and this is the chain it described
//	--anchor --key     + signature         — …and a key you named signed it
type anchorOptions struct {
	anchorPath   string
	previousPath string
	previousHash string
	keyPath      string
	keyTrust     string
}

// anchorResult is what the anchor half of a verification established.
type anchorResult struct {
	bind verify.BindResult

	// assumedGenesis records that no predecessor was supplied, so the anchor
	// was checked as though it were the first in its chain. Reported because a
	// head mismatch alongside it almost certainly means the missing input
	// rather than an attack — the exact confusion `_51` was about.
	assumedGenesis bool
}

// verifyAnchorFlags runs the anchor half of `proof verify`.
//
// # Description
//
// Resolves the predecessor hash, loads the key if one was given, and calls
// either [verify.BindAnchor] or [verify.VerifyAnchor]. Returns nil when no
// --anchor was supplied, which leaves `proof verify` doing exactly what it
// always did.
//
// # Inputs
//
//   - opts: the anchor flags
//   - entries: the chain already loaded for the linkage check
//
// # Outputs
//
//   - *anchorResult: nil when no anchor was requested
//   - error: a usage or I/O failure; a FAILED verification is not an error, it
//     is a result
//
// # Example
//
//	res, err := verifyAnchorFlags(opts, entries)
//
// # Limitations
//
//   - One key, one anchor. A trust store with many keys is a library concern.
//
// # Assumptions
//
//   - entries are the same ones the linkage check just walked.
func verifyAnchorFlags(opts anchorOptions, entries []verify.Entry) (*anchorResult, error) {
	if opts.anchorPath == "" {
		if opts.keyPath != "" {
			return nil, fmt.Errorf("--key was given without --anchor; there is nothing " +
				"for the key to verify. A key checks an ANCHOR's signature, not a chain")
		}
		if opts.previousPath != "" || opts.previousHash != "" {
			return nil, fmt.Errorf("--previous was given without --anchor; it identifies " +
				"the anchor an anchor chains from, and no anchor was supplied")
		}
		return nil, nil
	}

	a, err := loadAnchorFile(opts.anchorPath)
	if err != nil {
		return nil, err
	}

	previousHash, assumed, err := resolvePreviousHash(opts)
	if err != nil {
		return nil, err
	}
	out := &anchorResult{assumedGenesis: assumed}

	if opts.keyPath == "" {
		out.bind, err = verify.BindAnchor(*a, entries, previousHash)
		if err != nil {
			return nil, err
		}
		return out, nil
	}

	ring, err := loadPublicKeyRing(opts.keyPath, opts.keyTrust, a.SigningKeyID)
	if err != nil {
		return nil, err
	}
	out.bind, err = verify.VerifyAnchor(*a, entries, previousHash, ring)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// resolvePreviousHash works out which anchor this one chains from.
//
// # Description
//
// An anchor commits to its predecessor's chain hash but names that predecessor
// only by id, so the hash cannot be recovered from the anchor being checked. A
// caller supplies it as the previous anchor's FILE (the form `proof anchor
// --previous` already takes) or as raw hex, for a verifier who kept the hash
// but not the anchor.
//
// Defaulting to the genesis sentinel is a real choice with a real cost, and the
// second return value exists so the cost is reported rather than absorbed.
//
// # Inputs
//
//   - opts: the anchor flags
//
// # Outputs
//
//   - string: the predecessor's chain hash
//   - bool: true when nothing was supplied and genesis was assumed
//   - error: if both forms were given, or the file could not be read
//
// # Example
//
//	prev, assumed, err := resolvePreviousHash(opts)
//
// # Limitations
//
//   - Does not check that the predecessor is genuine, or that the anchor's
//     PreviousAnchorID names it. Walking to genesis is the caller's job.
//
// # Assumptions
//
//   - None.
func resolvePreviousHash(opts anchorOptions) (string, bool, error) {
	switch {
	case opts.previousPath != "" && opts.previousHash != "":
		return "", false, fmt.Errorf("--previous and --previous-hash both given; " +
			"they are two ways to say the same thing, so supply one")

	case opts.previousPath != "":
		prev, err := loadAnchorFile(opts.previousPath)
		if err != nil {
			return "", false, err
		}
		return prev.ChainHash, false, nil

	case opts.previousHash != "":
		return opts.previousHash, false, nil

	default:
		// Genesis is the only predecessor a caller who named none could have
		// meant. Reported, never silent: an anchor that is NOT the first will
		// come back as head_mismatch, and without this note that reads as
		// evidence the chain was tampered with.
		return anchor.SeedAnchorHash, true, nil
	}
}

// loadPublicKeyRing reads an ML-DSA-65 public key and builds a one-key ring.
//
// # Description
//
// Reads the SubjectPublicKeyInfo PEM that `proof keygen` writes, so an operator
// points at the file they already have rather than extracting raw bytes.
//
// # Inputs
//
//   - path: the public key PEM
//   - trustLabel: platform, provided, or self. Empty means provided.
//   - keyID: the anchor's signing key id, which this key is registered under
//
// # Outputs
//
//   - *anchor.KeyRing: holding exactly this key
//   - error: if the file cannot be read, is the wrong algorithm, or the trust
//     label is unrecognised
//
// # Example
//
//	ring, err := loadPublicKeyRing("pub.pem", "provided", a.SigningKeyID)
//
// # Limitations
//
//   - One key. A real trust store belongs in a caller, not in this CLI.
//
// # Assumptions
//
//   - The caller knows where the key came from; that is what trustLabel says,
//     and this tool cannot check it.
func loadPublicKeyRing(path, trustLabel, keyID string) (*anchor.KeyRing, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	alg, pub, err := keyfile.ParsePublicKey(pem)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if alg != keyfile.MLDSA65 {
		return nil, fmt.Errorf("%s holds a %s key, but anchors are signed with ML-DSA-65",
			path, alg)
	}

	trust := anchor.TrustProvided
	switch trustLabel {
	case "", string(anchor.TrustProvided):
	case string(anchor.TrustPlatform):
		trust = anchor.TrustPlatform
	case string(anchor.TrustSelf):
		trust = anchor.TrustSelf
	default:
		return nil, fmt.Errorf("--key-trust must be one of: platform, provided, self "+
			"(got %q). It decides what a successful verification actually claims, "+
			"so there is no default beyond 'provided'", trustLabel)
	}
	return anchor.NewKeyRing(trust, map[string][]byte{keyID: pub})
}

// printAnchorResult renders the anchor half of a verification.
func printAnchorResult(w *os.File, r *anchorResult) {
	fmt.Fprintln(w)
	if r.bind.Bound {
		fmt.Fprintf(w, "ANCHOR BOUND — %d entries covered\n", r.bind.EntriesCovered)
	} else {
		fmt.Fprintf(w, "ANCHOR DOES NOT DESCRIBE THIS CHAIN — %s\n", r.bind.Outcome)
		if r.bind.Detail != "" {
			fmt.Fprintf(w, "  %s\n", r.bind.Detail)
		}
	}

	if r.bind.SignatureVerified {
		fmt.Fprintf(w, "  signature verified (%s)\n", r.bind.Trust)
		fmt.Fprintf(w, "  establishes: %s\n", r.bind.Trust.Establishes())
	} else {
		fmt.Fprintln(w, "  signature NOT checked — no --key was given, so this says nothing")
		fmt.Fprintln(w, "  about where the anchor came from. Whoever can rewrite the chain")
		fmt.Fprintln(w, "  can also mint an anchor for it.")
	}

	if r.assumedGenesis && !r.bind.Bound {
		fmt.Fprintln(w, "\n  NOTE: no --previous was given, so this anchor was checked as the")
		fmt.Fprintln(w, "  FIRST in its chain. If it is not, that is the likely cause of the")
		fmt.Fprintln(w, "  mismatch above rather than tampering. An anchor names its")
		fmt.Fprintln(w, "  predecessor by id, not by hash, so the hash has to be supplied.")
	}

	fmt.Fprintf(w, "\n  Proven:     %s\n", r.bind.Proven)
	fmt.Fprintf(w, "  NOT proven: %s\n", r.bind.NotProven)
}

// anchorResultJSON is the machine-readable form.
type anchorResultJSON struct {
	Bind           verify.BindResult `json:"anchor"`
	AssumedGenesis bool              `json:"assumed_genesis,omitempty"`
}

// encodeCombinedJSON emits the chain result and the anchor result together.
func encodeCombinedJSON(w *os.File, chain verify.Result, a *anchorResult) error {
	type combined struct {
		verify.Result
		Anchor *anchorResultJSON `json:"anchor_check,omitempty"`
	}
	out := combined{Result: chain}
	if a != nil {
		out.Anchor = &anchorResultJSON{Bind: a.bind, AssumedGenesis: a.assumedGenesis}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
