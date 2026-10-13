// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/aleutian-ai/proof/exportbundle"
)

const sinkVerifyBundleUsage = `usage:
  proof sink verify-bundle <bundle.json> [--key <checkpoint public.pem>]… [--record-trust <record public.pem>]… [--json]

Verifies an export bundle (docs/bundle-format.md) without the sink it came
from. --key names a key trusted for checkpoints and --record-trust one trusted
for record signatures; both repeat. A bundle never adds a key: with no key, a
consistent bundle is UNAUTHENTICATED, not OK. --json prints the structured
result instead of text. This is the bundle writer's own implementation.
Exit: 0 ok · 1 failed · 2 usage, or a bundle or key file that is missing,
unreadable or invalid · 3 the bundle is unreadable · 4 unauthenticated ·
5 an internal error, never a verdict.`

// cmdSinkVerifyBundle runs `proof sink verify-bundle`. It returns the exit
// code of bundle-format §11, after all of its output has been written: the
// caller exits, this function never does.
func cmdSinkVerifyBundle(args []string, stdout, stderr io.Writer) (code int) {
	// A fault in the verifier is exit 5, never a verdict. The message is
	// fixed: a panic value could quote the bundle (bundle-format §10).
	defer func() {
		if recover() != nil {
			fmt.Fprintln(stderr, "proof sink verify-bundle: internal error; no verdict was reached")
			code = exportbundle.ExitInternal
		}
	}()

	fs := flag.NewFlagSet("sink verify-bundle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintln(stderr, sinkVerifyBundleUsage) }
	var keyPaths, recordPaths multiFlag
	fs.Var(&keyPaths, "key", "an ML-DSA-65 public key (PEM) trusted for checkpoints; repeatable")
	fs.Var(&recordPaths, "record-trust", "an ML-DSA-65 public key (PEM) trusted for record signatures; repeatable")
	asJSON := fs.Bool("json", false, "print the structured result (bundle-format §9) instead of text")

	// The bundle path may come before, between or after the flags.
	var bundlePaths []string
	for rest := args; ; {
		if err := fs.Parse(rest); err != nil {
			return exportbundle.ExitUsage
		}
		if rest = fs.Args(); len(rest) == 0 {
			break
		}
		bundlePaths = append(bundlePaths, rest[0])
		rest = rest[1:]
	}
	if len(bundlePaths) != 1 {
		fmt.Fprintf(stderr, "proof sink verify-bundle: want exactly one bundle file, got %d\n\n%s\n",
			len(bundlePaths), sinkVerifyBundleUsage)
		return exportbundle.ExitUsage
	}

	var trust exportbundle.Trust
	for _, set := range []struct {
		paths []string
		keys  *[]exportbundle.PublicKey
	}{{keyPaths, &trust.Checkpoint}, {recordPaths, &trust.Record}} {
		for _, path := range set.paths {
			key, err := exportbundle.ReadPublicKeyFile(path)
			if err != nil {
				fmt.Fprintf(stderr, "proof sink verify-bundle: %v\n", err)
				return exportbundle.ExitUsage
			}
			*set.keys = append(*set.keys, key)
		}
	}
	for _, ck := range trust.Checkpoint {
		for _, rk := range trust.Record {
			if ck.ID() == rk.ID() {
				fmt.Fprintf(stderr, "warning: key %s is trusted for checkpoints and for records: "+
					"one compromise forges both\n", ck.ID())
			}
		}
	}

	limits := exportbundle.DefaultLimits()
	data, err := exportbundle.ReadBundleFile(bundlePaths[0], limits.BundleBytes)
	if err != nil {
		fmt.Fprintf(stderr, "proof sink verify-bundle: %v\n", err)
		return exportbundle.ExitUsage
	}
	res, err := exportbundle.Verify(data, trust)
	if err != nil {
		fmt.Fprintf(stderr, "proof sink verify-bundle: internal error: %v\n", err)
		return exportbundle.ExitInternal
	}

	// Built whole, then written in one call that is checked: a reader of a
	// pipe gets all of it or an exit code that says it did not.
	var out bytes.Buffer
	if *asJSON {
		text, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "proof sink verify-bundle: internal error: %v\n", err)
			return exportbundle.ExitInternal
		}
		out.Write(text)
		out.WriteByte('\n')
	} else if err := res.WriteText(&out); err != nil {
		fmt.Fprintf(stderr, "proof sink verify-bundle: internal error: %v\n", err)
		return exportbundle.ExitInternal
	}
	if _, err := stdout.Write(out.Bytes()); err != nil {
		fmt.Fprintf(stderr, "proof sink verify-bundle: writing the result: %v\n", err)
		return exportbundle.ExitInternal
	}
	return res.ExitCode()
}
