// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	ctx "context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/aleutian-ai/proof/sink"
)

const sinkExportUsage = `usage:
  proof sink export [--dir D] (--chain C… | --subject S [--class K] | --all)
                    [--disclose none|all|<entry id>,…] --out bundle.json

Writes the selected chains as a bundle (docs/bundle-format.md) that anyone can
verify without this folder or proof. Without --disclose it holds no content:
integrity only. It is still pseudonymous personal data. Messages go to
standard error; the bundle goes only to --out, which must not exist.`

// cmdSinkExport runs `proof sink export`.
//
// The bundle is written to a temporary file beside --out, synced and closed,
// then linked into place only if --out does not exist; on any failure the
// temporary file is removed, so a failed export leaves nothing behind.
func cmdSinkExport(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sink export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "sink-data", "the sink folder")
	out := fs.String("out", "", "the bundle file to write (required; never overwritten)")
	var chains multiFlag
	fs.Var(&chains, "chain", "a chain id to export; repeatable")
	subject := fs.String("subject", "", "export this subject's chains (found through the secret index; "+
		"the subject itself is never written)")
	class := fs.String("class", "", "with --subject: only this class")
	all := fs.Bool("all", false, "export every chain")
	disclose := fs.String("disclose", "none", "none, all, or a comma-separated list of entry ids whose "+
		"content and nonce to include")
	fs.Usage = func() { fmt.Fprintln(stderr, sinkExportUsage) }
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "proof sink export: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	if *out == "" {
		fmt.Fprintln(stderr, "proof sink export: --out is required (a bundle never goes to standard output)")
		return exitUsage
	}
	sel := sink.ExportSelection{Chains: chains, Subject: *subject, Class: *class, All: *all}
	switch *disclose {
	case "none":
		sel.Disclose = sink.DiscloseNone
	case "all":
		sel.Disclose = sink.DiscloseAll
	default:
		sel.Disclose = sink.DiscloseListed
		for _, id := range strings.Split(*disclose, ",") {
			if id = strings.TrimSpace(id); id != "" {
				sel.DiscloseIDs = append(sel.DiscloseIDs, id)
			}
		}
	}
	n := 0
	for _, set := range []bool{len(chains) > 0, *subject != "", *all} {
		if set {
			n++
		}
	}
	if n != 1 {
		fmt.Fprintln(stderr, "proof sink export: give exactly one of --chain, --subject or --all")
		return exitUsage
	}
	if *class != "" && *subject == "" {
		fmt.Fprintln(stderr, "proof sink export: --class narrows --subject")
		return exitUsage
	}
	if _, err := os.Lstat(*out); err == nil {
		fmt.Fprintf(stderr, "proof sink export: %s exists; a bundle is never overwritten\n", *out)
		return exitUsage
	}

	s, err := sink.Open(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "proof sink export: %v\n", err)
		return exitIOError
	}
	// Ctrl-C or SIGTERM cancels the export, so the temporary file (which may
	// hold disclosed content) is removed rather than left behind.
	c, stop := signal.NotifyContext(ctx.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	sum, err := writeBundle(c, s, sel, *out)
	if err != nil {
		fmt.Fprintf(stderr, "proof sink export: %v\n", err)
		switch {
		case errors.Is(err, sink.ErrBusy):
			return exitBusy
		case errors.Is(err, sink.ErrExportEmpty), errors.Is(err, sink.ErrDisclosure),
			errors.Is(err, sink.ErrExportSelection), errors.Is(err, sink.ErrExportTooLarge):
			// The caller's to fix: narrow or correct the selection.
			return exitUsage
		}
		return exitIOError
	}

	fmt.Fprintf(stderr, "wrote %s: %d chain(s), %d entries, %d checkpoint(s), %d event(s) disclosed\n",
		*out, sum.Chains, sum.Entries, sum.Checkpoints, sum.Disclosed)
	if len(sum.CheckpointKeyIDs) > 0 {
		fmt.Fprintf(stderr, "checkpoints signed by key id(s) %s: send the recipient those public keys "+
			"(never in the bundle)\n", strings.Join(sum.CheckpointKeyIDs, ", "))
	}
	if len(sum.RecordKeyIDs) > 0 {
		fmt.Fprintf(stderr, "records signed by key id(s) %s: send the recipient those public keys too. Use one "+
			"record key per sink when bundles go to different parties: a shared key id links sinks.\n",
			strings.Join(sum.RecordKeyIDs, ", "))
	}
	if sum.PendingErasures > 0 {
		fmt.Fprintf(stderr, "WARNING: %d chain(s) belong to a subject whose erasure is not finished; nothing on "+
			"them was disclosed. Run: proof sink erase --dir %s --resume\n", sum.PendingErasures, *dir)
	}
	if sum.IncompleteErasures > 0 {
		fmt.Fprintf(stderr, "WARNING: %d chain(s) have content left before an erasure (an interrupted erasure); "+
			"it was not exported. Run: proof sink erase --dir %s --resume\n", sum.IncompleteErasures, *dir)
	}
	if *subject != "" {
		fmt.Fprintln(stderr, "PRIVACY: this bundle is about one subject. Whoever receives it and knows who it "+
			"is about can link that person to these chains for good: a later erasure does not reach their copy. "+
			"Send it only to the subject, or to a recipient with a lawful basis.")
	}
	if sum.Disclosed > 0 {
		fmt.Fprintln(stderr, "PRIVACY: this bundle discloses content and nonces. Disclosure is permanent: a "+
			"later erasure does not reach copies already handed over. Check the content for other people's data "+
			"before sending it.")
	}
	return exitOK
}

// writeBundle exports to a temporary file beside out, then links it into place
// only if out does not exist. Nothing is left behind on failure.
func writeBundle(c ctx.Context, s *sink.Sink, sel sink.ExportSelection, out string) (sink.ExportSummary, error) {
	dir := filepath.Dir(out)
	f, err := os.CreateTemp(dir, ".proof-bundle-*")
	if err != nil {
		return sink.ExportSummary{}, err
	}
	tmp := f.Name()
	keep := false
	defer func() {
		if !keep {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return sink.ExportSummary{}, err
	}
	sum, err := s.Export(c, sel, f)
	if err != nil {
		return sum, err
	}
	if err := f.Sync(); err != nil {
		return sum, err
	}
	if err := f.Close(); err != nil {
		return sum, err
	}
	// Link, not rename: link refuses an existing target, so a file created at
	// --out meanwhile is never replaced. A filesystem without hard links
	// (exFAT, some network mounts) falls back to check-then-rename, which has
	// a small window in which a file created at --out could be replaced.
	if err := os.Link(tmp, out); err != nil {
		if errors.Is(err, os.ErrExist) {
			return sum, fmt.Errorf("%s appeared while exporting; a bundle is never overwritten", out)
		}
		if _, statErr := os.Lstat(out); statErr == nil {
			return sum, fmt.Errorf("%s appeared while exporting; a bundle is never overwritten", out)
		}
		if err := os.Rename(tmp, out); err != nil {
			return sum, err
		}
	}
	keep = true
	os.Remove(tmp)
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return sum, nil
}
