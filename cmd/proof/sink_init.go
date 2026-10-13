// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	ctx "context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/sink"
)

// cmdSinkInit makes a sink's record and checkpoint keys, the recommended way:
// two ML-DSA-65 keys, one per role.
//
// # Description
//
// The record key is online in the writer (every commit and erase signs with
// it); the checkpoint key is used only to checkpoint and can be kept elsewhere,
// so a leaked record key cannot also unpin what checkpoints pinned. Keys are
// written beside the sink folder, never inside it: the folder holds the secret
// files, and parts of it are handed to others. With --op-vault the checkpoint
// key goes to 1Password and its private file is removed. It reuses keygen's
// generation, self-test and 1Password storage.
//
// It also puts the sink into signing mode (sink.RequireRecordSigning), creating
// the folder if needed: a sink signs from its first commit or never, so without
// this a first commit that forgot --record-key would make the sink unsigned for
// good. With the mode set, that commit is refused instead. This is done BEFORE
// any key is generated: a sink that already holds unsigned records is refused
// with nothing written.
//
// # Outputs
//
//   - int: exitOK; exitUsage for a refusal (keys inside the sink folder, keys
//     already there, a sink that already holds unsigned records); exitBusy
//     when another process holds the folder; exitIOError when generation or
//     1Password fails (files already written are kept, and the sink stays in
//     signing mode)
func cmdSinkInit(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("sink init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "sink-data", "the sink folder the printed commands use")
	keysDir := fs.String("keys-dir", "", "where the keys go (default: <dir>.keys, beside the sink folder)")
	opVault := fs.String("op-vault", "", "store the CHECKPOINT key in this 1Password vault and remove its "+
		"private file (requires the op CLI)")
	oneKey := fs.Bool("one-key", false, "one key for both roles (weaker: allowed, warned about on every run)")
	force := fs.Bool("force", false, "overwrite existing key files")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "proof sink init: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}
	if *keysDir == "" {
		abs, err := filepath.Abs(*dir)
		if err != nil {
			fmt.Fprintf(stderr, "proof sink init: %v\n", err)
			return exitIOError
		}
		*keysDir = abs + ".keys"
	}
	if inside, err := within(*keysDir, *dir); err != nil {
		fmt.Fprintf(stderr, "proof sink init: %v\n", err)
		return exitIOError
	} else if inside {
		fmt.Fprintln(stderr, "proof sink init: --keys-dir is the sink folder or inside it; keys must stay "+
			"out of the sink folder (parts of it are handed to others, and it is what gets backed up)")
		return exitUsage
	}
	if *oneKey && *opVault != "" {
		fmt.Fprintln(stderr, "proof sink init: --op-vault keeps the checkpoint key apart; it does not go "+
			"with --one-key")
		return exitUsage
	}
	roles := []string{"record", "checkpoint"}
	if *oneKey {
		roles = []string{"shared"}
	}
	// Every target checked BEFORE anything is generated: a refusal never
	// leaves a half-written key set.
	if !*force {
		for _, r := range roles {
			priv, pub := keyPaths(*keysDir, keyfile.MLDSA65, r)
			for _, f := range []string{priv, pub} {
				if _, err := os.Stat(f); err == nil {
					fmt.Fprintf(stderr, "proof sink init: %s already exists; use --force to overwrite "+
						"(a key that has signed records is still needed to verify them)\n", f)
					return exitUsage
				}
			}
		}
	}
	if *opVault != "" {
		// One item per title: a second would make every read (and the printed
		// op read) ambiguous. Refuse before generating anything.
		title := opItemTitle(keyfile.MLDSA65, "checkpoint", "")
		if _, err := exec.LookPath("op"); err != nil {
			fmt.Fprintln(stderr, "proof sink init: --op-vault needs the 1Password CLI (op) on PATH")
			return exitIOError
		}
		if err := exec.Command("op", "item", "get", title, "--vault="+*opVault).Run(); err == nil {
			fmt.Fprintf(stderr, "proof sink init: vault %s already holds an item %q; remove or rename it "+
				"first (a second would make reading it ambiguous)\n", *opVault, title)
			return exitUsage
		}
	}
	// The sink signs from here on: set before any key exists, so a sink that
	// cannot sign (it already holds unsigned records) is refused with nothing
	// generated, and a first commit that forgets --record-key is refused too.
	s, err := sink.Open(*dir)
	if err != nil {
		fmt.Fprintf(stderr, "proof sink init: %v\n", err)
		return exitIOError
	}
	switch err := s.RequireRecordSigning(ctx.Background()); {
	case errors.Is(err, sink.ErrSinkNotSigning):
		fmt.Fprintf(stderr, "proof sink init: %s already holds unsigned records, and a sink signs from its "+
			"first commit or never. Start a new sink (another --dir) to sign its records\n", *dir)
		return exitUsage
	case errors.Is(err, sink.ErrBusy):
		fmt.Fprintf(stderr, "proof sink init: %v\n", err)
		return exitBusy
	case err != nil:
		fmt.Fprintf(stderr, "proof sink init: %v\n", err)
		return exitIOError
	}
	if fi, err := os.Stat(*keysDir); err == nil && fi.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(stderr, "warning: %s is accessible to others (mode %04o); 0700 is advised for a "+
			"folder of private keys\n", *keysDir, fi.Mode().Perm())
	}
	if err := os.MkdirAll(*keysDir, 0o700); err != nil {
		fmt.Fprintf(stderr, "proof sink init: create %s: %v\n", *keysDir, err)
		return exitIOError
	}

	fail := func(err error) int {
		fmt.Fprintf(stderr, "proof sink init: %v\n", err)
		if _, isUsage := err.(*usageError); isUsage {
			return exitUsage
		}
		return exitIOError
	}
	a := keyfile.MLDSA65
	if *oneKey {
		if _, err := generateKey(a, *keysDir, "shared", "", "", *force, stdout, stderr); err != nil {
			return fail(err)
		}
		priv, pub := keyPaths(*keysDir, a, "shared")
		fmt.Fprintln(stdout, "\none key for both roles: weaker. If it leaks, checkpoints signed by it no "+
			"longer pin anything a forger rewrites. checkpoint and verify will warn on every run.")
		printNext(stdout, *dir, priv, pub, priv, pub, "")
		return exitOK
	}

	recFP, err := generateKey(a, *keysDir, "record", "", "", *force, stdout, stderr)
	if err != nil {
		return fail(err)
	}
	fmt.Fprintln(stdout, "  role     record key: online, every commit and erase signs with it")
	cpFP, err := generateKey(a, *keysDir, "checkpoint", "", "", *force, stdout, stderr)
	if err != nil {
		return fail(err)
	}
	fmt.Fprintln(stdout, "  role     checkpoint key: used only to checkpoint; keep it somewhere else")
	if recFP == cpFP {
		// As keygen --slot dual: two keys alike means the random source is broken.
		for _, s := range []string{"record", "checkpoint"} {
			priv, pub := keyPaths(*keysDir, a, s)
			_ = os.Remove(priv)
			_ = os.Remove(pub)
		}
		return fail(fmt.Errorf("the two keys are identical: the system random source is faulty; " +
			"both were removed"))
	}
	recPriv, recPub := keyPaths(*keysDir, a, "record")
	cpPriv, cpPub := keyPaths(*keysDir, a, "checkpoint")

	cpKey := cpPriv
	if *opVault != "" {
		keyID, _, err := readPublicKey(cpPub)
		if err != nil {
			return fail(err)
		}
		title := opItemTitle(a, "checkpoint", "")
		if err := storeIn1Password(*opVault, title, a, "checkpoint", keyID, cpFP, cpPriv, cpPub, stdout); err != nil {
			// Nothing removed: the key files are valid, and are the only copy.
			return fail(fmt.Errorf("1Password: %w; the key files are kept, store the checkpoint key yourself", err))
		}
		if err := os.Remove(cpPriv); err != nil {
			return fail(fmt.Errorf("stored in 1Password, but removing %s failed: %w", cpPriv, err))
		}
		fmt.Fprintf(stdout, "  removed  %s from disk (unlinked, not wiped: SSD and journal copies may remain)\n", cpPriv)
		cpKey = "<(op read " + shellQuote("op://"+*opVault+"/"+title+"/privkey_pem") + ")"
	}
	printNext(stdout, *dir, recPriv, recPub, cpKey, cpPub, *opVault)
	return exitOK
}

// generateKey is keygen's generateOne. A variable only so a test can make two
// keys come out alike, to reach the broken-random-source guard.
var generateKey = generateOne

// printNext prints the commands that use the keys just made.
func printNext(out *os.File, dir, recPriv, recPub, cpKey, cpPub, opVault string) {
	q := shellQuote
	if opVault == "" {
		cpKey = q(cpKey)
	}
	fmt.Fprintf(out, "\n%s now signs its records: a commit or erase without --record-key is refused.\n", q(dir))
	fmt.Fprintf(out, "\nnext:\n")
	fmt.Fprintf(out, "  proof sink commit     --dir %s … --record-key %s\n", q(dir), q(recPriv))
	fmt.Fprintf(out, "  proof sink erase      --dir %s … --record-key %s\n", q(dir), q(recPriv))
	fmt.Fprintf(out, "  proof sink checkpoint --dir %s --key %s --record-trust %s\n", q(dir), cpKey, q(recPub))
	fmt.Fprintf(out, "  proof sink verify     --dir %s --key %s --record-trust %s\n", q(dir), q(cpPub), q(recPub))
	if opVault != "" {
		fmt.Fprintln(out, "(the checkpoint command reads the key from 1Password, with no copy on disk; "+
			"<( ) needs bash or zsh)")
	}
	fmt.Fprintln(out, "Keep the keys out of version control, and out of the sink folder. The folder is not "+
		"something to hand over whole: evidence.db.secrets, .sources and .subjects in it are secret. Only "+
		"evidence.db, evidence.db.signatures and anchors/ are meant to be given to others.")
}

// within reports whether path is dir itself or inside it. Both are made
// absolute, and the deepest part of each that exists is resolved through
// symlinks (on macOS /tmp is /private/tmp); the comparison then ignores case,
// since the default macOS file system does. Conservative: two paths differing
// only in case are treated as one, a refusal at worst.
func within(path, dir string) (bool, error) {
	p, err := resolveExisting(path)
	if err != nil {
		return false, err
	}
	d, err := resolveExisting(dir)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(strings.ToLower(d), strings.ToLower(p))
	if err != nil {
		return false, nil
	}
	// "." (the folder itself) and any path below it are inside.
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)), nil
}

// resolveExisting makes path absolute and resolves symlinks in its deepest
// existing ancestor, keeping the part that does not exist yet as written.
func resolveExisting(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	rest := ""
	for cur := abs; ; {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			return filepath.Join(r, rest), nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// shellQuote quotes s for a POSIX shell when it holds anything but safe
// characters, so a printed command can be pasted as is.
func shellQuote(s string) string {
	safe := true
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._-+=:@", r)) {
			safe = false
			break
		}
	}
	if safe && s != "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
