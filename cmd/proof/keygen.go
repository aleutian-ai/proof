// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/mldsa"
	"github.com/aleutian-ai/proof/mlkem"
	"github.com/aleutian-ai/proof/xwing"
)

// keygenAlgorithms are the algorithms this command will mint a key for.
//
// An algorithm appears here only when this module can USE the key — a key file
// alone is not a capability, and minting a key nothing can operate with would
// be a trap. ML-KEM-512 is therefore absent: keyfile can read it, but no
// package here encapsulates with it.
var keygenAlgorithms = map[string]keyfile.Algorithm{
	"x-wing":      keyfile.XWing,
	"ml-kem-768":  keyfile.MLKEM768,
	"ml-kem-1024": keyfile.MLKEM1024,
	"ml-dsa-44":   keyfile.MLDSA44,
	"ml-dsa-65":   keyfile.MLDSA65,
	"ml-dsa-87":   keyfile.MLDSA87,
}

// cmdKeygen generates a key pair, proves it works, and writes it out.
//
// # Description
//
// The order matters: generate, SELF-TEST, then write. A key that fails its own
// round trip never reaches disk, so a silent generation fault cannot be
// discovered later, after data has been encrypted to it.
//
// # Outputs
//
//   - int: an exit code — exitOK, exitUsage, or exitIOError
func cmdKeygen(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	alg := fs.String("alg", "x-wing", "algorithm: x-wing, ml-kem-768, ml-kem-1024, ml-dsa-44, ml-dsa-65, ml-dsa-87")
	outDir := fs.String("out-dir", ".", "directory to write the key files into")
	slot := fs.String("slot", "", "primary, backup, or dual (two keys: a hot primary and a cold backup)")
	name := fs.String("name", "", "optional label recorded in the 1Password item title")
	opVault := fs.String("op-vault", "", "also store the key in this 1Password vault (requires the op CLI)")
	force := fs.Bool("force", false, "overwrite existing key files")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	a, ok := keygenAlgorithms[strings.ToLower(*alg)]
	if !ok {
		fmt.Fprintf(stderr, "proof keygen: unknown algorithm %q\n", *alg)
		fmt.Fprintf(stderr, "  choose one of: x-wing, ml-kem-768, ml-kem-1024, ml-dsa-44, ml-dsa-65, ml-dsa-87\n")
		return exitUsage
	}

	var slots []string
	switch strings.ToLower(*slot) {
	case "":
		slots = []string{""}
	case "primary":
		slots = []string{"primary"}
	case "backup":
		slots = []string{"backup"}
	case "dual":
		slots = []string{"primary", "backup"}
	default:
		fmt.Fprintf(stderr, "proof keygen: --slot must be primary, backup, or dual (got %q)\n", *slot)
		return exitUsage
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "proof keygen: create %s: %v\n", *outDir, err)
		return exitIOError
	}

	fingerprints := make(map[string]string, len(slots))
	for _, s := range slots {
		fp, err := generateOne(a, *outDir, s, *name, *opVault, *force, stdout, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "proof keygen: %v\n", err)
			if _, isUsage := err.(*usageError); isUsage {
				return exitUsage
			}
			return exitIOError
		}
		fingerprints[s] = fp
	}

	// Two keys minted moments apart with the same fingerprint means the random
	// source is not random. Cheap to check, catastrophic to miss.
	if len(slots) == 2 && fingerprints["primary"] == fingerprints["backup"] {
		fmt.Fprintf(stderr, "proof keygen: primary and backup fingerprints are identical — "+
			"the system random source is faulty. Both key files have been removed.\n")
		for _, s := range slots {
			priv, pub := keyPaths(*outDir, a, s)
			_ = os.Remove(priv)
			_ = os.Remove(pub)
		}
		return exitIOError
	}
	return exitOK
}

// selfTestFn is the pairwise consistency check generateOne runs before it
// writes anything. It is a variable for one reason: a faulty key cannot be
// produced from a working random source, so the only way to test that the
// guard is wired in — rather than merely present — is to make it fail on
// demand. Nothing but the test replaces it.
var selfTestFn = selfTest

// usageError marks an error as the caller's mistake rather than an I/O failure.
type usageError struct{ msg string }

// Error implements the error interface.
func (e *usageError) Error() string { return e.msg }

// generateOne mints one key pair, self-tests it, writes it, and reports its
// fingerprint.
//
// # Outputs
//
//   - string: the SHA-512 fingerprint of the public key, 128 hex characters
//   - error: a usageError for a refusal to overwrite, otherwise an I/O or
//     generation failure
func generateOne(a keyfile.Algorithm, outDir, slot, name, opVault string, force bool,
	stdout, stderr *os.File) (string, error) {

	privPath, pubPath := keyPaths(outDir, a, slot)
	if !force {
		for _, p := range []string{privPath, pubPath} {
			if _, err := os.Stat(p); err == nil {
				return "", &usageError{msg: fmt.Sprintf("%s already exists — use --force to overwrite", p)}
			}
		}
	}

	seed := make([]byte, a.SeedSize())
	if _, err := rand.Read(seed); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	defer zero(seed)

	pub, err := derivePublic(a, seed)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}
	// Prove the key works BEFORE writing it.
	if err := selfTestFn(a, seed, pub); err != nil {
		return "", fmt.Errorf("self-test failed, nothing written: %w", err)
	}

	privPEM, err := keyfile.MarshalPrivateKey(a, seed)
	if err != nil {
		return "", fmt.Errorf("encode private key: %w", err)
	}
	pubPEM, err := keyfile.MarshalPublicKey(a, pub)
	if err != nil {
		zero(privPEM)
		return "", fmt.Errorf("encode public key: %w", err)
	}
	writeErr := os.WriteFile(privPath, privPEM, 0o600)
	zero(privPEM) // zero even when the write failed
	if writeErr != nil {
		return "", fmt.Errorf("write %s: %w", privPath, writeErr)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", pubPath, err)
	}

	sum := sha512.Sum512(pub)
	fingerprint := hex.EncodeToString(sum[:])
	keyID, err := keyfile.KeyIDHex(a, pub)
	if err != nil {
		return "", fmt.Errorf("compute key id: %w", err)
	}

	label := a.String()
	if slot != "" {
		label += " (" + slot + ")"
	}
	fmt.Fprintf(stdout, "\n%s\n", label)
	fmt.Fprintf(stdout, "  private  %s   (0600 — this is the secret)\n", privPath)
	fmt.Fprintf(stdout, "  public   %s\n", pubPath)
	fmt.Fprintf(stdout, "  key id   %s\n", keyID)
	fmt.Fprintf(stdout, "  SHA-512  %s\n", groupFingerprint(fingerprint))
	fmt.Fprintf(stdout, "  self-test passed: %s\n", selfTestDescription(a))

	if opVault != "" {
		title := opItemTitle(a, slot, name)
		if err := storeIn1Password(opVault, title, a, slot, keyID, fingerprint, privPath, pubPath, stdout); err != nil {
			// The files are on disk and valid; only the upload failed. Say so
			// rather than failing the whole command and leaving the operator
			// unsure whether they have a key.
			fmt.Fprintf(stderr, "  1Password: %v\n", err)
			fmt.Fprintf(stderr, "  the key files above are valid — store them yourself\n")
			return fingerprint, nil
		}
	}
	return fingerprint, nil
}

// keyPaths returns the private and public file paths for an algorithm and slot.
func keyPaths(outDir string, a keyfile.Algorithm, slot string) (priv, pub string) {
	base := strings.ToLower(strings.ReplaceAll(a.String(), " ", "-"))
	if slot != "" {
		base += "-" + slot
	}
	return filepath.Join(outDir, base+"-private.pem"), filepath.Join(outDir, base+"-public.pem")
}

// derivePublic computes the public key for a freshly generated seed.
func derivePublic(a keyfile.Algorithm, seed []byte) ([]byte, error) {
	switch a {
	case keyfile.XWing:
		priv, err := xwing.NewPrivateKey(seed)
		if err != nil {
			return nil, err
		}
		pub, err := priv.PublicKey()
		if err != nil {
			return nil, err
		}
		return pub.MarshalBinary()
	case keyfile.MLKEM768:
		return mlkem.PublicKeyFromSeed(mlkem.MLKEM768, seed)
	case keyfile.MLKEM1024:
		return mlkem.PublicKeyFromSeed(mlkem.MLKEM1024, seed)
	case keyfile.MLDSA44:
		return mldsa.PublicKeyFromSeed(mldsa.MLDSA44, seed)
	case keyfile.MLDSA65:
		return mldsa.PublicKeyFromSeed(mldsa.MLDSA65, seed)
	case keyfile.MLDSA87:
		return mldsa.PublicKeyFromSeed(mldsa.MLDSA87, seed)
	default:
		return nil, fmt.Errorf("no key generation for %s", a)
	}
}

// selfTest exercises the new key end to end: encapsulate then decapsulate for a
// KEM, sign then verify for a signature scheme.
//
// # Description
//
// FIPS 140-3 requires a pairwise consistency test after key generation for
// exactly this reason — a subtly faulty generation is otherwise silent until
// data has already been encrypted to the bad key, or signatures made with it
// are rejected.
//
// # Outputs
//
//   - error: non-nil if the key does not work; the caller must not write it
func selfTest(a keyfile.Algorithm, seed, pub []byte) error {
	switch a {
	case keyfile.XWing:
		priv, err := xwing.NewPrivateKey(seed)
		if err != nil {
			return err
		}
		parsed, err := xwing.UnmarshalPublicKey(pub)
		if err != nil {
			return err
		}
		ct, sender, err := xwing.Encapsulate(parsed)
		if err != nil {
			return err
		}
		recipient, err := xwing.Decapsulate(ct, priv)
		if err != nil {
			return err
		}
		if sender != recipient {
			return fmt.Errorf("encapsulate/decapsulate produced different secrets")
		}
	case keyfile.MLKEM768, keyfile.MLKEM1024:
		set := mlkem.MLKEM768
		if a == keyfile.MLKEM1024 {
			set = mlkem.MLKEM1024
		}
		ct, sender, err := mlkem.Encapsulate(set, pub)
		if err != nil {
			return err
		}
		recipient, err := mlkem.Decapsulate(set, seed, ct)
		if err != nil {
			return err
		}
		if sender != recipient {
			return fmt.Errorf("encapsulate/decapsulate produced different secrets")
		}
	case keyfile.MLDSA44, keyfile.MLDSA65, keyfile.MLDSA87:
		set := map[keyfile.Algorithm]mldsa.ParameterSet{
			keyfile.MLDSA44: mldsa.MLDSA44,
			keyfile.MLDSA65: mldsa.MLDSA65,
			keyfile.MLDSA87: mldsa.MLDSA87,
		}[a]
		msg := []byte("proof keygen self-test")
		sig, err := mldsa.Sign(set, seed, msg)
		if err != nil {
			return err
		}
		if err := mldsa.Verify(set, pub, msg, sig); err != nil {
			return err
		}
	default:
		return fmt.Errorf("no self-test for %s", a)
	}
	return nil
}

// selfTestDescription says, in plain words, what the self-test proved — which
// differs by key kind: a KEM key encrypts to itself, a signature key signs and
// verifies.
func selfTestDescription(a keyfile.Algorithm) string {
	switch a {
	case keyfile.MLDSA44, keyfile.MLDSA65, keyfile.MLDSA87:
		return "this key signed a message and verified its own signature"
	default:
		return "this key encrypted a secret to itself and recovered it"
	}
}

// storeIn1Password creates a Secure Note holding the key pair, then reads the
// fingerprint back to confirm what actually landed.
//
// # Description
//
// The key files are passed to `op` as FILE references, never as command
// arguments, so the secret never appears in the process list. The read-back
// exists because "the upload command exited 0" is not the same as "the item
// contains the right key".
//
// # Outputs
//
//   - error: if op is missing, the item could not be created, or the
//     fingerprint read back does not match
func storeIn1Password(vault, title string, a keyfile.Algorithm, slot, keyID, fingerprint,
	privPath, pubPath string, stdout *os.File) error {

	if _, err := exec.LookPath("op"); err != nil {
		return fmt.Errorf("the 1Password CLI (op) is not on PATH")
	}
	args := []string{
		"item", "create",
		"--vault=" + vault,
		"--category=Secure Note",
		"--title=" + title,
		"algorithm[text]=" + a.String(),
		"key_id[text]=" + keyID,
		"fingerprint[text]=" + fingerprint,
		"created_at[text]=" + time.Now().UTC().Format(time.RFC3339),
		"privkey_pem[file]=" + privPath,
		"pubkey_pem[file]=" + pubPath,
	}
	if slot != "" {
		args = append(args, "slot[text]="+slot)
	}
	if out, err := exec.Command("op", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("op item create failed: %s", strings.TrimSpace(string(out)))
	}

	readBack, err := exec.Command("op", "item", "get", title,
		"--vault="+vault, "--field=fingerprint", "--reveal").Output()
	if err != nil {
		return fmt.Errorf("stored, but reading it back failed: %w", err)
	}
	if strings.TrimSpace(string(readBack)) != fingerprint {
		return fmt.Errorf("stored, but the fingerprint read back does not match — check the item by hand")
	}
	fmt.Fprintf(stdout, "  1Password  %s (vault %s) — fingerprint verified\n", title, vault)
	return nil
}

// opItemTitle builds a stable, descriptive 1Password item title.
func opItemTitle(a keyfile.Algorithm, slot, name string) string {
	parts := []string{"proof", strings.ToLower(strings.ReplaceAll(a.String(), " ", "-"))}
	if name != "" {
		parts = append(parts, name)
	}
	if slot != "" {
		parts = append(parts, slot)
	}
	return strings.Join(parts, "-")
}

// groupFingerprint splits a hex fingerprint into four-character groups so two
// people can read it to each other and not lose their place.
func groupFingerprint(fp string) string {
	var b strings.Builder
	for i := 0; i < len(fp); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
			if i%32 == 0 {
				b.WriteString("\n           ")
			}
		}
		end := i + 4
		if end > len(fp) {
			end = len(fp)
		}
		b.WriteString(fp[i:end])
	}
	return b.String()
}

// zero overwrites b, for buffers this command owns.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
