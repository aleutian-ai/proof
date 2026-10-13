// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
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
		// Lstat, not Stat: a symlink that points nowhere is still something at
		// the path, and writing "through" it would put the key wherever it
		// points.
		for _, p := range []string{privPath, pubPath} {
			if _, err := os.Lstat(p); err == nil {
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
	// The private key's mode is set on the file that was just created, so it
	// is 0600 whatever was at the path before and whatever the umask is.
	writeErr := writeFileAtomic(privPath, 0o600, true, privPEM)
	zero(privPEM) // zero even when the write failed
	if writeErr != nil {
		return "", fmt.Errorf("write %s: %w", privPath, writeErr)
	}
	if err := writeFileAtomic(pubPath, 0o644, false, pubPEM); err != nil {
		return "", fmt.Errorf("write %s: %w", pubPath, err)
	}

	fingerprint := fingerprintOf(pub)
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

// atomicFile is a file being written beside its destination, to be renamed
// over it once it is complete.
//
// The destination is never opened. A reader sees the old file or the whole new
// one, an interrupted write leaves the destination as it was, and whatever is
// at the destination (a file with a looser mode, a symlink) is replaced, not
// written into.
type atomicFile struct {
	*os.File
	dest string
}

// createAtomic starts writing dest: it creates a temp file in dest's
// directory with O_EXCL and O_NOFOLLOW, so the file is new and is not reached
// through a link. With exactMode the file's mode is set to perm after it is
// created, where the umask would otherwise only have narrowed it.
func createAtomic(dest string, perm os.FileMode, exactMode bool) (*atomicFile, error) {
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return nil, fmt.Errorf("read random bytes: %w", err)
	}
	tmp := filepath.Join(filepath.Dir(dest),
		"."+filepath.Base(dest)+"."+hex.EncodeToString(suffix[:])+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, perm)
	if err != nil {
		return nil, err
	}
	a := &atomicFile{File: f, dest: dest}
	if exactMode {
		if err := f.Chmod(perm); err != nil {
			a.abort()
			return nil, err
		}
	}
	return a, nil
}

// commit makes the file durable and moves it to its destination: fsync, close,
// rename, then fsync the directory so the rename itself survives a crash.
func (a *atomicFile) commit() error {
	if err := a.Sync(); err != nil {
		a.abort()
		return err
	}
	if err := a.Close(); err != nil {
		_ = os.Remove(a.Name())
		return err
	}
	if err := os.Rename(a.Name(), a.dest); err != nil {
		_ = os.Remove(a.Name())
		return err
	}
	dir, err := os.Open(filepath.Dir(a.dest))
	if err != nil {
		return fmt.Errorf("sync the directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync the directory: %w", err)
	}
	return nil
}

// abort discards the file. The destination is untouched.
func (a *atomicFile) abort() {
	_ = a.Close()
	_ = os.Remove(a.Name())
}

// writeFileAtomic writes data to dest through a temp file; see atomicFile.
func writeFileAtomic(dest string, perm os.FileMode, exactMode bool, data []byte) error {
	a, err := createAtomic(dest, perm, exactMode)
	if err != nil {
		return err
	}
	if _, err := a.Write(data); err != nil {
		a.abort()
		return err
	}
	return a.commit()
}

// opCommand runs the 1Password CLI and returns what it printed.
//
// It is a variable so a test can stand in for the CLI: the read-back below is
// the part worth testing, and it cannot be run against a real vault there.
// Nothing but a test replaces it.
var opCommand = func(args ...string) ([]byte, error) {
	if _, err := exec.LookPath("op"); err != nil {
		return nil, errors.New("the 1Password CLI (op) is not on PATH")
	}
	out, err := exec.Command("op", args...).Output()
	if err != nil {
		// op explains itself on stderr. That text is its own message, not the
		// item's contents, which only ever arrive on stdout.
		var exit *exec.ExitError
		if errors.As(err, &exit) && len(bytes.TrimSpace(exit.Stderr)) != 0 {
			return nil, errors.New(strings.TrimSpace(string(exit.Stderr)))
		}
		return nil, err
	}
	return out, nil
}

// opCreatedItem is the part of `op item create --format=json` that names what
// was created.
type opCreatedItem struct {
	ID    string `json:"id"`
	Vault struct {
		ID string `json:"id"`
	} `json:"vault"`
}

// opIDPattern is the shape of a 1Password item or vault id. Checked before an
// id is put into a secret reference, where a "/" or "?" would mean something.
var opIDPattern = regexp.MustCompile(`^[a-z0-9]{26}$`)

// storeIn1Password creates a Secure Note holding the key pair, then reads the
// stored keys back and checks that they are this key.
//
// # Description
//
// The key files are passed to `op` as FILE references, never as command
// arguments, so the secret never appears in the process list. The read-back
// exists because "the upload command exited 0" is not the same as "the item
// contains the right key".
//
// What is read back is the two ATTACHED key files, by the id of the item that
// was just created. Each is parsed, and the SHA-512 of its public key (derived
// from the seed, for the private file) must equal this key's fingerprint. The
// item's fingerprint text field is not consulted: it is a string this function
// wrote a moment earlier, and comparing it says nothing about the attachments.
//
// # Outputs
//
//   - error: if op is missing, the item could not be created, or a key read
//     back is not the key that was generated
func storeIn1Password(vault, title string, a keyfile.Algorithm, slot, keyID, fingerprint,
	privPath, pubPath string, stdout *os.File) error {

	args := []string{
		"item", "create",
		"--format=json",
		"--vault=" + vault,
		"--category=Secure Note",
		"--title=" + title,
		"algorithm[text]=" + a.String(),
		"key_id[text]=" + keyID,
		"fingerprint[text]=" + fingerprint,
		"created_at[text]=" + time.Now().UTC().Format(time.RFC3339),
		opPrivateFile + "[file]=" + privPath,
		opPublicFile + "[file]=" + pubPath,
	}
	if slot != "" {
		args = append(args, "slot[text]="+slot)
	}
	created, err := opCommand(args...)
	if err != nil {
		return fmt.Errorf("op item create failed: %w", err)
	}
	var item opCreatedItem
	if err := json.Unmarshal(created, &item); err != nil ||
		!opIDPattern.MatchString(item.ID) || !opIDPattern.MatchString(item.Vault.ID) {
		return errors.New("stored, but op did not say which item it created, so the keys " +
			"could not be read back — check the item by hand")
	}

	if err := verifyStoredKeys(item, a, fingerprint); err != nil {
		return fmt.Errorf("stored, but %w — check the item by hand", err)
	}
	fmt.Fprintf(stdout, "  1Password  %s (vault %s) — stored keys read back and verified\n", title, vault)
	return nil
}

// The names the two key files are attached under.
const (
	opPrivateFile = "privkey_pem"
	opPublicFile  = "pubkey_pem"
)

// verifyStoredKeys reads the two attached key files back from the item and
// checks each is the key with this fingerprint.
//
// The item and vault are named by id. A title is not unique in a vault: after
// a --force there are two items with the same one, and a read by title could
// be answered from the older.
func verifyStoredKeys(item opCreatedItem, a keyfile.Algorithm, fingerprint string) error {
	ref := "op://" + item.Vault.ID + "/" + item.ID + "/"

	pubPEM, err := opCommand("read", ref+opPublicFile)
	if err != nil {
		return fmt.Errorf("reading the public key back failed: %w", err)
	}
	alg, pub, err := keyfile.ParsePublicKey(pubPEM)
	if err != nil || alg != a {
		return errors.New("the public key read back is not a key file for this algorithm")
	}
	if fingerprintOf(pub) != fingerprint {
		return errors.New("the public key read back is not the key that was generated")
	}

	privPEM, err := opCommand("read", ref+opPrivateFile)
	defer zero(privPEM)
	if err != nil {
		return fmt.Errorf("reading the private key back failed: %w", err)
	}
	alg, seed, err := keyfile.ParsePrivateKey(privPEM)
	defer zero(seed)
	if err != nil || alg != a {
		return errors.New("the private key read back is not a key file for this algorithm")
	}
	derived, err := derivePublic(a, seed)
	if err != nil {
		return errors.New("the private key read back does not derive a public key")
	}
	if fingerprintOf(derived) != fingerprint {
		return errors.New("the private key read back is not the key that was generated")
	}
	return nil
}

// fingerprintOf is the SHA-512 of a public key, in hex: the fingerprint keygen
// prints.
func fingerprintOf(pub []byte) string {
	sum := sha512.Sum512(pub)
	return hex.EncodeToString(sum[:])
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
