// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/aleutian-ai/proof/anchor"
)

const (
	sigChainA = "payments.0123456789abcdef0123456789abcdef"
	sigChainB = "auth.fedcba9876543210fedcba9876543210"
	sigEntry1 = "sink-11111111111111111111111111111111"
	sigEntry2 = "sink-22222222222222222222222222222222"
	sigKey1   = "3fb85abc3e8bae42952ee9194ae1f615"
	sigKey2   = "00112233445566778899aabbccddeeff"
)

func sigBytes(fill byte) []byte { return bytes.Repeat([]byte{fill}, anchor.SignatureSize) }

func openTestSignatures(t *testing.T) (*signaturesStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "evidence.db.signatures")
	st, err := openSignatures(path, DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st, path
}

func TestSignatures_PutGet(t *testing.T) {
	st, _ := openTestSignatures(t)
	if on, err := st.signing(); err != nil || on {
		t.Fatalf("a new file reports signing=%t, %v", on, err)
	}
	if err := st.putAll(map[string]map[string]signatureRow{
		sigChainA: {sigEntry1: {keyID: sigKey1, sig: sigBytes(1)}, sigEntry2: {keyID: sigKey1, sig: sigBytes(2)}},
		sigChainB: {sigEntry1: {keyID: sigKey1, sig: sigBytes(3)}},
	}); err != nil {
		t.Fatal(err)
	}
	row, found, malformed, err := st.get(sigChainA, sigEntry2)
	if err != nil || !found || malformed {
		t.Fatalf("get = found %t, malformed %t, %v", found, malformed, err)
	}
	if row.keyID != sigKey1 || !bytes.Equal(row.sig, sigBytes(2)) {
		t.Fatalf("got key %s and a different signature", row.keyID)
	}
	// Same entry id on another chain is another row.
	if row, _, _, _ := st.get(sigChainB, sigEntry1); !bytes.Equal(row.sig, sigBytes(3)) {
		t.Fatal("rows of two chains collided")
	}
	if _, found, _, err := st.get(sigChainB, sigEntry2); err != nil || found {
		t.Fatalf("a missing row was found (%v)", err)
	}
	if on, _ := st.signing(); !on {
		t.Fatal("the first put did not mark the sink as signing")
	}
}

// TestSignatures_KeyIDsAreKeptThroughRotation: every record key ever used is
// in the set, and deleting rows never removes one (Checkpoint's warning must
// hold after rotation).
func TestSignatures_KeyIDsAreKeptThroughRotation(t *testing.T) {
	st, _ := openTestSignatures(t)
	if err := st.putAll(map[string]map[string]signatureRow{sigChainA: {sigEntry1: {keyID: sigKey1, sig: sigBytes(1)}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.putAll(map[string]map[string]signatureRow{sigChainA: {sigEntry2: {keyID: sigKey2, sig: sigBytes(2)}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.deleteRows(map[string][]string{sigChainA: {sigEntry1, sigEntry2}}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{sigKey1, sigKey2} {
		if has, err := st.hasRecordKey(id); err != nil || !has {
			t.Fatalf("key %s used before is not recorded (%v)", id, err)
		}
	}
	if has, _ := st.hasRecordKey(strings.Repeat("9", 32)); has {
		t.Fatal("a key never used is reported as used")
	}
	if _, err := st.hasRecordKey("record_key\x00"); err == nil {
		t.Fatal("a lookup by a non-key-id was accepted")
	}
	if _, found, _, _ := st.get(sigChainA, sigEntry1); found {
		t.Fatal("deleteRows left the row")
	}
}

// TestSignatures_PutAllIsAllOrNothing: one invalid row refuses the call and
// writes nothing, not even the valid rows or the mode.
func TestSignatures_PutAllIsAllOrNothing(t *testing.T) {
	bad := map[string]signatureRow{
		"key id not hex":          {keyID: strings.Repeat("z", 32), sig: sigBytes(1)},
		"key id short":            {keyID: "3fb85abc", sig: sigBytes(1)},
		"signature short":         {keyID: sigKey1, sig: sigBytes(1)[:100]},
		"signature empty":         {keyID: sigKey1},
		"signature one byte long": {keyID: sigKey1, sig: append(sigBytes(1), 0)},
	}
	for name, row := range bad {
		t.Run(name, func(t *testing.T) {
			st, _ := openTestSignatures(t)
			err := st.putAll(map[string]map[string]signatureRow{
				sigChainA: {sigEntry1: {keyID: sigKey1, sig: sigBytes(1)}, sigEntry2: row},
			})
			if err == nil {
				t.Fatal("accepted")
			}
			if _, found, _, _ := st.get(sigChainA, sigEntry1); found {
				t.Fatal("the valid row was written although the call failed")
			}
			if on, _ := st.signing(); on {
				t.Fatal("the mode was set although the call failed")
			}
		})
	}
	st, _ := openTestSignatures(t)
	for _, key := range [][2]string{{"../x", sigEntry1}, {sigChainA, "jo@example.com"}} {
		if err := st.putAll(map[string]map[string]signatureRow{
			sigChainB: {sigEntry1: {keyID: sigKey1, sig: sigBytes(1)}},
			key[0]:    {key[1]: {keyID: sigKey1, sig: sigBytes(1)}},
		}); err == nil {
			t.Fatalf("accepted a row keyed %q/%q", key[0], key[1])
		}
		if _, found, _, _ := st.get(sigChainB, sigEntry1); found {
			t.Fatal("a valid row was written beside a refused one")
		}
		if on, _ := st.signing(); on {
			t.Fatal("the mode was set by a refused call")
		}
	}
}

// TestSignatures_MalformedValue: a planted value of the wrong size is reported,
// not parsed (and not copied).
func TestSignatures_MalformedValue(t *testing.T) {
	st, _ := openTestSignatures(t)
	for _, v := range [][]byte{{1, 2, 3}, make([]byte, 1<<20)} {
		if err := st.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(signaturesBucket).Put(rowKey(sigChainA, sigEntry1), v)
		}); err != nil {
			t.Fatal(err)
		}
		row, found, malformed, err := st.get(sigChainA, sigEntry1)
		if err != nil || !found || !malformed || row.sig != nil {
			t.Fatalf("%d-byte value: found %t malformed %t sig %d bytes, %v", len(v), found, malformed, len(row.sig), err)
		}
	}
}

func TestSignatures_ReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.db.signatures")

	if st, err := openSignaturesReadOnly(path, DefaultLockTimeout); err != nil || st != nil {
		t.Fatalf("absent file: %v, %v; want nil, nil", st, err)
	}
	if _, err := os.Lstat(path); err == nil {
		t.Fatal("a read-only open created the file")
	}

	// G3: a file with no buckets at all (a crash before initialisation) holds
	// nothing: read as absent, and a writer repairs it.
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if st, err := openSignaturesReadOnly(path, DefaultLockTimeout); err != nil || st != nil {
		t.Fatalf("a bucketless file: %v, %v; want nil, nil (absent)", st, err)
	}
	if w, err := openSignatures(path, DefaultLockTimeout); err != nil {
		t.Fatalf("a writer did not repair a bucketless file: %v", err)
	} else {
		w.Close()
	}
	if st, err := openSignaturesReadOnly(path, DefaultLockTimeout); err != nil || st == nil {
		t.Fatalf("after the repair: %v, %v", st, err)
	} else {
		st.Close()
	}
	os.Remove(path)

	// Anything else that is not a signatures file is refused.
	for name, buckets := range map[string][]string{
		"only one bucket": {"signatures"},
		"foreign bucket":  {"entries"},
	} {
		db, err := bolt.Open(path, 0o600, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Update(func(tx *bolt.Tx) error {
			for _, b := range buckets {
				if _, err := tx.CreateBucket([]byte(b)); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		db.Close()
		if _, err := openSignaturesReadOnly(path, DefaultLockTimeout); err == nil {
			t.Fatalf("%s: accepted", name)
		}
		os.Remove(path)
	}

	st, err := openSignatures(path, DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.putAll(map[string]map[string]signatureRow{sigChainA: {sigEntry1: {keyID: sigKey1, sig: sigBytes(1)}}}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	ro, err := openSignaturesReadOnly(path, DefaultLockTimeout)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if _, found, _, _ := ro.get(sigChainA, sigEntry1); !found {
		t.Fatal("read-only open cannot read")
	}
	if err := ro.putAll(map[string]map[string]signatureRow{sigChainA: {sigEntry2: {keyID: sigKey1, sig: sigBytes(2)}}}); err == nil {
		t.Fatal("a read-only store wrote")
	}
}

func TestSignatures_RefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere")
	path := filepath.Join(dir, "evidence.db.signatures")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := openSignatures(path, DefaultLockTimeout); err == nil {
		t.Fatal("opened a symlink read-write")
	}
	if _, err := openSignaturesReadOnly(path, DefaultLockTimeout); err == nil {
		t.Fatal("opened a symlink read-only")
	}
	if _, err := os.Lstat(target); err == nil {
		t.Fatal("something was written where the symlink points")
	}
}

// TestSignatures_EmptyPutIsRefused: an empty call must not switch a sink to
// signing (F2: the mode is set by a real signed commit attempt only).
func TestSignatures_EmptyPutIsRefused(t *testing.T) {
	st, _ := openTestSignatures(t)
	for _, rows := range []map[string]map[string]signatureRow{nil, {}, {sigChainA: {}}} {
		if err := st.putAll(rows); err == nil {
			t.Fatalf("accepted %v", rows)
		}
	}
	if on, _ := st.signing(); on {
		t.Fatal("an empty call set the signing mode")
	}
}

// TestSignatures_ModeKeptAfterCleanup: F2, fail closed: a failed first signed
// commit's cleanup deletes its rows but the sink stays a signing sink.
func TestSignatures_ModeKeptAfterCleanup(t *testing.T) {
	st, _ := openTestSignatures(t)
	if err := st.putAll(map[string]map[string]signatureRow{sigChainA: {sigEntry1: {keyID: sigKey1, sig: sigBytes(1)}}}); err != nil {
		t.Fatal(err)
	}
	if err := st.deleteRows(map[string][]string{sigChainA: {sigEntry1, sigEntry2}}); err != nil {
		t.Fatalf("deleting a row that is not there is an error: %v", err)
	}
	if on, _ := st.signing(); !on {
		t.Fatal("the cleanup cleared the signing mode")
	}
}

// TestSignatures_AlteredModeIsAnError: a marker this sink never writes is
// reported, not read as either mode.
func TestSignatures_AlteredModeIsAnError(t *testing.T) {
	st, _ := openTestSignatures(t)
	if err := st.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(metaBucket).Put(metaRecordSigning, []byte("ed25519"))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.signing(); err == nil {
		t.Fatal("an altered signing mode was accepted")
	}
}
