// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package safebolt

import (
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// TestMeasureCheck times Check on a database of about 1 GiB. It is the
// measurement behind the pre-flight check's defaults, and is skipped unless
// PROOF_MEASURE_CHECK is set: it writes a gigabyte.
//
//	PROOF_MEASURE_CHECK=1 go test ./internal/safebolt -run TestMeasureCheck -v
func TestMeasureCheck(t *testing.T) {
	if os.Getenv("PROOF_MEASURE_CHECK") == "" {
		t.Skip("set PROOF_MEASURE_CHECK=1 to build a 1 GiB database and time Check")
	}
	path := filepath.Join(t.TempDir(), "big.db")
	db, err := bolt.Open(path, 0o600, &bolt.Options{NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	// Rows shaped like a secrets file's: a 70-byte key and a 200-byte value.
	const rows, perTx = 3_300_000, 50_000
	value := make([]byte, 200)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 70)
	for done := 0; done < rows; done += perTx {
		if err := db.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists([]byte("content"))
			if err != nil {
				return err
			}
			b.FillPercent = 0.9
			for i := done; i < done+perTx; i++ {
				binary.BigEndian.PutUint64(key, uint64(i))
				if err := b.Put(key, value); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	gib := float64(fi.Size()) / (1 << 30)
	for i := 0; i < 3; i++ {
		start := time.Now()
		if err := Check(path, nil); err != nil {
			t.Fatal(err)
		}
		d := time.Since(start)
		t.Logf("run %d: %.2f GiB checked in %v: %.2f s per GiB", i+1, gib, d, d.Seconds()/gib)
	}
}
