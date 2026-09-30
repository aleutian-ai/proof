// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// TestScale measures Verify and ChainSubjects on a large sink (ticket _74). It
// is skipped unless SINK_SCALE (the number of subjects, one chain each) is set:
//
//	SINK_SCALE=100000 SINK_SCALE_DIR=/tmp/sink-100k go test ./sink -run TestScale -v -timeout 0
//
// SINK_SCALE_DIR keeps the built sink between runs (building is the slow part);
// without it a temporary folder is used. SINK_SCALE_CHECKPOINT=1 also
// checkpoints every chain (one ML-DSA-65 signature each), so Verify checks
// signatures as it would in production.
func TestScale(t *testing.T) {
	n, err := strconv.Atoi(os.Getenv("SINK_SCALE"))
	if err != nil || n <= 0 {
		t.Skip("set SINK_SCALE=<subjects> to run the scale measurement")
	}
	dir := os.Getenv("SINK_SCALE_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	ctx := context.Background()
	s, err := Open(dir, WithLockTimeout(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	signer, ring := newSigner(t)

	if _, err := os.Stat(filepath.Join(dir, "evidence.db")); err != nil {
		start := time.Now()
		for from := 0; from < n; from += MaxBatch {
			recs := make([]Record, 0, MaxBatch)
			for i := from; i < n && i < from+MaxBatch; i++ {
				recs = append(recs, Record{Class: "events", Subject: fmt.Sprintf("u-%d", i),
					Content: []byte(fmt.Sprintf(`{"user":"u-%d","event":"login"}`, i))})
			}
			if _, err := s.Commit(ctx, recs); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("build: %d subjects, %d chains, committed in %s", n, n, time.Since(start).Round(time.Millisecond))
		if os.Getenv("SINK_SCALE_CHECKPOINT") == "1" {
			start = time.Now()
			if _, err := s.Checkpoint(ctx, signer, nil); err != nil {
				t.Fatal(err)
			}
			t.Logf("checkpoint: %d chains signed in %s", n, time.Since(start).Round(time.Millisecond))
		}
	} else {
		t.Logf("reusing the sink in %s (%d subjects expected)", dir, n)
	}
	for _, f := range []string{"evidence.db", "evidence.db.nonces", "evidence.db.subjects"} {
		if fi, err := os.Stat(filepath.Join(dir, f)); err == nil {
			t.Logf("file %-22s %8.1f MiB", f, float64(fi.Size())/(1<<20))
		}
	}

	// Verify, while a second writer tries to commit.
	var verr error
	var rep Report
	peak, alloc, took := measure(func() { rep, verr = s.Verify(ctx, ring) }, func() {
		time.Sleep(200 * time.Millisecond)
		w, _ := Open(dir, WithLockTimeout(10*time.Minute))
		start := time.Now()
		if _, err := w.Commit(ctx, []Record{{Class: "events", Subject: "writer-probe", Content: []byte("x")}}); err != nil {
			t.Logf("writer probe: %v", err)
			return
		}
		t.Logf("writer probe waited %s behind Verify", time.Since(start).Round(time.Millisecond))
	})
	if verr != nil {
		t.Fatal(verr)
	}
	t.Logf("Verify: %d chains in %s · peak heap %.1f MiB · allocated %.1f MiB · %.1f µs/chain · OK=%v",
		len(rep.Chains), took.Round(time.Millisecond), mib(peak), mib(alloc),
		float64(took.Microseconds())/float64(max(1, len(rep.Chains))), rep.OK())

	var rows []ChainSubject
	var cerr error
	peak, alloc, took = measure(func() { rows, cerr = s.ChainSubjects(ctx) }, nil)
	if cerr != nil {
		t.Fatal(cerr)
	}
	t.Logf("ChainSubjects: %d rows in %s · peak heap %.1f MiB · allocated %.1f MiB",
		len(rows), took.Round(time.Millisecond), mib(peak), mib(alloc))
}

// measure runs op, sampling the live heap every 5 ms, and runs side (if any)
// concurrently. It returns the peak heap in use above the starting level, the
// bytes allocated, and op's duration.
func measure(op, side func()) (peak, alloc uint64, took time.Duration) {
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	var hi atomic.Uint64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if m.HeapInuse > hi.Load() {
				hi.Store(m.HeapInuse)
			}
			select {
			case <-stop:
				return
			case <-tick.C:
			}
		}
	}()
	sideDone := make(chan struct{})
	if side != nil {
		go func() { defer close(sideDone); side() }()
	} else {
		close(sideDone)
	}
	start := time.Now()
	op()
	took = time.Since(start)
	close(stop)
	<-done
	<-sideDone
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if h := hi.Load(); h > before.HeapInuse {
		peak = h - before.HeapInuse
	}
	return peak, after.TotalAlloc - before.TotalAlloc, took
}

func mib(b uint64) float64 { return float64(b) / (1 << 20) }
