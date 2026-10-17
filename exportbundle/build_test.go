// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package exportbundle

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/anchor"
	"github.com/aleutian-ai/proof/mldsa"
)

// bareEntry is the smallest entry the reader accepts: every required member,
// each an empty string. It is out of shape, which is a problem, not a reason
// the bundle is unreadable.
const bareEntry = `{"entry_id":"","entry_type":"","global_seq":"","previous_hash":"","timestamp":"","content_hash":"","chain_hash":""}`

// testChainID returns a valid chain id for position i.
func testChainID(i int) string { return fmt.Sprintf("events.%032x", i) }

// bareBundle builds a readable bundle of bare entries and one-byte
// checkpoints: the cheapest input that reaches the count limits.
func bareBundle(chains, entriesEach, checkpointsEach int) []byte {
	var b bytes.Buffer
	b.WriteString(`{"format":"` + FormatV1 + `","chains":[`)
	for c := 0; c < chains; c++ {
		if c > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"chain_id":%q,"entries":[`, testChainID(c))
		b.WriteString(strings.TrimSuffix(strings.Repeat(bareEntry+",", entriesEach), ","))
		b.WriteString(`],"checkpoints":[`)
		b.WriteString(strings.TrimSuffix(strings.Repeat(`"x",`, checkpointsEach), ","))
		b.WriteString(`]}`)
	}
	b.WriteString(`]}`)
	return b.Bytes()
}

// hashHex is SHA-512 as lowercase hex.
func hashHex(s string) string {
	sum := sha512.Sum512([]byte(s))
	return hex.EncodeToString(sum[:])
}

// eventEntries builds n linked sink.event entries. The chain hash is computed
// here from format-spec §2.1 as written, over the stored strings, so a chain
// that verifies also shows the package's chain hash agrees with the formula.
func eventEntries(n int) []rawEntry {
	entries := make([]rawEntry, n)
	start := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	previous := ""
	for i := range entries {
		e := &entries[i]
		e.entryID = fmt.Sprintf("sink-%032x", i)
		e.entryType = typeEvent
		e.globalSeq = fmt.Sprint(i)
		e.previousHash = previous
		e.timestamp = start.Add(time.Duration(i) * time.Microsecond).Format("2006-01-02T15:04:05.000000Z")
		e.contentHash = hashHex(fmt.Sprintf("content %d", i))
		e.chainHash = hashHex("aleutian.chain.v3:" + e.previousHash + "|" + e.globalSeq + "|" + e.timestamp + "|" + e.contentHash)
		previous = e.chainHash
	}
	return entries
}

// testCheckpoint builds the text of checkpoint number k (0-based) covering the
// first count entries, after a checkpoint with the given id and hash. With a
// seed it is signed; without, its signature is 3309 zero bytes. It returns the
// text, and the id and anchor chain hash the next checkpoint builds on.
func testCheckpoint(t testing.TB, chainID string, entries []rawEntry, count, k int, previousID, previousHash string,
	seed []byte) (text, id, chainHash string) {
	t.Helper()
	first, tip := entries[0], entries[count-1]
	id = fmt.Sprintf("anchor_%08d", k)
	chainHash = hashHex("aleutian.anchor.v2:" + previousHash + "|" + chainID + "|" + first.entryID + "|" + tip.entryID + "|" + tip.chainHash)
	signature := make([]byte, signatureSize)
	keyID := strings.Repeat("0", 32)
	if seed != nil {
		pub, err := mldsa.PublicKeyFromSeed(mldsa.MLDSA65, seed)
		if err != nil {
			t.Fatal(err)
		}
		key, err := NewPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		keyID = key.ID()
		canonical, err := anchor.Canonicalize(anchor.Anchor{
			Version: 6, AnchorID: id, Subject: chainID, ChainHash: chainHash,
			Range:      anchor.EntryRange{StartEntryID: first.entryID, EndEntryID: tip.entryID},
			EntryCount: int64(count), SigningKeyID: keyID, CreatedAtMs: 1, PreviousAnchorID: previousID,
			VerifiedThrough: int64(count),
		})
		if err != nil {
			t.Fatal(err)
		}
		if signature, err = mldsa.Sign(mldsa.MLDSA65, seed, canonical); err != nil {
			t.Fatal(err)
		}
	}
	text = fmt.Sprintf(`{"version":6,"anchor_id":%q,"subject":%q,"chain_hash":%q,`+
		`"range":{"start_entry_id":%q,"end_entry_id":%q},"entry_count":%d,"signature":%q,`+
		`"signing_key_id":%q,"created_at_ms":1,"previous_anchor_id":%q,"verified_through":%d}`,
		id, chainID, chainHash, first.entryID, tip.entryID, count,
		base64.StdEncoding.EncodeToString(signature), keyID, previousID, count)
	return text, id, chainHash
}

// encodeBundle writes chains as a bundle, in the exporter's member order.
func encodeBundle(t testing.TB, chains ...rawChain) []byte {
	t.Helper()
	str := func(s string) string {
		out, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	var b bytes.Buffer
	b.WriteString(`{"format":"` + FormatV1 + `","chains":[`)
	for ci, c := range chains {
		if ci > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"chain_id":` + str(c.id) + `,"entries":[`)
		for i, e := range c.entries {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `{"entry_id":%s,"entry_type":%s,"global_seq":%s,"previous_hash":%s,"timestamp":%s,"content_hash":%s,"chain_hash":%s`,
				str(e.entryID), str(e.entryType), str(e.globalSeq), str(e.previousHash), str(e.timestamp),
				str(e.contentHash), str(e.chainHash))
			if e.sig != nil {
				fmt.Fprintf(&b, `,"record_signature":{"key_id":%s,"signature":%s}`, str(e.sig.a), str(e.sig.b))
			}
			if e.disclosed != nil {
				fmt.Fprintf(&b, `,"disclosed":{"content":%s,"nonce":%s}`, str(e.disclosed.a), str(e.disclosed.b))
			}
			b.WriteByte('}')
		}
		b.WriteString(`],"checkpoints":[`)
		for i, text := range c.checkpoints {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(str(string(text)))
		}
		b.WriteString(`]}`)
	}
	b.WriteString(`]}`)
	return b.Bytes()
}

// mustVerify runs VerifyWithLimits and fails on an internal error.
func mustVerify(t testing.TB, data []byte, trust Trust, lim Limits) Result {
	t.Helper()
	res, err := VerifyWithLimits(data, trust, lim)
	if err != nil {
		t.Fatalf("internal error: %v", err)
	}
	return res
}

// reasonOf returns the unreadable reason, or "" for a readable bundle.
func reasonOf(res Result) string {
	if res.Readable {
		return ""
	}
	return res.Reason
}

// problemCodes lists a chain's problems as "code:count:first".
func problemCodes(ps []Problem) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		first := "null"
		if p.First != nil {
			first = fmt.Sprint(*p.First)
		}
		parts[i] = fmt.Sprintf("%s:%d:%s", p.Code, p.Count, first)
	}
	return strings.Join(parts, " ")
}

// measure runs f and returns the bytes it allocated in total, the most the
// heap grew by while it ran, and how long it took. The total counts every
// buffer a growing slice went through, so it overstates what was held at any
// moment; the peak is sampled, with the collector kept eager so that garbage
// does not count for long.
func measure(f func()) (allocated, peak uint64, elapsed time.Duration) {
	defer debug.SetGCPercent(debug.SetGCPercent(10))
	var before, after, sample runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	stop, stopped := make(chan struct{}), make(chan struct{})
	tick := time.NewTicker(200 * time.Microsecond)
	defer tick.Stop()
	go func() {
		defer close(stopped)
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				runtime.ReadMemStats(&sample)
				if sample.HeapAlloc > before.HeapAlloc && sample.HeapAlloc-before.HeapAlloc > peak {
					peak = sample.HeapAlloc - before.HeapAlloc
				}
			}
		}
	}()
	start := time.Now()
	f()
	elapsed = time.Since(start)
	close(stop)
	<-stopped
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc, peak, elapsed
}
