// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package sink

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/fixtures"
)

// validRecordFields is a well-formed envelope input; tests change one field.
func validRecordFields() recordFields {
	return recordFields{
		chainID:     "payments.0123456789abcdef0123456789abcdef",
		entryID:     "sink-fedcba9876543210fedcba9876543210",
		entryType:   EntryTypeEvent,
		globalSeq:   41,
		prevHash:    strings.Repeat("ef", 64),
		timestamp:   time.Date(2026, 9, 30, 12, 0, 0, 123456000, time.UTC),
		contentHash: strings.Repeat("ab", 64),
		keyID:       "3fb85abc3e8bae42952ee9194ae1f615",
	}
}

// recordVectorFile is fixtures/testdata/record_v1_vectors.json.
type recordVectorFile struct {
	Vectors []struct {
		Name   string            `json:"name"`
		Fields map[string]string `json:"fields"`
		Hex    string            `json:"envelope_hex"`
		SHA512 string            `json:"envelope_sha512"`
		UnixNs string            `json:"timestamp_unix_ns"`
	} `json:"vectors"`
	Reject []struct {
		Name   string            `json:"name"`
		Fields map[string]string `json:"fields"`
	} `json:"reject"`
	Regression struct {
		Vector    string `json:"vector"`
		SeedHex   string `json:"seed_hex"`
		PublicHex string `json:"public_key_hex"`
		SigHex    string `json:"signature_hex"`
	} `json:"regression_signature"`
}

func loadRecordVectors(t *testing.T) recordVectorFile {
	t.Helper()
	var file recordVectorFile
	if err := json.Unmarshal(fixtures.RecordV1Vectors(), &file); err != nil {
		t.Fatal(err)
	}
	return file
}

// fieldsFromStrings reads a vector's fields STRICTLY, as a verifier reading
// text must: a sequence or timestamp that does not re-encode to the same
// string is refused, not normalised.
func fieldsFromStrings(m map[string]string) (recordFields, error) {
	seq, err := strconv.ParseInt(m["global_seq"], 10, 64)
	if err != nil || strconv.FormatInt(seq, 10) != m["global_seq"] {
		return recordFields{}, fmt.Errorf("global_seq %q is not canonical", m["global_seq"])
	}
	ts, err := time.Parse(time.RFC3339Nano, m["timestamp"])
	if err != nil || ts.UTC().Format("2006-01-02T15:04:05.000000Z") != m["timestamp"] {
		return recordFields{}, fmt.Errorf("timestamp %q is not canonical", m["timestamp"])
	}
	return recordFields{
		chainID: m["chain_id"], entryID: m["entry_id"], entryType: m["entry_type"],
		globalSeq: seq, prevHash: m["previous_hash"], timestamp: ts,
		contentHash: m["content_hash"], keyID: m["signing_key_id"],
	}, nil
}

// TestRecordEnvelope_Vectors: the Go encoder reproduces, byte for byte, the
// envelopes computed independently in Python from the spec.
func TestRecordEnvelope_Vectors(t *testing.T) {
	file := loadRecordVectors(t)
	if len(file.Vectors) < 7 {
		t.Fatalf("only %d vectors", len(file.Vectors))
	}
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			f, err := fieldsFromStrings(v.Fields)
			if err != nil {
				t.Fatal(err)
			}
			if v.UnixNs != "" {
				// Format from the instant, not from the string: Python truncated
				// it independently, and Go must agree.
				ns, err := strconv.ParseInt(v.UnixNs, 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				f.timestamp = time.Unix(0, ns)
			}
			got, err := recordEnvelope(f)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != v.Hex {
				t.Fatalf("envelope differs from the independent vector\n got %x\nwant %s", got, v.Hex)
			}
			sum := sha512.Sum512(got)
			if hex.EncodeToString(sum[:]) != v.SHA512 {
				t.Fatal("envelope SHA-512 differs")
			}
		})
	}
}

// TestRecordEnvelope_RejectVectors: every must-refuse case of the vectors is
// refused, when read strictly from text or encoded.
func TestRecordEnvelope_RejectVectors(t *testing.T) {
	file := loadRecordVectors(t)
	if len(file.Reject) < 10 {
		t.Fatalf("only %d reject cases", len(file.Reject))
	}
	for _, r := range file.Reject {
		t.Run(r.Name, func(t *testing.T) {
			f, err := fieldsFromStrings(r.Fields)
			if err != nil {
				return // refused on reading
			}
			if env, err := recordEnvelope(f); err == nil {
				t.Fatalf("accepted: %x", env)
			}
		})
	}
}

// TestRecordEnvelope_RefusesInvalidFields: every field is checked, so nothing
// the sink would never write can be signed (or rebuilt for verification).
func TestRecordEnvelope_RefusesInvalidFields(t *testing.T) {
	cases := map[string]func(f *recordFields){
		"chain id not minted by the sink":  func(f *recordFields) { f.chainID = "../escape" },
		"chain id empty":                   func(f *recordFields) { f.chainID = "" },
		"entry id not assigned by it":      func(f *recordFields) { f.entryID = "jo@example.com" },
		"entry type unknown":               func(f *recordFields) { f.entryType = "tombstone" },
		"negative sequence":                func(f *recordFields) { f.globalSeq = -1 },
		"previous hash on the first entry": func(f *recordFields) { f.globalSeq = 0 },
		"no previous hash after the first": func(f *recordFields) { f.prevHash = "" },
		"previous hash upper case":         func(f *recordFields) { f.prevHash = strings.Repeat("EF", 64) },
		"timestamp unset":                  func(f *recordFields) { f.timestamp = time.Time{} },
		"year 0":                           func(f *recordFields) { f.timestamp = time.Date(0, 6, 1, 0, 0, 0, 0, time.UTC) },
		"year past 9999":                   func(f *recordFields) { f.timestamp = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
		"year before 0":                    func(f *recordFields) { f.timestamp = time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC) },
		"content hash upper case":          func(f *recordFields) { f.contentHash = strings.Repeat("AB", 64) },
		"content hash short":               func(f *recordFields) { f.contentHash = strings.Repeat("ab", 32) },
		"key id upper case":                func(f *recordFields) { f.keyID = "3FB85ABC3E8BAE42952EE9194AE1F615" },
		"key id short":                     func(f *recordFields) { f.keyID = "3fb85abc" },
		"key id empty":                     func(f *recordFields) { f.keyID = "" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := validRecordFields()
			change(&f)
			if env, err := recordEnvelope(f); err == nil {
				t.Fatalf("accepted: %x", env)
			}
		})
	}
}

// TestRecordEnvelope_EveryFieldIsBound: changing any one field changes the
// bytes signed.
func TestRecordEnvelope_EveryFieldIsBound(t *testing.T) {
	base, err := recordEnvelope(validRecordFields())
	if err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(f *recordFields){
		"chain":        func(f *recordFields) { f.chainID = "auth.0123456789abcdef0123456789abcdef" },
		"entry id":     func(f *recordFields) { f.entryID = "sink-" + strings.Repeat("1", 32) },
		"entry type":   func(f *recordFields) { f.entryType = EntryTypeErasure },
		"sequence":     func(f *recordFields) { f.globalSeq = 42 },
		"previous":     func(f *recordFields) { f.prevHash = strings.Repeat("01", 64) },
		"timestamp":    func(f *recordFields) { f.timestamp = f.timestamp.Add(time.Microsecond) },
		"content hash": func(f *recordFields) { f.contentHash = strings.Repeat("cd", 64) },
		"key id":       func(f *recordFields) { f.keyID = strings.Repeat("0", 32) },
	}
	for name, change := range changes {
		f := validRecordFields()
		change(&f)
		env, err := recordEnvelope(f)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bytes.Equal(env, base) {
			t.Errorf("changing the %s did not change the envelope", name)
		}
	}
}

// TestRecordEnvelope_TimestampEncoding: UTC, six digits, sub-microsecond
// truncated (format-spec §4), exactly as the chain hash encodes it.
func TestRecordEnvelope_TimestampEncoding(t *testing.T) {
	f := validRecordFields()
	base, _ := recordEnvelope(f)

	f.timestamp = f.timestamp.Add(999 * time.Nanosecond)
	if got, _ := recordEnvelope(f); !bytes.Equal(got, base) {
		t.Fatal("sub-microsecond precision changed the envelope (must be truncated)")
	}
	f.timestamp = validRecordFields().timestamp.In(time.FixedZone("X", 5*3600))
	if got, _ := recordEnvelope(f); !bytes.Equal(got, base) {
		t.Fatal("the same instant in another zone changed the envelope (must be UTC)")
	}
	if !bytes.Contains(base, []byte("2026-09-30T12:00:00.123456Z")) {
		t.Fatalf("timestamp not in the §4 form: %q", base)
	}
}
