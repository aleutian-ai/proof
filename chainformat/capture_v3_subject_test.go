// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package chainformat

import (
	"encoding/json"
	"strings"
	"testing"
)

// subjectTestEntry is the package's standard valid leaf with only the subject
// varied, so these tests exercise the subject rule and nothing else.
func subjectTestEntry(subject string) CaptureRequestV3 {
	e := validFullEntry()
	e.Subject = subject
	return e
}

// TestSubject_AcceptsAnyNamespace is the point of this change: an adopter must
// not have to mint an Aleutian tenant ULID to describe their own data.
//
// Until 2026-09-23 the subject had to match `^comp_<26-char Crockford-base32
// ULID>$`, so every one of these was refused.
func TestSubject_AcceptsAnyNamespace(t *testing.T) {
	subjects := []string{
		"my-laptop",
		"acme-prod",
		"research/experiment-4",
		"alice@example.org",
		"a",
		"comp_01HZX9K2M3N4P5Q6R7S8T9V0WA", // the old shape is still fine
		strings.Repeat("s", maxV3StringFieldBytes),
		"日本語",
	}
	for _, subject := range subjects {
		t.Run(subject, func(t *testing.T) {
			if _, _, err := EncodeAndHashV3(subjectTestEntry(subject)); err != nil {
				t.Errorf("subject %q was refused: %v", subject, err)
			}
		})
	}
}

// TestSubject_EmptyIsStillRefused: an entry that commits to no namespace can be
// replayed into another chain. Widening the field is not the same as removing
// the field.
func TestSubject_EmptyIsStillRefused(t *testing.T) {
	_, _, err := EncodeAndHashV3(subjectTestEntry(""))
	if err == nil {
		t.Fatal("an empty subject was accepted")
	}
	if !strings.Contains(err.Error(), "subject") {
		t.Errorf("the error does not name the field: %v", err)
	}
}

// TestSubject_OverlongIsRefused: the existing field limits still apply — the
// regex was removed, not the bounds.
func TestSubject_OverlongIsRefused(t *testing.T) {
	if _, _, err := EncodeAndHashV3(subjectTestEntry(strings.Repeat("s", maxV3StringFieldBytes+1))); err == nil {
		t.Error("an over-long subject was accepted")
	}
}

// TestSubject_ControlBytesRefused: the delimiter-safety rules are unchanged.
func TestSubject_ControlBytesRefused(t *testing.T) {
	for _, bad := range []string{"has\x00nul", "has\nnewline"} {
		if _, _, err := EncodeAndHashV3(subjectTestEntry(bad)); err == nil {
			t.Errorf("subject %q was accepted", bad)
		}
	}
}

// TestSubject_RenameChangedNoHashedByte is the central claim of this change.
//
// The canonical form appends VALUES positionally and never writes a field name,
// so renaming company_id to subject cannot move a byte. Proven by hashing the
// same value under the new field and comparing with the digest recorded before
// the rename.
func TestSubject_RenameChangedNoHashedByte(t *testing.T) {
	e := subjectTestEntry("comp_01HZX9K2M3N4P5Q6R7S8T9V0WA")
	_, got, err := EncodeAndHashV3(e)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if got != goldenSubjectRenameHash {
		t.Errorf("the rename changed the hashed bytes:\n got  %s\n want %s", got, goldenSubjectRenameHash)
	}
}

// goldenSubjectRenameHash was computed by the PRE-RENAME code — the version of
// this package at git HEAD before 2026-09-23, with the field named CompanyID
// and the `^comp_<ULID>$` regex still in force — over the same entry
// validFullEntry() builds.
//
// It is independent evidence, not a value copied out of the current
// implementation. Regenerating it from today's code would make this test
// assert only that the code agrees with itself, which is exactly what it
// exists to rule out.
const goldenSubjectRenameHash = "444491ecb9705c9dc27bbaf21aaad3f0fb1ec25398a2e1086bb7f557919b8e0aa12ac6c95d051cccd1263e00f7728d15a35f2bacb2de0f8896bab73e77951c94"

// TestSubject_LegacyCompanyIDKeyStillLoads: files written under the old key
// exist. They describe the same entry — the key name was never hashed — so
// they must load and produce the same content hash.
func TestSubject_LegacyCompanyIDKeyStillLoads(t *testing.T) {
	want := subjectTestEntry("comp_01HZX9K2M3N4P5Q6R7S8T9V0WA")
	_, wantHash, err := EncodeAndHashV3(want)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	legacy := strings.Replace(string(raw), `"subject"`, `"company_id"`, 1)
	if legacy == string(raw) {
		t.Fatal("the marshalled entry does not use the subject key")
	}

	var got CaptureRequestV3
	if err := json.Unmarshal([]byte(legacy), &got); err != nil {
		t.Fatalf("a legacy company_id file failed to load: %v", err)
	}
	if got.Subject != want.Subject {
		t.Errorf("subject = %q, want %q", got.Subject, want.Subject)
	}
	_, gotHash, err := EncodeAndHashV3(got)
	if err != nil {
		t.Fatalf("encode the loaded entry: %v", err)
	}
	if gotHash != wantHash {
		t.Error("an entry loaded under the legacy key hashed differently")
	}
}

// TestSubject_ConflictingKeysRefused: two different values under two spellings
// is a corrupt file. Preferring one would produce a leaf whose hash matches
// neither reading the file admits.
func TestSubject_ConflictingKeysRefused(t *testing.T) {
	var e CaptureRequestV3
	err := json.Unmarshal([]byte(`{"subject":"one","company_id":"two"}`), &e)
	if err == nil {
		t.Fatal("an entry carrying two different subjects was accepted")
	}
	if !strings.Contains(err.Error(), "company_id") {
		t.Errorf("the error does not name the conflict: %v", err)
	}

	// The SAME value under both keys is not a conflict; it is a file written
	// during the transition.
	var ok CaptureRequestV3
	if err := json.Unmarshal([]byte(`{"subject":"one","company_id":"one"}`), &ok); err != nil {
		t.Errorf("matching keys were refused: %v", err)
	}
	if ok.Subject != "one" {
		t.Errorf("subject = %q", ok.Subject)
	}
}

// TestSubject_MarshalsUnderTheNewKey: the old name is read, never written.
func TestSubject_MarshalsUnderTheNewKey(t *testing.T) {
	raw, err := json.Marshal(subjectTestEntry("my-laptop"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"subject":"my-laptop"`) {
		t.Errorf("marshalled without a subject key:\n%s", raw)
	}
	if strings.Contains(string(raw), "company_id") {
		t.Errorf("marshalled with the legacy key:\n%s", raw)
	}
}

// TestSubject_IsNFCNormalized matters more now than it did before.
//
// Every other field is ASCII-restricted by regex, so NFC normalisation was a
// no-op in practice. A subject may carry free text, so it is the first field
// where two different byte sequences can denote the same string — "é" as one
// code point and as "e" plus a combining accent. They must hash identically,
// or a producer and a verifier on different platforms disagree about an entry
// neither of them altered.
func TestSubject_IsNFCNormalized(t *testing.T) {
	precomposed := "café" // é as U+00E9
	decomposed := "café" // e + U+0301 combining acute

	if precomposed == decomposed {
		t.Fatal("the two spellings are identical; the test proves nothing")
	}

	_, a, err := EncodeAndHashV3(subjectTestEntry(precomposed))
	if err != nil {
		t.Fatalf("precomposed: %v", err)
	}
	_, b, err := EncodeAndHashV3(subjectTestEntry(decomposed))
	if err != nil {
		t.Fatalf("decomposed: %v", err)
	}
	if a != b {
		t.Errorf("the same subject hashed differently by spelling:\n NFC %s\n NFD %s", a, b)
	}
}
