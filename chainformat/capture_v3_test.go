// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package chainformat

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/fixtures"
)

// validFullEntry returns a fully-populated pii_inspection capture leaf with
// every field set, used as the base for happy-path + mutation tests.
func validFullEntry() CaptureRequestV3 {
	return CaptureRequestV3{
		CompanyID:           "comp_01HZX9K2M3N4P5Q6R7S8T9V0WA",
		SigningKeyID:        "capture-leaf-signer-2026-v1",
		TimestampMs:         1751068800000, // 2025-06-28T00:00:00Z-ish; fixed for determinism
		CaptureMethod:       "fetch_intercept",
		ContentHash:         strings.Repeat("a", 128),
		DLP:                 strings.Repeat("b", 128),
		EncryptionMode:      "aleutian-managed",
		Model:               "gpt-4o-2024-08-06",
		PIIAction:           "flagged",
		PIICategories:       strings.Repeat("c", 128),
		PIIDetected:         true,
		PIIDigestKeyVersion: "sm:v1", // digests present ⇒ version required
		ProcessingMode:      "pii_inspection",
		Provider:            "openai",
		Region:              "us",
		SourceType:          "extension",
		TrustLevel:          "self-reported", // exercises the hyphen (real TrustLevel value)
		UserID:              strings.Repeat("d", 128),
	}
}

// validMinimalZKEntry returns a zk-mode leaf with all optional/compliance
// fields at their empty form — exercises the 0-length-prefix path.
func validMinimalZKEntry() CaptureRequestV3 {
	return CaptureRequestV3{
		CompanyID:           "comp_01HZX9K2M3N4P5Q6R7S8T9V0WA",
		SigningKeyID:        "capture-leaf-signer-2026-v1",
		TimestampMs:         1751068800000,
		CaptureMethod:       "",
		ContentHash:         strings.Repeat("e", 128),
		DLP:                 "",
		EncryptionMode:      "zero-knowledge",
		Model:               "",
		PIIAction:           "none",
		PIICategories:       "",
		PIIDetected:         false,
		PIIDigestKeyVersion: "",   // no digest ⇒ version empty (holds on every zk leaf)
		ProcessingMode:      "zk", // zk ⇒ empty compliance surface (above) — the enforced invariant
		Provider:            "",
		Region:              "",
		SourceType:          "",
		TrustLevel:          "",
		UserID:              strings.Repeat("f", 128),
	}
}

// goldenFixture is the cross-language contract record: the input fields plus the
// expected canonical hex + content-hash hex that every SDK port (01c/d/e) must
// reproduce byte-for-byte.
// --- Cross-language golden fixture schema (neutral; shared with the SDK ports) ---
//
// testdata/v3_golden_capture_request.json is THE byte contract every language port
// (Go SDK 01c, Python 01d, JS 01e) pins against; it is copied byte-identical into
// each SDK's testdata/. Schema mirrors the consent v3_golden_sar_*.json convention:
// a domain_prefix_v3 + entry_type + a `vectors` array whose `input` blocks use
// language-neutral snake_case field names, with the baked expected canonical and
// content-hash hexes.

type captureGoldenFile struct {
	SchemaComment  string                `json:"$schema_comment"`
	DomainPrefixV3 string                `json:"domain_prefix_v3"`
	EntryType      string                `json:"entry_type"`
	Vectors        []captureGoldenVector `json:"vectors"`
}

type captureGoldenVector struct {
	Comment                      string              `json:"$comment,omitempty"`
	Name                         string              `json:"name"`
	Input                        captureFixtureInput `json:"input"`
	ExpectedCanonicalBytesHex    string              `json:"expected_canonical_bytes_hex"`
	ExpectedContentHashSHA512Hex string              `json:"expected_content_hash_sha512_hex"`
}

// captureFixtureInput is the language-neutral input projection of CaptureRequestV3.
// The SDK ports declare a structurally-identical type with the SAME json tags so
// every language consumes one fixture file.
type captureFixtureInput struct {
	CompanyID           string `json:"company_id"`
	SigningKeyID        string `json:"signing_key_id"`
	TimestampMs         int64  `json:"timestamp_ms"`
	CaptureMethod       string `json:"capture_method"`
	ContentHash         string `json:"content_hash"`
	DLP                 string `json:"dlp"`
	EncryptionMode      string `json:"encryption_mode"`
	Model               string `json:"model"`
	PIIAction           string `json:"pii_action"`
	PIICategories       string `json:"pii_categories"`
	PIIDetected         bool   `json:"pii_detected"`
	PIIDigestKeyVersion string `json:"pii_digest_key_version"`
	ProcessingMode      string `json:"processing_mode"`
	Provider            string `json:"provider"`
	Region              string `json:"region"`
	SourceType          string `json:"source_type"`
	TrustLevel          string `json:"trust_level"`
	UserID              string `json:"user_id"`
}

func (in captureFixtureInput) toEntry() CaptureRequestV3 {
	return CaptureRequestV3{
		CompanyID:           in.CompanyID,
		SigningKeyID:        in.SigningKeyID,
		TimestampMs:         in.TimestampMs,
		CaptureMethod:       in.CaptureMethod,
		ContentHash:         in.ContentHash,
		DLP:                 in.DLP,
		EncryptionMode:      in.EncryptionMode,
		Model:               in.Model,
		PIIAction:           in.PIIAction,
		PIICategories:       in.PIICategories,
		PIIDetected:         in.PIIDetected,
		PIIDigestKeyVersion: in.PIIDigestKeyVersion,
		ProcessingMode:      in.ProcessingMode,
		Provider:            in.Provider,
		Region:              in.Region,
		SourceType:          in.SourceType,
		TrustLevel:          in.TrustLevel,
		UserID:              in.UserID,
	}
}

func entryToFixtureInput(e CaptureRequestV3) captureFixtureInput {
	return captureFixtureInput{
		CompanyID:           e.CompanyID,
		SigningKeyID:        e.SigningKeyID,
		TimestampMs:         e.TimestampMs,
		CaptureMethod:       e.CaptureMethod,
		ContentHash:         e.ContentHash,
		DLP:                 e.DLP,
		EncryptionMode:      e.EncryptionMode,
		Model:               e.Model,
		PIIAction:           e.PIIAction,
		PIICategories:       e.PIICategories,
		PIIDetected:         e.PIIDetected,
		PIIDigestKeyVersion: e.PIIDigestKeyVersion,
		ProcessingMode:      e.ProcessingMode,
		Provider:            e.Provider,
		Region:              e.Region,
		SourceType:          e.SourceType,
		TrustLevel:          e.TrustLevel,
		UserID:              e.UserID,
	}
}

const captureGoldenSchemaComment = "Cross-language v3 golden vectors for capture.request.v3 (chainlinker_modernization_01b; pii_digest_key_version added by pii_hmac_key_rotation_R3). Each vector's input uses language-neutral snake_case fields; expected_canonical_bytes_hex is the length-prefixed TLV (4-field header + 15-field alphabetical body) and expected_content_hash_sha512_hex is SHA-512 of 'aleutian.chain.entry.v3:' || canonical_bytes. Go SDK (01c), Python (01d), JS (01e) read this file and assert byte+hash equality on re-encode. Baked from the Go producer encoder."

// captureGoldenSeeds returns the canonical input vectors (without baked hexes).
func captureGoldenSeeds() []captureGoldenVector {
	clean := validFullEntry()
	clean.ProcessingMode = "pii_inspection"
	clean.PIIDetected = false
	clean.PIIAction = "none"
	clean.PIICategories = ""
	clean.DLP = ""
	clean.PIIDigestKeyVersion = "" // digests cleared ⇒ version must be empty too
	return []captureGoldenVector{
		{
			Comment: "aleutian-managed custody + pii_inspection + full verdict; every field non-empty incl hyphenated trust_level.",
			Name:    "full_pii_inspection",
			Input:   entryToFixtureInput(validFullEntry()),
		},
		{
			Comment: "zero-knowledge custody + zk processing; compliance surface empty (the enforced zk invariant) + all optional fields 0-length.",
			Name:    "minimal_zk",
			Input:   entryToFixtureInput(validMinimalZKEntry()),
		},
		{
			Comment: "inspection authorized but scanner found nothing — empty verdict with processing_mode=pii_inspection (disambiguated from zk by the sealed mode).",
			Name:    "inspected_clean",
			Input:   entryToFixtureInput(clean),
		},
	}
}

// buildCaptureGoldenFile bakes the expected hexes for every seed via this encoder.
func buildCaptureGoldenFile(t *testing.T) captureGoldenFile {
	t.Helper()
	seeds := captureGoldenSeeds()
	for i := range seeds {
		canonical, contentHash, err := EncodeAndHashV3(seeds[i].Input.toEntry())
		if err != nil {
			t.Fatalf("vector %s: EncodeAndHashV3: %v", seeds[i].Name, err)
		}
		seeds[i].ExpectedCanonicalBytesHex = hex.EncodeToString(canonical)
		seeds[i].ExpectedContentHashSHA512Hex = contentHash
	}
	return captureGoldenFile{
		SchemaComment:  captureGoldenSchemaComment,
		DomainPrefixV3: DomainPrefixV3,
		EntryType:      EntryTypeCaptureRequestV3,
		Vectors:        seeds,
	}
}

// TestCanonicalV3_Golden bakes the fixture from this encoder and asserts byte-equality
// against the committed cross-language file. UPDATE_GOLDEN=1 (re)writes it after an
// intentional, reviewed contract change.
func TestCanonicalV3_Golden(t *testing.T) {
	// aleutianchain_20: one copy, in fixtures/. Regeneration writes the file;
	// verification reads the EMBEDDED bytes, so what is checked is exactly what
	// ships to consumers — a file read could pass against an on-disk copy that
	// never made it into a build.
	path := filepath.Join("..", "fixtures", "testdata", "v3_golden_capture_request.json")
	got, err := json.MarshalIndent(buildCaptureGoldenFile(t), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		t.Logf("wrote golden fixture %s", path)
		t.Log("NOTE: rebuild before the embedded copy (and any consumer) reflects this")
		return
	}

	want := fixtures.CaptureRequestV3Golden()
	if len(want) == 0 {
		t.Fatal("embedded capture golden is empty (run UPDATE_GOLDEN=1, then rebuild)")
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("golden fixture drift — the producer encoder no longer matches the committed\n"+
			"cross-language contract %s. If this change is intentional + reviewed, regenerate with\n"+
			"UPDATE_GOLDEN=1 and re-bake the SDK ports (01c/d/e).", path)
	}
}

// NOTE (aleutianchain_05): the producer's TestCanonicalV3_SDKFixtureInSync was
// deliberately NOT ported. It compared the producer fixture against
// sdk/verification-go/testdata/, a path that does not exist from inside this
// module. The equivalent guards live where they can actually see both copies:
// aleutianchain_21 (producer <-> Go SDK, discovery-based) and aleutianchain_20
// (this module <-> the monorepo's shared copy).

// TestCanonicalV3_GoldenSelfConsistent reproduces every committed vector from its own
// stored input and asserts the baked hexes — the exact assertion the SDK ports run, so
// a divergence here predicts an SDK parity failure.
func TestCanonicalV3_GoldenSelfConsistent(t *testing.T) {
	raw := fixtures.CaptureRequestV3Golden()
	var f captureGoldenFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}
	if f.DomainPrefixV3 != DomainPrefixV3 {
		t.Errorf("domain prefix drift: fixture=%q const=%q", f.DomainPrefixV3, DomainPrefixV3)
	}
	if f.EntryType != EntryTypeCaptureRequestV3 {
		t.Errorf("entry_type drift: fixture=%q const=%q", f.EntryType, EntryTypeCaptureRequestV3)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("golden file has no vectors")
	}
	for _, v := range f.Vectors {
		canonical, contentHash, err := EncodeAndHashV3(v.Input.toEntry())
		if err != nil {
			t.Fatalf("vector %s: encode: %v", v.Name, err)
		}
		if got := hex.EncodeToString(canonical); got != v.ExpectedCanonicalBytesHex {
			t.Errorf("vector %s canonical mismatch:\n want %s\n  got %s", v.Name, v.ExpectedCanonicalBytesHex, got)
		}
		if contentHash != v.ExpectedContentHashSHA512Hex {
			t.Errorf("vector %s content_hash mismatch:\n want %s\n  got %s", v.Name, v.ExpectedContentHashSHA512Hex, contentHash)
		}
	}
}

// TestCanonicalV3_Idempotent locks that encoding the same entry twice yields
// identical bytes (no map iteration, no time, no randomness in the path).
func TestCanonicalV3_Idempotent(t *testing.T) {
	e := validFullEntry()
	a, err := CanonicalV3(e)
	if err != nil {
		t.Fatalf("first encode: %v", err)
	}
	b, err := CanonicalV3(e)
	if err != nil {
		t.Fatalf("second encode: %v", err)
	}
	if !strings.EqualFold(hex.EncodeToString(a), hex.EncodeToString(b)) {
		t.Fatalf("non-deterministic encode:\n a=%x\n b=%x", a, b)
	}
}

// TestCanonicalV3_ContentHashWiring pins that EncodeAndHashV3's content hash is
// exactly SHA-512(prefix || canonical) — i.e. the prefix is wired in.
func TestCanonicalV3_ContentHashWiring(t *testing.T) {
	e := validFullEntry()
	canonical, ch, err := EncodeAndHashV3(e)
	if err != nil {
		t.Fatalf("EncodeAndHashV3: %v", err)
	}
	if got := ContentHashV3(canonical); got != ch {
		t.Fatalf("content hash wiring mismatch: EncodeAndHash=%s recompute=%s", ch, got)
	}
	if len(ch) != 128 {
		t.Fatalf("content hash not 128 hex chars: got %d", len(ch))
	}
}

// TestDomainPrefixV3_MatchesConsentEncoder pins the capture and consent chains
// to the SAME domain prefix (domain separation is via entry_type, not prefix).
func TestDomainPrefixV3_MatchesConsentEncoder(t *testing.T) {
	// Literal rather than an import: this module is the public definition of the
	// format, so the value the consent chain must agree with is pinned HERE. A
	// change on either side has to break this test rather than silently agree.
	const consentChainCanonicalV3DomainPrefix = "aleutian.chain.entry.v3:"
	if DomainPrefixV3 != consentChainCanonicalV3DomainPrefix {
		t.Fatalf("domain prefix drift: chainformat=%q consent=%q (MUST match — domain separation is via entry_type)",
			DomainPrefixV3, consentChainCanonicalV3DomainPrefix)
	}
}

// TestCanonicalV3_TLVStructure parses the canonical bytes back and asserts the
// exact field count, order, and the sealed entry_type — guards against a
// silently dropped/reordered field.
func TestCanonicalV3_TLVStructure(t *testing.T) {
	e := validFullEntry()
	canonical, err := CanonicalV3(e)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	fields := parseTLV(t, canonical)
	// 4 header fields (company_id, entry_type, signing_key_id, timestamp_ms[u64])
	// + 15 body fields (pii_detected is the only u64 body field).
	if len(fields) != 19 {
		t.Fatalf("expected 19 TLV fields (4 header + 15 body), got %d", len(fields))
	}
	// Header order.
	assertStrField(t, fields[0], "company_id", e.CompanyID)
	assertStrField(t, fields[1], "entry_type", EntryTypeCaptureRequestV3)
	assertStrField(t, fields[2], "signing_key_id", e.SigningKeyID)
	assertU64Field(t, fields[3], "timestamp_ms", uint64(e.TimestampMs))
	// Body order (alphabetical).
	assertStrField(t, fields[4], "capture_method", e.CaptureMethod)
	assertStrField(t, fields[5], "content_hash", e.ContentHash)
	assertStrField(t, fields[6], "dlp", e.DLP)
	assertStrField(t, fields[7], "encryption_mode", e.EncryptionMode)
	assertStrField(t, fields[8], "model", e.Model)
	assertStrField(t, fields[9], "pii_action", e.PIIAction)
	assertStrField(t, fields[10], "pii_categories", e.PIICategories)
	assertU64Field(t, fields[11], "pii_detected", 1)
	assertStrField(t, fields[12], "pii_digest_key_version", e.PIIDigestKeyVersion)
	assertStrField(t, fields[13], "processing_mode", e.ProcessingMode)
	assertStrField(t, fields[14], "provider", e.Provider)
	assertStrField(t, fields[15], "region", e.Region)
	assertStrField(t, fields[16], "source_type", e.SourceType)
	assertStrField(t, fields[17], "trust_level", e.TrustLevel)
	assertStrField(t, fields[18], "user_id", e.UserID)
}

// TestCanonicalV3_PIIDetectedEncoding pins false→0, true→1 for pii_detected.
func TestCanonicalV3_PIIDetectedEncoding(t *testing.T) {
	for _, tc := range []struct {
		detected bool
		want     uint64
	}{{false, 0}, {true, 1}} {
		e := validFullEntry()
		e.PIIDetected = tc.detected
		canonical, err := CanonicalV3(e)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		fields := parseTLV(t, canonical)
		assertU64Field(t, fields[11], "pii_detected", tc.want)
	}
}

// TestCanonicalV3_ValidModeCombinations locks that encryption_mode (custody) and
// processing_mode (inspection authorization) are ORTHOGONAL — every legal pairing
// encodes successfully — and that an inspected-but-clean row is valid. These are
// the positive cases the rejection table cannot express.
func TestCanonicalV3_ValidModeCombinations(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*CaptureRequestV3)
	}{
		{"zero-knowledge_custody_with_inspection", func(e *CaptureRequestV3) {
			// Client-side key custody but the tenant authorized inspection — a
			// legal combo precisely because the two modes are independent.
			e.EncryptionMode = "zero-knowledge"
			e.ProcessingMode = "pii_inspection"
			// keeps the full entry's verdict (pii_detected=true, dlp, categories)
		}},
		{"aleutian-managed_custody_with_zk_processing", func(e *CaptureRequestV3) {
			e.EncryptionMode = "aleutian-managed"
			e.ProcessingMode = "zk"
			e.PIIDetected = false
			e.PIIAction = "none"
			e.PIICategories = ""
			e.DLP = ""
			e.PIIDigestKeyVersion = "" // no digest ⇒ no version
		}},
		{"inspected_and_clean", func(e *CaptureRequestV3) {
			// Inspection authorized, scanner ran, found nothing → verdict is the
			// empty form but processing_mode is pii_inspection (NOT zk). Disambiguated
			// from a zk row by the sealed processing_mode.
			e.ProcessingMode = "pii_inspection"
			e.PIIDetected = false
			e.PIIAction = "none"
			e.PIICategories = ""
			e.DLP = ""
			e.PIIDigestKeyVersion = "" // no digest ⇒ no version
		}},
		{"cmek_custody", func(e *CaptureRequestV3) { e.EncryptionMode = "cmek" }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			e := validFullEntry()
			tc.mutate(&e)
			if _, _, err := EncodeAndHashV3(e); err != nil {
				t.Fatalf("expected valid combination %s to encode, got %v", tc.name, err)
			}
		})
	}
}

// TestCanonicalV3_Rejections covers every validation rejection path.
func TestCanonicalV3_Rejections(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*CaptureRequestV3)
	}{
		{"empty_company_id", func(e *CaptureRequestV3) { e.CompanyID = "" }},
		{"bad_company_id", func(e *CaptureRequestV3) { e.CompanyID = "comp_lowercase" }},
		{"empty_signing_key_id", func(e *CaptureRequestV3) { e.SigningKeyID = "" }},
		{"bad_signing_key_id", func(e *CaptureRequestV3) { e.SigningKeyID = "has space" }},
		{"zero_timestamp", func(e *CaptureRequestV3) { e.TimestampMs = 0 }},
		{"negative_timestamp", func(e *CaptureRequestV3) { e.TimestampMs = -1 }},
		{"bad_content_hash_short", func(e *CaptureRequestV3) { e.ContentHash = "abc" }},
		{"bad_content_hash_uppercase", func(e *CaptureRequestV3) { e.ContentHash = strings.Repeat("A", 128) }},
		{"empty_content_hash", func(e *CaptureRequestV3) { e.ContentHash = "" }},
		{"empty_user_id", func(e *CaptureRequestV3) { e.UserID = "" }},
		{"bad_user_id", func(e *CaptureRequestV3) { e.UserID = strings.Repeat("z", 128) }},
		{"bad_dlp_digest", func(e *CaptureRequestV3) { e.DLP = "nothex" }},
		{"bad_pii_categories_digest", func(e *CaptureRequestV3) { e.PIICategories = strings.Repeat("g", 64) }},
		{"bad_encryption_mode", func(e *CaptureRequestV3) { e.EncryptionMode = "plaintext" }},
		{"empty_encryption_mode", func(e *CaptureRequestV3) { e.EncryptionMode = "" }},
		{"bad_pii_action", func(e *CaptureRequestV3) { e.PIIAction = "deleted" }},
		{"bad_provider_charset", func(e *CaptureRequestV3) { e.Provider = "Open AI" }},
		{"bad_model_charset", func(e *CaptureRequestV3) { e.Model = "gpt 4o" }},
		{"bad_region_charset", func(e *CaptureRequestV3) { e.Region = "US_EAST" }},
		{"bad_capture_method_charset", func(e *CaptureRequestV3) { e.CaptureMethod = "Browser-Ext" }},
		{"control_byte_in_source_type", func(e *CaptureRequestV3) { e.SourceType = "chat\tcompletion" }},
		{"oversize_model", func(e *CaptureRequestV3) { e.Model = strings.Repeat("a", 129) }},
		{"far_future_timestamp", func(e *CaptureRequestV3) { e.TimestampMs = maxPlausibleTimestampMs + 1 }},
		{"model_with_colon", func(e *CaptureRequestV3) { e.Model = "llama3:8b" }}, // F6: ':' dropped from alphabet
		// Mode-vocabulary correctness: the OLD conflated values must now be rejected.
		{"encryption_mode_is_processing_value", func(e *CaptureRequestV3) { e.EncryptionMode = "zk" }},
		{"empty_processing_mode", func(e *CaptureRequestV3) { e.ProcessingMode = "" }},
		{"bad_processing_mode", func(e *CaptureRequestV3) { e.ProcessingMode = "zero-knowledge" }}, // custody value, not a processing value
		// zk cross-field invariant: processing_mode=zk requires the empty compliance surface.
		{"zk_with_pii_detected", func(e *CaptureRequestV3) {
			e.ProcessingMode = "zk"
			e.PIIDetected = true
		}},
		{"zk_with_pii_action", func(e *CaptureRequestV3) {
			e.ProcessingMode = "zk"
			e.PIIDetected = false
			e.PIIAction = "flagged"
		}},
		{"zk_with_pii_categories", func(e *CaptureRequestV3) {
			e.ProcessingMode = "zk"
			e.PIIDetected = false
			e.PIIAction = "none"
		}}, // PIICategories stays non-empty from validFullEntry → rejected
		{"zk_with_dlp", func(e *CaptureRequestV3) {
			e.ProcessingMode = "zk"
			e.PIIDetected = false
			e.PIIAction = "none"
			e.PIICategories = ""
		}}, // DLP stays non-empty from validFullEntry → rejected
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			e := validFullEntry()
			tc.mutate(&e)
			_, err := CanonicalV3(e)
			if err == nil {
				t.Fatalf("expected rejection for %s, got nil", tc.name)
			}
			if !errors.Is(err, ErrInvalidEntryV3) {
				t.Fatalf("expected ErrInvalidEntryV3, got %v", err)
			}
		})
	}
}

// TestAppendStr_NFCNormalizes exercises the REAL NFC machinery directly on the
// encoder helper (4-agent review F3). Every public CaptureRequestV3 field is
// regex-pinned to an ASCII subset, so NFC is a no-op through the public API and
// a struct-level test gives false coverage. This drives appendStr with a
// decomposed vs a precomposed form of "é" and asserts (a) identical emitted
// bytes and (b) that the length prefix is the POST-NFC UTF-8 byte length (2),
// not the pre-NFC decomposed byte length (3) — the exact cross-language contract
// a Python/JS port must reproduce (NFC, not NFKC; byte length, not code points).
func TestAppendStr_NFCNormalizes(t *testing.T) {
	decomposed := "é" // 'e' + COMBINING ACUTE ACCENT (3 UTF-8 bytes)
	precomposed := "é" // 'é' (2 UTF-8 bytes)

	var a, b v3Encoder
	a.appendStr(decomposed)
	b.appendStr(precomposed)
	if a.err != nil || b.err != nil {
		t.Fatalf("appendStr errored: a=%v b=%v", a.err, b.err)
	}
	if !bytes.Equal(a.buf, b.buf) {
		t.Fatalf("NFC not applied: decomposed=%x precomposed=%x", a.buf, b.buf)
	}
	// 0x00000002 length prefix (post-NFC byte length) + UTF-8 of 'é' (0xC3 0xA9).
	want := []byte{0x00, 0x00, 0x00, 0x02, 0xc3, 0xa9}
	if !bytes.Equal(a.buf, want) {
		t.Fatalf("post-NFC byte-length contract broken: want %x got %x", want, a.buf)
	}
}

// TestEntryType_DisjointFromConsent pins the domain-separation invariant
// (4-agent review F5): the capture entry_type MUST NOT collide with any consent
// entry_type, since the two chains share DomainPrefixV3 and separate only via
// this length-prefixed header field.
func TestEntryType_DisjointFromConsent(t *testing.T) {
	// Literals, not an import. Pinning the exact strings is stronger than
	// depending on another package's constants: if a consent entry type is ever
	// renamed TO "capture.request.v3", that must fail here, and it would not if
	// this test merely followed whatever that package currently declares.
	consentTypes := []string{
		"consent_granted",
		"consent_revoked",
		"processing_mode_change",
		"consent_expired",
		"sar_intent",
		"sar_acknowledged",
		"sar_fulfilled",
		"sar_rejected",
		"sar_extended",
	}
	for _, ct := range consentTypes {
		if ct == EntryTypeCaptureRequestV3 {
			t.Fatalf("capture entry_type %q collides with consent entry_type %q", EntryTypeCaptureRequestV3, ct)
		}
	}
}

// TestCanonicalV3_HandDerivedHeaderPrefix is an INDEPENDENT oracle (4-agent
// review M3): rather than trusting the encoder to agree with itself, it hand-
// computes the first canonical record (company_id) and asserts the encoder
// emits exactly those bytes — catching a systematic endianness/framing bug that
// a self-referential golden regen would bake in.
func TestCanonicalV3_HandDerivedHeaderPrefix(t *testing.T) {
	e := validMinimalZKEntry()
	canonical, err := CanonicalV3(e)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	cid := []byte(e.CompanyID)
	var want []byte
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(cid))) // u32-BE length prefix
	want = append(want, lp[:]...)
	want = append(want, cid...)
	if !bytes.HasPrefix(canonical, want) {
		t.Fatalf("hand-derived company_id record mismatch:\n want prefix %x\n got        %x", want, canonical[:len(want)])
	}
}

// --- TLV parse helpers ---

type tlvField struct {
	isU64 bool
	str   string
	u64   uint64
}

// parseTLV walks the capture canonical layout. Because the layout is a fixed
// schedule (str×3, u64, then str×7, u64, str×6), the parser is schedule-driven
// rather than self-describing — it knows position 3 and position 11 are u64.
//
// The u64 positions {3, 11} are hardcoded to mirror encodeCanonical's field
// order (header timestamp_ms at index 3, body pii_detected at index 11). If that
// schedule ever changes, TestCanonicalV3_TLVStructure fails loudly on the
// resulting field-count/type mismatch — keep the two in sync.
func parseTLV(t *testing.T, b []byte) []tlvField {
	t.Helper()
	u64Positions := map[int]bool{3: true, 11: true}
	var fields []tlvField
	pos := 0
	idx := 0
	for pos < len(b) {
		if u64Positions[idx] {
			if pos+8 > len(b) {
				t.Fatalf("truncated u64 at field %d", idx)
			}
			fields = append(fields, tlvField{isU64: true, u64: binary.BigEndian.Uint64(b[pos : pos+8])})
			pos += 8
			idx++
			continue
		}
		if pos+4 > len(b) {
			t.Fatalf("truncated length prefix at field %d", idx)
		}
		n := int(binary.BigEndian.Uint32(b[pos : pos+4]))
		pos += 4
		if pos+n > len(b) {
			t.Fatalf("truncated string body at field %d (len=%d)", idx, n)
		}
		fields = append(fields, tlvField{str: string(b[pos : pos+n])})
		pos += n
		idx++
	}
	return fields
}

func assertStrField(t *testing.T, f tlvField, name, want string) {
	t.Helper()
	if f.isU64 {
		t.Fatalf("%s: expected string field, got u64", name)
	}
	if f.str != want {
		t.Errorf("%s: want %q got %q", name, want, f.str)
	}
}

func assertU64Field(t *testing.T, f tlvField, name string, want uint64) {
	t.Helper()
	if !f.isU64 {
		t.Fatalf("%s: expected u64 field, got string %q", name, f.str)
	}
	if f.u64 != want {
		t.Errorf("%s: want %d got %d", name, want, f.u64)
	}
}
