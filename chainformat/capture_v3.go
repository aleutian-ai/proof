// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package chainformat

// This file is the producer-side canonical encoder for the V3 typed-TLV capture
// leaf — the entry describing one AI request. It is NOT the package
// documentation; see doc.go for that.
//
// # The locked domain prefix
//
// Leaves are encoded under "aleutian.chain.entry.v3:". A sibling encoder in
// Aleutian's private tree encodes a consent/SAR sub-chain under the SAME
// prefix; the two are separated by the header `entry_type` field
// ("capture.request.v3" here), not by the prefix. An adopter defining their own
// entry types must keep them distinct from that value for the same reason.
//
// # Field order is frozen, and does not follow the field NAMES
//
// Header, in the order the format was defined with:
//
//	company_id, entry_type, signing_key_id, timestamp_ms
//
// The first field is now called `subject`. The ORDER did not follow the rename,
// and must not: these are positional VALUES and the encoder never writes a key
// name, so moving one would change every content hash ever computed. See
// encodeCanonicalV3.
//
// `timestamp_ms` is the server-stamped arrival clock and is NOT repeated in the
// body. Body fields follow, every one emitted unconditionally with a 0-length
// prefix (or 0) when empty, so the layout is independent of which fields a
// particular entry happens to populate:
//
//	capture_method, content_hash, dlp, encryption_mode, model, pii_action,
//	pii_categories, pii_detected, pii_digest_key_version, processing_mode,
//	provider, region, source_type, trust_level, user_id
//
// `encryption_mode` {zero-knowledge|aleutian-managed|cmek} is KEY CUSTODY;
// `processing_mode` {zk|pii_inspection} is INSPECTION AUTHORIZATION. They are
// orthogonal, and conflating them is the mistake this note exists to prevent.
// processing_mode=="zk" requires an empty compliance surface, which is enforced.
//
// # SECURITY DELEGATION — this encoder validates SHAPE, not keying
//
// `user_id`, `pii_categories` and `dlp` are expected to be keyed digests (128
// lowercase hex, or empty), minted UPSTREAM by whoever produces the entry. This
// encoder never sees cleartext and checks only the shape.
//
// **A 128-hex string is byte-indistinguishable between a correctly keyed HMAC
// and a plain unkeyed SHA-512** — or a digest minted under the wrong key. This
// encoder cannot tell them apart from the value alone, and it does not try.
//
// Because the bytes it produces become immutable and signed, a keying regression
// upstream is UNRECOVERABLE after the fact. The producer therefore owns these,
// and they belong in that producer's release gate, not here:
//
//   - the digest key is non-empty and valid. An empty key silently degrades to
//     a plain hash, which turns the chain into an immutable, signed,
//     cross-namespace correlation oracle that cannot be remediated after
//     sealing;
//   - the digest was minted for the same subject the leaf names, so two
//     namespaces cannot be spliced;
//   - a known-answer test pins that two distinct keys produce distinct digests
//     for the same input.
//
// # Concurrency
//
// Every exported function here is a pure function over its inputs and is safe
// for concurrent use.

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// DomainPrefixV3 is the locked v3 domain prefix shared with the consent chain
// (internal/consent.ChainCanonicalV3DomainPrefix). Per the v3 spec the prefix
// is concatenated with canonical_bytes to form the content-hash + signature
// preimage but is NOT itself part of canonical_bytes.
//
// # WARNING — load-bearing constant
//
// Changing this byte sequence invalidates every signed v3 chain entry across
// BOTH chains and all language ports. It MUST stay byte-identical to the
// consent encoder's prefix (pinned by
// TestDomainPrefixV3_MatchesConsentEncoder). Bumping requires a v4 ticket chain
// + cross-language verifier coordination.
const DomainPrefixV3 = "aleutian.chain.entry.v3:"

// EntryTypeCaptureRequestV3 is the entry_type discriminator for a capture-chain
// AI-request leaf. It is the load-bearing domain separator between the capture
// chain and the consent chain (which share DomainPrefixV3); the SDK verifier
// dispatch switches on this exact string.
//
// # Why the shared prefix is collision-safe
//
// The capture and consent chains share DomainPrefixV3 and separate ONLY via
// this entry_type. That is sound because entry_type is a length-prefixed field
// at a FIXED header offset (index 1) identical in both encoders: a capture
// canonical and a consent canonical differ in the field-1 bytes, and the u32-BE
// length prefix makes the two byte sequences non-collidable (a cross-chain
// collision would require two DISTINCT length-prefixed entry_type strings to
// coincide, which is impossible). A capture leaf therefore cannot be
// reinterpreted as a consent entry without changing the content hash and
// breaking the ML-DSA-65 signature. This invariant rests on entry_type staying
// length-prefixed at a fixed offset in both encoders — pinned by
// TestEntryType_DisjointFromConsent and TestDomainPrefixV3_MatchesConsentEncoder.
//
// # WARNING — load-bearing constant
//
// Changing this string re-domains every capture leaf and breaks signature
// verification for all history. v4-class event.
const EntryTypeCaptureRequestV3 = "capture.request.v3"

// maxV3StringFieldBytes is the per-field length cap (post-NFC, post-UTF-8),
// identical to the consent encoder's cap. Hash/digest fields are pinned tighter
// (exactly 128 hex) by their own validators.
const maxV3StringFieldBytes = 256

// MaxCanonicalBytesV3 caps the total canonical byte length, mirroring the
// v3 spec's 4096-byte total cap and the verifier's MaxCanonicalBytesV3.
//
// This is a true belt-and-suspenders guard: the per-field regexes cap the body
// far tighter than 256 bytes each (hex fields are exactly 128, the enums are a
// handful of bytes, model ≤128), so a validation-passing entry tops out around
// ~1.1 KB — the 4096 cap can never fire for a valid entry. It exists only to
// fail-closed against a future field addition that forgets its own bound.
const MaxCanonicalBytesV3 = 4096

// maxPlausibleTimestampMs is an absolute far-future sanity ceiling (~year 2200)
// for the server-stamped anchor clock. TimestampMs is stamped at ingest
// (time.Now), so any value beyond this is an obvious misconfiguration/bug, not a
// real anchor — reject it before it becomes immutable (4-agent review F8;
// mirrors the consent SARExtended path's upper-bound discipline). Pure constant
// so the encoder stays a deterministic pure function.
const maxPlausibleTimestampMs int64 = 7258118400000 // 2200-01-01T00:00:00Z in UnixMilli

// v3SHA512HexLen is the length of a SHA-512 / HMAC-SHA512 hex string.
const v3SHA512HexLen = 128

// PIIDigestKeyVersionCharClass is the SINGLE source-of-truth character class for
// the `pii_digest_key_version` field, shared by the capture leaf (here), the
// consent/SAR leaf (internal/consent), and the audit-api wire DTO
// (cmd/audit-api/handlers). Source-namespaced lowercase IDs ("sm:v1") — the `:`
// separates source from version. The three regexes differ ONLY in their length
// quantifier (`{0,64}` for the on-chain encoders which permit empty; `{1,64}`
// for the DTO which is gated on non-empty), so pinning the charset here closes
// the "no third regex" drift the R6 review (M1) flagged. A cross-package test in
// internal/ingest asserts the compiled patterns stay in lockstep.
const PIIDigestKeyVersionCharClass = `[a-z0-9:_.-]`

// PIIDigestKeyVersionRegexpString returns the compiled capture-leaf
// pii_digest_key_version pattern as a string, so a cross-package test can pin it
// in lockstep with the consent leaf's pattern (R6 M1).
func PIIDigestKeyVersionRegexpString() string { return v3PIIDigestKeyVersionRe.String() }

// ErrInvalidEntryV3 is the wrapped sentinel returned by encoder
// validation failures. Callers can errors.Is(err, ErrInvalidEntryV3) to
// distinguish encoder rejections from upstream errors.
var ErrInvalidEntryV3 = errors.New("invalid v3 chain entry")

// Shape validators. These mirror the consent encoder's local-regex discipline
// (avoid an import cycle, keep the byte contract self-contained).
var (

	// v3SigningKeyIDRe constrains signing_key_id to a registry-issued opaque
	// shape: 1-128 chars from [A-Za-z0-9_./-]. Identical to the consent
	// encoder's v3SigningKeyIDRe.
	v3SigningKeyIDRe = regexp.MustCompile(`^[A-Za-z0-9_./-]{1,128}$`)

	// v3SHA512HexRe matches exactly 128 lowercase hex chars. Used for
	// content_hash (a real SHA-512) and for the HMAC-SHA512 digest fields
	// user_id / pii_categories / dlp (whose keying is enforced upstream at
	// mint time; here we pin only the shape).
	v3SHA512HexRe = regexp.MustCompile(`^[0-9a-f]{128}$`)

	// v3EncryptionModeAllowed is the locked vocabulary for encryption_mode — the
	// KEY-CUSTODY field on storage.RawEntry (verified 2026-06-28 against
	// types.go:502-515: who can decrypt the GCS payload). This is ORTHOGONAL to
	// processing_mode (inspection authorization) below — the two were conflated
	// in the 01a draft and corrected here. `cmek` is defined but not yet emitted
	// by any resolver; included for forward-compat.
	v3EncryptionModeAllowed = map[string]struct{}{
		"zero-knowledge":   {},
		"aleutian-managed": {},
		"cmek":             {},
	}

	// v3ProcessingModeAllowed is the locked vocabulary for processing_mode — the
	// INSPECTION-AUTHORIZATION field (storage/processing_mode_types.go:30-41),
	// orthogonal to encryption_mode. "zk" = inspection NOT authorized → the
	// compliance surface MUST be empty (enforced by the zk invariant in
	// validate()); "pii_inspection" = inspection authorized.
	v3ProcessingModeAllowed = map[string]struct{}{
		"zk":             {},
		"pii_inspection": {},
	}

	// v3PIIActionAllowed is the closed vocabulary for pii_action. "none" is the
	// default the producer emits when no action was taken; the other three
	// mirror the PII scanner's Action outputs (internal/ingest PII scan).
	v3PIIActionAllowed = map[string]struct{}{
		"none":     {},
		"flagged":  {},
		"blocked":  {},
		"redacted": {},
	}

	// v3ProvenanceEnumRe constrains the small low-cardinality provenance /
	// classification enums (capture_method, source_type, trust_level) to a tight
	// snake/kebab alphabet. The hyphen is REQUIRED: the real TrustLevel enum
	// includes "self-reported" (storage/types.go) — verified 2026-06-28 against
	// the actual producer vocabularies. Empty is permitted (0-length on chain).
	// Closed at the byte level; open vocabulary at the value level — defends
	// against operator/free-text injection into chain bytes.
	v3ProvenanceEnumRe = regexp.MustCompile(`^[a-z0-9_-]{0,32}$`)

	// v3ProviderRe constrains provider (e.g. "openai", "anthropic", "google").
	// Empty permitted.
	v3ProviderRe = regexp.MustCompile(`^[a-z0-9_.-]{0,64}$`)

	// v3PIIDigestKeyVersionRe constrains pii_digest_key_version
	// (pii_hmac_key_rotation_R3). Source-namespaced lowercase IDs like "sm:v1";
	// the `:` separates source from version. Empty permitted (no digest present).
	// Built from the single shared charset PIIDigestKeyVersionCharClass (R6 M1)
	// so the consent leaf + the audit-api DTO cannot drift from it.
	v3PIIDigestKeyVersionRe = regexp.MustCompile(`^` + PIIDigestKeyVersionCharClass + `{0,64}$`)

	// v3ModelRe constrains model (e.g. "gpt-4o-2024-08-06", "claude-opus-4-8",
	// "meta-llama/Llama-3"). Closed to the alphabet real provider/model
	// identifiers use — letters, digits, and the `_./-` separators — and
	// length-capped. The `:` separator was dropped (4-agent review F6): no
	// shipping model id requires it and it needlessly widened the signed-byte
	// alphabet. Empty permitted.
	//
	// CALLER CONTRACT (data minimization): `model` is provider/operator-
	// controlled METADATA. It MUST NOT be populated from user-controlled or
	// content-derived strings — it is the loosest open-charset field and is the
	// only slot that could otherwise smuggle an identifying free-text token into
	// the immutable signed canonical.
	v3ModelRe = regexp.MustCompile(`^[A-Za-z0-9_./-]{0,128}$`)

	// v3RegionRe constrains region ("us", "eu", "jp"). Empty permitted.
	v3RegionRe = regexp.MustCompile(`^[a-z0-9-]{0,16}$`)
)

// CaptureRequestV3 is the typed, fully-validated capture-chain leaf record. Every
// field is the FINAL canonical value (pseudonyms/digests already minted
// upstream at ingest); this type carries no cleartext.
//
// Field provenance maps to storage.RawEntry as established by the 01b
// field-timing trace: Subject/UserID/Provider/Model/Region/EncryptionMode/
// ContentHash and the server-stamped ingested_at are known synchronously at
// ingest; PIIDetected/PIIAction/PIICategories/DLP/TrustLevel/CaptureMethod/
// SourceType are computed inline before the first write. Dedup + linkage fields
// are deliberately absent (async — owned by the slow/anchor layers).
type CaptureRequestV3 struct {
	// --- Header (4 fields) ---

	// Subject is the namespace this entry belongs to: whatever the chain is
	// ABOUT. Any non-empty string within the field limits — a hostname, a
	// project name, an account identifier, an opaque id.
	//
	// It is hashed into the leaf so an entry cannot be replayed into a chain
	// with a different subject. It is NOT an identity claim and nothing here
	// authenticates it; it separates namespaces, it does not prove one.
	//
	// Until 2026-09-23 this was CompanyID and had to match
	// `^comp_<26-char Crockford-base32 ULID>$`, a private platform's tenant
	// scheme. The JSON key "company_id" is still accepted on read, and
	// `comp_<ULID>` is still a perfectly good subject.
	Subject string `json:"subject"`

	// SigningKeyID is the trust-manifest alias of the per-tenant
	// FamilyCaptureLeaf ML-DSA-65 key that will sign this leaf (01k). Opaque
	// registry shape; never a tenant slug.
	SigningKeyID string `json:"signing_key_id"`

	// TimestampMs is the server-stamped ingested_at anchor clock in UnixMilli.
	// It is the header timestamp_ms and is NOT repeated in the body. Must be > 0.
	TimestampMs int64 `json:"timestamp_ms"`

	// --- Body (14 fields, alphabetical) ---

	// CaptureMethod is the provenance enum for how the entry was captured
	// (e.g. extension vs API). Low-cardinality; empty permitted.
	CaptureMethod string `json:"capture_method"`

	// ContentHash is the existing SHA-512 payload hash (request \x00 response),
	// 128 lowercase hex. Nested here so the payload stays sealed transitively.
	ContentHash string `json:"content_hash"`

	// DLP is the per-tenant HMAC-SHA512 digest (128 hex) of the canonical DLP
	// verdict, OR empty when no DLP verdict was produced (empty on every
	// ingest-path row; populated only on the proxy path). Minted upstream at 01k.
	DLP string `json:"dlp"`

	// EncryptionMode is the KEY-CUSTODY flag from storage.RawEntry, one of
	// {zero-knowledge, aleutian-managed, cmek} — who can decrypt the payload.
	// It is ORTHOGONAL to ProcessingMode (inspection authorization) and does NOT
	// by itself gate the compliance fields: a zero-knowledge (client-key) row can
	// still carry a PII verdict if inspection was authorized.
	EncryptionMode string `json:"encryption_mode"`

	// Model is the model identifier. Empty permitted.
	Model string `json:"model"`

	// PIIAction is the action the PII scanner took, one of
	// {none, flagged, blocked, redacted}.
	PIIAction string `json:"pii_action"`

	// PIICategories is the per-tenant HMAC-SHA512 digest (128 hex) of the
	// sorted union of request+response PII category labels, OR empty. A digest
	// (not a CSV) so the low-entropy label set is not a cross-tenant
	// correlation oracle (B4/C3). Minted upstream at 01k.
	PIICategories string `json:"pii_categories"`

	// PIIDetected is the regulator-facing verdict; encoded as the u64 0 or 1.
	PIIDetected bool `json:"pii_detected"`

	// PIIDigestKeyVersion is the source-namespaced PII-HMAC master key version
	// ("sm:v1") that produced the pii_categories + dlp digests, recorded so the
	// digests survive a key rotation (pii_hmac_key_rotation_R3). It is a SIGNED
	// field (mirrors consent's actor_pseudonym_key_version). INVARIANT: present
	// (non-empty) iff a digest is present, i.e. iff pii_categories OR dlp is
	// non-empty; empty otherwise (including every zk leaf). Sorts between
	// pii_detected and processing_mode in the canonical body.
	PIIDigestKeyVersion string `json:"pii_digest_key_version"`

	// ProcessingMode is the INSPECTION-AUTHORIZATION flag, one of
	// {zk, pii_inspection} (storage/processing_mode_types.go). It is the mode that
	// actually governs the compliance surface: when "zk", inspection is not
	// authorized and the compliance fields (PIIDetected/PIIAction/PIICategories/
	// DLP) MUST be empty — enforced by the zk invariant in validate(). 01k sources
	// this from the write-time processing decision (NOT storage.RawEntry, which
	// does not carry it).
	//
	// DEPENDENCY: the zk invariant only holds in production once the ingest PII
	// scanner is gated to skip/zero verdicts in zk mode (see the
	// chainlinker_modernization_17 (zk_scanner_gate) privacy ticket). Until then a real zk-mode row may
	// carry a non-empty verdict and this encoder will (correctly) refuse to seal
	// it — so v3 cutover (01j) MUST NOT precede that gate.
	ProcessingMode string `json:"processing_mode"`

	// Provider is the AI provider identifier. Empty permitted.
	Provider string `json:"provider"`

	// Region is the data-residency region ("us"/"eu"/"jp"). Empty permitted.
	Region string `json:"region"`

	// SourceType is the provenance enum for the capture source. Empty permitted.
	SourceType string `json:"source_type"`

	// TrustLevel is the classification/trust enum. Empty permitted.
	TrustLevel string `json:"trust_level"`

	// UserID is the per-tenant HMAC-SHA512 actor pseudonym (128 hex). The raw
	// actor identifier never reaches this struct — pseudonymization happens at
	// ingest (01k). Required (non-empty).
	UserID string `json:"user_id"`
}

// =============================================================================
// Public API
// =============================================================================

// CanonicalV3 validates the entry and emits the deterministic length-prefixed
// TLV canonical byte sequence.
//
// # Description
//
// Writes the 4-field header (company_id, entry_type, signing_key_id,
// timestamp_ms) in alphabetical order, then the 15-field body in alphabetical
// order. Strings are NFC-normalized then written as a u32-BE post-NFC byte
// length prefix followed by the UTF-8 bytes; the single u64 (pii_detected) is
// written big-endian; bool pii_detected encodes as 0 or 1.
//
// # Inputs
//
//   - entry: a fully-populated CaptureRequestV3 (digests/pseudonyms already minted)
//
// # Outputs
//
//   - []byte: canonical bytes; nil on validation/encoding failure
//   - error: wrapped ErrInvalidEntryV3 on any validation or cap failure
//
// # Example
//
//	canonical, err := chainformat.CanonicalV3(e)
//	if err != nil {
//	    return err
//	}
//
// # Limitations
//
//   - Does NOT sign or link; signing (ML-DSA-65) happens at 01k, linkage at 01h.
//
// # Assumptions
//
//   - user_id/pii_categories/dlp are already HMAC-SHA512 digests minted under
//     the per-tenant key; this function only verifies their 128-hex shape.
//
// # Concurrency
//
// Pure function; safe for concurrent use.
func CanonicalV3(entry EntryV3) ([]byte, error) {
	if entry == nil {
		return nil, fmt.Errorf("chainformat: %w: entry is nil", ErrInvalidEntryV3)
	}
	if err := entry.validateV3(); err != nil {
		return nil, err
	}
	enc := &v3Encoder{buf: make([]byte, 0, 512)}
	entry.encodeCanonicalV3(enc)
	if enc.err != nil {
		return nil, enc.err
	}
	if len(enc.buf) > MaxCanonicalBytesV3 {
		// Opaque on the actual length: per-field caps do not bound the sum, and
		// echoing it back would be a size oracle over the entry's contents
		// (Privacy Inv 4 — mirrors the SDK verifier).
		return nil, fmt.Errorf("chainformat.CanonicalV3: %w: canonical exceeds %d bytes",
			ErrInvalidEntryV3, MaxCanonicalBytesV3)
	}
	return enc.buf, nil
}

// ContentHashV3 returns SHA-512(DomainPrefixV3 || canonical) hex-encoded.
//
// # Description
//
// This is the capture leaf's content-hash. The domain prefix is concatenated
// with the canonical bytes (it is NOT part of canonical bytes) and the pair is
// SHA-512'd. The verifier (01i) recomputes this and constant-time-compares it
// against the stored column, and the linker (01h) links the chain hash over it.
// It is a SEPARATE integrity gate from the ML-DSA-65 signature, which signs
// DomainPrefixV3 || canonical directly; neither replaces the other.
//
// # Inputs
//
//   - canonical: the bytes from CanonicalV3 (already validated)
//
// # Outputs
//
//   - string: 128-char lowercase hex SHA-512 of DomainPrefixV3 || canonical
//
// # Example
//
//	canonical, _ := chainformat.CanonicalV3(e)
//	ch := chainformat.ContentHashV3(canonical)
//
// # Limitations
//
//   - Does not validate the input; pass only bytes produced by CanonicalV3.
//     Hashing arbitrary bytes yields a hash but not a meaningful leaf.
//
// # Assumptions
//
//   - canonical is the exact byte sequence CanonicalV3 emitted (no trimming/
//     re-encoding), so the hash matches across languages.
//
// # Concurrency
//
// Pure function; safe for concurrent use.
func ContentHashV3(canonical []byte) string {
	h := sha512.New()
	h.Write([]byte(DomainPrefixV3))
	h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil))
}

// EncodeAndHashV3 is the one-call wrapper pairing CanonicalV3 +
// ContentHashV3.
//
// # Description
//
// Validates + encodes the entry to canonical TLV bytes, then computes the
// content hash over DomainPrefixV3 || canonical. Production callers SHOULD
// prefer this two-in-one form so the domain-prefix wiring cannot be forgotten
// (computing SHA-512 of the bare canonical without the prefix is a silent
// cross-impl divergence).
//
// # Inputs
//
//   - entry: a fully-populated CaptureRequestV3 (digests/pseudonyms already minted)
//
// # Outputs
//
//   - canonical: the deterministic TLV bytes (nil on failure)
//   - contentHashHex: 128-char lowercase hex SHA-512 of DomainPrefixV3 || canonical
//     ("" on failure)
//   - error: wrapped ErrInvalidEntryV3 on any validation/encoding failure
//
// # Example
//
//	canonical, contentHash, err := chainformat.EncodeAndHashV3(e)
//	if err != nil {
//	    return err
//	}
//
// # Limitations
//
//   - Does NOT sign or link; ML-DSA-65 signing happens at ingest (01k) and
//     chain linkage at the linker (01h).
//
// # Assumptions
//
//   - user_id/pii_categories/dlp are already HMAC-SHA512 digests minted under
//     the per-tenant key (shape-validated only here — see the package doc).
//
// # Concurrency
//
// Pure function; safe for concurrent use.
func EncodeAndHashV3(entry EntryV3) (canonical []byte, contentHashHex string, err error) {
	canonical, err = CanonicalV3(entry)
	if err != nil {
		return nil, "", err
	}
	return canonical, ContentHashV3(canonical), nil
}

// =============================================================================
// Encoder helper (shared shape with the consent encoder's v3Encoder)
// =============================================================================

// v3Encoder bundles the buffer + a captured first-error slot so the body
// encoder can append fields without explicit error plumbing on every call.
type v3Encoder struct {
	buf []byte
	err error
}

// appendStr writes a length-prefixed UTF-8 string with the spec's "post-NFC,
// post-UTF-8 byte length" semantics. The cap and the emitted bytes operate on
// the SAME post-NFC byte sequence so cross-language ports reproduce it exactly.
// Short-circuits if a prior error is already captured.
func (e *v3Encoder) appendStr(s string) {
	if e.err != nil {
		return
	}
	nfc := norm.NFC.String(s)
	if len(nfc) > maxV3StringFieldBytes {
		e.err = fmt.Errorf("chainformat: appendStr: %w: field exceeds %d bytes after NFC",
			ErrInvalidEntryV3, maxV3StringFieldBytes)
		return
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(nfc)))
	e.buf = append(e.buf, lenBuf[:]...)
	e.buf = append(e.buf, nfc...)
}

// appendU64 writes a u64-BE non-negative integer. Negative input is an
// encoder-invariant violation (the validator must have rejected it).
func (e *v3Encoder) appendU64(v int64) {
	if e.err != nil {
		return
	}
	if v < 0 {
		e.err = fmt.Errorf("chainformat: appendU64: encoder invariant violated (negative int64 reached encoder; validator must have rejected): got %d", v)
		return
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	e.buf = append(e.buf, b[:]...)
}

// appendBool writes a bool as the u64 0 or 1. It does not itself check
// e.err — the short-circuit is carried by the appendU64 it delegates to. Any
// future logic added here BEFORE that delegation must add its own guard.
func (e *v3Encoder) appendBool(v bool) {
	if v {
		e.appendU64(1)
		return
	}
	e.appendU64(0)
}

// encodeCanonical writes the capture-leaf canonical bytes: the 4-field header
// then the 15-field body, both alphabetical.
func (e CaptureRequestV3) encodeCanonicalV3(enc *v3Encoder) {
	// Header (alphabetical BY THE NAMES THIS FORMAT WAS DEFINED WITH):
	// company_id, entry_type, signing_key_id, timestamp_ms. The first field is
	// now called `subject`; the ORDER cannot follow the rename, because these
	// are positional VALUES and moving one would change every content hash
	// ever computed.
	enc.appendStr(e.Subject)
	enc.appendStr(EntryTypeCaptureRequestV3)
	enc.appendStr(e.SigningKeyID)
	enc.appendU64(e.TimestampMs)

	// Body (alphabetical).
	enc.appendStr(e.CaptureMethod)       // 1
	enc.appendStr(e.ContentHash)         // 2
	enc.appendStr(e.DLP)                 // 3
	enc.appendStr(e.EncryptionMode)      // 4
	enc.appendStr(e.Model)               // 5
	enc.appendStr(e.PIIAction)           // 6
	enc.appendStr(e.PIICategories)       // 7
	enc.appendBool(e.PIIDetected)        // 8
	enc.appendStr(e.PIIDigestKeyVersion) // 9
	enc.appendStr(e.ProcessingMode)      // 10
	enc.appendStr(e.Provider)            // 11
	enc.appendStr(e.Region)              // 12
	enc.appendStr(e.SourceType)          // 13
	enc.appendStr(e.TrustLevel)          // 14
	enc.appendStr(e.UserID)              // 15
}

// =============================================================================
// Validation
// =============================================================================

// validate runs every header + body check against the SAME post-NFC byte
// sequence the encoder will emit. Returns the first failure wrapped in
// ErrInvalidEntryV3.
func (e CaptureRequestV3) validateV3() error {
	// --- Header ---
	// A subject has no required shape. An entry that commits to no namespace at
	// all can be replayed into another chain, so empty is still refused.
	if e.Subject == "" {
		return fmt.Errorf("chainformat: %w: subject empty", ErrInvalidEntryV3)
	}
	if err := validateStringField("subject", e.Subject); err != nil {
		return err
	}
	if e.SigningKeyID == "" {
		return fmt.Errorf("chainformat: %w: signing_key_id empty", ErrInvalidEntryV3)
	}
	if !v3SigningKeyIDRe.MatchString(e.SigningKeyID) {
		return fmt.Errorf("chainformat: %w: signing_key_id must match ^[A-Za-z0-9_./-]{1,128}$",
			ErrInvalidEntryV3)
	}
	if err := validateStringField("signing_key_id", e.SigningKeyID); err != nil {
		return err
	}
	if e.TimestampMs <= 0 {
		return fmt.Errorf("chainformat: %w: timestamp_ms must be positive (got %d)",
			ErrInvalidEntryV3, e.TimestampMs)
	}
	if e.TimestampMs > maxPlausibleTimestampMs {
		return fmt.Errorf("chainformat: %w: timestamp_ms %d exceeds the year-2200 sanity ceiling (anchor clock is server-stamped at ingest)",
			ErrInvalidEntryV3, e.TimestampMs)
	}

	// --- Body: required hex fields ---
	if !v3SHA512HexRe.MatchString(e.ContentHash) {
		return fmt.Errorf("chainformat: %w: content_hash must be exactly %d lowercase hex chars (SHA-512)",
			ErrInvalidEntryV3, v3SHA512HexLen)
	}
	if !v3SHA512HexRe.MatchString(e.UserID) {
		return fmt.Errorf("chainformat: %w: user_id must be exactly %d lowercase hex chars (HMAC-SHA512 pseudonym)",
			ErrInvalidEntryV3, v3SHA512HexLen)
	}

	// --- Body: optional hex digest fields (empty OR 128-hex) ---
	if err := validateOptionalHexDigest("dlp", e.DLP); err != nil {
		return err
	}
	if err := validateOptionalHexDigest("pii_categories", e.PIICategories); err != nil {
		return err
	}

	// --- Body: pii_digest_key_version (pii_hmac_key_rotation_R3) ---
	if !v3PIIDigestKeyVersionRe.MatchString(e.PIIDigestKeyVersion) {
		return fmt.Errorf("chainformat: %w: pii_digest_key_version must match ^[a-z0-9:_.-]{0,64}$ (got %q)",
			ErrInvalidEntryV3, e.PIIDigestKeyVersion)
	}
	if err := validateStringField("pii_digest_key_version", e.PIIDigestKeyVersion); err != nil {
		return err
	}
	// Present iff a digest is present: a sealed pii/dlp digest with no recorded
	// key version is exactly the rotation gap this field closes; a version with
	// no digest to apply it to is meaningless.
	hasDigest := e.PIICategories != "" || e.DLP != ""
	if hasDigest && e.PIIDigestKeyVersion == "" {
		return fmt.Errorf("chainformat: %w: pii_digest_key_version required when pii_categories or dlp is present",
			ErrInvalidEntryV3)
	}
	if !hasDigest && e.PIIDigestKeyVersion != "" {
		return fmt.Errorf("chainformat: %w: pii_digest_key_version must be empty when no pii/dlp digest is present (got %q)",
			ErrInvalidEntryV3, e.PIIDigestKeyVersion)
	}

	// --- Body: closed-vocabulary enums ---
	if _, ok := v3EncryptionModeAllowed[e.EncryptionMode]; !ok {
		return fmt.Errorf("chainformat: %w: encryption_mode must be one of {zero-knowledge, aleutian-managed, cmek} (got %q)",
			ErrInvalidEntryV3, e.EncryptionMode)
	}
	if _, ok := v3ProcessingModeAllowed[e.ProcessingMode]; !ok {
		return fmt.Errorf("chainformat: %w: processing_mode must be one of {zk, pii_inspection} (got %q)",
			ErrInvalidEntryV3, e.ProcessingMode)
	}
	if _, ok := v3PIIActionAllowed[e.PIIAction]; !ok {
		return fmt.Errorf("chainformat: %w: pii_action must be one of {none, flagged, blocked, redacted} (got %q)",
			ErrInvalidEntryV3, e.PIIAction)
	}

	// zk cross-field invariant (corrected 2026-06-28). The compliance surface is
	// gated on PROCESSING_MODE (inspection authorization), NOT encryption_mode
	// (key custody) — the two are orthogonal. When processing_mode=="zk",
	// inspection is not authorized, so the compliance fields MUST be empty.
	// Enforcing this here makes "zk ⇒ no sealed verdict" a real, immutable
	// guarantee rather than a producer convention, and fail-closes if a zk-mode
	// row ever arrives with a verdict (which it can until the ingest scanner is
	// gated — see the chainlinker_modernization_17 (zk_scanner_gate) ticket; v3 cutover must not precede
	// that gate).
	if e.ProcessingMode == "zk" {
		if e.PIIDetected {
			return fmt.Errorf("chainformat: %w: processing_mode=zk forbids pii_detected=true (inspection not authorized)",
				ErrInvalidEntryV3)
		}
		if e.PIIAction != "none" {
			return fmt.Errorf("chainformat: %w: processing_mode=zk requires pii_action=none (got %q)",
				ErrInvalidEntryV3, e.PIIAction)
		}
		if e.PIICategories != "" {
			return fmt.Errorf("chainformat: %w: processing_mode=zk requires empty pii_categories",
				ErrInvalidEntryV3)
		}
		if e.DLP != "" {
			return fmt.Errorf("chainformat: %w: processing_mode=zk requires empty dlp",
				ErrInvalidEntryV3)
		}
	}

	// --- Body: charset-pinned open-vocabulary fields (empty permitted) ---
	if !v3ProviderRe.MatchString(e.Provider) {
		return fmt.Errorf("chainformat: %w: provider must match ^[a-z0-9_.-]{0,64}$ (got %q)",
			ErrInvalidEntryV3, e.Provider)
	}
	if !v3ModelRe.MatchString(e.Model) {
		return fmt.Errorf("chainformat: %w: model must match ^[A-Za-z0-9_./-]{0,128}$ (got %q)",
			ErrInvalidEntryV3, e.Model)
	}
	if !v3RegionRe.MatchString(e.Region) {
		return fmt.Errorf("chainformat: %w: region must match ^[a-z0-9-]{0,16}$ (got %q)",
			ErrInvalidEntryV3, e.Region)
	}
	if !v3ProvenanceEnumRe.MatchString(e.CaptureMethod) {
		return fmt.Errorf("chainformat: %w: capture_method must match ^[a-z0-9_-]{0,32}$ (got %q)",
			ErrInvalidEntryV3, e.CaptureMethod)
	}
	if !v3ProvenanceEnumRe.MatchString(e.SourceType) {
		return fmt.Errorf("chainformat: %w: source_type must match ^[a-z0-9_-]{0,32}$ (got %q)",
			ErrInvalidEntryV3, e.SourceType)
	}
	if !v3ProvenanceEnumRe.MatchString(e.TrustLevel) {
		return fmt.Errorf("chainformat: %w: trust_level must match ^[a-z0-9_-]{0,32}$ (got %q)",
			ErrInvalidEntryV3, e.TrustLevel)
	}

	// Defense-in-depth control-byte / UTF-8 / NFC-cap guard on every string
	// body field (the regexes above already constrain charset; this is the
	// secondary guard in case a regex is ever loosened, mirroring the consent
	// encoder's M1 posture).
	for _, f := range []struct{ name, val string }{
		{"capture_method", e.CaptureMethod},
		{"content_hash", e.ContentHash},
		{"dlp", e.DLP},
		{"encryption_mode", e.EncryptionMode},
		{"model", e.Model},
		{"pii_action", e.PIIAction},
		{"pii_categories", e.PIICategories},
		{"processing_mode", e.ProcessingMode},
		{"provider", e.Provider},
		{"region", e.Region},
		{"source_type", e.SourceType},
		{"trust_level", e.TrustLevel},
		{"user_id", e.UserID},
	} {
		if err := validateStringField(f.name, f.val); err != nil {
			return err
		}
	}
	return nil
}

// validateOptionalHexDigest accepts an empty string (field not set → 0-length
// on chain) OR exactly 128 lowercase hex chars.
func validateOptionalHexDigest(name, value string) error {
	if value == "" {
		return nil
	}
	if !v3SHA512HexRe.MatchString(value) {
		return fmt.Errorf("chainformat: %w: %s must be empty or exactly %d lowercase hex chars (HMAC-SHA512 digest)",
			ErrInvalidEntryV3, name, v3SHA512HexLen)
	}
	return nil
}

// validateStringField runs the per-string-field checks against the SAME
// post-NFC byte sequence the encoder emits: UTF-8 validity, NFC cap, strict
// control-byte rejection.
func validateStringField(name, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("chainformat: %w: %s is not valid UTF-8",
			ErrInvalidEntryV3, name)
	}
	nfc := norm.NFC.String(value)
	if len(nfc) > maxV3StringFieldBytes {
		return fmt.Errorf("chainformat: %w: %s exceeds %d bytes after NFC",
			ErrInvalidEntryV3, name, maxV3StringFieldBytes)
	}
	if hasDisallowedControlBytes(nfc) {
		return fmt.Errorf("chainformat: %w: %s contains a disallowed control byte",
			ErrInvalidEntryV3, name)
	}
	return nil
}

// hasDisallowedControlBytes rejects ANY C0 control byte (0x00–0x1F) plus DEL
// (0x7F). v3 fields are all single-token; whitespace/control bytes have no
// legitimate use and are an injection + cross-port-portability hazard.
func hasDisallowedControlBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b < 0x20 || b == 0x7F {
			return true
		}
	}
	return false
}
