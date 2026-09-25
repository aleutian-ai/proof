// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package keyfile_test

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/keyfile"
)

// read loads a fixture from testdata.
func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

// seedPattern returns the seed the RFC examples use: 0x00, 0x01, 0x02, …
func seedPattern(n int) []byte {
	s := make([]byte, n)
	for i := range s {
		s[i] = byte(i)
	}
	return s
}

// rfcCases are the good examples published in RFC 9935 (ML-KEM), RFC 9881
// (ML-DSA), and Appendix D of the X-Wing draft.
var rfcCases = []struct {
	alg        keyfile.Algorithm
	seedFile   string
	bothFile   string // "" when the spec publishes no both-form example
	expFile    string // expandedKey-only example, "" when none
	publicFile string
}{
	{keyfile.MLKEM512, "mlkem512_seed.pem", "mlkem512_both.pem", "mlkem512_expanded.pem", "mlkem512_public.pem"},
	{keyfile.MLKEM768, "mlkem768_seed.pem", "mlkem768_both.pem", "mlkem768_expanded.pem", "mlkem768_public.pem"},
	{keyfile.MLKEM1024, "mlkem1024_seed.pem", "mlkem1024_both.pem", "mlkem1024_expanded.pem", "mlkem1024_public.pem"},
	{keyfile.MLDSA44, "mldsa44_seed.pem", "mldsa44_both.pem", "mldsa44_expanded.pem", "mldsa44_public.pem"},
	{keyfile.MLDSA65, "mldsa65_seed.pem", "mldsa65_both.pem", "mldsa65_expanded.pem", "mldsa65_public.pem"},
	{keyfile.MLDSA87, "mldsa87_seed.pem", "mldsa87_both.pem", "mldsa87_expanded.pem", "mldsa87_public.pem"},
	{keyfile.XWing, "xwing_private.pem", "", "", "xwing_public.pem"},
}

// TestParseSpecExamples checks every published example parses to the expected
// algorithm and seed.
//
// These fixtures come from the specifications themselves, not from this code,
// so passing means agreeing with the standard rather than with ourselves.
func TestParseSpecExamples(t *testing.T) {
	for _, tc := range rfcCases {
		t.Run(tc.alg.String(), func(t *testing.T) {
			alg, seed, err := keyfile.ParsePrivateKey(read(t, tc.seedFile))
			if err != nil {
				t.Fatalf("parse private: %v", err)
			}
			if alg != tc.alg {
				t.Errorf("algorithm = %v, want %v", alg, tc.alg)
			}
			if want := seedPattern(tc.alg.SeedSize()); !bytes.Equal(seed, want) {
				t.Errorf("seed does not match the specification's example seed")
			}

			palg, pub, err := keyfile.ParsePublicKey(read(t, tc.publicFile))
			if err != nil {
				t.Fatalf("parse public: %v", err)
			}
			if palg != tc.alg {
				t.Errorf("public algorithm = %v, want %v", palg, tc.alg)
			}
			if len(pub) != tc.alg.PublicKeySize() {
				t.Errorf("public key is %d bytes, want %d", len(pub), tc.alg.PublicKeySize())
			}
		})
	}
}

// TestReencodeSpecExamplesByteForByte is the interoperability proof: what this
// package writes must equal what the standards bodies published, exactly.
func TestReencodeSpecExamplesByteForByte(t *testing.T) {
	for _, tc := range rfcCases {
		t.Run(tc.alg.String(), func(t *testing.T) {
			original := read(t, tc.seedFile)
			_, seed, err := keyfile.ParsePrivateKey(original)
			if err != nil {
				t.Fatalf("parse private: %v", err)
			}
			got, err := keyfile.MarshalPrivateKey(tc.alg, seed)
			if err != nil {
				t.Fatalf("marshal private: %v", err)
			}
			if !bytes.Equal(normalize(got), normalize(original)) {
				t.Errorf("re-encoded private key differs from the specification's example")
			}

			originalPub := read(t, tc.publicFile)
			_, pub, err := keyfile.ParsePublicKey(originalPub)
			if err != nil {
				t.Fatalf("parse public: %v", err)
			}
			gotPub, err := keyfile.MarshalPublicKey(tc.alg, pub)
			if err != nil {
				t.Fatalf("marshal public: %v", err)
			}
			if !bytes.Equal(normalize(gotPub), normalize(originalPub)) {
				t.Errorf("re-encoded public key differs from the specification's example")
			}
		})
	}
}

// normalize strips line breaks so a comparison is of PEM CONTENT, not of line
// wrapping, which RFC text reflows.
func normalize(b []byte) []byte {
	return []byte(strings.ReplaceAll(strings.ReplaceAll(string(b), "\n", ""), "\r", ""))
}

// TestBothFormYieldsTheSameSeed checks the both form is accepted and returns
// the same seed as the seed-only file for the same key.
func TestBothFormYieldsTheSameSeed(t *testing.T) {
	for _, tc := range rfcCases {
		if tc.bothFile == "" {
			continue
		}
		t.Run(tc.alg.String(), func(t *testing.T) {
			_, seedOnly, err := keyfile.ParsePrivateKey(read(t, tc.seedFile))
			if err != nil {
				t.Fatalf("parse seed form: %v", err)
			}
			alg, fromBoth, err := keyfile.ParsePrivateKey(read(t, tc.bothFile))
			if err != nil {
				t.Fatalf("parse both form: %v", err)
			}
			if alg != tc.alg {
				t.Errorf("algorithm = %v, want %v", alg, tc.alg)
			}
			if !bytes.Equal(seedOnly, fromBoth) {
				t.Errorf("both form produced a different seed than the seed form")
			}
		})
	}
}

// TestExpandedKeyOnlyIsRejected pins the rule that matters most for this
// module: expansion is one-way, so a file without a seed is unusable here and
// must fail loudly rather than appear to work.
func TestExpandedKeyOnlyIsRejected(t *testing.T) {
	for _, tc := range rfcCases {
		if tc.expFile == "" {
			continue
		}
		t.Run(tc.alg.String(), func(t *testing.T) {
			_, _, err := keyfile.ParsePrivateKey(read(t, tc.expFile))
			if !errors.Is(err, keyfile.ErrExpandedKeyOnly) {
				t.Fatalf("error = %v, want ErrExpandedKeyOnly", err)
			}
		})
	}
}

// TestLegacyFilesStillParse covers existing customer key files, Keychain
// entries, and 1Password items: they must keep working with no migration.
//
// The fixtures were generated with the real github.com/aleutian-ai/xwing-keyfile
// library from the same seed as the X-Wing draft's Appendix D example, so the
// legacy and standard files must carry identical key material.
func TestLegacyFilesStillParse(t *testing.T) {
	alg, seed, err := keyfile.ParsePrivateKey(read(t, "legacy_xwing_private.pem"))
	if err != nil {
		t.Fatalf("parse legacy private: %v", err)
	}
	if alg != keyfile.XWing {
		t.Errorf("algorithm = %v, want X-Wing", alg)
	}
	_, stdSeed, err := keyfile.ParsePrivateKey(read(t, "xwing_private.pem"))
	if err != nil {
		t.Fatalf("parse standard private: %v", err)
	}
	if !bytes.Equal(seed, stdSeed) {
		t.Error("legacy and standard X-Wing files hold different seeds")
	}

	palg, pub, err := keyfile.ParsePublicKey(read(t, "legacy_xwing_public.pem"))
	if err != nil {
		t.Fatalf("parse legacy public: %v", err)
	}
	if palg != keyfile.XWing {
		t.Errorf("public algorithm = %v, want X-Wing", palg)
	}
	_, stdPub, err := keyfile.ParsePublicKey(read(t, "xwing_public.pem"))
	if err != nil {
		t.Fatalf("parse standard public: %v", err)
	}
	if !bytes.Equal(pub, stdPub) {
		t.Error("legacy and standard X-Wing files hold different public keys")
	}
}

// TestRoundTrip checks marshal → parse for every algorithm.
func TestRoundTrip(t *testing.T) {
	for _, alg := range []keyfile.Algorithm{
		keyfile.MLKEM512, keyfile.MLKEM768, keyfile.MLKEM1024,
		keyfile.MLDSA44, keyfile.MLDSA65, keyfile.MLDSA87, keyfile.XWing,
	} {
		t.Run(alg.String(), func(t *testing.T) {
			seed := seedPattern(alg.SeedSize())
			data, err := keyfile.MarshalPrivateKey(alg, seed)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			gotAlg, gotSeed, err := keyfile.ParsePrivateKey(data)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if gotAlg != alg || !bytes.Equal(gotSeed, seed) {
				t.Errorf("round trip changed the key: alg %v, seed equal %v", gotAlg, bytes.Equal(gotSeed, seed))
			}

			pub := make([]byte, alg.PublicKeySize())
			for i := range pub {
				pub[i] = byte(i % 251)
			}
			pubPEM, err := keyfile.MarshalPublicKey(alg, pub)
			if err != nil {
				t.Fatalf("marshal public: %v", err)
			}
			gotAlg, gotPub, err := keyfile.ParsePublicKey(pubPEM)
			if err != nil {
				t.Fatalf("parse public: %v", err)
			}
			if gotAlg != alg || !bytes.Equal(gotPub, pub) {
				t.Errorf("public round trip changed the key")
			}
		})
	}
}

// TestReturnedSeedIsACopy guards against a returned seed aliasing an internal
// buffer this package zeroizes.
func TestReturnedSeedIsACopy(t *testing.T) {
	data := read(t, "mlkem768_seed.pem")
	_, first, err := keyfile.ParsePrivateKey(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for i := range first {
		first[i] = 0xff
	}
	_, second, err := keyfile.ParsePrivateKey(data)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if !bytes.Equal(second, seedPattern(keyfile.MLKEM768.SeedSize())) {
		t.Error("mutating a returned seed affected a later parse")
	}
}

// TestMalformedInputsRejected covers the structural rules.
func TestMalformedInputsRejected(t *testing.T) {
	good := read(t, "mlkem768_seed.pem")
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"empty", nil, keyfile.ErrMalformed},
		{"no PEM block", []byte("not a key"), keyfile.ErrMalformed},
		{"trailing data", append(append([]byte{}, good...), []byte("trailing")...), keyfile.ErrMalformed},
		{"wrong PEM label", bytes.ReplaceAll(good, []byte("PRIVATE KEY"), []byte("SOMETHING ELSE")), keyfile.ErrMalformed},
		{"truncated DER", good[:len(good)/2], keyfile.ErrMalformed},
		{"oversize input", bytes.Repeat([]byte("A"), 70000), keyfile.ErrMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := keyfile.ParsePrivateKey(tc.data); !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestTrailingNewlineAccepted: a trailing newline is normal in files and must
// not be mistaken for trailing data.
func TestTrailingNewlineAccepted(t *testing.T) {
	data := append(read(t, "mlkem768_seed.pem"), '\n', '\n')
	if _, _, err := keyfile.ParsePrivateKey(data); err != nil {
		t.Errorf("trailing newline rejected: %v", err)
	}
}

// TestWrongSizedInputsRejected checks the marshal side.
func TestWrongSizedInputsRejected(t *testing.T) {
	if _, err := keyfile.MarshalPrivateKey(keyfile.MLDSA65, make([]byte, 31)); !errors.Is(err, keyfile.ErrMalformed) {
		t.Errorf("short seed accepted")
	}
	if _, err := keyfile.MarshalPublicKey(keyfile.MLKEM768, make([]byte, 10)); !errors.Is(err, keyfile.ErrMalformed) {
		t.Errorf("short public key accepted")
	}
	if _, err := keyfile.MarshalPrivateKey(keyfile.Unknown, make([]byte, 32)); !errors.Is(err, keyfile.ErrUnsupportedAlgorithm) {
		t.Errorf("unknown algorithm accepted")
	}
}

// buildPrivate assembles a PKCS#8 private key by hand, so a test can produce
// structures a correct encoder would never emit.
func buildPrivate(t *testing.T, oid asn1.ObjectIdentifier, inner []byte, withPublicKey []byte) []byte {
	t.Helper()
	type outKey struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
		PublicKey  asn1.BitString `asn1:"optional,tag:1"`
	}
	k := outKey{Version: 0, Algorithm: pkix.AlgorithmIdentifier{Algorithm: oid}, PrivateKey: inner}
	if withPublicKey != nil {
		k.PublicKey = asn1.BitString{Bytes: withPublicKey, BitLength: len(withPublicKey) * 8}
	}
	der, err := asn1.Marshal(k)
	if err != nil {
		t.Fatalf("build DER: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// seedChoice wraps a seed in the CHOICE's [0] IMPLICIT OCTET STRING.
func seedChoice(t *testing.T, seed []byte) []byte {
	t.Helper()
	b, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: seed})
	if err != nil {
		t.Fatalf("encode seed choice: %v", err)
	}
	return b
}

// TestWrongSeedSizeInsideValidDERRejected: the seed length must be enforced
// against the ALGORITHM, not accepted because the file is otherwise well formed.
// Without this, a 16-byte "ML-DSA-65 key" would parse and silently become a
// weak key.
func TestWrongSeedSizeInsideValidDERRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		alg  keyfile.Algorithm
		size int
	}{
		{"ML-DSA-65 seed too short", keyfile.MLDSA65, 16},
		{"ML-DSA-65 seed too long", keyfile.MLDSA65, 64},
		{"ML-KEM-768 seed too short", keyfile.MLKEM768, 32},
		{"ML-KEM-768 seed empty", keyfile.MLKEM768, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := buildPrivate(t, tc.alg.OID(), seedChoice(t, make([]byte, tc.size)), nil)
			if _, _, err := keyfile.ParsePrivateKey(data); !errors.Is(err, keyfile.ErrMalformed) {
				t.Errorf("error = %v, want ErrMalformed", err)
			}
		})
	}
	// X-Wing carries its seed raw, with no CHOICE — check that path too.
	data := buildPrivate(t, keyfile.XWing.OID(), make([]byte, 16), nil)
	if _, _, err := keyfile.ParsePrivateKey(data); !errors.Is(err, keyfile.ErrMalformed) {
		t.Errorf("X-Wing short seed: error = %v, want ErrMalformed", err)
	}
}

// TestEmbeddedPublicKeyRejected: PKCS#8 may carry a public key, but this
// package cannot check it against the seed, and a mismatched one would tell a
// caller the file is a key it is not.
func TestEmbeddedPublicKeyRejected(t *testing.T) {
	seed := seedPattern(keyfile.MLDSA65.SeedSize())
	pub := make([]byte, keyfile.MLDSA65.PublicKeySize())
	data := buildPrivate(t, keyfile.MLDSA65.OID(), seedChoice(t, seed), pub)
	if _, _, err := keyfile.ParsePrivateKey(data); !errors.Is(err, keyfile.ErrMalformed) {
		t.Errorf("error = %v, want ErrMalformed", err)
	}
}

// TestUnknownAlgorithmRejected: the algorithm comes from the OID, and an
// unknown one is never guessed at from the key's length.
func TestUnknownAlgorithmRejected(t *testing.T) {
	bogus := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	data := buildPrivate(t, bogus, seedChoice(t, make([]byte, 32)), nil)
	if _, _, err := keyfile.ParsePrivateKey(data); !errors.Is(err, keyfile.ErrUnsupportedAlgorithm) {
		t.Errorf("error = %v, want ErrUnsupportedAlgorithm", err)
	}
}

// TestAlgorithmParametersRejected: all these algorithms require absent
// parameters; a file carrying them is malformed.
func TestAlgorithmParametersRejected(t *testing.T) {
	type outKey struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	der, err := asn1.Marshal(outKey{
		Version: 0,
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  keyfile.MLDSA65.OID(),
			Parameters: asn1.RawValue{Tag: asn1.TagNull},
		},
		PrivateKey: seedChoice(t, seedPattern(32)),
	})
	if err != nil {
		t.Fatalf("build DER: %v", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, _, err := keyfile.ParsePrivateKey(data); !errors.Is(err, keyfile.ErrMalformed) {
		t.Errorf("error = %v, want ErrMalformed", err)
	}
}

// legacyFileWith rebuilds a legacy-format file with a substituted magic or
// version byte.
func legacyFileWith(t *testing.T, label string, payload []byte, magic []byte, version byte) []byte {
	t.Helper()
	out := append([]byte(nil), payload...)
	copy(out[:4], magic)
	out[4] = version
	return pem.EncodeToMemory(&pem.Block{Type: label, Bytes: out})
}

// legacyPayload returns the raw payload inside a legacy fixture.
func legacyPayload(t *testing.T, file string) []byte {
	t.Helper()
	block, _ := pem.Decode(read(t, file))
	if block == nil {
		t.Fatalf("%s: no PEM block", file)
	}
	return block.Bytes
}

// TestLegacyHeaderValidated: the legacy format's magic and version identify the
// file's layout. Accepting a wrong one would mean interpreting arbitrary bytes
// as a private key.
func TestLegacyHeaderValidated(t *testing.T) {
	const privLabel = "ALEUTIAN HYBRID KEM PRIVATE KEY"
	const pubLabel = "ALEUTIAN HYBRID KEM PUBLIC KEY"
	goodMagic := []byte("ALT1")
	priv := legacyPayload(t, "legacy_xwing_private.pem")
	pub := legacyPayload(t, "legacy_xwing_public.pem")

	tests := []struct {
		name  string
		data  []byte
		parse func([]byte) (keyfile.Algorithm, []byte, error)
	}{
		{"private: wrong magic", legacyFileWith(t, privLabel, priv, []byte("XXXX"), 0x81), keyfile.ParsePrivateKey},
		{"private: wrong version", legacyFileWith(t, privLabel, priv, goodMagic, 0x01), keyfile.ParsePrivateKey},
		{"public: wrong magic", legacyFileWith(t, pubLabel, pub, []byte("XXXX"), 0x01), keyfile.ParsePublicKey},
		{"public: wrong version", legacyFileWith(t, pubLabel, pub, goodMagic, 0x81), keyfile.ParsePublicKey},
		{"private: truncated", pem.EncodeToMemory(&pem.Block{Type: privLabel, Bytes: priv[:20]}), keyfile.ParsePrivateKey},
		{"public: truncated", pem.EncodeToMemory(&pem.Block{Type: pubLabel, Bytes: pub[:100]}), keyfile.ParsePublicKey},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := tc.parse(tc.data); !errors.Is(err, keyfile.ErrMalformed) {
				t.Errorf("error = %v, want ErrMalformed", err)
			}
		})
	}
}

// TestPlatformKeygenFilesParse covers the OTHER legacy format: the plain-PEM
// files that Aleutian's own `aleutian-keygen` writes, in all three slot
// variants.
//
// These are the files real customers hold — the onboarding ceremony produces
// them — and they use different PEM labels from the xwing-keyfile format
// checked above. Supporting only one of the two would mean a customer's actual
// key file could not be read.
//
// Every fixture uses the same seed as the X-Wing draft's Appendix D example, so
// all of them must yield identical key material to the standard file.
func TestPlatformKeygenFilesParse(t *testing.T) {
	_, wantSeed, err := keyfile.ParsePrivateKey(read(t, "xwing_private.pem"))
	if err != nil {
		t.Fatalf("parse standard private: %v", err)
	}
	_, wantPub, err := keyfile.ParsePublicKey(read(t, "xwing_public.pem"))
	if err != nil {
		t.Fatalf("parse standard public: %v", err)
	}

	privateFiles := []string{
		"keygen_xwing_private.pem",
		"keygen_xwing_primary_private.pem", // carries a Name: PEM header
		"keygen_xwing_backup_private.pem",
	}
	for _, f := range privateFiles {
		t.Run(f, func(t *testing.T) {
			alg, seed, err := keyfile.ParsePrivateKey(read(t, f))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if alg != keyfile.XWing {
				t.Errorf("algorithm = %v, want X-Wing", alg)
			}
			if !bytes.Equal(seed, wantSeed) {
				t.Error("seed differs from the standard file for the same key")
			}
		})
	}

	publicFiles := []string{
		"keygen_xwing_public.pem",
		"keygen_xwing_primary_public.pem",
		"keygen_xwing_backup_public.pem",
	}
	for _, f := range publicFiles {
		t.Run(f, func(t *testing.T) {
			alg, pub, err := keyfile.ParsePublicKey(read(t, f))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if alg != keyfile.XWing {
				t.Errorf("algorithm = %v, want X-Wing", alg)
			}
			if !bytes.Equal(pub, wantPub) {
				t.Error("public key differs from the standard file for the same key")
			}
		})
	}
}

// TestPlatformKeygenFilesValidateSize: the platform format has no magic and no
// version byte, so the LENGTH is the only structural check available. A file
// of the wrong size must be rejected rather than truncated or padded into a key.
func TestPlatformKeygenFilesValidateSize(t *testing.T) {
	cases := []struct {
		label string
		size  int
		parse func([]byte) (keyfile.Algorithm, []byte, error)
	}{
		{"ALEUTIAN XWING PRIVATE KEY", 31, keyfile.ParsePrivateKey},
		{"ALEUTIAN XWING PRIMARY PRIVATE KEY", 33, keyfile.ParsePrivateKey},
		{"ALEUTIAN XWING BACKUP PRIVATE KEY", 0, keyfile.ParsePrivateKey},
		{"ALEUTIAN XWING PUBLIC KEY", 1215, keyfile.ParsePublicKey},
		{"ALEUTIAN XWING PRIMARY PUBLIC KEY", 1217, keyfile.ParsePublicKey},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			data := pem.EncodeToMemory(&pem.Block{Type: tc.label, Bytes: make([]byte, tc.size)})
			if _, _, err := tc.parse(data); !errors.Is(err, keyfile.ErrMalformed) {
				t.Errorf("error = %v, want ErrMalformed", err)
			}
		})
	}
}
