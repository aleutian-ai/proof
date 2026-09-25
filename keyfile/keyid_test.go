// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package keyfile_test

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"regexp"
	"testing"

	"github.com/aleutian-ai/proof/keyfile"
	"github.com/aleutian-ai/proof/xwing"
)

// TestXWingKeyIDMatchesTheExistingImplementation is the compatibility anchor:
// every wrapped key and tenant fingerprint the platform has stored contains an
// X-Wing key id computed by xwing.PublicKey.KeyID. If these two ever disagree,
// stored data stops resolving.
func TestXWingKeyIDMatchesTheExistingImplementation(t *testing.T) {
	_, pub, err := keyfile.ParsePublicKey(read(t, "xwing_public.pem"))
	if err != nil {
		t.Fatalf("parse public: %v", err)
	}
	fromKeyfile, err := keyfile.KeyID(keyfile.XWing, pub)
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}

	parsed, err := xwing.UnmarshalPublicKey(pub)
	if err != nil {
		t.Fatalf("xwing.UnmarshalPublicKey: %v", err)
	}
	fromXWing, err := parsed.KeyID()
	if err != nil {
		t.Fatalf("xwing KeyID: %v", err)
	}
	if fromKeyfile != fromXWing {
		t.Errorf("keyfile.KeyID and xwing.PublicKey.KeyID disagree:\n %x\n %x", fromKeyfile, fromXWing)
	}

	hexFromKeyfile, err := keyfile.KeyIDHex(keyfile.XWing, pub)
	if err != nil {
		t.Fatalf("KeyIDHex: %v", err)
	}
	hexFromXWing, err := parsed.KeyIDHex()
	if err != nil {
		t.Fatalf("xwing KeyIDHex: %v", err)
	}
	if hexFromKeyfile != hexFromXWing {
		t.Errorf("hex ids disagree: %s vs %s", hexFromKeyfile, hexFromXWing)
	}
}

// TestKeyIDIsAlgorithmBound: for everything except X-Wing the id covers the
// SubjectPublicKeyInfo, which embeds the algorithm's object identifier. A plain
// hash of the key bytes would let the same bytes under two algorithms collide.
func TestKeyIDIsAlgorithmBound(t *testing.T) {
	for _, tc := range rfcCases {
		if tc.alg == keyfile.XWing {
			continue // grandfathered scheme, checked above
		}
		t.Run(tc.alg.String(), func(t *testing.T) {
			_, pub, err := keyfile.ParsePublicKey(read(t, tc.publicFile))
			if err != nil {
				t.Fatalf("parse public: %v", err)
			}
			got, err := keyfile.KeyID(tc.alg, pub)
			if err != nil {
				t.Fatalf("KeyID: %v", err)
			}

			// It must NOT be a bare hash of the key bytes.
			bare := sha512.Sum512(pub)
			if bytes.Equal(got[:], bare[:keyfile.KeyIDSize]) {
				t.Error("key id is a bare hash of the key bytes — the algorithm is not bound in")
			}

			// It must equal SHA-512(domain ‖ SPKI DER)[:16], recomputed here.
			spkiPEM, err := keyfile.MarshalPublicKey(tc.alg, pub)
			if err != nil {
				t.Fatalf("marshal public: %v", err)
			}
			block, _ := pem.Decode(spkiPEM)
			if block == nil {
				t.Fatal("no PEM block")
			}
			h := sha512.New()
			h.Write([]byte("proof.keyid.v1:"))
			h.Write(block.Bytes)
			var want [keyfile.KeyIDSize]byte
			copy(want[:], h.Sum(nil))
			if got != want {
				t.Error("key id does not match SHA-512(domain ‖ SPKI)[:16]")
			}
		})
	}
}

// TestKeyIDsAreDistinctAcrossKeysAndAlgorithms: different keys, and the same
// key material under different algorithms, must not share an id.
func TestKeyIDsAreDistinctAcrossKeysAndAlgorithms(t *testing.T) {
	seen := map[[keyfile.KeyIDSize]byte]string{}
	for _, tc := range rfcCases {
		_, pub, err := keyfile.ParsePublicKey(read(t, tc.publicFile))
		if err != nil {
			t.Fatalf("parse public: %v", err)
		}
		id, err := keyfile.KeyID(tc.alg, pub)
		if err != nil {
			t.Fatalf("KeyID: %v", err)
		}
		if prev, dup := seen[id]; dup {
			t.Errorf("%s and %s share a key id", tc.alg, prev)
		}
		seen[id] = tc.alg.String()

		// A one-bit change in the key must change the id.
		altered := append([]byte(nil), pub...)
		altered[0] ^= 0x01
		other, err := keyfile.KeyID(tc.alg, altered)
		if err != nil {
			t.Fatalf("KeyID (altered): %v", err)
		}
		if other == id {
			t.Errorf("%s: a one-bit key change did not change the id", tc.alg)
		}
	}
	if len(seen) != len(rfcCases) {
		t.Errorf("got %d distinct ids for %d keys", len(seen), len(rfcCases))
	}
}

// knownKeyIDs pins the key ids of the specification's example keys.
//
// Key ids are written into wrapped keys and configuration, so a change here
// means stored data stops resolving to the key it names. If this fails, the id
// SCHEME changed — do not update these values without deciding what happens to
// every id already stored.
var knownKeyIDs = map[keyfile.Algorithm]string{
	keyfile.MLKEM512:  "00808647b5552364d15f3153faa2bad8",
	keyfile.MLKEM768:  "45eb4308b4ecb11cf91262ab31406e34",
	keyfile.MLKEM1024: "b15eaa958658f3c1369579ae51fc1a5d",
	keyfile.MLDSA44:   "c4dbbe33b8ffa07dabbcd03ebf91e41a",
	keyfile.MLDSA65:   "3fb85abc3e8bae42952ee9194ae1f615",
	keyfile.MLDSA87:   "a517c6aecc3f07a5b694601fa43b4bba",
	keyfile.XWing:     "6ba5ba0db298b98ec2498a2e21ddfc79",
}

// TestKeyIDIsStable checks each example key against its pinned id, and that the
// id is 32 lowercase hex characters — the shape the platform's configuration
// already expects.
func TestKeyIDIsStable(t *testing.T) {
	shape := regexp.MustCompile(`^[0-9a-f]{32}$`)
	for _, tc := range rfcCases {
		t.Run(tc.alg.String(), func(t *testing.T) {
			_, pub, err := keyfile.ParsePublicKey(read(t, tc.publicFile))
			if err != nil {
				t.Fatalf("parse public: %v", err)
			}
			got, err := keyfile.KeyIDHex(tc.alg, pub)
			if err != nil {
				t.Fatalf("KeyIDHex: %v", err)
			}
			if !shape.MatchString(got) {
				t.Errorf("%q is not 32 lowercase hex characters", got)
			}
			want, ok := knownKeyIDs[tc.alg]
			if !ok {
				t.Fatalf("no pinned id for %s", tc.alg)
			}
			if got != want {
				t.Errorf("key id changed:\n got  %s\n want %s\n"+
					"Key ids are stored in wrapped keys and config; changing the "+
					"scheme orphans them.", got, want)
			}
			again, err := keyfile.KeyIDHex(tc.alg, pub)
			if err != nil || again != got {
				t.Errorf("recomputation differs (%v)", err)
			}
		})
	}
}

// TestKeyIDRejectsBadInput covers the argument checks.
func TestKeyIDRejectsBadInput(t *testing.T) {
	if _, err := keyfile.KeyID(keyfile.Unknown, make([]byte, 32)); !errors.Is(err, keyfile.ErrUnsupportedAlgorithm) {
		t.Errorf("unknown algorithm accepted: %v", err)
	}
	if _, err := keyfile.KeyID(keyfile.MLDSA65, make([]byte, 10)); !errors.Is(err, keyfile.ErrMalformed) {
		t.Errorf("short public key accepted: %v", err)
	}
	if _, err := keyfile.KeyIDHex(keyfile.XWing, nil); !errors.Is(err, keyfile.ErrMalformed) {
		t.Errorf("nil public key accepted: %v", err)
	}
	if _, err := hex.DecodeString(""); err != nil {
		t.Fatal("sanity")
	}
}
