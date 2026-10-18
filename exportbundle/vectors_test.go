// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package exportbundle

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/fixtures"
)

// vectorCases is how many cases bundle_v1_vectors.json holds. A file with
// fewer would pass every case it has and prove less.
const vectorCases = 114

type vectorKey struct {
	PublicKeyHex string `json:"public_key_hex"`
	PublicKeyPEM string `json:"public_key_pem"`
	KeyID        string `json:"key_id"`
}

type vectorCase struct {
	Name      string `json:"name"`
	BundleB64 string `json:"bundle_b64"`
	Trust     struct {
		CheckpointKeys []string `json:"checkpoint_keys"`
		RecordKeys     []string `json:"record_keys"`
	} `json:"trust"`
	Expected json.RawMessage `json:"expected"`
}

type vectorFile struct {
	Keys  map[string]vectorKey `json:"keys"`
	Cases []vectorCase         `json:"cases"`
}

// loadVectors reads the conformance vectors and their keys.
func loadVectors(t testing.TB) (vectorFile, map[string]PublicKey) {
	t.Helper()
	return loadVectorsFrom(t, fixtures.BundleV1Vectors())
}

// loadVectorsFrom reads a conformance vector file of the v1 file's shape.
func loadVectorsFrom(t testing.TB, raw []byte) (vectorFile, map[string]PublicKey) {
	t.Helper()
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("bundle vectors: %v", err)
	}
	keys := make(map[string]PublicKey, len(vf.Keys))
	for name, k := range vf.Keys {
		key, err := ParsePublicKeyPEM([]byte(k.PublicKeyPEM))
		if err != nil {
			t.Fatalf("key %s: %v", name, err)
		}
		keys[name] = key
	}
	return vf, keys
}

// vectorBundle returns one case's bundle bytes and trust.
func vectorBundle(t testing.TB, vf vectorFile, keys map[string]PublicKey, name string) ([]byte, Trust) {
	t.Helper()
	for _, c := range vf.Cases {
		if c.Name != name {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(c.BundleB64)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return data, caseTrust(t, c, keys)
	}
	t.Fatalf("no vector case %q", name)
	return nil, Trust{}
}

func caseTrust(t testing.TB, c vectorCase, keys map[string]PublicKey) Trust {
	t.Helper()
	var trust Trust
	for _, name := range c.Trust.CheckpointKeys {
		k, ok := keys[name]
		if !ok {
			t.Fatalf("%s: unknown key %q", c.Name, name)
		}
		trust.Checkpoint = append(trust.Checkpoint, k)
	}
	for _, name := range c.Trust.RecordKeys {
		k, ok := keys[name]
		if !ok {
			t.Fatalf("%s: unknown key %q", c.Name, name)
		}
		trust.Record = append(trust.Record, k)
	}
	return trust
}

// canonicalJSON rewrites one JSON value with every object's members sorted
// and no whitespace, so that two results compare as structures: every member,
// every value, and nothing extra on either side.
func canonicalJSON(t testing.TB, data []byte) string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	out := canonicalValue(t, dec)
	if dec.More() {
		t.Fatal("trailing data after the JSON value")
	}
	return out
}

func canonicalValue(t testing.TB, dec *json.Decoder) string {
	t.Helper()
	tok, err := dec.Token()
	if err != nil {
		t.Fatalf("result JSON: %v", err)
	}
	switch v := tok.(type) {
	case json.Delim:
		if v == '[' {
			var items []string
			for dec.More() {
				items = append(items, canonicalValue(t, dec))
			}
			if _, err := dec.Token(); err != nil {
				t.Fatalf("result JSON: %v", err)
			}
			return "[" + strings.Join(items, ",") + "]"
		}
		members := map[string]string{}
		var names []string
		for dec.More() {
			nameTok, err := dec.Token()
			if err != nil {
				t.Fatalf("result JSON: %v", err)
			}
			name, _ := nameTok.(string)
			if _, dup := members[name]; dup {
				t.Fatalf("result JSON repeats member %q", name)
			}
			members[name] = canonicalValue(t, dec)
			names = append(names, name)
		}
		if _, err := dec.Token(); err != nil {
			t.Fatalf("result JSON: %v", err)
		}
		sort.Strings(names)
		parts := make([]string, len(names))
		for i, name := range names {
			parts[i] = fmt.Sprintf("%q:%s", name, members[name])
		}
		return "{" + strings.Join(parts, ",") + "}"
	case string:
		return fmt.Sprintf("%q", v)
	case json.Number:
		return v.String()
	case bool:
		return fmt.Sprint(v)
	}
	return "null"
}

// Every conformance case, compared as the whole §9 result (bundle-format §15;
// v2, §16).
func TestVectors_EveryCase(t *testing.T) {
	t.Run("v1", func(t *testing.T) { everyCase(t, fixtures.BundleV1Vectors(), vectorCases) })
	t.Run("v2", func(t *testing.T) { everyCase(t, fixtures.BundleV2Vectors(), vectorCasesV2) })
}

// vectorCasesV2 is how many cases bundle_v2_vectors.json holds.
const vectorCasesV2 = 193

func everyCase(t *testing.T, raw []byte, vectorCases int) {
	vf, keys := loadVectorsFrom(t, raw)
	if len(vf.Cases) != vectorCases {
		t.Fatalf("the vector file holds %d cases, want %d", len(vf.Cases), vectorCases)
	}
	seen := map[string]bool{}
	passed := 0
	for _, c := range vf.Cases {
		if seen[c.Name] {
			t.Fatalf("case name %q repeats", c.Name)
		}
		seen[c.Name] = true
		t.Run(c.Name, func(t *testing.T) {
			data, err := base64.StdEncoding.DecodeString(c.BundleB64)
			if err != nil {
				t.Fatal(err)
			}
			res, err := Verify(data, caseTrust(t, c, keys))
			if err != nil {
				t.Fatalf("internal error: %v", err)
			}
			got, err := json.Marshal(res)
			if err != nil {
				t.Fatal(err)
			}
			if g, w := canonicalJSON(t, got), canonicalJSON(t, c.Expected); g != w {
				t.Fatalf("result differs\n got %s\nwant %s", g, w)
			}
			passed++
		})
	}
	if passed != vectorCases {
		t.Fatalf("%d of %d cases pass", passed, vectorCases)
	}
}

// The key ids this package computes are the vectors' (format-spec §9.6), and
// the raw-key and PEM constructors agree.
func TestVectors_KeyIDs(t *testing.T) {
	vf, keys := loadVectors(t)
	if len(vf.Keys) == 0 {
		t.Fatal("no keys")
	}
	for name, k := range vf.Keys {
		if keys[name].ID() != k.KeyID {
			t.Fatalf("%s: key id %s, want %s", name, keys[name].ID(), k.KeyID)
		}
		raw, err := hex.DecodeString(k.PublicKeyHex)
		if err != nil {
			t.Fatal(err)
		}
		fromRaw, err := NewPublicKey(raw)
		if err != nil || fromRaw.ID() != k.KeyID {
			t.Fatalf("%s: from raw: %v, id %s", name, err, fromRaw.ID())
		}
	}
}

// The JSON has §9's members in §9's order: a consumer that reads positionally,
// or a diff against the specification's example, sees the same thing.
func TestResult_MemberOrder(t *testing.T) {
	vf, keys := loadVectors(t)
	data, trust := vectorBundle(t, vf, keys, "ok_both_trusts")
	res, err := Verify(data, trust)
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	last := -1
	for _, member := range []string{`"result"`, `"readable"`, `"checkpoint_trust"`, `"record_trust"`, `"verdict"`,
		`"bundle_problems"`, `"chains"`, `"erasure"`, `"counts"`, `"entries"`, `"events"`, `"erasures"`, `"opened"`,
		`"committed"`, `"erased"`, `"checkpoints"`, `"unanchored"`, `"authenticated"`, `"unauthenticated"`,
		`"checkpoint_authenticated"`, `"record_authenticated"`, `"record_signatures_present"`, `"problems"`} {
		at := bytes.Index(out, []byte(member+":"))
		if at <= last {
			t.Fatalf("member %s is missing or out of order in %s", member, out)
		}
		last = at
	}
	unreadable, err := json.Marshal(Result{Reason: ReasonJSON, CheckpointTrust: TrustChecked})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"result":"aleutian.proof.bundle-result.v1","readable":false,"reason":"json"}`; string(unreadable) != want {
		t.Fatalf("unreadable result %s, want %s", unreadable, want)
	}
}
