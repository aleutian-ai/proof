// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package chainformat

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/aleutian-ai/proof/fixtures"
)

type v4Vector struct {
	Name              string `json:"name"`
	Erased            bool   `json:"erased"`
	PreviousHash      string `json:"previous_hash"`
	GlobalSeq         string `json:"global_seq"`
	Timestamp         string `json:"timestamp"`
	EntryID           string `json:"entry_id"`
	EntryType         string `json:"entry_type"`
	ContentHash       string `json:"content_hash"`
	Salt              string `json:"salt"`
	LeafHash          string `json:"leaf_hash"`
	LeafPreimageHex   string `json:"leaf_preimage_hex"`
	ExpectedLeafHash  string `json:"expected_leaf_hash"`
	ExpectedChainHash string `json:"expected_chain_hash"`
}

// v4Inputs computes a vector's leaf hash (taken as given for an erased entry)
// and chain hash through the checked entry points.
func v4Inputs(v v4Vector) (leaf, chain string, err error) {
	seq, err := strconv.ParseInt(v.GlobalSeq, 10, 64)
	if err != nil || strconv.FormatInt(seq, 10) != v.GlobalSeq {
		return "", "", errNotCanonicalDecimal
	}
	ts, err := time.Parse(time.RFC3339Nano, v.Timestamp)
	if err != nil {
		return "", "", err
	}
	if ts.UTC().Format("2006-01-02T15:04:05.000000Z") != v.Timestamp {
		return "", "", errNotCanonicalDecimal
	}
	leaf = v.LeafHash
	if !v.Erased {
		if leaf, err = ComputeLeafHashV4(v.EntryID, v.EntryType, v.ContentHash, v.Salt); err != nil {
			return "", "", err
		}
	}
	chain, err = ComputeChainHashV4(v.PreviousHash, seq, ts, leaf)
	return leaf, chain, err
}

type vectorError string

func (e vectorError) Error() string { return string(e) }

const errNotCanonicalDecimal = vectorError("not in the one spelling the format allows")

// TestChainHashV4_SharedVectors holds Go to the v4 vectors, whose expected
// values were computed in Python from the spec — not by this package.
func TestChainHashV4_SharedVectors(t *testing.T) {
	var file struct {
		LeafDomain  string     `json:"leaf_domain"`
		ChainDomain string     `json:"chain_domain"`
		Vectors     []v4Vector `json:"vectors"`
		Reject      []v4Vector `json:"reject"`
		V3Prefix    []struct {
			GlobalSeq         string `json:"global_seq"`
			Timestamp         string `json:"timestamp"`
			ContentHash       string `json:"content_hash"`
			PreviousHash      string `json:"previous_hash"`
			ExpectedChainHash string `json:"expected_chain_hash"`
		} `json:"v3_prefix"`
	}
	if err := json.Unmarshal(fixtures.ChainV4Vectors(), &file); err != nil {
		t.Fatal(err)
	}
	if file.LeafDomain != LeafHashPrefixV4 || file.ChainDomain != ChainHashPrefixV4 {
		t.Fatalf("vectors are for %q / %q", file.LeafDomain, file.ChainDomain)
	}
	if len(file.Vectors) < 20 || len(file.Reject) < 20 || len(file.V3Prefix) != 2 {
		t.Fatalf("%d vectors / %d reject cases: the file was truncated", len(file.Vectors), len(file.Reject))
	}
	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if v.LeafPreimageHex != "" {
				// The preimage is pinned too, so a mismatch says which byte differs.
				want, _ := hex.DecodeString(v.LeafPreimageHex)
				if got := leafPreimageForTest(v.EntryID, v.EntryType, v.ContentHash, v.Salt); string(got) != string(want) {
					t.Errorf("leaf preimage = %x\n want %x", got, want)
				}
			}
			leaf, chain, err := v4Inputs(v)
			if err != nil {
				t.Fatal(err)
			}
			if !v.Erased && leaf != v.ExpectedLeafHash {
				t.Errorf("leaf hash = %s\n want %s", leaf, v.ExpectedLeafHash)
			}
			if chain != v.ExpectedChainHash {
				t.Errorf("chain hash = %s\n want %s", chain, v.ExpectedChainHash)
			}
		})
	}
	for _, v := range file.Reject {
		t.Run("reject: "+v.Name, func(t *testing.T) {
			if _, _, err := v4Inputs(v); err == nil {
				t.Error("accepted a case every implementation must refuse")
			}
		})
	}
	for i, p := range file.V3Prefix {
		seq, _ := strconv.ParseInt(p.GlobalSeq, 10, 64)
		ts, _ := time.Parse(time.RFC3339Nano, p.Timestamp)
		got, err := ComputeChainHashV3(p.PreviousHash, seq, ts, p.ContentHash)
		if err != nil || got != p.ExpectedChainHash {
			t.Errorf("v3_prefix[%d]: %s, %v", i, got, err)
		}
	}
}

// leafPreimageForTest rebuilds the leaf preimage the way the spec writes it,
// independently of ComputeLeafHashV4Unchecked's streaming writes.
func leafPreimageForTest(id, typ, content, salt string) []byte {
	b := []byte(LeafHashPrefixV4)
	b = append(b, byte(len(id)>>24), byte(len(id)>>16), byte(len(id)>>8), byte(len(id)))
	b = append(b, id...)
	b = append(b, byte(len(typ)>>24), byte(len(typ)>>16), byte(len(typ)>>8), byte(len(typ)))
	b = append(b, typ...)
	b = append(b, content...)
	return append(b, salt...)
}

// TestComputeLeafHashV4_TombstoneShapeIsItsOwnError: a verifier reports a v4
// tombstone as format_field_misuse, so the error must be distinguishable.
func TestComputeLeafHashV4_TombstoneShapeIsItsOwnError(t *testing.T) {
	salt := "00" + string(make([]byte, 0))
	for _, c := range []struct{ id, typ, content string }{
		{"ent", TombstoneEntryType, hex128},
		{TombstoneEntryIDPrefix + "x", "event", hex128},
		{"ent", "event", TombstoneContentHashPrefix + hex128[:64]},
	} {
		if err := ValidateLeafInputsV4(c.id, c.typ, c.content, salt); err != ErrTombstoneInV4 {
			t.Errorf("%+v: %v, want ErrTombstoneInV4", c, err)
		}
	}
}

const hex128 = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

// TestNewSaltV4 mints distinct, well-formed salts.
func TestNewSaltV4(t *testing.T) {
	a, err := NewSaltV4()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewSaltV4()
	if ValidateSaltV4(a) != nil || a == b {
		t.Errorf("salts %q and %q", a, b)
	}
}
