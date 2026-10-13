// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package exportbundle

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aleutian-ai/proof/keyfile"
)

// vectorPEM returns a valid key file and its key id.
func vectorPEM(t *testing.T) (text, id string) {
	t.Helper()
	vf, _ := loadVectors(t)
	k := vf.Keys["checkpoint"]
	if k.PublicKeyPEM == "" {
		t.Fatal("the vectors hold no checkpoint key")
	}
	return k.PublicKeyPEM, k.KeyID
}

// rewrap writes a DER block as a PUBLIC KEY file with lines of one width.
func rewrap(der []byte, width int, newline string) string {
	body := base64.StdEncoding.EncodeToString(der)
	var b strings.Builder
	b.WriteString("-----BEGIN PUBLIC KEY-----" + newline)
	for len(body) > 0 {
		n := min(width, len(body))
		b.WriteString(body[:n] + newline)
		body = body[n:]
	}
	b.WriteString("-----END PUBLIC KEY-----" + newline)
	return b.String()
}

// §6: what a key file is, and every way a file is not one.
func TestParsePublicKeyPEM(t *testing.T) {
	valid, id := vectorPEM(t)
	block, _ := pem.Decode([]byte(valid))
	if block == nil {
		t.Fatal("the vector key is not PEM")
	}
	der := block.Bytes
	body := base64.StdEncoding.EncodeToString(der)
	otherOID := bytes.Clone(der)
	otherOID[16] = 0x11 // id-ml-dsa-44
	trailing := append(bytes.Clone(der), 0)
	seed := make([]byte, keyfile.MLDSA65.SeedSize())
	private, err := keyfile.MarshalPrivateKey(keyfile.MLDSA65, seed)
	if err != nil {
		t.Fatal(err)
	}
	// The same bytes with the unused bits of the last character set: 1974
	// bytes fill their base64 exactly, so a byte is added to leave some.
	padded := base64.StdEncoding.EncodeToString(append(bytes.Clone(der), 0))
	nonCanonical := padded[:len(padded)-3] + "B=="
	if _, err := base64.StdEncoding.DecodeString(nonCanonical); err != nil {
		t.Fatalf("the non-canonical body must still decode leniently: %v", err)
	}

	cases := []struct {
		name string
		text string
		ok   bool
	}{
		{"as proof keygen writes it", valid, true},
		{"CRLF line endings", strings.ReplaceAll(valid, "\n", "\r\n"), true},
		{"lines of 76", rewrap(der, 76, "\n"), true},
		{"one line", rewrap(der, len(body), "\n"), true},
		{"lines of 1", rewrap(der, 1, "\n"), true},
		{"no final newline", strings.TrimSuffix(valid, "\n"), true},
		{"whitespace before and after", " \t\r\n\n" + valid + "\n \t\r\n", true},

		{"empty", "", false},
		{"whitespace only", " \n", false},
		{"text before", "key:\n" + valid, false},
		{"text after", valid + "end\n", false},
		{"a comment line after", valid + "# checkpoint key\n", false},
		{"a non-breaking space after", valid + "\xc2\xa0", false},
		{"a form feed after", valid + "\f", false},
		{"a NUL after", valid + "\x00", false},
		{"a byte-order mark before", "\xef\xbb\xbf" + valid, false},
		{"two blocks", valid + valid, false},
		{"a header", strings.Replace(valid, "KEY-----\n", "KEY-----\nComment: x\n\n", 1), false},
		{"an empty line in the body", strings.Replace(valid, "\n", "\n\n", 2), false},
		{"a space ending the last body line", strings.Replace(valid, "\n-----END", " \n-----END", 1), false},
		{"a space ending the first body line", rewrap(der, 64, " \n"), false},
		{"a tab inside the body", strings.Replace(valid, "MII", "M\tII", 1), false},
		{"another label", strings.ReplaceAll(valid, "PUBLIC KEY", "ML-DSA PUBLIC KEY"), false},
		{"the legacy label", strings.ReplaceAll(valid, "PUBLIC KEY", "ALEUTIAN HYBRID KEM PUBLIC KEY"), false},
		{"labels of another case", strings.ReplaceAll(valid, "PUBLIC KEY", "Public Key"), false},
		{"four dashes", strings.Replace(valid, "-----BEGIN", "----BEGIN", 1), false},
		{"no END line", strings.Split(valid, "-----END")[0], false},
		{"no body", "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n", false},
		{"a private key", string(private), false},
		{"URL-safe base64", strings.NewReplacer("+", "-", "/", "_").Replace(valid), false},
		{"padding removed", strings.Replace(rewrap(der[:len(der)-1], 64, "\n"), "=", "", 1), false},
		{"non-canonical base64", "-----BEGIN PUBLIC KEY-----\n" + nonCanonical + "\n-----END PUBLIC KEY-----\n", false},
		{"a key one byte short", rewrap(der[:len(der)-1], 64, "\n"), false},
		{"a byte after the key", rewrap(trailing, 64, "\n"), false},
		{"another algorithm's OID", rewrap(otherOID, 64, "\n"), false},
		{"the raw key without its SubjectPublicKeyInfo", rewrap(der[len(spkiPrefix):], 64, "\n"), false},
		{"over 16 KiB of whitespace", valid + strings.Repeat("\n", MaxKeyFileBytes), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key, err := ParsePublicKeyPEM([]byte(c.text))
			if c.ok {
				if err != nil || key.ID() != id {
					t.Fatalf("refused, or the wrong id %q: %v", key.ID(), err)
				}
				return
			}
			if !errors.Is(err, ErrKeyFile) {
				t.Fatalf("accepted, or the wrong error: %v", err)
			}
			if key.ID() != "" {
				t.Fatal("a refused file still gave a key")
			}
			// The refusal must not quote the file.
			if strings.Contains(err.Error(), "MII") || strings.Contains(err.Error(), "Comment") {
				t.Fatalf("the error quotes the file: %v", err)
			}
		})
	}
	// keyfile, which writes key files, writes what this accepts.
	written, err := keyfile.MarshalPublicKey(keyfile.MLDSA65, der[len(spkiPrefix):])
	if err != nil {
		t.Fatal(err)
	}
	if key, err := ParsePublicKeyPEM(written); err != nil || key.ID() != id {
		t.Fatalf("a key file keyfile wrote: id %q, %v", key.ID(), err)
	}
}

// A key file is a regular file of at most 16 KiB, opened once.
func TestReadPublicKeyFile(t *testing.T) {
	valid, id := vectorPEM(t)
	dir := t.TempDir()
	write := func(name, text string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if key, err := ReadPublicKeyFile(write("ok.pem", valid)); err != nil || key.ID() != id {
		t.Fatalf("a valid key file: id %q, %v", key.ID(), err)
	}
	atLimit := valid + strings.Repeat("\n", MaxKeyFileBytes-len(valid))
	if key, err := ReadPublicKeyFile(write("limit.pem", atLimit)); err != nil || key.ID() != id {
		t.Fatalf("a key file of exactly 16 KiB: %v", err)
	}
	if _, err := ReadPublicKeyFile(write("over.pem", atLimit+"\n")); !errors.Is(err, ErrKeyFile) {
		t.Fatalf("a key file of 16 KiB and a byte: %v", err)
	}
	// Far over the limit: no more than the limit and a byte is read.
	huge := write("huge.pem", valid+strings.Repeat("\n", 8<<20))
	allocated, _, _ := measure(func() {
		if _, err := ReadPublicKeyFile(huge); !errors.Is(err, ErrKeyFile) {
			t.Errorf("an 8 MiB key file: %v", err)
		}
	})
	if allocated > 4*MaxKeyFileBytes {
		t.Fatalf("allocated %d bytes to refuse an 8 MiB key file", allocated)
	}
	if _, err := ReadPublicKeyFile(dir); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("a directory: %v", err)
	}
	if _, err := ReadPublicKeyFile(filepath.Join(dir, "absent.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a missing file: %v", err)
	}
	if _, err := ReadPublicKeyFile(write("junk.pem", "not a key")); !errors.Is(err, ErrKeyFile) {
		t.Fatalf("a file that is not a key: %v", err)
	}
}

// A bundle file is a regular file, read to the limit and one byte: that byte
// is what makes an oversized bundle `too-large` instead of a cut-off `json`.
func TestReadBundleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "b.json")
	content := []byte(okDoc)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		limit, want int
		reason      string
	}{
		{len(content) + 10, len(content), ""},
		{len(content), len(content), ""},
		{len(content) - 1, len(content), ReasonTooLarge},
		{10, 11, ReasonTooLarge},
	} {
		data, err := ReadBundleFile(path, c.limit)
		if err != nil || len(data) != c.want || !bytes.HasPrefix(content, data) {
			t.Fatalf("limit %d: read %d bytes, want %d: %v", c.limit, len(data), c.want, err)
		}
		if got := reasonOf(mustVerify(t, data, Trust{}, Limits{BundleBytes: c.limit})); got != c.reason {
			t.Fatalf("limit %d: reason %q, want %q", c.limit, got, c.reason)
		}
	}
	if _, err := ReadBundleFile(dir, 100); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("a directory: %v", err)
	}
	if _, err := ReadBundleFile(filepath.Join(dir, "absent.json"), 100); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a missing file: %v", err)
	}
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadBundleFile(empty, 100); err != nil || len(data) != 0 {
		t.Fatalf("an empty file: %d bytes, %v", len(data), err)
	}
}

// NewPublicKey takes exactly an ML-DSA-65 public key, and copies it.
func TestNewPublicKey(t *testing.T) {
	for _, size := range []int{0, 32, publicKeySize - 1, publicKeySize + 1, 2592} {
		if _, err := NewPublicKey(make([]byte, size)); !errors.Is(err, ErrKeyFile) {
			t.Errorf("a %d-byte key: %v", size, err)
		}
	}
	valid, id := vectorPEM(t)
	block, _ := pem.Decode([]byte(valid))
	raw := bytes.Clone(block.Bytes[len(spkiPrefix):])
	key, err := NewPublicKey(raw)
	if err != nil || key.ID() != id {
		t.Fatalf("id %q: %v", key.ID(), err)
	}
	raw[0] ^= 0xff
	if set := keySet([]PublicKey{key, key, {}}); len(set) != 1 || set[id][0] == raw[0] {
		t.Fatal("the key set shares the caller's bytes, or counts a key twice, or counts the zero key")
	}
}
