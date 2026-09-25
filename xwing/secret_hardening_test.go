// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package xwing

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// Compile-time guard: the sentinels must stay CONSTANTS. A const declaration
// only accepts a constant expression, so reverting any sentinel to
// `var ErrX = errors.New(...)` breaks the build here rather than silently
// re-opening the fail-open path described on sentinelError.
const (
	_ = ErrInvalidPublicKey
	_ = ErrInvalidPrivateKey
	_ = ErrInvalidCiphertext
)

// secretFixtures returns a private key and shared secret filled with a byte
// whose decimal (165) and hex (a5) forms are easy to spot in leaked output.
func secretFixtures() (PrivateKey, SharedSecret) {
	var priv PrivateKey
	var ss SharedSecret
	for i := range priv.Seed {
		priv.Seed[i] = 0xa5
	}
	for i := range ss {
		ss[i] = 0xa5
	}
	return priv, ss
}

// leaks reports whether out contains the fixture byte in any common encoding.
func leaks(out string) bool {
	// 0xa5 as decimal, hex (both cases), escaped, octal, binary, and base64.
	for _, marker := range []string{"165", "a5a5", "A5A5", `\xa5`, "0xa5", "245", "10100101", "paWl"} {
		if strings.Contains(out, marker) {
			return true
		}
	}
	return false
}

// TestSecretsRedactUnderEveryVerb pins the fix for the %d leak: String and
// GoString covered only %v/%+v/%#v/%s, so %d printed the seed in decimal.
func TestSecretsRedactUnderEveryVerb(t *testing.T) {
	priv, ss := secretFixtures()
	verbs := []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%X", "%q", "%o", "%b", "%08d"}
	values := []struct {
		name string
		v    any
		want string
	}{
		{"PrivateKey", priv, "[REDACTED PrivateKey]"},
		{"*PrivateKey", &priv, "[REDACTED PrivateKey]"},
		{"SharedSecret", ss, "[REDACTED SharedSecret]"},
		{"*SharedSecret", &ss, "[REDACTED SharedSecret]"},
	}
	for _, val := range values {
		for _, verb := range verbs {
			out := fmt.Sprintf(verb, val.v)
			if leaks(out) {
				t.Errorf("%s with %s leaked key material: %q", val.name, verb, out)
			}
			if !strings.Contains(out, val.want) {
				t.Errorf("%s with %s = %q, want it to contain %q", val.name, verb, out, val.want)
			}
		}
	}
}

// TestSecretsRedactInsideExportedFields covers the common logging shape: a
// struct with EXPORTED fields holding secrets, printed whole. Asserts the exact
// output, not just the absence of known byte encodings, so a leak through an
// encoding the markers do not list still fails.
func TestSecretsRedactInsideExportedFields(t *testing.T) {
	priv, ss := secretFixtures()
	holder := struct {
		Key    PrivateKey
		Secret SharedSecret
	}{priv, ss}
	want := map[string]string{
		"%v":  "{[REDACTED PrivateKey] [REDACTED SharedSecret]}",
		"%+v": "{Key:[REDACTED PrivateKey] Secret:[REDACTED SharedSecret]}",
		"%d":  "{[REDACTED PrivateKey] [REDACTED SharedSecret]}",
		"%x":  "{[REDACTED PrivateKey] [REDACTED SharedSecret]}",
	}
	for verb, w := range want {
		if out := fmt.Sprintf(verb, holder); out != w {
			t.Errorf("struct with exported secret fields, %s = %q, want %q", verb, out, w)
		}
	}
	if out := fmt.Sprintf("%#v", holder); leaks(out) || !strings.Contains(out, "[REDACTED PrivateKey]") {
		t.Errorf("struct with exported secret fields, %%#v = %q", out)
	}
}

// TestSecretsRedactUnderSlog pins the LogValuer path. Without it, slog's
// handlers fall through to MarshalText, which refuses, and log an error string.
func TestSecretsRedactUnderSlog(t *testing.T) {
	priv, ss := secretFixtures()
	var buf bytes.Buffer
	for _, h := range []slog.Handler{slog.NewTextHandler(&buf, nil), slog.NewJSONHandler(&buf, nil)} {
		buf.Reset()
		slog.New(h).Info("k", "priv", priv, "ss", ss, "ptr", &ss)
		out := buf.String()
		if leaks(out) || strings.Contains(out, "ERROR") || !strings.Contains(out, "[REDACTED SharedSecret]") {
			t.Errorf("%T logged %q", h, out)
		}
	}
}

// TestPercentPLimitationIsDocumented pins a KNOWN leak that no method can close:
// fmt handles %p before consulting a Formatter and prints the value with method
// calls disabled. The test asserts the leak exists AND that doc.go warns about
// it — so if a future Go release fixes %p, this fails and the documentation
// gets corrected rather than silently going stale.
func TestPercentPLimitationIsDocumented(t *testing.T) {
	priv, ss := secretFixtures()
	if !leaks(fmt.Sprintf("%p", priv)) || !leaks(fmt.Sprintf("%p", ss)) {
		t.Fatalf("%%p no longer leaks key material — update the %%p limitation in doc.go and the CHANGELOG")
	}
	doc, err := os.ReadFile("doc.go")
	if err != nil {
		t.Fatalf("read doc.go: %v", err)
	}
	if !strings.Contains(string(doc), "%p prints the raw bytes") {
		t.Errorf("doc.go no longer documents the %%p limitation")
	}
}

// TestSecretsRefuseSerialization pins that every serializer FAILS rather than
// emitting either the secret or a placeholder that would hide the bug.
func TestSecretsRefuseSerialization(t *testing.T) {
	priv, ss := secretFixtures()
	cases := []struct {
		name string
		do   func() error
	}{
		{"json PrivateKey", func() error { _, err := json.Marshal(priv); return err }},
		{"json SharedSecret", func() error { _, err := json.Marshal(ss); return err }},
		{"json struct embedding PrivateKey", func() error {
			_, err := json.Marshal(struct{ K PrivateKey }{priv})
			return err
		}},
		{"json map keyed by SharedSecret (TextMarshaler)", func() error {
			_, err := json.Marshal(map[SharedSecret]int{ss: 1})
			return err
		}},
		{"text PrivateKey", func() error { _, err := priv.MarshalText(); return err }},
		{"text SharedSecret", func() error { _, err := ss.MarshalText(); return err }},
		{"gob PrivateKey", func() error { return gob.NewEncoder(&bytes.Buffer{}).Encode(priv) }},
		{"gob SharedSecret", func() error { return gob.NewEncoder(&bytes.Buffer{}).Encode(ss) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.do()
			if err == nil {
				t.Fatal("serialized secret key material without error")
			}
			if leaks(err.Error()) {
				t.Errorf("error message leaked key material: %q", err)
			}
		})
	}
}

// TestInvalidInputFailsClosed pins that every invalid-input path returns a
// NON-NIL error matching its sentinel — the property the constant sentinels
// guarantee. Before, a nil'd sentinel turned these into silent successes.
func TestInvalidInputFailsClosed(t *testing.T) {
	_, err := NewPrivateKey(make([]byte, 31))
	assertSentinel(t, "NewPrivateKey(31 bytes)", err, ErrInvalidPrivateKey)

	_, err = UnmarshalPublicKey(make([]byte, 1215))
	assertSentinel(t, "UnmarshalPublicKey(1215 bytes)", err, ErrInvalidPublicKey)

	ct, ss, err := Encapsulate(PublicKey{MLKEMPub: make([]byte, 10), X25519Pub: make([]byte, 32)})
	assertSentinel(t, "Encapsulate(bad public key)", err, ErrInvalidPublicKey)
	if ss != (SharedSecret{}) || len(ct.MLKEMCT) != 0 {
		t.Error("Encapsulate returned output alongside its error")
	}

	priv, _ := secretFixtures()
	_, err = Decapsulate(Ciphertext{MLKEMCT: make([]byte, 5), X25519EPK: make([]byte, 32)}, priv)
	assertSentinel(t, "Decapsulate(bad ciphertext)", err, ErrInvalidCiphertext)

	_, err = PublicKey{MLKEMPub: make([]byte, 1), X25519Pub: make([]byte, 32)}.KeyID()
	assertSentinel(t, "KeyID(bad public key)", err, ErrInvalidPublicKey)
}

// assertSentinel checks err is non-nil and matches want, both directly and
// wrapped with %w.
func assertSentinel(t *testing.T, what string, err, want error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: returned nil error — fails OPEN", what)
	}
	if !errors.Is(err, want) {
		t.Errorf("%s: errors.Is(%v, %v) = false", what, err, want)
	}
	if wrapped := fmt.Errorf("context: %w", err); !errors.Is(wrapped, want) {
		t.Errorf("%s: sentinel not matched through a %%w wrap", what)
	}
}
