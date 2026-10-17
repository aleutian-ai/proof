// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The codes a verdict reports are part of the API: a caller matches on them,
// and the other implementations report the same ones. This pins the complete
// list, read from the source, so a code cannot be added, renamed or removed
// without this test (and the changelog) saying so.
var (
	pinnedBreakTypes = []string{
		"format_field_misuse", "hash_mismatch", "invalid_field", "invalid_timestamp",
		"invalid_tombstone", "sequence_gap", "unknown_format",
	}
	pinnedBindOutcomes = []string{
		"bound", "chain_broken", "head_mismatch", "height_mismatch", "predecessor_mismatch",
		"range_end_mismatch", "range_start_mismatch", "signature_invalid", "tenant_mismatch",
	}
	pinnedVerdicts = []string{"BROKEN", "INTACT", "INTACT_ANCHORED"}
)

func TestCodesArePinned(t *testing.T) {
	got := constantsOfType(t, map[string]bool{"verify.go": true, "anchor.go": true})
	for typ, want := range map[string][]string{
		"BreakType": pinnedBreakTypes, "BindOutcome": pinnedBindOutcomes, "Verdict": pinnedVerdicts,
	} {
		if g := strings.Join(got[typ], " "); g != strings.Join(want, " ") {
			t.Errorf("%s values changed:\n got  %s\n want %s\nA change here is an API change: update the pinned "+
				"list, the changelog, and the other implementations together.", typ, g, strings.Join(want, " "))
		}
	}
}

// constantsOfType reads the string constants declared with an explicit type in
// the named files, sorted, by type name.
func constantsOfType(t *testing.T, files map[string]bool) map[string][]string {
	t.Helper()
	fset := token.NewFileSet()
	out := map[string][]string{}
	for name := range files {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok || g.Tok != token.CONST {
				continue
			}
			for _, sp := range g.Specs {
				v := sp.(*ast.ValueSpec)
				id, ok := v.Type.(*ast.Ident)
				if !ok || len(v.Values) != len(v.Names) {
					continue
				}
				for _, val := range v.Values {
					if lit, ok := val.(*ast.BasicLit); ok && lit.Kind == token.STRING {
						s, _ := strconv.Unquote(lit.Value)
						out[id.Name] = append(out[id.Name], s)
					}
				}
			}
		}
	}
	for k := range out {
		sort.Strings(out[k])
	}
	return out
}
