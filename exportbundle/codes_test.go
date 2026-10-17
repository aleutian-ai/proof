// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package exportbundle

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestProblemCodesAreTheSpecsClosedSet: the Code* constants are exactly the
// codes of bundle-format.md §12, which the result format declares a closed set
// (§9.4). A code added here and not there, or there and not here, fails.
func TestProblemCodesAreTheSpecsClosedSet(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "verify.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var code []string
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, sp := range g.Specs {
			v := sp.(*ast.ValueSpec)
			for i, n := range v.Names {
				if strings.HasPrefix(n.Name, "Code") && i < len(v.Values) {
					s, _ := strconv.Unquote(v.Values[i].(*ast.BasicLit).Value)
					code = append(code, s)
				}
			}
		}
	}
	doc, err := os.ReadFile("../docs/bundle-format.md")
	if err != nil {
		t.Fatal(err)
	}
	sec := string(doc)
	sec = sec[strings.Index(sec, "## 12. Problem codes"):]
	sec = sec[:strings.Index(sec, "\n## 13.")]
	var spec []string
	for _, m := range regexp.MustCompile("(?m)^\\| `([a-z-]+)` \\|").FindAllStringSubmatch(sec, -1) {
		spec = append(spec, m[1])
	}
	sort.Strings(code)
	sort.Strings(spec)
	if strings.Join(code, " ") != strings.Join(spec, " ") || len(code) != 24 {
		t.Fatalf("the problem codes differ from bundle-format.md §12:\n code %v\n spec %v", code, spec)
	}
}
