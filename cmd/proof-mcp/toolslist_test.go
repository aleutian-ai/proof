// Copyright 2026 Aleutian AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

var updateToolsList = flag.Bool("update-tools-list", false, "rewrite testdata/tools_list.golden.json")

// TestToolsList_IsPinned: the tool names and their argument and result
// schemas are part of the server's API. An agent's prompts and a client's code
// are written against them, so they change only on purpose: rerun with
// -update-tools-list, and say so in the changelog. Descriptions are not
// pinned; they are documentation.
func TestToolsList_IsPinned(t *testing.T) {
	tools := toolNames(t, connectWith(t, serverConfig{db: newCommitDB(t)}))
	type pinned struct {
		Name         string `json:"name"`
		InputSchema  any    `json:"input_schema"`
		OutputSchema any    `json:"output_schema,omitempty"`
	}
	var got []pinned
	for name, tool := range tools {
		got = append(got, pinned{Name: name, InputSchema: tool.InputSchema, OutputSchema: tool.OutputSchema})
	}
	sort.Slice(got, func(i, j int) bool { return got[i].Name < got[j].Name })
	raw, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	path := filepath.Join("testdata", "tools_list.golden.json")
	if *updateToolsList {
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (create it with -update-tools-list)", err)
	}
	if !bytes.Equal(raw, want) {
		t.Fatalf("tools/list changed from %s. A change here is an API change: rerun with -update-tools-list "+
			"if it is deliberate, and record it in the changelog.\n got:\n%s", path, raw)
	}
}
