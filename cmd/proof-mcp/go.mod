// The MCP server is a SEPARATE MODULE, deliberately.
//
// The official MCP SDK brings nine transitive dependencies and requires Go
// 1.25. Keeping it here means `go get github.com/aleutian-ai/proof` still
// resolves to two direct dependencies at Go 1.24 — someone who wants to verify
// a chain does not inherit a protocol SDK they will never call.
//
// See docs/decisions.md D12.
module github.com/aleutian-ai/proof/cmd/proof-mcp

go 1.25.0

// No replace directive: `go install .../cmd/proof-mcp@latest` refuses any module
// that has one. Depend on a PUBLISHED version of the library. To develop the
// server against unreleased library changes, use a go.work at the repo root
// (gitignored) rather than reintroducing a replace here.

require (
	github.com/aleutian-ai/proof v0.1.0
	github.com/cloudflare/circl v1.6.3
	github.com/modelcontextprotocol/go-sdk v1.7.0
)

require (
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/oauth2 v0.35.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)
