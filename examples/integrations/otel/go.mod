module github.com/aleutian-ai/proof/examples/integrations/otel

go 1.25.0

// proof is pinned to a COMMIT until its next release, then to that tag. After
// pushing a proof change this example needs:
//   GOWORK=off go get github.com/aleutian-ai/proof@<commit> && GOWORK=off go build ./...
// Never a replace directive to a local path.

require (
	github.com/aleutian-ai/proof v0.3.1-0.20261006011007-a7e7eab11fbc
	go.opentelemetry.io/collector/pdata v1.65.0
)

require (
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/hashicorp/go-version v1.9.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	go.etcd.io/bbolt v1.4.3 // indirect
	go.opentelemetry.io/collector/featuregate v1.65.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc v1.83.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
