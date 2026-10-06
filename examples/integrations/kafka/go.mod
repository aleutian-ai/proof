module github.com/aleutian-ai/proof/examples/integrations/kafka

go 1.25.0

// proof is pinned to a COMMIT until its next release, then to that tag. After
// pushing a proof change this example needs:
//   GOWORK=off go get github.com/aleutian-ai/proof@<commit> && GOWORK=off go build ./...
// Never a replace directive to a local path.

require (
	github.com/aleutian-ai/proof v0.3.1-0.20260930024546-259c329621a8
	github.com/twmb/franz-go v1.21.7
)

require (
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/klauspost/compress v1.19.2 // indirect
	github.com/pierrec/lz4/v4 v4.1.26 // indirect
	github.com/twmb/franz-go/pkg/kmsg v1.13.1 // indirect
	go.etcd.io/bbolt v1.4.3 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.21.0 // indirect
)
