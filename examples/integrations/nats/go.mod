module github.com/aleutian-ai/proof/examples/integrations/nats

go 1.25.0

// proof is pinned to a COMMIT until its next release, then to that tag. After
// pushing a proof change this example needs:
//   GOWORK=off go get github.com/aleutian-ai/proof@<commit> && GOWORK=off go build ./...
// Never a replace directive to a local path.

require (
	github.com/aleutian-ai/proof v0.3.1-0.20260929165125-458e746caed2
	github.com/nats-io/nats.go v1.53.0
)

require (
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/nats-io/nkeys v0.4.15 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	go.etcd.io/bbolt v1.4.3 // indirect
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
)
