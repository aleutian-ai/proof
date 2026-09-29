module github.com/aleutian-ai/proof/examples/integrations/redis

go 1.25.0

// proof is pinned to a COMMIT until its next release, then to that tag. After
// pushing a proof change this example needs:
//   GOWORK=off go get github.com/aleutian-ai/proof@<commit> && GOWORK=off go build ./...
// Never a replace directive to a local path.

require (
	github.com/aleutian-ai/proof v0.3.1-0.20260929004521-f88a575994de
	github.com/redis/go-redis/v9 v9.22.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	go.etcd.io/bbolt v1.4.3 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.21.0 // indirect
)
