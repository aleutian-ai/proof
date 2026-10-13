# opencode + a local model → proof-mcp

An AI agent records evidence of its own actions in a tamper-evident chain, and
anyone can check that record later **without trusting the agent, the model, or
the machine it ran on.** Everything is local: opencode runs on Alpine in a
container, the model is served by Ollama on the host, and nothing leaves the
machine.

```
  Alpine container                                        your machine
  ┌──────────────────────────────────────────┐            ┌──────────────────┐
  │ opencode ──MCP stdio──► proof-mcp        │            │ Ollama           │
  │    │                    --db /data/…     │            │  ministral-3:3b  │
  │    │                    --chains agent-… │            │  (or any model   │
  │    └──── OpenAI-compatible API ──────────┼──host.────►│   that can call  │
  │                                          │  containers│   tools)         │
  │ proof (CLI): verify · disclose · forget   │  .internal │                  │
  └──────────────────────────────────────────┘            └──────────────────┘
```

## The demo is not a deployment recipe

There is no broker here. The one network hop is from the container to Ollama on
the host, over plain HTTP with no TLS and no authentication, which is how Ollama
listens by default.

The image is not reproducible and should not be reused. In the
[`Containerfile`](Containerfile):

- the base image, `alpine:3.20`, is pinned by tag, not by digest, so it is
  whatever that tag points at on the day of the build;
- `apk add` installs whatever package versions that day's Alpine index has;
- opencode is installed by `curl -fsSL https://opencode.ai/install | bash`,
  run as root at build time: an unversioned installer, fetched over the network
  and not checked against any checksum or signature.

So the build trusts opencode.ai, Docker Hub and the Alpine mirrors at the moment
it runs, and two builds can differ. That is acceptable for a throwaway local
image. For anything else, pin the base by digest and install a named opencode
release whose checksum you verify.

## Run it

Needs podman, Go, and Ollama running with a model that supports tool calling.

```sh
./run.sh                          # ministral-3:3b (3 GB)
MODEL=ornith-1.5:9b ./run.sh     # any Ollama model with "tools" in `ollama show`
```

The script builds static Linux binaries of `proof` and `proof-mcp`, builds the
image, asks the agent to commit two actions, then checks the result with the
`proof` CLI and discloses one entry as the operator would.

## A real run (ministral-3:3b)

```
── opencode + ministral-3:3b (via host Ollama)
   tool calls: 1
   • aleutianchain_commit [completed]
       input : {"chain": "agent-actions", "entries": [
                 {"content": "refunded order 4411 for customer u-81"},
                 {"content": "emailed the refund receipt for order 4411"}]}
       output: {"chain":"agent-actions","committed":2,"entries":[
                 {"commitment":"ee99b606…","entry_id":"mcp-4fe5445357b5fbb3e371de97fb5f69d3",
                  "entry_type":"mcp.salted","global_seq":"0","nonce_stored":true, …
   model said: Entry IDs: `mcp-4fe5445357b5fbb3e371de97fb5f69d3`,
               `mcp-21657de127c06afebebdfe165fe293a8`
── checking with the proof CLI (no model, no MCP)
INTACT — 2 entries verified
── the operator proves the agent's first entry (proof disclose)
{
  "chain": "agent-actions",
  "entry_id": "mcp-4fe5445357b5fbb3e371de97fb5f69d3",
  "entry_type": "mcp.salted",
  "global_seq": 0,
  "timestamp": "2026-09-28T01:11:39.501258Z",
  "commitment": "ee99b606e59cafb2515e4500c2d32fcb8a2f7de49478934f03e0dc9aaa3e9e924d537eeb0bd4df005ab4b673b02dad2d368b8013d29f9a460f96c96f8adfc4a7",
  "nonce": "727d8d7b6040839c16290407242991297bcd0c0645d41f2b22bc2ca50729236c"
}
```

A 3-billion-parameter model found the tool, called it once with valid arguments,
and reported the right entry ids — in three runs out of three. On some runs it
added its own labels (`"label": "refund"`), which the server validated and turned
into `mcp.salted.refund`.

## What each part proves

| Step | Who | Proves |
|---|---|---|
| `commit` | the agent, over MCP | these entries were recorded, in this order, and cannot change afterwards |
| `proof verify` | anyone, no secrets | nothing in the chain was edited |
| `proof disclose` | the operator | this exact content is what that entry committed to |

What it does **not** prove: that the agent's claims are true. The chain records
*"the agent said it refunded order 4411"*, permanently. Add a signed checkpoint
with `proof anchor` to also prove that nothing was removed from the front.

## Worth knowing

- **The content passes through the model.** The agent sends it as a tool
  argument, so the model provider — here, your own Ollama — sees it. The nonce
  never enters the conversation: it is kept in `evidence.db.nonces`.
- **Only the chain you allow.** `--chains agent-actions` in `opencode.json` is the
  only chain this agent can write. An agent told to write elsewhere is refused.
- **Container → host.** `host.containers.internal:11434` reaches Ollama on the
  host's loopback through podman's network, so Ollama needs no extra listen address.
- **Why the build uses the workspace.** `proof-mcp` depends on library packages
  not yet in a published release, so `run.sh` builds it through the repo's
  `go.work`. That goes away once `proof v0.3.0` is tagged.
