# Integrating proof

How to put a system's records on proof, where everything proof writes ends up,
and how each party points a verifier at it. This guide covers the **sink**, the
shape almost every integration wants: one opaque chain per (class, subject),
erasable per subject. The formats are in [sink-format.md](sink-format.md) and
[bundle-format.md](bundle-format.md); this is the map.

```
  your system ──records──► sink folder ──checkpoint──► signed checkpoints
  (CLI, Go, OTel,          sink-data/       (on a schedule)   sink-data/anchors/
   a queue, a shipper)         │                               + heads file, kept elsewhere
                               │
            operator ◄─────────┤  proof sink verify     (the folder + public keys)
                               │
                               └──export──► bundle.json ──► recipient
                                                           proof sink verify-bundle
                                                           aleutian-verify (Python, JS)
                                                           proof-mcp (an agent)
```

## 1. What you send: a record

Every way in takes the same four things ([sink.Record](../sink)):

| Field | What it is | Rule |
|---|---|---|
| **class** | the kind of evidence: `loan-extractions`, `agent-actions` | `[a-z0-9][a-z0-9_-]{0,30}`; fixed by the operator, never read from untrusted data |
| **subject** | whose evidence it is | a **pseudonym** (`app-2c91`, `u-81`), never an email or a name. The sink allows only `[a-z0-9][a-z0-9._-]{0,127}`, which refuses an email but cannot tell a lower-case name from a pseudonym. Kept only in the sink's secret index |
| **content** | the bytes to keep: any format, JSON is usual | up to 64 KiB. Personal data in it can be erased |
| **source** | a stable delivery id: a document id, a message position, a `log.record.uid` | the same source with the same content is recognised and not committed twice; with **other** content it is refused. Opaque: never content, never a name |

The source is what makes a retry, a redelivery or a re-run safe. Without one
(`--source-prefix` aside), committing the same input twice records it twice.

## 2. How records get in

Pick the one that matches where the records already are. None needs the
application to know about proof except the first two.

| Your records are… | Use | Status |
|---|---|---|
| lines of JSON your job writes | `proof sink commit` (reads JSONL on stdin) | shipped |
| produced inside a Go service | the `sink` package: `sink.Open`, `(*Sink).Commit` | shipped |
| OpenTelemetry logs | [`otel-sink`](../examples/integrations/otel), behind a collector or the SDK's exporter | example: build it |
| log files | [Fluent Bit](../examples/integrations/fluent-bit) → `otel-sink`, configuration only | example |
| messages on NATS, Redis Streams or Kafka | [nats](../examples/integrations/nats), [redis](../examples/integrations/redis), [kafka](../examples/integrations/kafka) consumers | examples: build them |
| an AI pipeline's outputs | [document-parser](../examples/integrations/document-parser): the CLI, or OpenTelemetry | example |

**From the command line:**

```sh
proof sink init --dir sink-data          # once: the folder, and keys in sink-data.keys/
my-job | proof sink commit --dir sink-data --class loan-extractions \
    --subject-field applicant --source-field doc_id \
    --record-key sink-data.keys/ml-dsa-65-record-private.pem
```

**From Go:**

```go
s, err := sink.Open("sink-data", sink.WithRecordSigner(signer)) // signer: sink.NewMLDSA65RecordSigner(seed)
if err != nil { … }
outcomes, err := s.Commit(ctx, []sink.Record{{
    Class: "loan-extractions", Subject: "app-2c91", Content: body, Source: docID,
}})
// outcomes[i].Committed, or .Duplicate when the source was already committed with this content.
// A *sink.RecordError names the record the sink refused (errors.Is(err, sink.ErrSourceConflict):
// its source is committed with other content). Set it aside and commit the rest; do not retry it.
```

`otel-sink`'s [receive.go](../examples/integrations/otel/receive.go) is a
complete consumer: refusals, retries, the record key read from a file.

**Record signing** is a choice made once: a sink signs every record from its
first commit (`--record-key`), or never. Signing lets a recipient check a
record without trusting your checkpoint schedule. Turn it on.

**One writer at a time.** The folder is locked per operation; a second process
waits, then fails as busy. Run one committer per folder.

## 3. Where the outputs live

After `init`, a commit, a checkpoint and an export, with the default names:

```
sink-data/                           the sink folder: back it up as one unit
├── evidence.db                      the chains: hashes, ids, links. No content
├── evidence.db.secrets              content and nonces (personal data; erasure deletes from here)
├── evidence.db.subjects             the secret index: subject ↔ chain
├── evidence.db.sources              source → entry, for recognising a retry
├── evidence.db.signatures           record signatures
├── evidence.db.lock
└── anchors/<chain id>/0001.json     signed checkpoints, one series per chain

sink-data.keys/                      written by init BESIDE the folder; move it
├── ml-dsa-65-checkpoint-private.pem   signs checkpoints: keep offline, or in 1Password
├── ml-dsa-65-checkpoint-public.pem    give to anyone who verifies
├── ml-dsa-65-record-private.pem       signs records: the committer holds it, as a FILE
└── ml-dsa-65-record-public.pem        give to anyone who verifies

checkpoint-heads.json                each chain's checkpoint count: NOT in the folder (refused)
bundle.json                          an export: what you hand someone outside
```

| Output | Secret? | Who needs it |
|---|---|---|
| `sink-data/` | yes: `.secrets` and `.subjects` hold personal data and the link to it | the committer, and the operator's own verification |
| the two **private** keys | yes | the checkpoint job; the committer. Never the same host as each other if you can help it |
| the two **public** keys | no | every verifier. Sent apart from any bundle: a bundle never carries a key |
| `checkpoint-heads.json` | no, but it must not be rewritable by the sink's operator | ideally a counterparty (the customer, the auditor); see [runbook.md](runbook.md#where-to-keep-checkpoint-heads) |
| `bundle.json` | about one subject, with content disclosed: treat as personal data | the recipient |

The `evidence.db*` files are this implementation's storage, not an interchange
format ([sink-format §8](sink-format.md)): another language verifies a bundle,
never these files.

## 4. The loop

| Step | When | Command |
|---|---|---|
| commit | continuously | as in §2 |
| checkpoint | on a schedule (hourly, daily): entries since the last one are "unanchored" until then | `proof sink checkpoint --dir sink-data --key <checkpoint private.pem> --heads <heads file>` (`--first` once, on the first) |
| verify | after each checkpoint, and in monitoring | §5 |
| export | when someone asks for their evidence, or an auditor does | `proof sink export --dir sink-data --subject app-2c91 --disclose all --out bundle.json` |
| erase | when a subject asks to be forgotten | `proof sink erase --dir sink-data --subject app-2c91 --key <checkpoint private.pem> --heads <heads file> --record-key <record private.pem>` |
| repair | after a committer crashed mid-commit | `proof sink repair --dir sink-data` |

Copy the heads file somewhere you cannot rewrite after each checkpoint: that
copy is what shows a checkpoint series was not deleted and restarted.

## 5. Pointing a verifier at it

Which verifier depends on who is checking and what they hold.

### The operator, with the folder

```sh
proof sink verify --dir sink-data \
    --key sink-data.keys/ml-dsa-65-checkpoint-public.pem \
    --record-trust sink-data.keys/ml-dsa-65-record-public.pem \
    --heads checkpoint-heads.json --require-checkpoint
```

```
chain loan-extractions.2f0efa2c… verifies 1 entry: 1 opened, 0 erased · 1 checkpoint, 0 unanchored · 1 signed
Record signatures: checked against --record-trust
all 3 chains verify
```

- `--key` is the checkpoint **public** key; `--record-trust` the record public
  key (repeat it for rotated keys). Given, every record must be signed.
- `--heads` compares each chain's checkpoints with the heads file, so a
  deleted or restarted series fails. `--require-checkpoint` fails a chain no
  checkpoint covers. **Use both in monitoring:** without them, a folder whose
  `anchors/` was removed still verifies.
- Exit 0 means every chain verifies. 1 means one failed, or was not
  checkpointed when you required it; 3 an error; 4 busy. Alert on anything but 0.
- The output names chain ids, never subjects (`--show-subjects` adds them,
  and makes the output secret).

### A recipient, with a bundle and your public keys

The recipient has no folder: only `bundle.json` and the two public keys you
sent them separately. Three implementations read the same format, and give the
same verdict on the shared conformance vectors:

```sh
proof sink verify-bundle bundle.json --key checkpoint.pub --record-trust record.pub
pip install aleutian-verification && \
  aleutian-verify verify-proof-bundle --checkpoint-key checkpoint.pub --record-key record.pub bundle.json
npx -p @aleutian/verification aleutian-verify verify-proof-bundle \
  --checkpoint-key checkpoint.pub --record-key record.pub bundle.json
```

The Python and JavaScript verifiers were written from the specification without
reading the Go code: they are the independent check. `proof sink
verify-bundle` is the writer's own.

| Exit | Verdict |
|---|---|
| 0 | **OK**: consistent, and every entry authenticated by a key the verifier gave |
| 1 | **FAILED**: a problem code says what, and the first index: `modified`, a broken link, a bad signature |
| 2 | usage, or a key or bundle file that cannot be read |
| 3 | the bundle is unreadable |
| 4 | **UNAUTHENTICATED**: consistent, but not signed by a key the verifier gave. Given no key, every bundle ends here |
| 5 | internal error, never a verdict |

`proof sink export` prints the key ids that signed the bundle, so you know which
public keys to send.

### An agent, over MCP

`proof-mcp`'s `verify_export_bundle` does the same check for an agent. The
person who starts the server binds the keys; a tool call names only the file:

```sh
claude mcp add proof-audit -- proof-mcp --root ./dispute \
    --bundle-checkpoint-key ./dispute/checkpoint.pub --bundle-record-trust ./dispute/record.pub
```

Then ask the agent whether `bundle.json` verifies. The result carries the
verdict, the problem codes, and what is and is not proven; it names no chain id.
Without keys bound, nothing is OK. (`proof-mcp` v0.6.0 and later.)

## 6. What a passing verification does not tell you

Every verifier above prints this, and it belongs in whatever you build on it:

- **that every record was sent.** A record your system never committed leaves
  no trace. A bundle shows what it holds, not that nothing was left out.
- **that the content is true.** An extraction committed faithfully can still be
  wrong.
- **anything against someone who holds the folder and every key the verifier
  trusts.** The heads file kept by a counterparty, and checkpoints sent where you
  cannot rewrite them, are what narrow that.
- **that erasure reached copies:** a bundle handed over before an erasure, a
  backup of the folder.

The full list is [bundle-format §1](bundle-format.md) and
[verification-model.md](verification-model.md).

## 7. Not a sink: one chain

`proof init`, `proof commit`, `proof anchor` and `proof verify` keep a single
chain in one database file, exported as `entries.json` and checked against a
signed anchor. That is the [README's quickstart](../README.md#quickstart), and
what `proof-mcp --db` writes when an agent records its own actions. Use it for
one stream with one owner; use a sink when records belong to many subjects who
may each ask for theirs, or to be forgotten.
