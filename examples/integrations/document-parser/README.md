# An AI document parser → proof: every extraction on the record

A lender runs loan applications through a model that pulls out the fields
underwriting needs: income, employer, the amount asked for. Months later an
applicant disputes a decision: *what did your AI read from my application?*
The lender's database can say anything; it can be edited. This example makes
the answer something the applicant, or an auditor, can check without trusting
the lender.

```
  intake ─► parse.py ──────────────────────────► proof sink commit ─► sink-data/
            pypdf: the PDF's text                 --class loan-extractions
            Ollama (local): fields as JSON,       --subject-field applicant
              held to a schema                    --source-field doc_id
            one record per document:              --record-key …  (every record signed)
              document SHA-512, model + digest,
              prompt SHA-512, what it extracted
```

`parse.py` knows nothing about proof. It prints one JSON line per document, the
way it would write a log line, and `proof sink commit` reads them. Each
applicant's records go on their own opaque chain; only the sink's secret index
links a pseudonym (`app-2c91`) to its chain. The name in the application is in
the record's content, which the sink can erase.

## Run it

Needs Go, Python 3.10+, network access to PyPI, and Ollama with a model pulled.

```sh
./run.sh                          # ministral-3:3b (3 GB)
MODEL=ornith-1.5:9b ./run.sh     # any Ollama model
```

It builds `proof` from this tree, makes three sample applications (the people,
the lender and the numbers are made up), and then:

1. **Parses** them: pypdf, then the model, one record each.
2. **Commits** the records, and commits them again: the second run records
   nothing (`--source-field doc_id`), so a retried batch or a re-run pipeline
   never records a document twice. The first extraction stands.
3. **Checkpoints and verifies.** The checkpoint is signed with ML-DSA-65.
4. **The dispute.** The lender exports applicant `app-2c91`'s records with the
   content disclosed. The auditor checks the bundle with the published Python
   verifier (`pip install aleutian-verification`), which shares no code with
   the Go writer, and compares the record's document hash with the PDF the
   applicant holds. They match: this is what the model read from that
   document.
5. **The cover-up.** Someone changes the extracted income in the bundle before
   handing it over. The auditor's verifier refuses it: `problem: modified`.
6. **Erasure.** The applicant asks to be forgotten. `proof sink erase` deletes
   the content and the link from pseudonym to chain, signs the erasure, and
   every chain still verifies.

## A real run (ministral-3:3b)

```
── the dispute: applicant app-2c91 asks what the AI read from their application
$ aleutian-verify verify-proof-bundle --checkpoint-key …checkpoint-public.pem --record-key …record-public.pem bundle.json
Verdict: OK
Checkpoint trust: checked
Record trust: checked
Chain loan-extractions.d207ed8b…: OK, erasure none; 1 entries, 1 authenticated, 1 checkpoints, 0 unanchored; events: 1 opened, 0 committed, 0 erased

what the record says, and the applicant's own copy of the PDF:
   model     ministral-3:3b (316262d960e2…), parser pypdf 6.15.0
   extracted
     applicant_name     Luis Ferreira
     employer           Bayside Dental Group
     years_employed     2
     annual_income_usd  51000
     loan_amount_usd    15000
     loan_purpose       debt consolidation
   document  144028f4a3f3aa12357a82fb342a373b… in the record
             144028f4a3f3aa12357a82fb342a373b… the PDF the applicant holds
   same document

── the cover-up: someone 'corrects' the extracted income before handing the bundle over
   annual_income_usd  51000 → 4250
Verdict: FAILED
  problem: modified (count 1, first at index 0)
```

That application gives income per month ($4,250); the prompt asks for an annual
figure. This model got it right. A smaller or different one may not, and that
is the point: whatever it said is on the record, with the document, the model's
digest and the prompt's hash beside it.

## The same pipeline through OpenTelemetry and MCP

Most AI stacks already emit OpenTelemetry, and an auditor may well work through
an agent. [`run-otel-mcp.sh`](run-otel-mcp.sh) runs the same three
applications that way. No containers; it needs what `run.sh` needs.

```
  parse.py --otlp ─OTLP/HTTP─► otel-sink ─► proof/sink ─► proof sink export ─► bundle.json
  OpenTelemetry SDK            (../otel)                                           │
  body: the record                                     auditor's agent ─MCP─► proof-mcp
  enduser.pseudo.id: app-2c91                                         verify_export_bundle
  log.record.uid: set by the app                          keys bound at launch, never in a call
```

- **The parser only logs.** With `--otlp`, `parse.py` emits each record as an
  OpenTelemetry log record with the SDK's own OTLP/HTTP exporter
  (`opentelemetry-sdk` 1.45.1), as it would to any backend. The record is the
  body; `gen_ai.provider.name` and `gen_ai.request.model` are attributes.
  [`otel-sink`](../otel) commits it, signed, to the applicant's chain. It could
  as well sit behind a collector, as in that example.
- **The app sets `log.record.uid`:** a UUID derived from the document id, the
  model's digest and the prompt's hash. A re-run of the same pipeline sends
  the same uid with other content (new timestamps), and `otel-sink` refuses
  it: the first extraction stands, as with `--source-field doc_id` above. A new
  model or prompt is a new uid, and so a new event on the applicant's chain.
- **The auditor's agent verifies over MCP.** `proof-mcp` has a
  `verify_export_bundle` tool. The keys it trusts are the ones the auditor
  binds when starting the server; a tool call names only the file, so a
  prompt-injected bundle cannot bring its own key. The result names no chain
  id, and states what is not proven on every call.

```
── the parser: pypdf and ministral-3:3b read each PDF; the OpenTelemetry SDK exports each extraction
otel-sink: committed 3 · already committed 0 · refused 0
the pipeline runs again over the same documents (same log.record.uid, new timestamps):
request 4: refused: log.record.uid is already committed with other content
otel-sink: committed 0 · already committed 0 · refused 3

── the dispute: applicant app-2c91 asks what the AI read from their application
   claude mcp add proof-audit -- proof-mcp --root dispute --bundle-checkpoint-key dispute/checkpoint.pub --bundle-record-trust dispute/record.pub
$ python3 -I mcp_verify.py bundle.json -- proof-mcp --root dispute …
   MCP aleutianchain … · verify_export_bundle · bundle.json
   verdict: OK   (checkpoint trust checked, record trust checked)
   chain 0: ok, 1 entries, 1 opened, 1 authenticated
   …
── the cover-up: someone 'corrects' the extracted income before handing the bundle over
   annual_income_usd  51000 → 4250
   verdict: FAILED   (checkpoint trust checked, record trust checked)
   chain 0: failed, 1 entries, 0 opened, 1 authenticated
     problem: modified (count 1, first at index 0)
```

`mcp_verify.py` makes the MCP call an agent would (initialize, then
`tools/call`), without a model, so the run is the same every time. To ask an
agent instead, register the server with the `claude mcp add` line above, run
from the folder holding `dispute/`, and ask it whether `bundle.json` verifies.
[`demo-otel-mcp.tape`](demo-otel-mcp.tape) renders this run as a GIF and MP4
(`vhs examples/integrations/document-parser/demo-otel-mcp.tape`, from the
repository root).

What differs from `run.sh`:

- **`proof-mcp` is the bundle writer's own implementation,** like `proof sink
  verify-bundle`. The independent check is still the Python verifier.
- **`otel-sink` takes OTLP without TLS or authentication** on localhost (see
  [its README](../otel)). Anyone who can reach the port can put records on a
  chain.
- **A refused re-run is answered in OTLP's `partial_success`,** which the
  Python exporter does not retry; nothing tells the pipeline beyond that.

## What this proves, and what it does not

**Proven,** to anyone holding the lender's two public keys:

- this record has not changed since the lender's sink signed it;
- the document it names by SHA-512 is the one the applicant holds, if the
  hashes match;
- the model, digest and prompt hash in it are what the pipeline recorded when
  it ran;
- an erasure happened, and was signed.

**Not proven:**

- **that the model was right.** proof records what it said. The record is
  what makes checking it possible.
- **that every document was recorded.** A lender that skips the sink for one
  application leaves no trace. A bundle shows what it holds, not that nothing
  was left out (bundle-format.md §1).
- **that the record names the model that really ran.** `parse.py` writes the
  model's tag and digest; a dishonest pipeline could write another. The record
  shows what the lender's pipeline claimed, signed, at the time.
- **that erasure reached every copy.** The auditor's bundle was disclosed
  before the erasure and keeps the content; so do backups of `sink-data/`.
- **anything against a lender who controls the sink and every key you trust.**
  Signed checkpoints sent somewhere the lender cannot rewrite them (a regulator,
  a timestamping service) are what close that.

Credit scoring is listed as high-risk in the EU AI Act, which requires such
systems to keep logs automatically (Article 12). This is the kind of record that
asks for. proof does not make a system compliant.

## The demo is not a deployment recipe

- The model runs over Ollama's plain HTTP on localhost, with no TLS and no
  authentication, which is how Ollama listens by default.
- The sink's private keys sit beside the sink folder, as `proof sink init`
  writes them. Keep them elsewhere in production (the main README, "Keeping keys
  in 1Password").
- The checkpoint heads file is in the same temporary folder. In production it
  goes on storage the sink's writer cannot rewrite (docs/runbook.md, "Where to
  keep checkpoint heads").
- `pypdf` and `aleutian-verification` are pinned by version, not by hash.
