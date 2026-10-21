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
   extracted {"annual_income_usd": 51000, "applicant_name": "Luis Ferreira", "employer": "Bayside Dental Group", "loan_amount_usd": 15000, "loan_purpose": "debt consolidation", "years_employed": 2}
   document  144028f4a3f3aa12357a82fb342a373b… in the record
             144028f4a3f3aa12357a82fb342a373b… the PDF the applicant holds

── the cover-up: someone 'corrects' the extracted income before handing the bundle over
   annual_income_usd → 4250
Verdict: FAILED
  problem: modified (count 1, first at index 0)
```

That application gives income per month ($4,250); the prompt asks for an annual
figure. This model got it right. A smaller or different one may not, and that
is the point: whatever it said is on the record, with the document, the model's
digest and the prompt's hash beside it.

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
