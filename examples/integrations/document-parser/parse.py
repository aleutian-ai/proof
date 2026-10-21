# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
"""Extract fields from loan applications with a local model, one record each.

    python3 parse.py DOC_DIR > records.jsonl

For every document in DOC_DIR/intake.jsonl it reads the PDF's text with pypdf,
asks the model served by Ollama for the fields as JSON (held to a schema), and
prints one JSON line: what went in, what read it, and what came out. Those
lines are what `proof sink commit` records. This script knows nothing about
proof; it writes the record the way it would write a log line.

The record identifies the document by its SHA-512, so whoever holds the PDF can
check that this is the document the model read. It names the model by its
Ollama digest as well as its tag, because a tag can later point at different
weights, and the prompt by its SHA-512, because a changed prompt is a changed
extractor.

Environment: MODEL (default ministral-3:3b), OLLAMA_URL (default
http://127.0.0.1:11434).
"""

import hashlib
import json
import os
import sys
import urllib.request
from pathlib import Path

import pypdf

MODEL = os.environ.get("MODEL", "ministral-3:3b")
OLLAMA = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")

PROMPT = """You extract fields from a loan application for underwriting.
Use only what the document says. If the document gives income per month,
annual_income_usd is twelve times it. Give amounts as plain numbers.

The document:
"""

SCHEMA = {
    "type": "object",
    "properties": {
        "applicant_name": {"type": "string"},
        "employer": {"type": "string"},
        "years_employed": {"type": "number"},
        "annual_income_usd": {"type": "number"},
        "loan_amount_usd": {"type": "number"},
        "loan_purpose": {"type": "string"},
    },
    "required": [
        "applicant_name",
        "employer",
        "years_employed",
        "annual_income_usd",
        "loan_amount_usd",
        "loan_purpose",
    ],
}


def ollama(path: str, body: dict | None = None) -> dict:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(OLLAMA + path, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return json.load(r)


def model_digest() -> str:
    for m in ollama("/api/tags")["models"]:
        if m["name"] == MODEL or m["model"] == MODEL:
            return m["digest"]
    sys.exit(f"{MODEL} is not pulled in Ollama")


def extract(text: str) -> dict:
    reply = ollama(
        "/api/chat",
        {
            "model": MODEL,
            "messages": [{"role": "user", "content": PROMPT + text}],
            "format": SCHEMA,
            "stream": False,
            "options": {"temperature": 0, "seed": 1},
        },
    )
    return json.loads(reply["message"]["content"])


def main() -> None:
    docs = Path(sys.argv[1])
    digest = model_digest()
    prompt_sha512 = hashlib.sha512((PROMPT + json.dumps(SCHEMA, sort_keys=True)).encode()).hexdigest()
    for line in open(docs / "intake.jsonl"):
        intake = json.loads(line)
        raw = (docs / intake["file"]).read_bytes()
        text = "\n".join(page.extract_text() for page in pypdf.PdfReader(docs / intake["file"]).pages)
        record = {
            "doc_id": intake["doc_id"],
            "applicant": intake["applicant"],
            "document_sha512": hashlib.sha512(raw).hexdigest(),
            "parser": f"pypdf {pypdf.__version__}",
            "model": MODEL,
            "model_digest": digest,
            "prompt_sha512": prompt_sha512,
            "extracted": extract(text),
        }
        print(json.dumps(record, sort_keys=True), flush=True)
        print(f"   {intake['doc_id']}: {json.dumps(record['extracted'])}", file=sys.stderr)


if __name__ == "__main__":
    main()
