# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
"""Extract fields from loan applications with a local model, one record each.

    python3 parse.py DOC_DIR > records.jsonl
    python3 parse.py --otlp http://127.0.0.1:4320/v1/logs DOC_DIR

For every document in DOC_DIR/intake.jsonl it reads the PDF's text with pypdf,
asks the model served by Ollama for the fields as JSON (held to a schema), and
prints one JSON line: what went in, what read it, and what came out. Those
lines are what `proof sink commit` records. This script knows nothing about
proof; it writes the record the way it would write a log line.

With --otlp URL it prints nothing: it emits each record as an OpenTelemetry
log record instead, with the OpenTelemetry SDK's own OTLP/HTTP exporter, to a
collector or straight to otel-sink. The record is the body; the applicant's
pseudonym is enduser.pseudo.id; the delivery id, log.record.uid, is set here,
by the app, so a retried export is recognised and a re-run is not recorded
twice (see ../otel).

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
import uuid
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


# The namespace of log.record.uid. The uid is a document read by one model with
# one prompt: the same on a re-run, so a re-run is not recorded twice, and new
# when the model or the prompt changes, so a re-extraction is a new event. It
# holds none of the record's fields (../otel: it must be opaque), though whoever
# knows the document id, the digests and this namespace can compute it.
UID_NAMESPACE = uuid.UUID("6f0f3c1e-8b0a-4a4e-9a51-2d2f1c7b9e10")


def otel_logger(endpoint: str):
    """An OpenTelemetry logger exporting OTLP/HTTP to endpoint, and its provider."""
    from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
    from opentelemetry.sdk._logs import LoggerProvider
    from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
    from opentelemetry.sdk.resources import Resource

    provider = LoggerProvider(resource=Resource.create({"service.name": "loan-intake-parser"}))
    provider.add_log_record_processor(BatchLogRecordProcessor(OTLPLogExporter(endpoint=endpoint)))
    return provider.get_logger("loan-intake-parser"), provider


def main() -> None:
    args = sys.argv[1:]
    logger = provider = None
    if args[:1] == ["--otlp"]:
        logger, provider = otel_logger(args[1])
        args = args[2:]
    docs = Path(args[0])
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
        if logger is None:
            print(json.dumps(record, sort_keys=True), flush=True)
        else:
            logger.emit(
                event_name="loan.application.extracted",
                body=record,
                attributes={
                    "enduser.pseudo.id": intake["applicant"],
                    "log.record.uid": str(uuid.uuid5(UID_NAMESPACE, f"{intake['doc_id']} {digest} {prompt_sha512}")),
                    "gen_ai.provider.name": "ollama",
                    "gen_ai.request.model": MODEL,
                },
            )
        print(f"   {intake['doc_id']}: {json.dumps(record['extracted'])}", file=sys.stderr)
    if provider is not None:
        provider.shutdown()  # flushes: every record is exported, or the exporter has given up


if __name__ == "__main__":
    main()
