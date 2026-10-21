# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
"""Show the disclosed record in a bundle, and check its document hash.

    python3 show_record.py BUNDLE PDF

PDF is the copy of the application the reader holds. Exits non-zero when its
SHA-512 is not the one the record names. Run it after the bundle verifies:
this script checks nothing else. The record is the parser's JSON line, or the
body of the OpenTelemetry log record it emitted (OTLP JSON, as otel-sink
commits it).
"""

import base64
import hashlib
import json
import sys


def any_value(v: dict):
    """An OTLP JSON AnyValue as a Python value."""
    if "kvlistValue" in v:
        return {kv["key"]: any_value(kv["value"]) for kv in v["kvlistValue"].get("values", [])}
    if "arrayValue" in v:
        return [any_value(x) for x in v["arrayValue"].get("values", [])]
    if "intValue" in v:
        return int(v["intValue"])
    for k in ("stringValue", "doubleValue", "boolValue"):
        if k in v:
            return v[k]
    return None


bundle = json.load(open(sys.argv[1]))
record = json.loads(base64.b64decode(bundle["chains"][0]["entries"][0]["disclosed"]["content"]))
if "resourceLogs" in record:
    rl = record["resourceLogs"][0]
    log = rl["scopeLogs"][0]["logRecords"][0]
    attrs = {kv["key"]: any_value(kv["value"]) for kv in rl["resource"].get("attributes", []) + log.get("attributes", [])}
    print(f"   OTel log  {log.get('eventName', '')} · service {attrs.get('service.name')}")
    print(f"             enduser.pseudo.id {attrs.get('enduser.pseudo.id')}")
    record = any_value(log["body"])
held = hashlib.sha512(open(sys.argv[2], "rb").read()).hexdigest()
print(f"   model     {record['model']} ({record['model_digest'][:12]}…), parser {record['parser']}")
print("   extracted")
for k, v in record["extracted"].items():
    print(f"     {k:<18} {v}")
print(f"   document  {record['document_sha512'][:32]}… in the record")
print(f"             {held[:32]}… the PDF the applicant holds")
if held != record["document_sha512"]:
    sys.exit("THE DOCUMENT HASH DOES NOT MATCH")
print("   same document")
