# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
"""Show the disclosed record in a bundle, and check its document hash.

    python3 show_record.py BUNDLE PDF

PDF is the copy of the application the reader holds. Exits non-zero when its
SHA-512 is not the one the record names. Run it after the bundle verifies:
this script checks nothing else.
"""

import base64
import hashlib
import json
import sys

bundle = json.load(open(sys.argv[1]))
record = json.loads(base64.b64decode(bundle["chains"][0]["entries"][0]["disclosed"]["content"]))
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
