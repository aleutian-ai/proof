# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
"""The cover-up: change the extracted income in a bundle's disclosed record.

    python3 edit_bundle.py IN OUT

Writes OUT with annual_income_usd set to 4250, the record otherwise as it was.
A verifier must refuse OUT.
"""

import base64
import json
import sys

bundle = json.load(open(sys.argv[1]))
d = bundle["chains"][0]["entries"][0]["disclosed"]
record = json.loads(base64.b64decode(d["content"]))
before = record["extracted"]["annual_income_usd"]
record["extracted"]["annual_income_usd"] = 4250
d["content"] = base64.b64encode(json.dumps(record, sort_keys=True).encode()).decode()
json.dump(bundle, open(sys.argv[2], "w"))
print(f"   annual_income_usd  {before} → 4250")
