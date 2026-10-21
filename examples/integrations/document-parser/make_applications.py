# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
"""Write three sample loan applications as PDFs, and the intake list for them.

    python3 make_applications.py OUT_DIR

The people, the lender and the numbers are made up. The PDFs are written by
hand (one page, Helvetica, text only) so the example needs no PDF library to
make them; parse.py reads them with a real one.

intake.jsonl is what a lender's intake system would hold before any AI sees
the document: the document's id and the applicant's pseudonym. The pseudonym,
not the name, is what proof's sink files each record under.
"""

import json
import sys
from pathlib import Path

LENDER = "Harbor Street Credit Union (fictional)"

APPLICATIONS = [
    {
        "doc_id": "LA-2026-0141",
        "applicant": "app-7f3a",
        "lines": [
            "Applicant: Dana Okafor",
            "Employer: Northwind Logistics",
            "Years with employer: 6",
            "Annual income: $88,500",
            "Loan amount requested: $24,000",
            "Purpose: vehicle purchase",
        ],
    },
    {
        # Income given per month: the model is asked for an annual figure.
        "doc_id": "LA-2026-0142",
        "applicant": "app-2c91",
        "lines": [
            "Applicant: Luis Ferreira",
            "Employer: Bayside Dental Group",
            "Years with employer: 2",
            "Monthly income: $4,250",
            "Loan amount requested: $15,000",
            "Purpose: debt consolidation",
        ],
    },
    {
        "doc_id": "LA-2026-0143",
        "applicant": "app-e04d",
        "lines": [
            "Applicant: Mei Tanaka",
            "Employer: self-employed (graphic design)",
            "Years with employer: 9",
            "Annual income: $61,200",
            "Loan amount requested: $40,000",
            "Purpose: home renovation",
        ],
    },
]


def pdf(lines: list[str]) -> bytes:
    """A one-page PDF holding lines of text."""

    def esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    text = ["BT", "/F1 11 Tf", "72 720 Td", "16 TL"]
    for line in lines:
        text.append(f"({esc(line)}) Tj T*")
    text.append("ET")
    stream = "\n".join(text).encode("latin-1")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        xref,
    )
    return bytes(out)


def main() -> None:
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "intake.jsonl", "w") as intake:
        for app in APPLICATIONS:
            name = f"{app['doc_id']}.pdf"
            header = [LENDER, "Personal loan application", f"Application no. {app['doc_id']}", ""]
            (out / name).write_bytes(pdf(header + app["lines"]))
            intake.write(json.dumps({"doc_id": app["doc_id"], "applicant": app["applicant"], "file": name}) + "\n")


if __name__ == "__main__":
    main()
