#!/usr/bin/env python3
# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
"""Independent reference computation for three conformance vector files.

WHY THIS EXISTS
    A vector's expected output must not come from the implementation it tests —
    that only proves the code agrees with itself. These values are computed here,
    in Python, from docs/format-spec.md alone, using nothing but hashlib and
    hand-written encoders. Go, Python-SDK and JS-SDK implementations are then
    held to them.

WHEN TO RUN
    Only to ADD a vector deliberately. Never to make a failing implementation
    pass: if an implementation disagrees with a vector, the implementation is
    wrong until the spec says otherwise. Running this rewrites the three files
    below and their entries in fixtures/MANIFEST.json.

    python3 scripts/independent-vectors.py

WRITES
    fixtures/testdata/chain_v3_vectors.json          chain hash v3 (spec §2)
    fixtures/testdata/anchor_v6_canonical_vectors.json  anchor v6 canonical form (§ Anchors)
    fixtures/testdata/keyid_vectors.json             key ids (§ Anchors)
"""
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTDATA = os.path.join(ROOT, "fixtures", "testdata")


def sha512_hex(b: bytes) -> str:
    return hashlib.sha512(b).hexdigest()


# ---------------------------------------------------------------------------
# Chain hash v3:  SHA-512("aleutian.chain.v3:" ‖ prev ‖ "|" ‖ global_seq ‖ "|" ‖ ts ‖ "|" ‖ content)
# ---------------------------------------------------------------------------

def chain_v3(prev: str, seq: int, ts: str, content: str) -> str:
    return sha512_hex(f"aleutian.chain.v3:{prev}|{seq}|{ts}|{content}".encode())


def chain_v3_file() -> dict:
    c0 = sha512_hex(b"evidence 0")
    c1 = sha512_hex(b"evidence 1")
    first = chain_v3("", 0, "2026-09-28T12:00:00.000000Z", c0)
    vectors = [
        {"name": "first_entry", "previous_hash": "", "global_seq": "0",
         "timestamp": "2026-09-28T12:00:00.000000Z", "content_hash": c0,
         "expected_hash": first},
        {"name": "linked_entry", "previous_hash": first, "global_seq": "1",
         "timestamp": "2026-09-28T12:00:01.000000Z", "content_hash": c1,
         "expected_hash": chain_v3(first, 1, "2026-09-28T12:00:01.000000Z", c1)},
        {"name": "global_seq_above_2_pow_53", "previous_hash": first,
         "global_seq": "9007199254740993", "timestamp": "2026-09-28T12:00:02.000000Z",
         "content_hash": c1,
         "expected_hash": chain_v3(first, 9007199254740993, "2026-09-28T12:00:02.000000Z", c1)},
        {"name": "global_seq_max_int64", "previous_hash": first,
         "global_seq": "9223372036854775807", "timestamp": "2026-09-28T12:00:03.000000Z",
         "content_hash": c1,
         "expected_hash": chain_v3(first, 9223372036854775807, "2026-09-28T12:00:03.000000Z", c1)},
        {"name": "tombstone_content_hash", "previous_hash": first, "global_seq": "2",
         "timestamp": "2026-09-28T12:00:04.000000Z",
         "content_hash": "TOMBSTONE:" + "c3d4e5f6a1b2" * 5 + "c3d4",
         "expected_hash": chain_v3(first, 2, "2026-09-28T12:00:04.000000Z",
                                   "TOMBSTONE:" + "c3d4e5f6a1b2" * 5 + "c3d4")},
        # A timestamp with nanoseconds is TRUNCATED to microseconds before hashing.
        {"name": "sub_microsecond_input_is_truncated", "previous_hash": first,
         "global_seq": "3", "timestamp_input": "2026-09-28T12:00:05.123456789Z",
         "timestamp": "2026-09-28T12:00:05.123456Z", "content_hash": c1,
         "expected_hash": chain_v3(first, 3, "2026-09-28T12:00:05.123456Z", c1)},
    ]
    reject = [
        {"name": "negative_global_seq", "previous_hash": first, "global_seq": "-1",
         "timestamp": "2026-09-28T12:00:00.000000Z", "content_hash": c0},
        {"name": "uppercase_previous_hash", "previous_hash": first.upper(), "global_seq": "1",
         "timestamp": "2026-09-28T12:00:00.000000Z", "content_hash": c0},
        {"name": "delimiter_in_previous_hash", "previous_hash": first[:127] + "|",
         "global_seq": "1", "timestamp": "2026-09-28T12:00:00.000000Z", "content_hash": c0},
        {"name": "short_content_hash", "previous_hash": first, "global_seq": "1",
         "timestamp": "2026-09-28T12:00:00.000000Z", "content_hash": c0[:127]},
    ]
    return {
        "_comment": "Chain hash v3: SHA-512(\"aleutian.chain.v3:\" || previous_hash || \"|\" || "
                    "global_seq || \"|\" || timestamp || \"|\" || content_hash). global_seq is "
                    "decimal ASCII, carried here as a STRING because JSON numbers lose precision "
                    "above 2^53. Expected values computed in Python "
                    "(scripts/independent-vectors.py), independently of any implementation under "
                    "test. 'vectors' MUST reproduce; every 'reject' case MUST be refused. See "
                    "docs/format-spec.md section 2.",
        "domain": "aleutian.chain.v3:",
        "vectors": vectors,
        "reject": reject,
    }


# ---------------------------------------------------------------------------
# Anchor v6 canonical form: compact JSON, keys sorted, signature excluded,
# encoded exactly as Go's encoding/json does — including HTML escaping.
# ---------------------------------------------------------------------------

def go_json_string(s: str) -> str:
    """A JSON string literal byte-identical to Go's encoding/json (HTML escaping on)."""
    for ch in s:
        if ord(ch) < 0x20:
            raise ValueError("control characters are deliberately not used in these vectors")
    out = json.dumps(s, ensure_ascii=False)  # escapes only " and \ here
    return (out.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
               .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def canonical_v6(a: dict) -> str:
    r = a["range"]
    return ("{"
            f'"anchor_id":{go_json_string(a["anchor_id"])},'
            f'"chain_hash":{go_json_string(a["chain_hash"])},'
            f'"created_at_ms":{int(a["created_at_ms"])},'
            f'"entry_count":{int(a["entry_count"])},'
            f'"previous_anchor_id":{go_json_string(a["previous_anchor_id"])},'
            f'"range":{{"end_entry_id":{go_json_string(r["end_entry_id"])},'
            f'"start_entry_id":{go_json_string(r["start_entry_id"])}}},'
            f'"signing_key_id":{go_json_string(a["signing_key_id"])},'
            f'"subject":{go_json_string(a["subject"])},'
            f'"verified_through":{int(a["verified_through"])},'
            f'"version":{int(a["version"])}'
            "}")


def anchor_v6_file() -> dict:
    base = {
        "version": 6,
        "anchor_id": "anchor_0192f3a1-0000-7000-8000-000000000001",
        "chain_hash": sha512_hex(b"anchor chain hash"),
        "created_at_ms": 1790000000000,
        "entry_count": 42,
        "previous_anchor_id": "anchor_00000000-0000-0000-0000-000000000000",
        "range": {"start_entry_id": "e-0000", "end_entry_id": "e-0041"},
        "signing_key_id": "3fb85abc3e8bae42952ee9194ae1f615",
        "subject": "agent-actions",
        "verified_through": 42,
        # Present to show it is EXCLUDED from the canonical bytes.
        "signature": "SIGNATURE_MUST_NOT_APPEAR_IN_CANONICAL_BYTES",
    }
    cases = [
        ("plain", {}),
        ("html_escaping_in_subject", {"subject": "a<b>&c"}),
        ("non_ascii_subject", {"subject": "sübjeçt-ü-€"}),
        ("line_separator_in_subject", {"subject": "x\u2028y\u2029z"}),
        ("quote_and_backslash_in_subject", {"subject": 'say "hi" \\ bye'}),
    ]
    vectors = []
    for name, override in cases:
        a = dict(base, **override)
        canon = canonical_v6(a)
        vectors.append({"name": name, "anchor": a, "canonical_bytes": canon,
                        "canonical_sha512": sha512_hex(canon.encode())})
    return {
        "_comment": "Anchor v6 canonical form: compact JSON, keys in alphabetical order, "
                    "signature excluded, strings escaped exactly as Go's encoding/json with "
                    "HTML escaping ON (< > & as \\u003c \\u003e \\u0026; U+2028/U+2029 escaped; "
                    "other non-ASCII as UTF-8). canonical_sha512 lets an implementation check "
                    "bytes without trusting its JSON parser. Computed in Python "
                    "(scripts/independent-vectors.py). See docs/format-spec.md, Anchors.",
        "version": 1,
        "vectors": vectors,
    }


# ---------------------------------------------------------------------------
# Key ids.
#   ML-DSA / ML-KEM: first 16 bytes of SHA-512("proof.keyid.v1:" ‖ SPKI DER), hex.
#   X-Wing (legacy rule): first 16 bytes of SHA-512(raw public key), hex.
# ---------------------------------------------------------------------------

def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def der(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + der_len(len(body)) + body


def oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(reversed(chunk))
    return der(0x06, body)


def spki(alg_oid: str, pub: bytes) -> bytes:
    # RFC 9881: ML-DSA AlgorithmIdentifier parameters are ABSENT.
    return der(0x30, der(0x30, oid(alg_oid)) + der(0x03, b"\x00" + pub))


def keyid_file(mldsa65_pub: bytes) -> dict:
    d = spki("2.16.840.1.101.3.4.3.18", mldsa65_pub)
    xwing_pub = bytes(i % 256 for i in range(1216))
    return {
        "_comment": "Key ids, 32 lowercase hex. ML-DSA-65: first 16 bytes of "
                    "SHA-512(\"proof.keyid.v1:\" || SubjectPublicKeyInfo DER), with the RFC 9881 "
                    "AlgorithmIdentifier (parameters absent). X-Wing (legacy rule, no domain): "
                    "first 16 bytes of SHA-512(raw public key). The ML-DSA-65 public key was "
                    "derived from seed bytes 00..1f; the X-Wing input is a byte pattern (a key id "
                    "depends only on the encoding, not on key validity). Computed in Python "
                    "(scripts/independent-vectors.py).",
        "vectors": [
            {"name": "mldsa65", "algorithm": "ML-DSA-65",
             "public_key_hex": mldsa65_pub.hex(), "spki_der_hex": d.hex(),
             "key_id": hashlib.sha512(b"proof.keyid.v1:" + d).digest()[:16].hex()},
            {"name": "xwing_legacy_rule", "algorithm": "X-Wing",
             "public_key_hex": xwing_pub.hex(),
             "key_id": hashlib.sha512(xwing_pub).digest()[:16].hex()},
        ],
    }


def mldsa65_input() -> bytes:
    """The ML-DSA-65 public key INPUT: reused from the existing file if present."""
    existing = os.path.join(TESTDATA, "keyid_vectors.json")
    if os.path.exists(existing):
        for v in json.load(open(existing))["vectors"]:
            if v["algorithm"] == "ML-DSA-65":
                return bytes.fromhex(v["public_key_hex"])
    if len(sys.argv) != 2:
        sys.exit("first run: pass a file holding the ML-DSA-65 public key as hex")
    return bytes.fromhex(open(sys.argv[1]).read().strip())


def write(name: str, obj: dict, manifest: dict) -> None:
    raw = (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode()
    with open(os.path.join(TESTDATA, name), "wb") as f:
        f.write(raw)
    manifest["vectors"][name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    print(f"wrote {name} ({len(raw)} bytes)")


def main() -> None:
    mpath = os.path.join(ROOT, "fixtures", "MANIFEST.json")
    manifest = json.load(open(mpath))
    write("chain_v3_vectors.json", chain_v3_file(), manifest)
    write("anchor_v6_canonical_vectors.json", anchor_v6_file(), manifest)
    write("keyid_vectors.json", keyid_file(mldsa65_input()), manifest)
    manifest["vectors"] = dict(sorted(manifest["vectors"].items()))
    with open(mpath, "w") as f:
        f.write(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
