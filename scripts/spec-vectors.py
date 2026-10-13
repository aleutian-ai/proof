#!/usr/bin/env python3
# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
"""Reference computation for five conformance vector files, from the spec.

WHY THIS EXISTS
    Four of these files used to be written by the code they test: two by Go
    tests under UPDATE_GOLDEN=1, one "by the producer", and one was attributed
    to a script that never wrote it. A vector written by the implementation it
    checks proves only that the implementation agrees with itself. Every value
    here is computed in Python from docs/format-spec.md, with hashlib,
    unicodedata and hand-written encoders, and nothing from the Go module.

    When this script first ran it reproduced the four existing files byte for
    byte, so the stored values did not change when their writer did.

WHEN TO RUN
    Only to ADD or CHANGE a vector deliberately. Never to make a failing
    implementation pass: if an implementation disagrees with a vector, the
    implementation is wrong until the spec says otherwise. Running this
    rewrites the files below and their entries in fixtures/MANIFEST.json.

    python3 scripts/spec-vectors.py

WRITES
    fixtures/testdata/chain_vectors.json              chain hash v2 (spec §2.3)
    fixtures/testdata/v3_golden_capture_request.json  capture leaf (§6)
    fixtures/testdata/merkle_golden.json              Merkle trees (§7, RFC 9162)
    fixtures/testdata/commitment_vectors.json         salted commitments (§8)
    fixtures/testdata/anchor_chain_hash_vectors.json  anchor chain hash (§9.4)

Standard library only.
"""
import hashlib
import json
import os
import unicodedata

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTDATA = os.path.join(ROOT, "fixtures", "testdata")


def sha512(b: bytes) -> bytes:
    return hashlib.sha512(b).digest()


def sha512_hex(b: bytes) -> str:
    return hashlib.sha512(b).hexdigest()


# ---------------------------------------------------------------------------
# Chain hash v2 (§2.3):
#   SHA-512("aleutian.chain.v2:" ‖ prev ‖ "|" ‖ run_id ‖ "|" ‖ sequence_num
#           ‖ "|" ‖ timestamp ‖ "|" ‖ content_hash)
# global_seq is NOT in the v2 preimage.
# ---------------------------------------------------------------------------

def chain_v2(prev: str, run_id: str, seq: int, ts: str, content: str) -> str:
    return sha512_hex(f"aleutian.chain.v2:{prev}|{run_id}|{seq}|{ts}|{content}".encode())


def chain_v2_file() -> list:
    run = "run_550e8400-e29b-41d4-a716-446655440000"
    # A content hash is SHA-512: 128 lowercase hex (§2.3). The first two cases
    # used 64-hex values until 2026-10, which the format's own rule refuses.
    c0 = sha512_hex(b"chain v2 vector content 0")
    c1 = sha512_hex(b"chain v2 vector content 1")
    tomb = "TOMBSTONE:" + "c3d4e5f6a1b2" * 5 + "c3d4"
    t0, t1, t2 = "2026-01-20T12:00:00.000000Z", "2026-01-20T12:00:01.123456Z", "2026-01-20T12:00:02.000000Z"
    h0 = chain_v2("", run, 0, t0, c0)
    h1 = chain_v2(h0, run, 1, t1, c1)
    h2 = chain_v2(h1, run, 2, t2, tomb)

    def case(name, prev, seq, ts, content, expected):
        return {"name": name, "previous_hash": prev, "run_id": run, "sequence_num": seq,
                "timestamp": ts, "content_hash": content, "expected_hash": expected}

    return [
        case("first_entry_empty_previous", "", 0, t0, c0, h0),
        case("subsequent_entry", h0, 1, t1, c1, h1),
        case("tombstone_content_hash", h1, 2, t2, tomb, h2),
    ]


# ---------------------------------------------------------------------------
# Capture leaf capture.request.v3 (§6):
#   string  NFC-normalise, 4-byte big-endian BYTE length, the UTF-8 bytes
#   u64     8-byte big-endian          bool    as u64 0 or 1
#   19 records: 4 header (subject, entry_type, signing_key_id, timestamp_ms),
#   then 15 body fields in alphabetical order.
#   content_hash = SHA-512("aleutian.chain.entry.v3:" ‖ canonical_bytes)
# ---------------------------------------------------------------------------

CAPTURE_DOMAIN = "aleutian.chain.entry.v3:"
CAPTURE_ENTRY_TYPE = "capture.request.v3"
CAPTURE_BODY = ["capture_method", "content_hash", "dlp", "encryption_mode", "model",
                "pii_action", "pii_categories", "pii_detected", "pii_digest_key_version",
                "processing_mode", "provider", "region", "source_type", "trust_level", "user_id"]


def tlv_str(s: str) -> bytes:
    b = unicodedata.normalize("NFC", s).encode("utf-8")
    return len(b).to_bytes(4, "big") + b


def tlv_u64(n: int) -> bytes:
    return int(n).to_bytes(8, "big")


def capture_canonical(f: dict) -> bytes:
    # The header's first value is the subject. The vector file carries it under
    # its original key, company_id; the position is what is encoded (§6.2).
    out = (tlv_str(f["company_id"]) + tlv_str(CAPTURE_ENTRY_TYPE)
           + tlv_str(f["signing_key_id"]) + tlv_u64(f["timestamp_ms"]))
    for name in CAPTURE_BODY:
        v = f[name]
        out += tlv_u64(1 if v else 0) if isinstance(v, bool) else tlv_str(v)
    return out


def capture_file() -> dict:
    full = {
        "company_id": "comp_01HZX9K2M3N4P5Q6R7S8T9V0WA",
        "signing_key_id": "capture-leaf-signer-2026-v1",
        "timestamp_ms": 1751068800000,
        "capture_method": "fetch_intercept",
        "content_hash": "a" * 128,
        "dlp": "b" * 128,
        "encryption_mode": "aleutian-managed",
        "model": "gpt-4o-2024-08-06",
        "pii_action": "flagged",
        "pii_categories": "c" * 128,
        "pii_detected": True,
        "pii_digest_key_version": "sm:v1",
        "processing_mode": "pii_inspection",
        "provider": "openai",
        "region": "us",
        "source_type": "extension",
        "trust_level": "self-reported",
        "user_id": "d" * 128,
    }
    minimal_zk = dict(full, capture_method="", content_hash="e" * 128, dlp="",
                      encryption_mode="zero-knowledge", model="", pii_action="none",
                      pii_categories="", pii_detected=False, pii_digest_key_version="",
                      processing_mode="zk", provider="", region="", source_type="",
                      trust_level="", user_id="f" * 128)
    clean = dict(full, dlp="", pii_action="none", pii_categories="", pii_detected=False,
                 pii_digest_key_version="")
    cases = [
        ("aleutian-managed custody + pii_inspection + full verdict; every field non-empty "
         "incl hyphenated trust_level.", "full_pii_inspection", full),
        ("zero-knowledge custody + zk processing; compliance surface empty (the enforced zk "
         "invariant) + all optional fields 0-length.", "minimal_zk", minimal_zk),
        ("inspection authorized but scanner found nothing — empty verdict with "
         "processing_mode=pii_inspection (disambiguated from zk by the sealed mode).",
         "inspected_clean", clean),
    ]
    vectors = []
    for comment, name, f in cases:
        canon = capture_canonical(f)
        vectors.append({
            "$comment": comment, "name": name, "input": f,
            "expected_canonical_bytes_hex": canon.hex(),
            "expected_content_hash_sha512_hex": sha512_hex(CAPTURE_DOMAIN.encode() + canon),
        })
    return {
        "$schema_comment": "Cross-language golden vectors for the capture.request.v3 leaf. Each "
                           "vector's input uses language-neutral snake_case field names; "
                           "expected_canonical_bytes_hex is the length-prefixed TLV encoding (a "
                           "4-field header followed by a 15-field alphabetical body) and "
                           "expected_content_hash_sha512_hex is SHA-512 of domain_prefix_v3 || "
                           "canonical_bytes. An implementation in any language should re-encode "
                           "each input and assert byte-for-byte equality with both. NOTE: the "
                           "header's first field is serialized in the position it was defined in, "
                           "under its original name 'company_id'; it is now called 'subject' and "
                           "the ORDER deliberately did not follow the rename, because these are "
                           "positional values and moving one would change every content hash ever "
                           "computed.",
        "domain_prefix_v3": CAPTURE_DOMAIN,
        "entry_type": CAPTURE_ENTRY_TYPE,
        "vectors": vectors,
    }


# ---------------------------------------------------------------------------
# Merkle trees (§7): RFC 9162 §2.1 with SHA-512.
#   MTH({})    = SHA-512()
#   MTH({d})   = SHA-512(0x00 ‖ d)
#   MTH(D[n])  = SHA-512(0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n])),  k the largest
#                power of two smaller than n
# A leaf's data is the RAW BYTES of a content hash, not its hex text.
# ---------------------------------------------------------------------------

def split_point(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def leaf_hash(d: bytes) -> bytes:
    return sha512(b"\x00" + d)


def mth(d: list) -> bytes:
    if len(d) == 0:
        return sha512(b"")
    if len(d) == 1:
        return leaf_hash(d[0])
    k = split_point(len(d))
    return sha512(b"\x01" + mth(d[:k]) + mth(d[k:]))


def inclusion_path(m: int, d: list) -> list:
    """RFC 9162 §2.1.3.1, PATH(m, D[n])."""
    if len(d) == 1:
        return []
    k = split_point(len(d))
    if m < k:
        return inclusion_path(m, d[:k]) + [mth(d[k:])]
    return inclusion_path(m - k, d[k:]) + [mth(d[:k])]


def subproof(m: int, d: list, whole: bool) -> list:
    """RFC 9162 §2.1.4.1, SUBPROOF(m, D[n], b)."""
    if m == len(d):
        return [] if whole else [mth(d)]
    k = split_point(len(d))
    if m <= k:
        return subproof(m, d[:k], whole) + [mth(d[k:])]
    return subproof(m - k, d[k:], False) + [mth(d[:k])]


def consistency_proof(m: int, d: list) -> list:
    # RFC 9162 defines PROOF(m, D[n]) for 0 < m < n. The two edges the file
    # also pins have an empty proof: an empty tree is a prefix of every tree,
    # and a tree is consistent with itself.
    if m == 0 or m == len(d):
        return []
    return subproof(m, d, True)


def merkle_file() -> dict:
    n = 13
    # Leaf i's content hash is SHA-512 of i as 8 big-endian bytes.
    data = [sha512(i.to_bytes(8, "big")) for i in range(n)]
    inclusion = [{"index": i, "tree_size": n, "leaf_hash": leaf_hash(data[i]).hex(),
                  "path": [p.hex() for p in inclusion_path(i, data)]}
                 for i in (0, 1, 4, 7, 12)]
    consistency = [{"m": m, "n": size, "first_root": mth(data[:m]).hex(),
                    "second_root": mth(data[:size]).hex(),
                    "proof": [p.hex() for p in consistency_proof(m, data[:size])]}
                   for m, size in ((0, 13), (1, 13), (5, 13), (8, 13), (4, 8), (13, 13),
                                   (0, 1), (1, 8), (2, 8), (8, 8))]
    return {
        "hash": "SHA-512",
        "note": "RFC 9162 Merkle tree, SHA-512, leaf=0x00, node=0x01; leaves are content_hash hex; ADR 003.",
        "leaves": [d.hex() for d in data],
        "root": mth(data).hex(),
        "inclusion": inclusion,
        "consistency": consistency,
    }


# ---------------------------------------------------------------------------
# Salted commitments (§8):
#   commitment = SHA-512("aleutian.commit.v1:" ‖ nonce ‖ SHA-512(content))
# nonce is exactly 32 bytes; any other length MUST be refused, not hashed.
# ---------------------------------------------------------------------------

COMMIT_DOMAIN = "aleutian.commit.v1:"
NONCE_SIZE = 32


def commitment_unchecked(nonce: bytes, content: bytes) -> str:
    """The formula with NO length check: what an implementation that forgot
    the check computes. Used for the valid vectors (where the length is right)
    and to build the wrong-length reject cases."""
    return sha512_hex(COMMIT_DOMAIN.encode() + nonce + sha512(content))


def commitment_file() -> dict:
    nonce = bytes(range(32))
    yes, no = b"consent: yes", b"consent: no"
    record = b'{"actor":"agent-7","action":"refund","amount_cents":1999}'
    long_record = record[:-1] + b',"note":"' + b"x" * 200 + b'"}'
    cases = [
        ("low-entropy content: the guessing case this construction exists for", nonce, yes),
        ("same nonce, other content: must differ", nonce, no),
        ("same content, other nonce: must differ", b"\xff" * 32, yes),
        ("empty content", nonce, b""),
        ("binary content including NUL and high bytes", nonce, bytes.fromhex("00017f80feff")),
        ("JSON record", nonce, record),
        ("content of 111 bytes: the longest that fits one SHA-512 block", nonce, bytes(range(111))),
        ("content of 112 bytes: the first that needs two SHA-512 blocks", nonce, bytes(range(112))),
        ("content of 128 bytes: exactly one block of data", nonce, bytes(range(128))),
        ("long content spanning several blocks", nonce, long_record),
    ]
    vectors = []
    for description, n, content in cases:
        assert len(n) == NONCE_SIZE
        vectors.append({"description": description, "nonce_hex": n.hex(),
                        "content_hex": content.hex(), "commitment": commitment_unchecked(n, content)})

    good = commitment_unchecked(nonce, yes)

    def rejected(description, n, content, commitment):
        return {"description": description, "nonce_hex": n.hex(),
                "content_hex": content.hex(), "commitment": commitment}

    # Wrong-length nonces. The stored commitment IS the formula applied to that
    # nonce, so an implementation with no length check recomputes it, finds it
    # equal, and accepts. Only a refusal on the nonce's length passes the case.
    # (Until 2026-10 these three stored an unrelated commitment, which a
    # non-checking implementation also failed to match, and so passed.)
    wrong_length = [
        ("nonce of 0 bytes", b"", b"x"),
        ("nonce of 31 bytes", nonce[:31], yes),
        ("nonce of 33 bytes", nonce + b"\x00", yes),
    ]
    reject = [rejected(d, n, c, commitment_unchecked(n, c)) for d, n, c in wrong_length]
    reject += [
        rejected("uppercase commitment: commitments compare exactly", nonce, yes, good.upper()),
        rejected("truncated commitment (127 chars)", nonce, yes, good[:127]),
        rejected("other content under the same commitment", nonce, no, good),
    ]
    return {
        "_comment": "Salted commitments: SHA-512(\"aleutian.commit.v1:\" || nonce || "
                    "SHA-512(content)), nonce exactly 32 bytes. Expected values computed with "
                    "Python hashlib (scripts/spec-vectors.py), independently of any "
                    "implementation under test. 'vectors' MUST reproduce exactly; every 'reject' "
                    "case MUST fail verification. In the three wrong-length-nonce reject cases the "
                    "stored commitment is the formula applied to that nonce without a length "
                    "check, so an implementation that hashes a nonce of the wrong length accepts "
                    "the case and fails it; only refusing the nonce passes. See "
                    "docs/format-spec.md section 8.",
        "domain": COMMIT_DOMAIN,
        "nonce_size": NONCE_SIZE,
        "vectors": vectors,
        "reject": reject,
    }


# ---------------------------------------------------------------------------
# Anchor chain hash (§9.4):
#   SHA-512("aleutian.anchor.v2:" ‖ previous_anchor_hash ‖ "|" ‖ subject ‖ "|"
#           ‖ start_entry_id ‖ "|" ‖ end_entry_id ‖ "|" ‖ tip_chain_hash)
# The first anchor's previous_anchor_hash is SHA-512("aleutian.anchor.seed.v2").
# The file names the subject by its original key, company_id (§9.4).
# ---------------------------------------------------------------------------

def anchor_chain_hash(prev: str, subject: str, start_id: str, end_id: str, tip: str) -> str:
    return sha512_hex(f"aleutian.anchor.v2:{prev}|{subject}|{start_id}|{end_id}|{tip}".encode())


def anchor_chain_hash_file() -> dict:
    seed = sha512_hex(b"aleutian.anchor.seed.v2")
    prev, tip = "a" * 128, "b" * 128
    subject = "comp_01HZX9K2M3N4P5Q6R7S8T9V0WA"
    start = "0192f3a1-1111-7000-8000-aaaaaaaaaaaa"
    later = "0192f3a1-3333-7000-8000-cccccccccccc"
    cases = [
        ("genesis", seed, subject, start, "0192f3a1-2222-7000-8000-bbbbbbbbbbbb"),
        ("subsequent", prev, subject, start, later),
        ("tombstone_range_end", prev, subject, start, "tomb_0192f3a1-4444-7000-8000-dddddddddddd"),
        ("different_company_same_range", prev, subject[:-1] + "B", start, later),
        ("empty_range_bounds", prev, subject, "", ""),
    ]
    return {
        "_comment": "Anchor-of-anchors chain hash vectors, domain aleutian.anchor.v2:. Computed "
                    "in Python from docs/format-spec.md section 9.4 (scripts/spec-vectors.py), "
                    "independently of any implementation under test. The values are the ones a "
                    "producer first emitted; the script reproduced them byte for byte before it "
                    "became their writer. company_id is the subject, under its original key.",
        "vectors": [{"name": name, "previous_anchor_hash": p, "company_id": s,
                     "start_entry_id": a, "end_entry_id": b, "tip_chain_hash": tip,
                     "expected_chain_hash": anchor_chain_hash(p, s, a, b, tip)}
                    for name, p, s, a, b in cases],
        "version": 1,
    }


def write(name: str, obj, manifest: dict) -> None:
    raw = (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode()
    with open(os.path.join(TESTDATA, name), "wb") as f:
        f.write(raw)
    manifest["vectors"][name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    print(f"wrote {name} ({len(raw)} bytes)")


def main() -> None:
    mpath = os.path.join(ROOT, "fixtures", "MANIFEST.json")
    manifest = json.load(open(mpath))
    write("chain_vectors.json", chain_v2_file(), manifest)
    write("v3_golden_capture_request.json", capture_file(), manifest)
    write("merkle_golden.json", merkle_file(), manifest)
    write("commitment_vectors.json", commitment_file(), manifest)
    write("anchor_chain_hash_vectors.json", anchor_chain_hash_file(), manifest)
    manifest["vectors"] = dict(sorted(manifest["vectors"].items()))
    with open(mpath, "w") as f:
        f.write(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
