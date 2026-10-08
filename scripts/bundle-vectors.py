#!/usr/bin/env python3
# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
"""Bundle conformance vectors (docs/bundle-format.md §15), computed from the spec.

Writes fixtures/testdata/bundle_v1_vectors.json and updates MANIFEST.json.

How the expected results are made (owner decision V2): each case is BUILT here
from a known-good bundle plus one stated defect, and its expected result is
DECLARED from that construction and the spec's rules. No verifier runs here:
a verifier in this script would be a second copy of the SDKs' code, written
by the same hand.

Signatures (V1): ML-DSA-65 via dilithium-py, deterministic, from fixed seeds.
It reproduces proof's Go signer byte for byte. Because the Python SDK verifies
with the same library, sink/bundle_vectors_test.go checks every signature's
stated validity with a different implementation (circl).

The real-export case (V4) embeds scripts/bundlefixture/real_export.json, a real
`proof sink export`; its expected result comes from the facts of what that
program built, never from the bundle bytes.

Requires: dilithium-py (as the Python SDK does). Run from anywhere:
    python3 scripts/bundle-vectors.py
"""

import base64
import copy
import hashlib
import importlib.util
import json
import os

from dilithium_py.ml_dsa import ML_DSA_65 as D

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
_spec = importlib.util.spec_from_file_location("iv", os.path.join(HERE, "independent-vectors.py"))
iv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(iv)

MLDSA65_OID = "2.16.840.1.101.3.4.3.18"
SHA512_OID_DER = bytes.fromhex("0609608648016503040203")
SEED_ANCHOR_ID = "anchor_00000000-0000-0000-0000-000000000000"
SEED_ANCHOR_HASH = hashlib.sha512(b"aleutian.anchor.seed.v2").hexdigest()
RESULT_ID = "aleutian.proof.bundle-result.v1"
BUNDLE_FORMAT = "aleutian.proof.bundle.v1"


# ---------------------------------------------------------------- keys

def make_key(name: str, seed_byte: int) -> dict:
    seed = bytes([seed_byte]) * 32
    pk, sk = D.key_derive(seed)
    der = iv.spki(MLDSA65_OID, pk)
    kid = hashlib.sha512(b"proof.keyid.v1:" + der).digest()[:16].hex()
    b64 = base64.b64encode(der).decode()
    pem = "-----BEGIN PUBLIC KEY-----\n" + "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64)) \
        + "\n-----END PUBLIC KEY-----\n"
    return {"name": name, "seed_hex": seed.hex(), "public_key_hex": pk.hex(), "public_key_pem": pem,
            "key_id": kid, "_sk": sk, "_pk": pk}


KEYS = {k["name"]: k for k in (make_key("checkpoint", 0x11), make_key("record", 0x22), make_key("other", 0x33))}


def sign(key: dict, msg: bytes, mode: str = "pure") -> bytes:
    """ML-DSA-65, deterministic. mode: pure (empty context, what proof uses),
    ctx (a non-empty context), hashml (HashML-DSA with SHA-512)."""
    if mode == "pure":
        return D.sign(key["_sk"], msg, deterministic=True)
    if mode == "ctx":
        return D.sign(key["_sk"], msg, ctx=b"proof", deterministic=True)
    if mode == "hashml":
        m_prime = bytes([1, 0]) + SHA512_OID_DER + hashlib.sha512(msg).digest()
        tr = hashlib.shake_256(key["_pk"]).digest(64)
        mu = hashlib.shake_256(tr + m_prime).digest(64)
        return D.sign_external_mu(key["_sk"], mu, deterministic=True)
    raise ValueError(mode)


def duplicate_hint_index(sig: bytes) -> bytes:
    """Re-encode sig's hint section with one index repeated (FIPS 204 Algorithm
    21 refuses it; a lenient decoder reads the same hint set and accepts it).
    Malleability, not forgery: it needs a valid signature to start from."""
    omega, k = 55, 6
    h = sig[-(omega + k):]
    offs, total = list(h[omega:]), h[omega + k - 1]
    j = next((j for j in range(k) if offs[j] > (offs[j - 1] if j else 0)), None)
    if j is None or total >= omega:
        raise ValueError("this signature cannot carry a repeated hint index")
    start = offs[j - 1] if j else 0
    idx = list(h[:total])
    idx.insert(start, idx[start])
    offs = [o + (1 if t >= j else 0) for t, o in enumerate(offs)]
    return sig[:-(omega + k)] + bytes(idx) + bytes(omega - len(idx)) + bytes(offs)


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


# ---------------------------------------------------------------- chains

_ID = [0]


def next_entry_id() -> str:
    _ID[0] += 1
    return "sink-%032x" % _ID[0]


def commitment(nonce: bytes, content: bytes) -> str:
    return hashlib.sha512(b"aleutian.commit.v1:" + nonce + hashlib.sha512(content).digest()).hexdigest()


def erasure_hash(prev_seq: int) -> str:
    record = ('{"erased":"every earlier event on this chain","through_global_seq":"%d"}' % prev_seq).encode()
    return hashlib.sha512(b"aleutian.sink.erasure.v1:" + record).hexdigest()


def ts(i: int) -> str:
    return "2026-10-07T12:00:00.%06dZ" % (i + 1)


def record_fields(chain_id: str, e: dict, key_id: str) -> dict:
    return {"chain_id": chain_id, "entry_id": e["entry_id"], "entry_type": e["entry_type"],
            "global_seq": e["global_seq"], "previous_hash": e["previous_hash"], "timestamp": e["timestamp"],
            "content_hash": e["content_hash"], "signing_key_id": key_id}


def sign_entry(chain_id: str, e: dict, key: dict, mode: str = "pure") -> None:
    sig = sign(key, iv.record_v1(record_fields(chain_id, e, key["key_id"])), mode)
    e["record_signature"] = {"key_id": key["key_id"], "signature": b64(sig)}


def build_chain(chain_id: str, kinds: list, disclose: set) -> list:
    """kinds: 'event' or 'erasure' per entry. Each entry is linked, hashed and
    signed by the record key; events in `disclose` carry content and nonce."""
    entries, prev = [], ""
    for i, kind in enumerate(kinds):
        e = {"entry_id": next_entry_id(), "entry_type": "sink." + kind, "global_seq": str(i),
             "previous_hash": prev, "timestamp": ts(i)}
        if kind == "event":
            content = ('{"chain":"%s","n":%d}' % (chain_id[-4:], i)).encode()
            nonce = hashlib.sha256(chain_id.encode() + bytes([i])).digest()
            e["content_hash"] = commitment(nonce, content)
            if i in disclose:
                e["disclosed"] = {"content": b64(content), "nonce": nonce.hex()}
        else:
            e["content_hash"] = erasure_hash(i - 1)
        e["chain_hash"] = iv.chain_v3(prev, i, e["timestamp"], e["content_hash"])
        prev = e["chain_hash"]
        sign_entry(chain_id, e, KEYS["record"])
        entries.append(e)
    return entries


def append_event(chain_id: str, entries: list) -> None:
    """One more signed event, linked after the last entry."""
    i, prev = len(entries), entries[-1]["chain_hash"]
    content = ('{"chain":"%s","n":%d}' % (chain_id[-4:], i)).encode()
    e = {"entry_id": next_entry_id(), "entry_type": "sink.event", "global_seq": str(i), "previous_hash": prev,
         "timestamp": ts(i), "content_hash": commitment(bytes([i]) * 32, content)}
    e["chain_hash"] = iv.chain_v3(prev, i, e["timestamp"], e["content_hash"])
    sign_entry(chain_id, e, KEYS["record"])
    entries.append(e)


def append_erasure(chain_id: str, entries: list) -> None:
    """A genuine erasure, linked after the last entry, built from its stored global_seq."""
    i, prev = len(entries), entries[-1]["chain_hash"]
    e = {"entry_id": next_entry_id(), "entry_type": "sink.erasure", "global_seq": str(i), "previous_hash": prev,
         "timestamp": ts(i), "content_hash": erasure_hash(int(entries[-1]["global_seq"]))}
    e["chain_hash"] = iv.chain_v3(prev, i, e["timestamp"], e["content_hash"])
    sign_entry(chain_id, e, KEYS["record"])
    entries.append(e)


def reseal(chain_id: str, e: dict) -> None:
    """Recompute e's chain hash from its (changed) stored fields and sign it
    again: the entry is then consistent with itself, so only the rules that
    look beyond it can object."""
    e["chain_hash"] = iv.chain_v3(e["previous_hash"], int(e["global_seq"]), e["timestamp"], e["content_hash"])
    sign_entry(chain_id, e, KEYS["record"])


def anchor_hash(prev_hash: str, subject: str, start: str, end: str, tip: str) -> str:
    return hashlib.sha512(("aleutian.anchor.v2:%s|%s|%s|%s|%s" % (prev_hash, subject, start, end, tip)).encode()) \
        .hexdigest()


def make_anchor(chain_id: str, entries: list, count: int, prev: dict = None, key: dict = None,
                mode: str = "pure", **override) -> dict:
    """A v6 checkpoint over the first `count` entries, linked to `prev`. Fields
    in `override` replace the honest values BEFORE hashing and signing (so the
    checkpoint is a consistent, validly signed lie), except `_sig` and
    `_text`, applied after."""
    key = key or KEYS["checkpoint"]
    a = {"version": 6, "anchor_id": "anchor_%s-%04d" % (chain_id[-8:], count),
         "subject": chain_id, "entry_count": count, "verified_through": count,
         "previous_anchor_id": prev["anchor_id"] if prev else SEED_ANCHOR_ID,
         "range": {"start_entry_id": entries[0]["entry_id"], "end_entry_id": entries[min(count, len(entries)) - 1]["entry_id"]},
         "signing_key_id": key["key_id"], "created_at_ms": 1791374400000 + count}
    a.update({k: v for k, v in override.items() if not k.startswith("_")})
    tip = entries[min(count, len(entries)) - 1]["chain_hash"]
    a["chain_hash"] = anchor_hash(prev["chain_hash"] if prev else SEED_ANCHOR_HASH, a["subject"],
                                  a["range"]["start_entry_id"], a["range"]["end_entry_id"], tip)
    if "chain_hash" in override:
        a["chain_hash"] = override["chain_hash"]
    a["signature"] = b64(sign(key, iv.canonical_v6(a).encode(), mode))
    if "_sig" in override:
        a["signature"] = override["_sig"]
    return a


def anchor_text(a: dict) -> str:
    canonical = iv.canonical_v6(a)
    return canonical[:-1] + ',"signature":' + iv.go_json_string(a["signature"]) + "}"


def chain_obj(chain_id: str, entries: list, anchors: list, texts: list = None) -> dict:
    return {"chain_id": chain_id, "entries": entries, "checkpoints": texts if texts is not None
            else [anchor_text(a) for a in anchors]}


def bundle_bytes(chains: list) -> bytes:
    return json.dumps({"format": BUNDLE_FORMAT, "chains": chains}, separators=(",", ":"),
                      ensure_ascii=False).encode()


# ---------------------------------------------------------------- expected results

COUNT_KEYS = ["entries", "events", "erasures", "opened", "committed", "erased", "checkpoints", "unanchored",
              "authenticated", "unauthenticated", "checkpoint_authenticated", "record_authenticated",
              "record_signatures_present"]


def chain_result(erasure: str, counts: dict, problems: list = ()) -> dict:
    c = {k: counts[k] for k in COUNT_KEYS}
    assert c["authenticated"] + c["unauthenticated"] == c["entries"], c
    probs = sorted(({"code": p[0], "count": p[1], "first": p[2]} for p in problems), key=lambda p: p["code"])
    if probs:
        verdict = "failed"
    elif c["unauthenticated"]:
        verdict = "unauthenticated"
    else:
        verdict = "ok"
    return {"verdict": verdict, "erasure": erasure, "counts": c, "problems": probs}


def result(trust: dict, chains: dict, bundle_problems: list = ()) -> dict:
    bp = sorted(({"code": p[0], "count": p[1], "first": p[2]} for p in bundle_problems), key=lambda p: p["code"])
    verdicts = [c["verdict"] for c in chains.values()]
    if bp or "failed" in verdicts:
        verdict = "failed"
    elif "unauthenticated" in verdicts or not chains:
        verdict = "unauthenticated"
    else:
        verdict = "ok"
    return {"result": RESULT_ID, "readable": True,
            "checkpoint_trust": "checked" if trust["checkpoint_keys"] else "not_checked",
            "record_trust": "checked" if trust["record_keys"] else "not_checked",
            "verdict": verdict, "bundle_problems": bp, "chains": chains}


def unreadable(reason: str) -> dict:
    return {"result": RESULT_ID, "readable": False, "reason": reason}


BOTH = {"checkpoint_keys": ["checkpoint"], "record_keys": ["record"]}
CP_ONLY = {"checkpoint_keys": ["checkpoint"], "record_keys": []}
REC_ONLY = {"checkpoint_keys": [], "record_keys": ["record"]}
NONE = {"checkpoint_keys": [], "record_keys": []}


def counts(**kw) -> dict:
    return kw


# ---------------------------------------------------------------- the cases

def cases() -> list:
    out = []

    def add(name, bundle, trust, expected, note=None, signatures=None):
        c = {"name": name, "bundle_b64": b64(bundle), "trust": trust, "expected": expected}
        if note:
            c["note"] = note
        if signatures:
            c["signatures"] = signatures  # for sink/bundle_vectors_test.go (circl)
        out.append(c)

    A, B, C = "events." + "a" * 32, "events." + "b" * 32, "events." + "c" * 32
    a_entries = build_chain(A, ["event", "event", "event"], disclose={0, 1})
    a_cp = make_anchor(A, a_entries, 3)
    b_entries = build_chain(B, ["event", "event", "erasure"], disclose=set())
    b_cp = make_anchor(B, b_entries, 3)

    def A_(entries=None, anchors=None, texts=None, chain_id=A):
        return chain_obj(chain_id, copy.deepcopy(entries if entries is not None else a_entries),
                         anchors if anchors is not None else [a_cp], texts)

    def B_(entries=None, anchors=None):
        return chain_obj(B, copy.deepcopy(entries if entries is not None else b_entries),
                         anchors if anchors is not None else [b_cp])

    a_ok = dict(entries=3, events=3, erasures=0, opened=2, committed=1, erased=0, checkpoints=1, unanchored=0,
                authenticated=3, unauthenticated=0, checkpoint_authenticated=3, record_authenticated=3,
                record_signatures_present=3)
    b_ok = dict(entries=3, events=2, erasures=1, opened=0, committed=0, erased=2, checkpoints=1, unanchored=0,
                authenticated=3, unauthenticated=0, checkpoint_authenticated=3, record_authenticated=3,
                record_signatures_present=3)

    def ac(**kw):
        return dict(a_ok, **kw)

    def bc(**kw):
        return dict(b_ok, **kw)

    good = bundle_bytes([A_(), B_()])

    # --- valid, every trust combination and erasure state
    add("ok_both_trusts", good, BOTH, result(BOTH, {A: chain_result("none", a_ok), B: chain_result("anchored", b_ok)}))
    add("ok_checkpoint_trust_only", good, CP_ONLY, result(CP_ONLY, {
        A: chain_result("none", ac(record_authenticated=0)),
        B: chain_result("anchored", bc(record_authenticated=0))}))
    add("ok_record_trust_only", good, REC_ONLY, result(REC_ONLY, {
        A: chain_result("none", ac(checkpoint_authenticated=0)),
        B: chain_result("signed", bc(checkpoint_authenticated=0))}),
        note="without checkpoint trust, checkpoints are still checked structurally and counted (§7.6); "
             "the erasure is signed, not anchored (§7.9, R6)")
    add("unauthenticated_no_trust", good, NONE, result(NONE, {
        A: chain_result("none", ac(authenticated=0, unauthenticated=3, checkpoint_authenticated=0,
                                   record_authenticated=0)),
        B: chain_result("recorded", bc(authenticated=0, unauthenticated=3, checkpoint_authenticated=0,
                                       record_authenticated=0))}),
        note="hashes recompute, but nothing establishes provenance (U1)")
    add("unauthenticated_empty_bundle", bundle_bytes([]), BOTH, result(BOTH, {}),
        note="an empty bundle proves nothing (§9.2)")

    a4 = copy.deepcopy(a_entries)
    append_event(A, a4)
    add("unauthenticated_unanchored_tail", bundle_bytes([A_(a4)]), CP_ONLY, result(CP_ONLY, {
        A: chain_result("none", ac(entries=4, events=4, committed=2, unanchored=1, authenticated=3,
                                   unauthenticated=1, record_authenticated=0, record_signatures_present=4))}),
        note="checkpoint trust only: the entry after the last checkpoint is not authenticated")

    c_entries = build_chain(C, ["event", "event", "event"], disclose=set())
    c_cp1 = make_anchor(C, c_entries, 2)
    add("ok_tail_truncated_to_earlier_checkpoint",
        bundle_bytes([chain_obj(C, copy.deepcopy(c_entries[:2]), [c_cp1])]), BOTH, result(BOTH, {
            C: chain_result("none", dict(entries=2, events=2, erasures=0, opened=0, committed=2, erased=0,
                                         checkpoints=1, unanchored=0, authenticated=2, unauthenticated=0,
                                         checkpoint_authenticated=2, record_authenticated=2,
                                         record_signatures_present=2))}),
        note="a chain cut back to an earlier checkpoint verifies: undetectable from the bundle (§1)")

    sw = copy.deepcopy(a_entries)
    sw[1]["entry_id"] = next_entry_id()
    add("ok_swapped_inner_entry_id_checkpoint_only", bundle_bytes([A_(sw)]), CP_ONLY, result(CP_ONLY, {
        A: chain_result("none", ac(record_authenticated=0))}),
        note="a checkpoint does not authenticate inner entry ids; only record signatures do (§1)")

    # --- bundle level
    add("duplicate_chain", bundle_bytes([A_(), A_()]), BOTH, result(BOTH, {
        "#0": chain_result("none", a_ok), "#1": chain_result("none", a_ok)},
        bundle_problems=[("duplicate-chain", 1, 1)]),
        note="every copy keyed by position (§8, §9.3)")

    # --- shape, ids, links
    bad_id = "events." + "A" * 32
    add("invalid_chain_id", bundle_bytes([A_(chain_id=bad_id)]), BOTH, result(BOTH, {
        "#0": chain_result("none", ac(checkpoints=0, unanchored=3, authenticated=0, unauthenticated=3,
                                      checkpoint_authenticated=0, record_authenticated=0),
                           [("invalid-chain-id", 1, None), ("checkpoint-subject", 1, 0), ("bad-signature", 3, 0)])}),
        note="no envelope can be built with an invalid chain id: bad-signature without verifying (§7.7)")

    fs = copy.deepcopy(a_entries)
    fs[1]["content_hash"] = fs[1]["content_hash"].upper()
    malformed_counts = ac(opened=1, committed=1, checkpoints=0, unanchored=3, authenticated=2,
                          unauthenticated=1, checkpoint_authenticated=0, record_authenticated=2)
    malformed_problems = [("field-shape", 1, 1), ("checkpoint-binding", 1, 0), ("bad-signature", 1, 1)]
    add("field_shape_uppercase_hash", bundle_bytes([A_(fs)]), BOTH, result(BOTH, {
        A: chain_result("none", malformed_counts, malformed_problems)}),
        note="a malformed entry: not hashed, linked, classified or authenticated; its successor's link is not "
             "checked; the checkpoint over it fails binding")

    tsx = copy.deepcopy(a_entries)
    tsx[1]["timestamp"] = "2026-02-30T12:00:00.000002Z"
    add("field_shape_impossible_timestamp", bundle_bytes([A_(tsx)]), BOTH, result(BOTH, {
        A: chain_result("none", malformed_counts, malformed_problems)}),
        note="the timestamp shape is a real UTC instant, not just a pattern (§4.3)")

    for label, bad_ts in (("second_60", "2026-10-07T12:00:60.000002Z"), ("year_0000", "0000-10-07T12:00:00.000002Z")):
        t2 = copy.deepcopy(a_entries)
        t2[1]["timestamp"] = bad_ts
        add("field_shape_timestamp_" + label, bundle_bytes([A_(t2)]), BOTH, result(BOTH, {
            A: chain_result("none", malformed_counts, malformed_problems)}))

    dup = copy.deepcopy(a_entries)
    dup[1]["entry_id"] = dup[0]["entry_id"]
    add("duplicate_entry_id", bundle_bytes([A_(dup)]), CP_ONLY, result(CP_ONLY, {
        A: chain_result("none", ac(record_authenticated=0), [("duplicate-entry-id", 1, 1)])}))

    dm = copy.deepcopy(a_entries)
    dm[1]["entry_id"] = dm[0]["entry_id"]
    dm[1]["content_hash"] = dm[1]["content_hash"].upper()
    add("duplicate_entry_id_repeat_malformed", bundle_bytes([A_(dm)]), BOTH, result(BOTH, {
        A: chain_result("none", malformed_counts, malformed_problems + [("duplicate-entry-id", 1, 1)])}),
        note="the repeat counts whether or not it is itself well-formed (§7.1 step 4, rev 3.1)")

    add("first_entry_front_truncated", bundle_bytes([A_(a_entries[1:])]), BOTH, result(BOTH, {
        A: chain_result("none", dict(entries=2, events=2, erasures=0, opened=1, committed=1, erased=0,
                                     checkpoints=0, unanchored=2, authenticated=2, unauthenticated=0,
                                     checkpoint_authenticated=0, record_authenticated=2,
                                     record_signatures_present=2),
                        [("first-entry", 1, 0), ("checkpoint-overreach", 1, 0)])}))

    sq = copy.deepcopy(a_entries)
    sq[2]["global_seq"] = "3"
    add("sequence", bundle_bytes([A_(sq)]), BOTH, result(BOTH, {
        A: chain_result("none", ac(record_authenticated=2),
                        [("sequence", 1, 2), ("chain-hash", 1, 2), ("bad-signature", 1, 2)])}))

    lk = copy.deepcopy(a_entries)
    lk[2]["previous_hash"] = "a" * 128
    add("link", bundle_bytes([A_(lk)]), BOTH, result(BOTH, {
        A: chain_result("none", ac(record_authenticated=2),
                        [("link", 1, 2), ("chain-hash", 1, 2), ("bad-signature", 1, 2)])}))

    ch = copy.deepcopy(a_entries)
    ch[1]["chain_hash"] = "b" * 128
    add("chain_hash", bundle_bytes([A_(ch)]), BOTH, result(BOTH, {
        A: chain_result("none", a_ok, [("chain-hash", 1, 1), ("link", 1, 2)])}),
        note="the record envelope does not include chain_hash; the checkpoint binds the tip's stored hash")

    et = copy.deepcopy(a_entries)
    et[2]["entry_type"] = "sink.other"
    add("entry_type", bundle_bytes([A_(et)]), BOTH, result(BOTH, {
        A: chain_result("none", ac(events=2, committed=0, record_authenticated=2),
                        [("entry-type", 1, 2), ("bad-signature", 1, 2)])}))

    el = copy.deepcopy(a_entries)
    el[2]["entry_type"] = "sink.erasure"
    add("erasure_invalid_label_without_hash", bundle_bytes([A_(el)]), BOTH, result(BOTH, {
        A: chain_result("none", ac(events=2, committed=0, record_authenticated=2),
                        [("erasure-invalid", 1, 2), ("bad-signature", 1, 2)])}))

    rl = copy.deepcopy(b_entries)
    rl[2]["entry_type"] = "sink.event"
    add("erasure_invalid_relabelled", bundle_bytes([B_(rl)]), BOTH, result(BOTH, {
        B: chain_result("none", bc(events=3, erasures=0, record_authenticated=2),
                        [("erasure-invalid", 1, 2), ("bad-signature", 1, 2)])}),
        note="the erasure is found by its hash whatever the label: the events before it stay erased (§7.3)")

    b4 = copy.deepcopy(b_entries)
    append_event(B, b4)
    add("after_erasure", bundle_bytes([B_(b4)]), BOTH, result(BOTH, {
        B: chain_result("recorded", bc(entries=4, events=3, unanchored=1, authenticated=4,
                                       record_authenticated=4, record_signatures_present=4),
                        [("after-erasure", 1, 3)])}))

    ed = copy.deepcopy(b_entries)
    content = ('{"chain":"%s","n":%d}' % (B[-4:], 0)).encode()
    ed[0]["disclosed"] = {"content": b64(content), "nonce": hashlib.sha256(B.encode() + bytes([0])).digest().hex()}
    add("erased_event_disclosed", bundle_bytes([B_(ed)]), BOTH, result(BOTH, {
        B: chain_result("recorded", bc(erased=1), [("erased-event-disclosed", 1, 0)])}))

    md = copy.deepcopy(a_entries)
    md[0]["disclosed"]["content"] = b64(b"tampered")
    add("modified", bundle_bytes([A_(md)]), BOTH, result(BOTH, {
        A: chain_result("none", ac(opened=1), [("modified", 1, 0)])}))

    # --- checkpoints: the first failing step is the one problem
    cp_fail = ac(checkpoints=0, unanchored=3, checkpoint_authenticated=0)

    def cp_case(name, anchor_or_text, code, note=None, signatures=None):
        texts = [anchor_or_text] if isinstance(anchor_or_text, str) else [anchor_text(anchor_or_text)]
        add(name, bundle_bytes([A_(texts=texts)]), BOTH, result(BOTH, {
            A: chain_result("none", cp_fail, [(code, 1, 0)])}), note=note, signatures=signatures)

    cp_case("checkpoint_malformed_version_5", anchor_text(make_anchor(A, a_entries, 3, version=5)),
            "checkpoint-malformed")
    cp_case("checkpoint_subject", make_anchor(A, a_entries, 3, subject="events." + "d" * 32),
            "checkpoint-subject")
    cp_case("checkpoint_sequence", make_anchor(A, a_entries, 3, previous_anchor_id="anchor_wrong"),
            "checkpoint-sequence")
    cp_case("checkpoint_overreach", make_anchor(A, a_entries, 4, range={
        "start_entry_id": a_entries[0]["entry_id"], "end_entry_id": a_entries[2]["entry_id"]}),
        "checkpoint-overreach")
    cp_case("checkpoint_binding", make_anchor(A, a_entries, 3, range={
        "start_entry_id": a_entries[0]["entry_id"], "end_entry_id": a_entries[1]["entry_id"]}),
        "checkpoint-binding")
    cp_case("checkpoint_unknown_key", make_anchor(A, a_entries, 3, key=KEYS["other"]), "checkpoint-unknown-key")
    flipped = make_anchor(A, a_entries, 3)
    sig = bytearray(base64.b64decode(flipped["signature"]))
    sig[100] ^= 1
    flipped["signature"] = b64(bytes(sig))
    cp_case("checkpoint_bad_signature", flipped, "checkpoint-bad-signature",
            signatures=[{"kind": "checkpoint", "index": 0, "valid": False}])
    cp_case("checkpoint_signed_with_context", make_anchor(A, a_entries, 3, mode="ctx"), "checkpoint-bad-signature",
            note="ML-DSA with a non-empty context MUST fail: catches libraries that ignore the context",
            signatures=[{"kind": "checkpoint", "index": 0, "valid": False}])
    cp_case("checkpoint_signed_hashml_dsa", make_anchor(A, a_entries, 3, mode="hashml"),
            "checkpoint-bad-signature", note="HashML-DSA MUST fail: proof uses pure ML-DSA",
            signatures=[{"kind": "checkpoint", "index": 0, "valid": False}])

    good_text = anchor_text(a_cp)
    cp_case("checkpoint_uppercase_key_id",
            good_text.replace(a_cp["signing_key_id"], a_cp["signing_key_id"].upper()), "checkpoint-malformed")
    sig_b64 = a_cp["signature"]
    add("checkpoint_signature_out_of_alphabet_record_trust_only",
        bundle_bytes([A_(texts=[good_text.replace(sig_b64, sig_b64[:-1] + "-")])]), REC_ONLY, result(REC_ONLY, {
            A: chain_result("none", ac(checkpoints=0, unanchored=3, checkpoint_authenticated=0),
                            [("checkpoint-malformed", 1, 0)])}),
        note="the signature's shape is judged in step a, without checkpoint trust too. (3309 bytes need no "
             "padding, so an unused-bits variant cannot exist; this is a character outside the alphabet)")
    cp_case("checkpoint_case_variant_member", good_text.replace('"subject":', '"Subject":'), "checkpoint-malformed",
            note="member names are case-sensitive (Go's decoder folds case)")
    cp_case("checkpoint_duplicate_member", good_text.replace('"version":6', '"version":6,"version":6'),
            "checkpoint-malformed")
    cp_case("checkpoint_escaped_duplicate_member",
            good_text.replace('"version":6', '"version":6,"v\\u0065rsion":6'), "checkpoint-malformed",
            note="duplicates are compared after unescaping")
    cp_case("checkpoint_number_exponent", good_text.replace('"entry_count":3', '"entry_count":3e0'),
            "checkpoint-malformed")
    cp_case("checkpoint_number_fraction", good_text.replace('"entry_count":3', '"entry_count":3.0'),
            "checkpoint-malformed")
    cp_case("checkpoint_number_over_2_53", good_text.replace(
        '"created_at_ms":%d' % a_cp["created_at_ms"], '"created_at_ms":9007199254740993'),
        "checkpoint-malformed", note="JS cannot hold it exactly; refused everywhere")

    # --- record signatures
    def rec_case(name, mutate, code, sig_valid=None, note=None, trust=BOTH, cnt=None):
        e = copy.deepcopy(a_entries)
        mutate(e[1])
        sigs = [{"kind": "record", "index": 1, "valid": sig_valid}] if sig_valid is not None else None
        add(name, bundle_bytes([A_(e)]), trust, result(trust, {
            A: chain_result("none", cnt or ac(record_authenticated=2), [(code, 1, 1)])}), note=note, signatures=sigs)

    rec_case("record_unsigned", lambda e: e.pop("record_signature"), "unsigned",
             cnt=ac(record_authenticated=2, record_signatures_present=2))
    rec_case("record_malformed_signature_length", lambda e: e["record_signature"].update(
        signature=b64(base64.b64decode(e["record_signature"]["signature"])[:-1])), "malformed-signature")
    rec_case("record_malformed_signature_alphabet", lambda e: e["record_signature"].update(
        signature=e["record_signature"]["signature"][:-2] + "-_"), "malformed-signature",
        note="canonical base64 only: no URL-safe alphabet")
    rec_case("record_unknown_key", lambda e: sign_entry(A, e, KEYS["other"]), "unknown-key")
    rec_case("record_signed_by_checkpoint_key", lambda e: sign_entry(A, e, KEYS["checkpoint"]), "unknown-key",
             note="the two trust dimensions are separate (§6)")

    def flip(e):
        s = bytearray(base64.b64decode(e["record_signature"]["signature"]))
        s[200] ^= 1
        e["record_signature"]["signature"] = b64(bytes(s))
    rec_case("record_bad_signature", flip, "bad-signature", sig_valid=False)
    rec_case("record_signed_with_context", lambda e: sign_entry(A, e, KEYS["record"], "ctx"), "bad-signature",
             sig_valid=False)
    rec_case("record_signed_hashml_dsa", lambda e: sign_entry(A, e, KEYS["record"], "hashml"), "bad-signature",
             sig_valid=False)

    rec_case("record_signature_repeated_hint_index", lambda e: e["record_signature"].update(
        signature=b64(duplicate_hint_index(base64.b64decode(e["record_signature"]["signature"])))),
        "bad-signature", sig_valid=False,
        note="a valid signature re-encoded with a repeated hint index: FIPS 204 Algorithm 21 refuses it")
    cp_hint = dict(a_cp, signature=b64(duplicate_hint_index(base64.b64decode(a_cp["signature"]))))
    cp_case("checkpoint_signature_repeated_hint_index", cp_hint, "checkpoint-bad-signature",
            signatures=[{"kind": "checkpoint", "index": 0, "valid": False}])

    # --- disclosed content shape
    nb = copy.deepcopy(a_entries)
    c = nb[0]["disclosed"]["content"]
    # Flip the last base64 character's unused bits: decodes leniently to the
    # same bytes, but is not canonical.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    body = c.rstrip("=")
    pad = len(c) - len(body)
    last = alphabet.index(body[-1])
    nb[0]["disclosed"]["content"] = body[:-1] + alphabet[last | (1 if pad else 0) | (2 if pad == 1 else 0)] \
        + "=" * pad
    assert nb[0]["disclosed"]["content"] != c, "the content must have padding to make non-canonical"
    add("disclosed_content_noncanonical_base64", bundle_bytes([A_(nb)]), BOTH, result(BOTH, {
        A: chain_result("none", ac(opened=1), [("field-shape", 1, 0)])}),
        note="non-canonical base64 is a value shape: field-shape, and the event gets no outcome")

    # --- erasure positions (§7.3)
    add("erasure_from_stored_global_seq", bundle_bytes([B_(b_entries[1:])]), BOTH, result(BOTH, {
        B: chain_result("recorded", dict(entries=2, events=1, erasures=1, opened=0, committed=0, erased=1,
                                         checkpoints=0, unanchored=2, authenticated=2, unauthenticated=0,
                                         checkpoint_authenticated=0, record_authenticated=2,
                                         record_signatures_present=2),
                        [("first-entry", 1, 0), ("checkpoint-overreach", 1, 0)])}),
        note="the erasure hash is built from the predecessor's STORED global_seq (1), not its index (0)")

    bm = copy.deepcopy(b_entries)
    bm[1]["content_hash"] = bm[1]["content_hash"].upper()
    add("erasure_after_malformed_entry", bundle_bytes([B_(bm)]), BOTH, result(BOTH, {
        B: chain_result("none", bc(events=2, erasures=0, committed=1, erased=0, checkpoints=0, unanchored=3,
                                   authenticated=2, unauthenticated=1, checkpoint_authenticated=0,
                                   record_authenticated=2),
                        [("field-shape", 1, 1), ("erasure-invalid", 1, 2), ("checkpoint-binding", 1, 0),
                         ("bad-signature", 1, 1)])}),
        note="an entry whose predecessor is malformed cannot hold the erasure hash (§7.3): E = -1")

    c0 = copy.deepcopy(c_entries)
    c0[0]["entry_type"] = "sink.erasure"
    c_cp2 = make_anchor(C, c_entries, 3, prev=c_cp1)
    c_ok = dict(entries=3, events=3, erasures=0, opened=0, committed=3, erased=0, checkpoints=2, unanchored=0,
                authenticated=3, unauthenticated=0, checkpoint_authenticated=3, record_authenticated=3,
                record_signatures_present=3)
    add("erasure_invalid_at_entry_0", bundle_bytes([chain_obj(C, c0, [c_cp1, c_cp2])]), BOTH, result(BOTH, {
        C: chain_result("none", dict(c_ok, events=2, committed=2, record_authenticated=2),
                        [("erasure-invalid", 1, 0), ("bad-signature", 1, 0)])}))

    b5 = copy.deepcopy(b_entries)
    append_event(B, b5)
    append_erasure(B, b5)
    add("ok_two_erasures", bundle_bytes([B_(b5, [make_anchor(B, b5, 5)])]), BOTH, result(BOTH, {
        B: chain_result("anchored", dict(entries=5, events=3, erasures=2, opened=0, committed=0, erased=3,
                                         checkpoints=1, unanchored=0, authenticated=5, unauthenticated=0,
                                         checkpoint_authenticated=5, record_authenticated=5,
                                         record_signatures_present=5))}),
        note="E is the LAST erasure; the earlier one is still genuine")

    be = copy.deepcopy(b_entries)
    be[2]["disclosed"] = {"content": b64(b"x"), "nonce": "00" * 32}
    add("disclosed_on_erasure", bundle_bytes([B_(be)]), BOTH, result(BOTH, {
        B: chain_result("none", bc(erasures=0), [("field-shape", 1, 2)])}),
        note="a misplaced disclosed is field-shape and the entry's only outcome (§7.1.3): it still holds the "
             "erasure hash, so E = 2 and the events before it are erased, but it is not a genuine erasure")

    # --- the checkpoint series (§7.6)
    def C_(anchors):
        return chain_obj(C, copy.deepcopy(c_entries), anchors)

    def flip_sig(a):
        a = dict(a)
        s = bytearray(base64.b64decode(a["signature"]))
        s[100] ^= 1
        a["signature"] = b64(bytes(s))
        return a

    add("ok_two_checkpoints", bundle_bytes([C_([c_cp1, c_cp2])]), BOTH, result(BOTH, {
        C: chain_result("none", c_ok)}), note="checkpoint 1 binds checkpoint 0's anchor chain hash")
    after_one = dict(c_ok, checkpoints=1, unanchored=1, checkpoint_authenticated=2)
    add("checkpoint_series_second_fails", bundle_bytes([C_([c_cp1, flip_sig(c_cp2)])]), BOTH, result(BOTH, {
        C: chain_result("none", after_one, [("checkpoint-bad-signature", 1, 1)])}),
        note="the last PASSING checkpoint decides coverage",
        signatures=[{"kind": "checkpoint", "index": 1, "valid": False}])
    add("checkpoint_series_stops_after_failure", bundle_bytes([C_([flip_sig(c_cp1), c_cp2])]), BOTH,
        result(BOTH, {C: chain_result("none", dict(c_ok, checkpoints=0, unanchored=3, checkpoint_authenticated=0),
                                      [("checkpoint-bad-signature", 1, 0)])}),
        note="checkpoint 1 is valid but never checked, and does not count",
        signatures=[{"kind": "checkpoint", "index": 0, "valid": False},
                    {"kind": "checkpoint", "index": 1, "valid": True}])
    add("checkpoint_sequence_not_growing",
        bundle_bytes([C_([c_cp1, make_anchor(C, c_entries, 2, prev=c_cp1, anchor_id="anchor_c-repeat")])]), BOTH,
        result(BOTH, {C: chain_result("none", after_one, [("checkpoint-sequence", 1, 1)])}))
    seed_linked = anchor_hash(SEED_ANCHOR_HASH, C, c_entries[0]["entry_id"], c_entries[2]["entry_id"],
                              c_entries[2]["chain_hash"])
    add("checkpoint_binding_previous_anchor_hash",
        bundle_bytes([C_([c_cp1, make_anchor(C, c_entries, 3, prev=c_cp1, chain_hash=seed_linked)])]), BOTH,
        result(BOTH, {C: chain_result("none", after_one, [("checkpoint-binding", 1, 1)])}),
        note="checkpoint 1's anchor chain hash starts from the seed hash instead of checkpoint 0's")
    cp_case("checkpoint_binding_anchor_chain_hash", make_anchor(A, a_entries, 3, chain_hash="c" * 128),
            "checkpoint-binding", note="range right, anchor chain hash wrong, validly signed")
    tip = copy.deepcopy(a_entries)
    tip[2]["chain_hash"] = "d" * 128
    add("checkpoint_binding_tip_hash", bundle_bytes([A_(tip)]), BOTH, result(BOTH, {
        A: chain_result("none", cp_fail, [("chain-hash", 1, 2), ("checkpoint-binding", 1, 0)])}),
        note="the checkpoint binds the tip's STORED chain hash")

    # --- §3 grammar in checkpoint text
    cp_case("checkpoint_number_negative", good_text.replace('"entry_count":3', '"entry_count":-3'),
            "checkpoint-malformed")
    cp_case("checkpoint_number_leading_zero", good_text.replace('"entry_count":3', '"entry_count":03'),
            "checkpoint-malformed")
    cp_case("checkpoint_lone_surrogate", good_text.replace('"anchor_id":"', '"anchor_id":"\\ud800', 1),
            "checkpoint-malformed")
    add("ok_checkpoint_number_2_53_minus_1",
        bundle_bytes([A_(anchors=[make_anchor(A, a_entries, 3, created_at_ms=9007199254740991)])]), BOTH,
        result(BOTH, {A: chain_result("none", a_ok)}), note="the largest number allowed is accepted")

    # --- entry value shapes
    for label, seq in (("leading_zero", "01"), ("negative", "-1"), ("over_2_63", "9223372036854775808")):
        g = copy.deepcopy(a_entries)
        g[1]["global_seq"] = seq
        add("field_shape_global_seq_" + label, bundle_bytes([A_(g)]), BOTH, result(BOTH, {
            A: chain_result("none", malformed_counts, malformed_problems)}))
    for label, bad_ts in (("hour_24", "2026-10-07T24:00:00.000002Z"), ("minute_60", "2026-10-07T12:60:00.000002Z")):
        t2 = copy.deepcopy(a_entries)
        t2[1]["timestamp"] = bad_ts
        add("field_shape_timestamp_" + label, bundle_bytes([A_(t2)]), BOTH, result(BOTH, {
            A: chain_result("none", malformed_counts, malformed_problems)}))

    mx = copy.deepcopy(a_entries)
    mx[2]["global_seq"] = "9223372036854775807"
    reseal(A, mx[2])
    add("global_seq_2_63_minus_1_accepted", bundle_bytes([A_(mx, [make_anchor(A, mx, 3)])]), BOTH, result(BOTH, {
        A: chain_result("none", a_ok, [("sequence", 1, 2)])}),
        note="2^63-1 is in shape (hashed, signed, checkpointed); only the sequence rule objects")

    ld = copy.deepcopy(a_entries)
    ld[2]["timestamp"] = "2028-02-29T12:00:00.000003Z"
    reseal(A, ld[2])
    add("ok_timestamp_leap_day", bundle_bytes([A_(ld, [make_anchor(A, ld, 3)])]), BOTH, result(BOTH, {
        A: chain_result("none", a_ok)}), note="timestamps are never ordered (temporal authority)")

    def disclosed_case(name, content, nonce_hex):
        d = copy.deepcopy(a_entries)
        d[0]["disclosed"] = {"content": b64(content), "nonce": nonce_hex}
        add(name, bundle_bytes([A_(d)]), BOTH, result(BOTH, {
            A: chain_result("none", ac(opened=1), [("field-shape", 1, 0)])}))

    disclosed_case("disclosed_nonce_short", b"x", "0" * 63)
    disclosed_case("disclosed_content_empty", b"", "00" * 32)
    disclosed_case("disclosed_content_65537_bytes", b"x" * 65537, "00" * 32)

    big = copy.deepcopy(a_entries)
    big_content, big_nonce = bytes(range(256)) * 256, bytes([7]) * 32
    big[2]["content_hash"] = commitment(big_nonce, big_content)
    big[2]["disclosed"] = {"content": b64(big_content), "nonce": big_nonce.hex()}
    reseal(A, big[2])
    add("ok_disclosed_content_65536_bytes", bundle_bytes([A_(big, [make_anchor(A, big, 3)])]), BOTH, result(BOTH, {
        A: chain_result("none", ac(opened=3, committed=0))}), note="the largest disclosed content allowed")

    # --- record signatures, more
    rm = copy.deepcopy(a_entries)
    rm[1]["record_signature"]["signature"] = "AAAA"
    add("ok_malformed_record_signature_without_record_trust", bundle_bytes([A_(rm)]), CP_ONLY, result(CP_ONLY, {
        A: chain_result("none", ac(record_authenticated=0))}),
        note="without record trust, record_signature members are neither problems nor evidence (§7.7)")

    p0 = copy.deepcopy(a_entries)
    p0[0]["previous_hash"] = "a" * 128
    reseal(A, p0[0])
    add("record_envelope_previous_hash_at_seq_0", bundle_bytes([A_(p0)]), BOTH, result(BOTH, {
        A: chain_result("none", ac(record_authenticated=2),
                        [("first-entry", 1, 0), ("bad-signature", 1, 0), ("link", 1, 1)])}),
        note="its signature is a valid ML-DSA-65 signature over that envelope, but no envelope may be built "
             "for a non-empty previous hash at sequence 0: bad-signature WITHOUT verifying (§7.7)")

    # --- bundle level, more
    add("duplicate_chain_three_extra", bundle_bytes([A_(), B_(), A_(), B_(), A_()]), BOTH, result(BOTH, {
        "#0": chain_result("none", a_ok), "#1": chain_result("anchored", b_ok), "#2": chain_result("none", a_ok),
        "#3": chain_result("anchored", b_ok), "#4": chain_result("none", a_ok)},
        bundle_problems=[("duplicate-chain", 3, 2)]), note="[A, B, A, B, A]: three extra copies, the first at 2")

    # --- unreadable bundles (§9.1)
    def text_case(name, raw: bytes, reason, note=None):
        add(name, raw, BOTH, unreadable(reason), note=note)

    gtxt = good.decode()
    text_case("unreadable_json_truncated", good[:-2], "json")
    text_case("unreadable_json_bom", b"\xef\xbb\xbf" + good, "json")
    text_case("unreadable_json_invalid_utf8", good.replace(b'"format"', b'"form\xffat"'), "json")
    text_case("unreadable_json_lone_surrogate", gtxt.replace('"chain_id":"', '"chain_id":"\\ud800', 1).encode(),
              "json")
    deep9 = json.loads(gtxt)
    deep9["chains"][0]["entries"][0]["record_signature"] = [[[[]]]]
    text_case("unreadable_json_depth_9", json.dumps(deep9, separators=(",", ":")).encode(), "json",
              note="top level is depth 1; record_signature's value here reaches 9")
    deep8 = json.loads(gtxt)
    deep8["chains"][0]["entries"][0]["record_signature"] = [[[]]]
    text_case("unreadable_structure_depth_8", json.dumps(deep8, separators=(",", ":")).encode(), "structure",
              note="depth 8 is allowed by the grammar; the wrong type is a structure violation")
    text_case("unreadable_duplicate_key", ('{"format":"%s",' % BUNDLE_FORMAT + gtxt[1:]).encode(), "duplicate-key")
    text_case("unreadable_escaped_duplicate_key", ('{"f\\u006frmat":"%s",' % BUNDLE_FORMAT + gtxt[1:]).encode(),
              "duplicate-key")
    text_case("unreadable_format", gtxt.replace(BUNDLE_FORMAT, "aleutian.proof.bundle.v2").encode(), "format")
    text_case("unreadable_precedence_duplicate_key_before_format",
              ('{"format":"x",' + gtxt[1:].replace(BUNDLE_FORMAT, "aleutian.proof.bundle.v2")).encode(),
              "duplicate-key", note="several reasons: the lowest-numbered is reported")
    text_case("unreadable_precedence_format_before_structure",
              ('{"note":"x",' + gtxt[1:].replace(BUNDLE_FORMAT, "aleutian.proof.bundle.v2")).encode(), "format",
              note="the structure violation comes first in the bytes; format still wins")
    text_case("unreadable_format_missing", ('{' + gtxt[len('{"format":"%s",' % BUNDLE_FORMAT):]).encode(), "format")
    text_case("unreadable_format_wrong_type", gtxt.replace('"%s"' % BUNDLE_FORMAT, "1", 1).encode(), "format",
              note="a top-level object whose format is not exactly the v1 string, of any type")
    text_case("unreadable_json_raw_surrogate_bytes", good.replace(b'"chain_id":"', b'"chain_id":"\xed\xa0\x80', 1),
              "json", note="a surrogate encoded as UTF-8 bytes is not valid UTF-8")
    text_case("unreadable_precedence_json_before_duplicate_key",
              ('{"format":"x",' + gtxt[1:])[:-1].encode(), "json",
              note="a duplicate key and a truncation: the JSON reason wins")
    text_case("unreadable_structure_unknown_member", gtxt.replace('"chains":', '"note":"x","chains":', 1).encode(),
              "structure")
    text_case("unreadable_structure_case_variant", gtxt.replace('"chains":', '"Chains":', 1).encode(), "structure")
    empty_entries = json.loads(gtxt)
    empty_entries["chains"][0]["entries"] = []
    text_case("unreadable_structure_empty_entries", json.dumps(empty_entries, separators=(",", ":")).encode(),
              "structure")
    num = json.loads(gtxt)
    num["chains"][0]["entries"][0]["global_seq"] = 0
    text_case("unreadable_structure_number", json.dumps(num, separators=(",", ":")).encode(), "structure",
              note="no numbers outside checkpoint text")
    for label, num in (("negative", "-1"), ("fraction", "1.5"), ("exponent", "1e3")):
        text_case("unreadable_structure_number_" + label,
                  gtxt.replace('"global_seq":"0"', '"global_seq":' + num, 1).encode(), "structure",
                  note="valid RFC 8259 but outside §3's number rule: in the bundle that is a wrong type (§3, rev 3.1)")
    text_case("unreadable_json_number_plus_sign", gtxt.replace('"global_seq":"0"', '"global_seq":+1', 1).encode(),
              "json", note="not RFC 8259 JSON at all")

    def inner(name, f):
        o = json.loads(gtxt)
        f(o["chains"][0]["entries"][0])
        text_case(name, json.dumps(o, separators=(",", ":")).encode(), "structure",
                  note="the members inside record_signature and disclosed are structure (§4.3, rev 3.1)")

    inner("unreadable_structure_record_signature_extra_member", lambda e: e["record_signature"].update(x="y"))
    inner("unreadable_structure_record_signature_missing_member", lambda e: e["record_signature"].pop("signature"))
    inner("unreadable_structure_record_signature_number", lambda e: e["record_signature"].update(key_id=5))
    inner("unreadable_structure_disclosed_extra_member", lambda e: e["disclosed"].update(x="y"))
    inner("unreadable_structure_disclosed_missing_member", lambda e: e["disclosed"].pop("nonce"))
    text_case("unreadable_structure_root_array", b"[" + good + b"]", "structure")

    # --- a real export (V4)
    real = json.load(open(os.path.join(HERE, "bundlefixture", "real_export.json")))
    chains = {}
    for b in real["built"]:
        # Every event precedes the one erasure, so all of them are erased.
        erased = b["erasure_index"] if b["erasure_index"] >= 0 else 0
        assert b["record_signed"] or b["last_checkpoint_entry_count"] == b["entries"]
        covered = b["erasure_index"] >= 0 and b["last_checkpoint_entry_count"] > b["erasure_index"]
        chains[b["chain_id"]] = chain_result(
            "anchored" if covered else ("recorded" if b["erasure_index"] >= 0 else "none"),
            dict(entries=b["entries"], events=b["events"], erasures=1 if b["erasure_index"] >= 0 else 0,
                 opened=b["disclosed_events"], committed=b["events"] - b["disclosed_events"] - erased,
                 erased=erased, checkpoints=b["checkpoints"],
                 unanchored=b["entries"] - b["last_checkpoint_entry_count"],
                 authenticated=b["entries"], unauthenticated=0,
                 checkpoint_authenticated=b["last_checkpoint_entry_count"],
                 record_authenticated=b["entries"] if b["record_signed"] else 0,
                 record_signatures_present=b["entries"] if b["record_signed"] else 0))
    add("real_export", base64.b64decode(real["bundle_b64"]), BOTH, result(BOTH, chains),
        note="exported by `proof sink export --disclose all` from a real sink (scripts/bundlefixture); "
             "expected result derived from what was built")
    return out


def main() -> None:
    doc = {
        "_comment": "Bundle conformance vectors (docs/bundle-format.md §15), computed by scripts/bundle-vectors.py "
                    "from the spec: each case is built with one stated defect and its expected result declared "
                    "from that construction. Keys by name; the trust of a case names the keys a verifier is "
                    "given. Compare the parsed result (§9), never its bytes. `too-large` is not represented: "
                    "the limits (256 MiB, 10^6 entries) are impractical in a vector file.",
        "version": 1,
        "keys": {n: {k: v for k, v in key.items() if not k.startswith("_") and k != "name"}
                 for n, key in KEYS.items()},
        "cases": cases(),
    }
    mpath = os.path.join(ROOT, "fixtures", "MANIFEST.json")
    manifest = json.load(open(mpath))
    iv.write("bundle_v1_vectors.json", doc, manifest)
    manifest["vectors"] = dict(sorted(manifest["vectors"].items()))
    with open(mpath, "w") as f:
        f.write(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
