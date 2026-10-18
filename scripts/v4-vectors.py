#!/usr/bin/env python3
# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
"""Conformance vectors for chain format v4 and anchor v7, from the spec.

Every expected value is computed here from docs/format-spec.md (§2.0, §2.5,
§5.0, §9.2 to §9.5) with hashlib, hand-written encoders and dilithium-py, and
nothing from the Go module. If an implementation disagrees with a vector, the
implementation is wrong until the spec says otherwise.

    python3 scripts/v4-vectors.py

WRITES
    fixtures/testdata/chain_v4_vectors.json             leaf hash and chain hash v4
    fixtures/testdata/anchor_v7_canonical_vectors.json  anchor v7 bytes, hash, signature
    fixtures/testdata/record_v2_vectors.json            sink record.v2 envelope and signatures
                                                        (docs/sink-format.md §9.1)

and their entries in fixtures/MANIFEST.json.

Requires dilithium-py (as bundle-vectors.py and the Python SDK do), for the
anchor and record signatures only. Signing is deterministic (FIPS 204, rnd = 0^32), so the
signatures are fixed values.
"""
import base64
import hashlib
import importlib.util
import json
import os

from dilithium_py.ml_dsa import ML_DSA_65 as D

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TESTDATA = os.path.join(ROOT, "fixtures", "testdata")

# go_json_string and spki are shared with the v6 vectors so that both versions
# use one encoder; neither imports anything from the Go module.
_spec = importlib.util.spec_from_file_location("iv", os.path.join(HERE, "independent-vectors.py"))
iv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(iv)

MLDSA65_OID = "2.16.840.1.101.3.4.3.18"
SEED_ANCHOR_ID = "anchor_00000000-0000-0000-0000-000000000000"
SEED_ANCHOR_HASH = hashlib.sha512(b"aleutian.anchor.seed.v2").hexdigest()
ANCHOR_V7_CONTEXT = b"aleutian.proof.anchor.v7"


def sha512_hex(b: bytes) -> str:
    return hashlib.sha512(b).hexdigest()


def u32(n: int) -> bytes:
    return n.to_bytes(4, "big")


# ---------------------------------------------------------------------------
# Chain format v4 (§2.0):
#   leaf_hash  = SHA-512("aleutian.chain.leaf.v4:" ‖ len(id) ‖ id ‖ len(type) ‖ type
#                        ‖ content_hash ‖ salt)
#   chain_hash = SHA-512("aleutian.chain.v4:" ‖ prev ‖ "|" ‖ seq ‖ "|" ‖ ts ‖ "|" ‖ leaf_hash)
# id and type are UTF-8 AS GIVEN, never normalised; len is a 4-byte big-endian
# byte count; content_hash, salt and leaf_hash are lowercase hex TEXT.
# ---------------------------------------------------------------------------

def leaf_preimage(entry_id: str, entry_type: str, content_hash: str, salt: str) -> bytes:
    i, t = entry_id.encode("utf-8"), entry_type.encode("utf-8")
    return (b"aleutian.chain.leaf.v4:" + u32(len(i)) + i + u32(len(t)) + t
            + content_hash.encode("ascii") + salt.encode("ascii"))


def leaf_v4(entry_id: str, entry_type: str, content_hash: str, salt: str) -> str:
    return sha512_hex(leaf_preimage(entry_id, entry_type, content_hash, salt))


def chain_v4(prev: str, seq: int, ts: str, leaf: str) -> str:
    return sha512_hex(f"aleutian.chain.v4:{prev}|{seq}|{ts}|{leaf}".encode("ascii"))


def chain_v3(prev: str, seq: int, ts: str, content: str) -> str:
    return sha512_hex(f"aleutian.chain.v3:{prev}|{seq}|{ts}|{content}".encode("ascii"))


def salt_of(label: str) -> str:
    """A fixed 32-byte salt for a vector. A writer mints salts at random; a
    vector needs a fixed one."""
    return hashlib.sha256(b"v4 vector salt " + label.encode()).hexdigest()


def chain_v4_file() -> dict:
    c = [sha512_hex(f"v4 vector content {i}".encode()) for i in range(8)]
    t = [f"2026-10-16T08:00:{i:02d}.{i * 111111 % 1000000:06d}Z" for i in range(20)]
    vectors = []

    def live(name, prev, seq, ts, entry_id, entry_type, content, salt, note=None):
        leaf = leaf_v4(entry_id, entry_type, content, salt)
        v = {"name": name, "previous_hash": prev, "global_seq": str(seq), "timestamp": ts,
             "entry_id": entry_id, "entry_type": entry_type, "content_hash": content, "salt": salt,
             "leaf_preimage_hex": leaf_preimage(entry_id, entry_type, content, salt).hex(),
             "expected_leaf_hash": leaf, "expected_chain_hash": chain_v4(prev, seq, ts, leaf)}
        if note:
            v["note"] = note
        vectors.append(v)
        return v["expected_chain_hash"]

    def erased(name, prev, seq, ts, leaf, note=None):
        v = {"name": name, "erased": True, "previous_hash": prev, "global_seq": str(seq),
             "timestamp": ts, "leaf_hash": leaf, "expected_chain_hash": chain_v4(prev, seq, ts, leaf)}
        if note:
            v["note"] = note
        vectors.append(v)
        return v["expected_chain_hash"]

    h0 = live("first_entry", "", 0, t[0], "ent_0001", "event", c[0], salt_of("0"),
              "previous_hash empty and global_seq 0: the only shape a v4 first entry has")
    h1 = live("linked_entry", h0, 1, t[1], "ent_0002", "event", c[1], salt_of("1"))
    # The entry linked_entry describes, erased: id, type, content hash and salt
    # are gone, and the chain hash recomputes from the kept leaf hash.
    erased("erased_entry_recomputes_from_leaf_hash", h0, 1, t[1],
           leaf_v4("ent_0002", "event", c[1], salt_of("1")),
           "linked_entry after erasure: expected_chain_hash equals linked_entry's")
    h2 = live("pipe_in_entry_id", h1, 2, t[2], "a|b|c", "event", c[2], salt_of("2"),
              "length-prefixed, so | is allowed in an id")
    live("pipe_in_entry_type", h2, 3, t[3], "ent_0004", "type|with|pipes", c[3], salt_of("3"))
    live("non_ascii_entry_id_nfc", h2, 3, t[3], "café-€-\U0001F600", "event", c[3], salt_of("3"),
         "UTF-8 bytes as given")
    live("non_ascii_entry_id_nfd", h2, 3, t[3], "café-€-\U0001F600", "event", c[3], salt_of("3"),
         "the decomposed spelling of non_ascii_entry_id_nfc: a different id, so a different leaf; "
         "an implementation that normalises gets the NFC leaf here and fails")
    live("non_ascii_entry_type", h2, 3, t[3], "ent_0004", "événement", c[3], salt_of("3"))
    live("entry_id_256_bytes", h2, 3, t[3], "x" * 256, "event", c[3], salt_of("3"), "the longest id")
    live("entry_id_256_bytes_multibyte", h2, 3, t[3], "€" * 85 + "x", "event", c[3], salt_of("3"),
         "85 three-byte characters and one ASCII: 256 bytes, 86 characters")
    live("entry_id_one_byte", h2, 3, t[3], "x", "e", c[3], salt_of("3"))
    live("nel_and_nbsp_in_entry_id", h2, 3, t[3], "a\u0085b\u00a0c", "event", c[3], salt_of("3"),
         "U+0085 and U+00A0 are not control characters in §2.0's sense (U+0000 to U+001F, U+007F): allowed")
    live("printable_ascii_entry_id", h2, 3, t[3], "".join(chr(i) for i in range(0x20, 0x7f)), "event",
         c[3], salt_of("3"), "every printable ASCII character, including space, quote and backslash")
    live("salt_all_zero", h2, 3, t[3], "ent_0004", "event", c[3], "00" * 32,
         "a valid encoding; a writer never mints it, but a verifier hashes what it is given")
    live("salt_all_ff", h2, 3, t[3], "ent_0004", "event", c[3], "ff" * 32)
    live("same_entry_other_salt", h2, 3, t[3], "ent_0004", "event", c[3], salt_of("other"),
         "same id, type and content as salt_all_ff with another salt: unrelated leaf")
    live("content_hash_all_zero", h2, 3, t[3], "ent_0004", "event", "0" * 128, salt_of("3"))
    live("global_seq_above_2_pow_53", h2, 9007199254740993, t[4], "ent_big", "event", c[4], salt_of("4"),
         "global_seq is decimal ASCII; parse as a 64-bit integer")
    live("global_seq_max_int64", h2, 9223372036854775807, t[5], "ent_max", "event", c[5], salt_of("5"))
    live("timestamp_year_9999", h2, 3, "9999-12-31T23:59:59.999999Z", "ent_0004", "event", c[3], salt_of("3"))

    # §2.5: a v3 chain (here starting at 1, as the hosted platform's do) continued in v4.
    v3a = chain_v3("", 1, t[10], c[6])
    v3b = chain_v3(v3a, 2, t[11], c[7])
    live("continued_from_v3_head", v3b, 3, t[12], "ent_v4_first", "event", c[0], salt_of("cont"),
         "the first v4 entry of a continued chain; previous_hash is the v3 head, "
         "whose v3 entries are in v3_prefix")
    erased("erased_first_entry", "", 0, t[0], leaf_v4("ent_0001", "event", c[0], salt_of("0")),
           "first_entry after erasure")

    v3_prefix = [
        {"global_seq": "1", "timestamp": t[10], "content_hash": c[6], "previous_hash": "",
         "expected_chain_hash": v3a},
        {"global_seq": "2", "timestamp": t[11], "content_hash": c[7], "previous_hash": v3a,
         "expected_chain_hash": v3b},
    ]

    def rej(name, reason, **f):
        base = {"previous_hash": h1, "global_seq": "2", "timestamp": t[2], "entry_id": "ent_r",
                "entry_type": "event", "content_hash": c[2], "salt": salt_of("r")}
        base.update(f)
        return dict({"name": name, "reason": reason}, **base)

    reject = [
        rej("salt_31_bytes", "salt is not 64 lowercase hex", salt=salt_of("r")[:62]),
        rej("salt_33_bytes", "salt is not 64 lowercase hex", salt=salt_of("r") + "00"),
        rej("salt_uppercase", "salt is not 64 lowercase hex", salt=salt_of("r").upper()),
        rej("salt_empty", "salt is not 64 lowercase hex", salt=""),
        rej("entry_id_empty", "entry_id is empty", entry_id=""),
        rej("entry_type_empty", "entry_type is empty", entry_type=""),
        rej("entry_id_257_bytes", "entry_id is longer than 256 bytes", entry_id="x" * 257),
        rej("entry_id_control_character", "entry_id contains a control character", entry_id="a\nb"),
        rej("entry_id_del_character", "entry_id contains a control character", entry_id="a\x7fb"),
        rej("entry_type_control_character", "entry_type contains a control character", entry_type="ev\x00"),
        rej("tombstone_entry_type", "a v4 entry has no tombstone type", entry_type="tombstone"),
        rej("tomb_prefixed_entry_id", "a v4 entry has no tomb_ id", entry_id="tomb_0192f3a1"),
        rej("tombstone_content_hash", "a v4 content hash is 128 hex",
            content_hash="TOMBSTONE:" + "c3d4e5f6a1b2" * 5 + "c3d4"),
        rej("content_hash_uppercase", "content_hash is not 128 lowercase hex", content_hash=c[2].upper()),
        rej("content_hash_64_hex", "content_hash is not 128 lowercase hex", content_hash=c[2][:64]),
        rej("delimiter_in_previous_hash", "previous_hash is not empty or 128 lowercase hex",
            previous_hash=h1[:127] + "|"),
        rej("first_entry_not_at_zero", "an entry with an empty previous_hash has global_seq 0",
            previous_hash="", global_seq="1"),
        rej("linked_entry_at_zero", "an entry with a previous_hash has global_seq above 0", global_seq="0"),
        rej("negative_global_seq", "global_seq is negative", global_seq="-1"),
        rej("global_seq_leading_zero", "global_seq is not canonical decimal", global_seq="02"),
        rej("global_seq_above_int64", "global_seq exceeds 2^63-1", global_seq="9223372036854775808"),
        rej("timestamp_offset", "timestamp is not the §4 form", timestamp="2026-10-16T08:00:02.000000+00:00"),
        rej("timestamp_millis", "timestamp is not the §4 form", timestamp="2026-10-16T08:00:02.000Z"),
        {"name": "erased_leaf_hash_uppercase", "reason": "leaf_hash is not 128 lowercase hex",
         "erased": True, "previous_hash": h1, "global_seq": "2", "timestamp": t[2],
         "leaf_hash": leaf_v4("ent_r", "event", c[2], salt_of("r")).upper()},
        {"name": "erased_leaf_hash_short", "reason": "leaf_hash is not 128 lowercase hex",
         "erased": True, "previous_hash": h1, "global_seq": "2", "timestamp": t[2],
         "leaf_hash": leaf_v4("ent_r", "event", c[2], salt_of("r"))[:126]},
    ]
    return {
        "_comment": "Chain format v4 (docs/format-spec.md §2.0, §2.5, §5.0). leaf_hash = "
                    "SHA-512(\"aleutian.chain.leaf.v4:\" || len(entry_id) || entry_id || "
                    "len(entry_type) || entry_type || content_hash || salt), len a 4-byte "
                    "big-endian byte count, id and type UTF-8 as given and NEVER normalised, "
                    "content_hash and salt as lowercase hex text. chain_hash = "
                    "SHA-512(\"aleutian.chain.v4:\" || previous_hash || \"|\" || global_seq || "
                    "\"|\" || timestamp || \"|\" || leaf_hash). global_seq is carried as a "
                    "STRING because JSON numbers lose precision above 2^53. An 'erased' vector "
                    "has only leaf_hash: the chain hash recomputes from it. 'vectors' MUST "
                    "reproduce; every 'reject' case MUST be refused, by whichever check the "
                    "implementation makes first. v3_prefix holds the v3 entries "
                    "continued_from_v3_head links from (§2.5; v3 formula, §2.1). Computed in "
                    "Python (scripts/v4-vectors.py), independently of any implementation under test.",
        "leaf_domain": "aleutian.chain.leaf.v4:",
        "chain_domain": "aleutian.chain.v4:",
        "vectors": vectors,
        "v3_prefix": v3_prefix,
        "reject": reject,
    }


# ---------------------------------------------------------------------------
# Anchor v7 (§9.1 to §9.5).
# ---------------------------------------------------------------------------

def make_key(seed_byte: int) -> dict:
    seed = bytes([seed_byte]) * 32
    pk, sk = D.key_derive(seed)
    der = iv.spki(MLDSA65_OID, pk)
    kid = hashlib.sha512(b"proof.keyid.v1:" + der).digest()[:16].hex()
    return {"seed_hex": seed.hex(), "public_key_hex": pk.hex(), "key_id": kid, "_sk": sk}


def canonical_v7(a: dict) -> str:
    """§9.2: keys sorted; entry_count, end_seq and start_seq are JSON strings."""
    s, r = iv.go_json_string, a["range"]
    return ("{"
            f'"anchor_id":{s(a["anchor_id"])},'
            f'"chain_hash":{s(a["chain_hash"])},'
            f'"created_at_ms":{int(a["created_at_ms"])},'
            f'"entry_count":{s(a["entry_count"])},'
            f'"previous_anchor_hash":{s(a["previous_anchor_hash"])},'
            f'"previous_anchor_id":{s(a["previous_anchor_id"])},'
            f'"range":{{"end_seq":{s(r["end_seq"])},"start_seq":{s(r["start_seq"])}}},'
            f'"signing_key_id":{s(a["signing_key_id"])},'
            f'"subject":{s(a["subject"])},'
            f'"version":{int(a["version"])}'
            "}")


def anchor_chain_hash_v7(prev: str, subject: str, start_seq: int, end_seq: int, tip: str) -> str:
    """§9.4, v7: the subject length-prefixed, the range by sequence."""
    sb = subject.encode("utf-8")
    return sha512_hex(b"aleutian.anchor.v7:" + prev.encode() + b"|" + u32(len(sb)) + sb + b"|"
                      + str(start_seq).encode() + b"|" + str(end_seq).encode() + b"|" + tip.encode())


def anchor_text(a: dict) -> str:
    """An anchor as a file holds it: the canonical members plus the signature,
    in the same order and escaping. Any JSON spelling of the same members is
    equally valid input; this one is fixed so the text is reproducible."""
    return canonical_v7(a)[:-1] + f',"signature":{json.dumps(a["signature"])}' + "}"


def anchor_v7_file() -> dict:
    key = make_key(0x44)
    other = make_key(0x55)
    tip0 = sha512_hex(b"v7 tip 0")
    tip1 = sha512_hex(b"v7 tip 1")
    vectors = []

    def build(name, subject, start, end, tip, prev_hash, prev_id, anchor_id, created=1790000000000,
              note=None, signer=key):
        a = {"version": 7, "anchor_id": anchor_id, "subject": subject,
             "entry_count": str(end - start + 1), "created_at_ms": created,
             "previous_anchor_id": prev_id, "previous_anchor_hash": prev_hash,
             "range": {"start_seq": str(start), "end_seq": str(end)},
             "signing_key_id": signer["key_id"]}
        a["chain_hash"] = anchor_chain_hash_v7(prev_hash, subject, start, end, tip)
        canon = canonical_v7(a)
        sig = D.sign(signer["_sk"], canon.encode("utf-8"), ctx=ANCHOR_V7_CONTEXT, deterministic=True)
        a["signature"] = base64.b64encode(sig).decode()
        v = {"name": name, "anchor": a, "tip_chain_hash": tip, "canonical_bytes": canon,
             "canonical_sha512": sha512_hex(canon.encode("utf-8")),
             "expected_chain_hash": a["chain_hash"], "text": anchor_text(a)}
        if note:
            v["note"] = note
        vectors.append(v)
        return a

    first = build("first_anchor", "agent-actions", 0, 2, tip0, SEED_ANCHOR_HASH, SEED_ANCHOR_ID,
                  "anchor_0192f3a1-0000-7000-8000-000000000071",
                  note="the first anchor of a series carries the seed id and the seed hash")
    build("second_anchor", "agent-actions", 0, 5, tip1, first["chain_hash"], first["anchor_id"],
          "anchor_0192f3a1-0000-7000-8000-000000000072", created=1790000060000,
          note="previous_anchor_hash is first_anchor's chain_hash")
    build("range_from_one", "platform-chain", 1, 3, tip0, SEED_ANCHOR_HASH, SEED_ANCHOR_ID,
          "anchor_0192f3a1-0000-7000-8000-000000000073",
          note="a chain whose first entry is at global_seq 1 (v2/v3 permit it): entry_count = end - start + 1")
    build("sequence_above_2_pow_53", "agent-actions", 0, 9007199254740993, tip0, SEED_ANCHOR_HASH,
          SEED_ANCHOR_ID, "anchor_0192f3a1-0000-7000-8000-000000000074",
          note="entry_count and end_seq beyond what a JSON number carries exactly; strings keep them exact")
    build("pipe_in_subject", "a|b", 0, 0, tip0, SEED_ANCHOR_HASH, SEED_ANCHOR_ID,
          "anchor_0192f3a1-0000-7000-8000-000000000075", note="length-prefixed in the chain hash")
    build("html_escaping_in_subject", "a<b>&c", 0, 0, tip0, SEED_ANCHOR_HASH, SEED_ANCHOR_ID,
          "anchor_0192f3a1-0000-7000-8000-000000000076")
    build("non_ascii_subject", "sübjeçt-€", 0, 0, tip0, SEED_ANCHOR_HASH, SEED_ANCHOR_ID,
          "anchor_0192f3a1-0000-7000-8000-000000000077")

    # Must-refuse anchors, as file text. Each starts from first_anchor and
    # changes one thing; where a signature could still cover the change it is
    # re-signed, so that only the rule named in 'reason' refuses it.
    def resign(a, ctx=ANCHOR_V7_CONTEXT, canon_fn=None, signer=key):
        canon = canon_fn(a) if canon_fn else canonical_v7(a)
        a["signature"] = base64.b64encode(D.sign(signer["_sk"], canon.encode("utf-8"), ctx=ctx,
                                                 deterministic=True)).decode()
        return a

    def variant(**changes):
        a = json.loads(json.dumps(first))
        for k, v in changes.items():
            if k == "range":
                a["range"] = v
            else:
                a[k] = v
        return a

    reject = []

    def rej(name, reason, text):
        reject.append({"name": name, "reason": reason, "text": text})

    a = resign(variant(), ctx=b"")
    rej("signed_with_empty_context", "a v7 signature is verified with the context aleutian.proof.anchor.v7",
        anchor_text(a))
    a = resign(variant(), ctx=b"aleutian.proof.record.v2")
    rej("signed_with_record_context", "a v7 signature is verified with the context aleutian.proof.anchor.v7",
        anchor_text(a))
    a = resign(variant(), signer=other)
    rej("signed_by_another_key", "the signature does not verify under the named key", anchor_text(a))
    a = variant(subject="another-subject")
    rej("subject_changed_after_signing", "the signature does not cover the anchor", anchor_text(a))
    a = resign(variant(entry_count="4"))
    rej("entry_count_not_range_length", "entry_count must equal end_seq - start_seq + 1", anchor_text(a))
    a = resign(variant(range={"start_seq": "3", "end_seq": "2"}, entry_count="0"))
    rej("start_after_end", "start_seq must not exceed end_seq", anchor_text(a))
    a = resign(variant(range={"start_seq": "00", "end_seq": "2"}, entry_count="3"))
    rej("leading_zero_in_start_seq", "sequence numbers use §2.1's decimal grammar", anchor_text(a))
    a = resign(variant(subject=""))
    rej("empty_subject", "a v7 subject is non-empty", anchor_text(a))
    a = resign(variant(previous_anchor_hash=SEED_ANCHOR_HASH.upper()))
    rej("uppercase_previous_anchor_hash", "previous_anchor_hash is 128 lowercase hex", anchor_text(a))
    a = resign(variant(previous_anchor_id="anchor_0192f3a1-0000-7000-8000-000000000070"))
    rej("seed_hash_with_non_seed_id", "the seed id goes with the seed hash and no other", anchor_text(a))
    a = resign(variant(previous_anchor_hash=sha512_hex(b"some anchor")))
    rej("seed_id_with_non_seed_hash", "the seed id goes with the seed hash and no other", anchor_text(a))
    a = resign(variant(signing_key_id=""))
    rej("empty_signing_key_id", "signing_key_id is non-empty", anchor_text(a))
    a = resign(variant(anchor_id=""))
    rej("empty_anchor_id", "a v7 anchor_id is non-empty (§9.3)", anchor_text(a))
    a = resign(variant(previous_anchor_id="", previous_anchor_hash=sha512_hex(b"some anchor")))
    rej("empty_previous_anchor_id", "a v7 previous_anchor_id is non-empty (§9.3)", anchor_text(a))

    # Shapes that are not v7 at all: refused when parsed, before any signature.
    t = anchor_text(first)
    rej("entry_count_as_number", "v7 entry_count is a JSON string",
        t.replace('"entry_count":"3"', '"entry_count":3'))
    rej("range_seq_as_numbers", "v7 sequence numbers are JSON strings",
        t.replace('"range":{"end_seq":"2","start_seq":"0"}', '"range":{"end_seq":2,"start_seq":0}'))
    rej("range_by_entry_id", "a v7 range names start_seq and end_seq",
        t.replace('"range":{"end_seq":"2","start_seq":"0"}',
                  '"range":{"end_entry_id":"ent_0003","start_entry_id":"ent_0001"}'))
    rej("missing_previous_anchor_hash", "a v7 anchor carries previous_anchor_hash",
        t.replace(f'"previous_anchor_hash":"{SEED_ANCHOR_HASH}",', ""))
    rej("carries_verified_through", "v7 has no verified_through",
        t.replace('"version":7', '"verified_through":3,"version":7'))
    rej("company_id_instead_of_subject", "a v7 subject is under the name subject",
        t.replace('"subject":', '"company_id":'))
    rej("duplicate_subject", "each member at most once",
        t.replace('"version":7', '"subject":"other","version":7'))
    rej("unknown_member", "only the members of §9.1", t.replace('"version":7', '"root_hash":"00","version":7'))
    for member in ("anchor_id", "subject", "previous_anchor_id", "signing_key_id"):
        old = f'"{member}":{json.dumps(first[member])}'
        assert old in t, member
        rej(f"{member}_null", "no v7 member is null (§9.8)", t.replace(old, f'"{member}":null'))
    rej("created_at_ms_null", "no v7 member is null (§9.8)",
        t.replace(f'"created_at_ms":{first["created_at_ms"]}', '"created_at_ms":null'))
    rej("start_seq_null", "no v7 member is null (§9.8)", t.replace('"start_seq":"0"', '"start_seq":null'))
    rej("lone_surrogate_in_subject", "an anchor's text is refused if it escapes a lone surrogate (§9.8, §2.0)",
        t.replace('"subject":"agent-actions"', '"subject":"agent-actions\\ud800"'))
    raw = t.replace('"subject":"agent-actions"', '"subject":"agent-actions\x00"').encode().replace(b"\x00", b"\xff")
    reject.append({"name": "invalid_utf8_in_subject",
                   "reason": "an anchor's text is refused if it is not UTF-8 (§9.8, §2.0); text_base64 is its bytes",
                   "text": "", "text_base64": base64.b64encode(raw).decode()})

    return {
        "_comment": "Anchor v7 (docs/format-spec.md §9). canonical_bytes: compact JSON, keys "
                    "sorted, signature excluded, Go encoding/json escaping with HTML escaping on; "
                    "entry_count, start_seq and end_seq are JSON STRINGS. expected_chain_hash = "
                    "SHA-512(\"aleutian.anchor.v7:\" || previous_anchor_hash || \"|\" || "
                    "len(subject) || subject || \"|\" || start_seq || \"|\" || end_seq || \"|\" || "
                    "tip_chain_hash), len a 4-byte big-endian byte count. signature: ML-DSA-65, "
                    "pure, deterministic, context \"aleutian.proof.anchor.v7\", standard base64, "
                    "under key (derived from seed_hex; key_id per §9.6). 'text' is the anchor as "
                    "a file would hold it. Every 'vectors' text MUST verify under key; every "
                    "'reject' text (or text_base64, the exact bytes of a text that is not UTF-8) MUST be "
                    "refused, by whichever check the implementation makes first. message_prefix_hex is "
                    "the prefix FIPS 204 puts before the canonical bytes for this context, "
                    "0x00 || len(ctx) || ctx. Computed in Python (scripts/v4-vectors.py) with dilithium-py, "
                    "independently of any implementation under test.",
        "context": ANCHOR_V7_CONTEXT.decode(),
        # FIPS 204 §5.2: what pure ML-DSA signs is M' = 0x00 || len(ctx) || ctx || M.
        "message_prefix_hex": (b"\x00" + bytes([len(ANCHOR_V7_CONTEXT)]) + ANCHOR_V7_CONTEXT).hex(),
        "seed_anchor_hash": SEED_ANCHOR_HASH,
        "key": {k: v for k, v in key.items() if not k.startswith("_")},
        "vectors": vectors,
        "reject": reject,
    }


# ---------------------------------------------------------------------------
# Sink record envelope aleutian.proof.record.v2 (docs/sink-format.md §9.1):
#   "aleutian.proof.record.v2" 0x00 ‖ field(1, chain_id) ‖ … ‖ field(8, signing_key_id)
#   ‖ field(9, leaf_hash)
#   field(tag, v) = tag (1 byte) ‖ len(v) (uint32 big-endian) ‖ v
# signed with ML-DSA-65, pure, context "aleutian.proof.record.v2".
# ---------------------------------------------------------------------------

RECORD_V2_DOMAIN = b"aleutian.proof.record.v2"
RECORD_V2_CONTEXT = b"aleutian.proof.record.v2"
RECORD_V2_ORDER = iv.RECORD_ORDER + ["leaf_hash"]
SHA512_OID_DER = bytes.fromhex("0609608648016503040203")


def record_v2(f: dict) -> bytes:
    out = RECORD_V2_DOMAIN + b"\x00"
    for tag, name in enumerate(RECORD_V2_ORDER, start=1):
        v = f[name].encode("ascii")
        out += bytes([tag]) + u32(len(v)) + v
    return out


def mldsa_sign(sk: bytes, pk: bytes, msg: bytes, ctx: bytes, mode: str = "pure") -> bytes:
    """ML-DSA-65, deterministic (rnd = 0^32). mode "pure" is FIPS 204 ML-DSA.Sign
    with ctx; "hashml" is HashML-DSA with SHA-512 and the same ctx (Algorithm 4:
    M' = 1 ‖ len(ctx) ‖ ctx ‖ OID ‖ SHA-512(M)), which a pure verifier refuses."""
    if mode == "pure":
        return D.sign(sk, msg, ctx=ctx, deterministic=True)
    if mode == "hashml":
        m_prime = bytes([1, len(ctx)]) + ctx + SHA512_OID_DER + hashlib.sha512(msg).digest()
        tr = hashlib.shake_256(pk).digest(64)
        mu = hashlib.shake_256(tr + m_prime).digest(64)
        return D.sign_external_mu(sk, mu, deterministic=True)
    raise ValueError(mode)


def record_v2_file() -> dict:
    seed = bytes([0x66]) * 32
    pk, sk = D.key_derive(seed)
    der = iv.spki(MLDSA65_OID, pk)
    kid = hashlib.sha512(b"proof.keyid.v1:" + der).digest()[:16].hex()
    prev = sha512_hex(b"record v2 previous entry")

    def leaf_fields(entry_id, entry_type, content_hash, salt):
        return {"entry_id": entry_id, "entry_type": entry_type, "content_hash": content_hash,
                "leaf_hash": leaf_v4(entry_id, entry_type, content_hash, salt)}

    event_salt = salt_of("record v2 event")
    event = {
        "chain_id": "payments.0123456789abcdef0123456789abcdef",
        "entry_id": "sink-fedcba9876543210fedcba9876543210",
        "entry_type": "sink.event",
        "global_seq": "41",
        "previous_hash": prev,
        "timestamp": "2026-09-30T12:00:00.123456Z",
        "content_hash": sha512_hex(b"record v2 content"),
        "signing_key_id": kid,
    }
    event["leaf_hash"] = leaf_v4(event["entry_id"], event["entry_type"], event["content_hash"], event_salt)
    record = b'{"erased":"every earlier event on this chain","through_global_seq":"41"}'
    instant_ns = 1790769600 * 1_000_000_000 + 123_456_789
    erasure_salt = salt_of("record v2 erasure")
    erasure_id, erasure_ch = "sink-00000000000000000000000000000042", sha512_hex(b"aleutian.sink.erasure.v1:" + record)
    cases = [
        ("event", {}, event_salt, None),
        ("erasure", dict(leaf_fields(erasure_id, "sink.erasure", erasure_ch, erasure_salt), global_seq="42"),
         erasure_salt, None),
        ("first_entry_seq_0_no_previous", {"global_seq": "0", "previous_hash": ""}, event_salt, None),
        ("seq_2_pow_63_minus_1", {"global_seq": str(2**63 - 1)}, event_salt, None),
        ("longest_class", {"chain_id": "a" * 31 + ".0123456789abcdef0123456789abcdef"}, event_salt, None),
        ("zero_microseconds", {"timestamp": "2026-01-01T00:00:00.000000Z"}, event_salt, None),
        ("nanoseconds_truncated", {"timestamp": iv.timestamp_from_unix_ns(instant_ns)}, event_salt, instant_ns),
        ("other_salt", leaf_fields(event["entry_id"], "sink.event", event["content_hash"], salt_of("other")),
         salt_of("other"), None),
    ]
    vectors = []
    by_name = {}
    for name, override, salt, ns in cases:
        f = dict(event, **override)
        assert f["leaf_hash"] == leaf_v4(f["entry_id"], f["entry_type"], f["content_hash"], salt)
        env = record_v2(f)
        v = {"name": name, "fields": f, "salt": salt, "envelope_hex": env.hex(),
             "envelope_sha512": sha512_hex(env)}
        if ns is not None:
            v["timestamp_unix_ns"] = str(ns)
        if name == "other_salt":
            v["note"] = "the event vector with another salt: only leaf_hash (0x09) differs, so the envelope does"
        vectors.append(v)
        by_name[name] = f

    reject = [
        ("chain_id_upper_case", {"chain_id": "Payments.0123456789abcdef0123456789abcdef"}),
        ("entry_id_not_sink", {"entry_id": "ent_000"}),
        ("entry_type_unknown", {"entry_type": "tombstone"}),
        ("global_seq_leading_zero", {"global_seq": "041"}),
        ("global_seq_plus_sign", {"global_seq": "+41"}),
        ("global_seq_negative", {"global_seq": "-1"}),
        ("global_seq_above_int64", {"global_seq": "9223372036854775808"}),
        ("previous_hash_empty_after_first", {"previous_hash": ""}),
        ("previous_hash_on_first", {"global_seq": "0"}),
        ("previous_hash_upper_case", {"previous_hash": prev.upper()}),
        ("timestamp_not_utc", {"timestamp": "2026-09-30T14:00:00.123456+02:00"}),
        ("timestamp_millis", {"timestamp": "2026-09-30T12:00:00.123Z"}),
        ("timestamp_year_0", {"timestamp": "0000-01-01T00:00:00.000000Z"}),
        ("content_hash_upper_case", {"content_hash": sha512_hex(b"x").upper()}),
        ("content_hash_tombstone", {"content_hash": "TOMBSTONE:" + "0" * 64}),
        ("key_id_short", {"signing_key_id": kid[:8]}),
        ("key_id_upper_case", {"signing_key_id": kid.upper()}),
        ("leaf_hash_upper_case", {"leaf_hash": event["leaf_hash"].upper()}),
        ("leaf_hash_short", {"leaf_hash": event["leaf_hash"][:126]}),
        ("leaf_hash_empty", {"leaf_hash": ""}),
        ("leaf_hash_64_hex", {"leaf_hash": event["leaf_hash"][:64]}),
    ]

    def sig(vector, valid, note, msg, ctx, mode="pure"):
        return {"vector": vector, "valid": valid, "note": note,
                "signature_hex": mldsa_sign(sk, pk, msg, ctx, mode).hex()}

    ev, er, first = by_name["event"], by_name["erasure"], by_name["first_entry_seq_0_no_previous"]
    v1_of = {k: ev[k] for k in iv.RECORD_ORDER}
    signatures = [
        sig("event", True, "over the v2 envelope, context aleutian.proof.record.v2", record_v2(ev), RECORD_V2_CONTEXT),
        sig("erasure", True, "over the v2 envelope, context aleutian.proof.record.v2", record_v2(er),
            RECORD_V2_CONTEXT),
        sig("first_entry_seq_0_no_previous", True, "over the v2 envelope, context aleutian.proof.record.v2",
            record_v2(first), RECORD_V2_CONTEXT),
        sig("event", False, "the v2 envelope signed with the EMPTY context: a v2 verifier MUST refuse it",
            record_v2(ev), b""),
        sig("event", False, "the v2 envelope signed with the anchor context aleutian.proof.anchor.v7",
            record_v2(ev), ANCHOR_V7_CONTEXT),
        sig("event", False, "HashML-DSA (SHA-512) over the v2 envelope with the v2 context: proof uses pure ML-DSA",
            record_v2(ev), RECORD_V2_CONTEXT, "hashml"),
        sig("event", False, "the record.v1 envelope of the same entry (fields 0x01-0x08, empty context): "
            "a v1 signature never verifies as v2", iv.record_v1(v1_of), b""),
        sig("event", False, "the record.v1 envelope of the same entry, with the v2 context", iv.record_v1(v1_of),
            RECORD_V2_CONTEXT),
        sig("other_salt", False, "the event vector's signature presented for other_salt: the salt is bound "
            "through leaf_hash", record_v2(ev), RECORD_V2_CONTEXT),
    ]
    return {
        "_comment": "Sink record-signing envelope aleutian.proof.record.v2 (docs/sink-format.md §9.1): the "
                    "exact bytes an ML-DSA-65 record signature over a chain-format-v4 entry covers. Domain "
                    "\"aleutian.proof.record.v2\" then 0x00, then nine fields in fixed order, each tag (1 byte) "
                    "|| length (uint32 big-endian) || ASCII value: 0x01-0x08 as record.v1 (chain_id, entry_id, "
                    "entry_type, global_seq, previous_hash, timestamp, content_hash, signing_key_id), then 0x09 "
                    "leaf_hash (format-spec §2.0, 128 lowercase hex). Each vector's salt is not in the envelope; "
                    "it is given so that leaf_hash can be recomputed. reject lists field values a signer MUST "
                    "refuse and a verifier MUST report unverifiable (record.v1's rules, plus leaf_hash's shape). "
                    "signatures: ML-DSA-65, pure, deterministic (rnd = 0^32), made in Python with dilithium-py "
                    "under key (seed_hex; key_id per format-spec §9.6, the vectors' signing_key_id). A v2 "
                    "verifier verifies over the vector's envelope with the context \"aleutian.proof.record.v2\": "
                    "valid true MUST verify, valid false MUST NOT. Computed in Python (scripts/v4-vectors.py), "
                    "independently of any implementation under test.",
        "version": 1,
        "domain": RECORD_V2_DOMAIN.decode(),
        "context": RECORD_V2_CONTEXT.decode(),
        "key": {"seed_hex": seed.hex(), "public_key_hex": pk.hex(), "key_id": kid},
        "vectors": vectors,
        "reject": [{"name": n, "fields": dict(event, **o)} for n, o in reject],
        "signatures": signatures,
    }


def write(name: str, obj, manifest: dict) -> None:
    raw = (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    with open(os.path.join(TESTDATA, name), "wb") as f:
        f.write(raw)
    manifest["vectors"][name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def main() -> None:
    mpath = os.path.join(ROOT, "fixtures", "MANIFEST.json")
    manifest = json.load(open(mpath))
    write("chain_v4_vectors.json", chain_v4_file(), manifest)
    write("anchor_v7_canonical_vectors.json", anchor_v7_file(), manifest)
    write("record_v2_vectors.json", record_v2_file(), manifest)
    manifest["vectors"] = dict(sorted(manifest["vectors"].items()))
    with open(mpath, "w") as f:
        f.write(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
