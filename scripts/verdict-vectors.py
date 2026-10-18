#!/usr/bin/env python3
# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
"""Verifier verdict vectors, written from docs/format-spec.md alone.

The hash vectors say what one hash is. These say what a VERIFIER concludes
about a whole chain, an entries file, an anchor's text, and a keyless bind of
an anchor to a chain: format-spec §4, §5.5, §9.4 and §9.8. Each case is a valid
chain with one stated defect, and its expected result is declared from that
construction, never computed by an implementation under test.

    python3 scripts/verdict-vectors.py

writes fixtures/testdata/verify_verdict_vectors.json (v2 and v3 chains, v6
anchors: FROZEN, its cases never change) and verify_verdict_v4_vectors.json
(chain format v4, continued chains and v7 anchors: §2.0, §2.5, §5.0, §9.7), and
their entries in fixtures/MANIFEST.json. Standard library only: no case needs a
signature.
"""

import copy
import hashlib
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTDATA = os.path.join(ROOT, "fixtures", "testdata")

SEED_ANCHOR_HASH = hashlib.sha512(b"aleutian.anchor.seed.v2").hexdigest()
SEED_ANCHOR_ID = "anchor_00000000-0000-0000-0000-000000000000"
SUBJECT = "vector-subject"



# The note every frozen file's _comment opens with.
FROZEN = ("FROZEN: this format is verified forever and never written after v0.5.0 (docs/format-spec.md "
          "§2.6, bundle-format.md §16); these cases will never change. ")

def sha512_hex(b: bytes) -> str:
    return hashlib.sha512(b).hexdigest()


def chain_v3(prev: str, seq: int, ts: str, content: str) -> str:
    """format-spec §2.1."""
    return sha512_hex(f"aleutian.chain.v3:{prev}|{seq}|{ts}|{content}".encode())


def anchor_chain_hash(prev_anchor_hash: str, subject: str, start_id: str, end_id: str, tip: str) -> str:
    """format-spec §9.4."""
    return sha512_hex(f"aleutian.anchor.v2:{prev_anchor_hash}|{subject}|{start_id}|{end_id}|{tip}".encode())


def ts(i: int) -> str:
    return f"2026-10-12T09:00:{i:02d}.000000Z"


def entry(i: int, seq: int, prev: str, content: str = None, timestamp: str = None) -> dict:
    content = content if content is not None else sha512_hex(f"evidence {i}".encode())
    timestamp = timestamp or ts(i)
    return {
        "entry_id": f"ent_{i:02d}", "entry_type": "event", "timestamp": timestamp,
        "format_version": 3, "run_id": "", "sequence_num": 0, "global_seq": seq,
        "content_hash": content, "chain_hash": chain_v3(prev, seq, timestamp, content),
    }


def chain(n: int, start: int = 0) -> list:
    out, prev = [], ""
    for i in range(n):
        e = entry(i, start + i, prev)
        out.append(e)
        prev = e["chain_hash"]
    return out


def relink(entries: list, parse_ts=lambda e: e["timestamp"]) -> list:
    """Recompute every chain hash from the entries' current fields, as someone
    with write access to the store would after an edit."""
    prev = ""
    for e in entries:
        e["chain_hash"] = chain_v3(prev, e["global_seq"], parse_ts(e), e["content_hash"])
        prev = e["chain_hash"]
    return entries


def tombstone(e: dict) -> dict:
    """format-spec §5: content hash replaced, type and id changed, chain hash kept."""
    e["entry_type"] = "tombstone"
    e["entry_id"] = "tomb_00000000-0000-0000-0000-000000000000"
    e["content_hash"] = "TOMBSTONE:" + "ab" * 32
    return e


INTACT = {"verdict": "INTACT", "first_break": -1, "first_break_type": "", "tombstones_found": 0, "last_tombstone": -1}


def broken(at: int, kind: str, **more) -> dict:
    return {**INTACT, "verdict": "BROKEN", "first_break": at, "first_break_type": kind, **more}


def chain_cases() -> list:
    cases = []

    def add(name, why, entries, expected, previous_hash=""):
        cases.append({"name": name, "why": why, "previous_hash": previous_hash,
                      "entries": entries, "expected": expected})

    add("intact", "four well-formed v3 entries", chain(4), INTACT)
    add("starts_at_global_seq_1", "§5.5: the first global_seq is not fixed; the hosted platform starts at 1",
        chain(4, start=1), INTACT)
    add("starts_at_global_seq_1001", "§5.5: nor is a later start a break", chain(4, start=1001), INTACT)

    c = chain(4)
    c[2]["content_hash"] = sha512_hex(b"something else")
    add("content_edited", "an edited content hash no longer hashes to the stored chain hash", c,
        broken(2, "hash_mismatch"))

    c = chain(4)
    c[3]["global_seq"] = 7
    add("sequence_gap", "global_seq must rise by one", c, broken(3, "sequence_gap"))

    # §4: one spelling of a timestamp. Each of these names the instant the entry
    # was hashed at, so the stored chain hash still matches; only the stored
    # form is wrong.
    for name, spelled in [
        ("timestamp_in_another_offset", "2026-10-12T14:30:01.000000+05:30"),
        ("timestamp_with_no_fraction", "2026-10-12T09:00:01Z"),
        ("timestamp_with_nanoseconds", "2026-10-12T09:00:01.000000999Z"),
        ("timestamp_lowercase_z", "2026-10-12T09:00:01.000000z"),
    ]:
        c = chain(4)
        c[1]["timestamp"] = spelled
        add(name, "§4: a stored timestamp in any spelling but YYYY-MM-DDTHH:MM:SS.ffffffZ is a break, "
            "even though it names the instant that was hashed", c, broken(1, "invalid_timestamp"))

    c = chain(4)
    c[1]["timestamp"] = "yesterday"
    add("timestamp_unparseable", "§4", c, broken(1, "invalid_timestamp"))

    # §5.5: field shapes are checked before recomputing. Each chain is re-linked
    # after the edit, so every stored chain hash is the hash of the fields.
    c = chain(4)
    c[1]["content_hash"] = "not|a|hash"
    add("content_hash_not_a_digest", "§5.5: re-linked, so the hashes agree; the shape does not",
        relink(c), broken(1, "invalid_field"))
    c = chain(4)
    c[1]["content_hash"] = "AB" * 64
    add("content_hash_uppercase", "§5.5: lowercase hex", relink(c), broken(1, "invalid_field"))
    c = chain(4)
    c[1]["content_hash"] = "ab" * 32
    add("content_hash_64_hex", "§2: a content hash is SHA-512, 128 hex characters", relink(c),
        broken(1, "invalid_field"))
    c = chain(4)
    for i, e in enumerate(c):
        e["global_seq"] = i - 7
    add("negative_global_seq", "§5.5", relink(c), broken(0, "invalid_field"))
    c = chain(4)
    c[2]["chain_hash"] = "short"
    add("chain_hash_not_a_digest", "§5.5: on any entry", c, broken(2, "invalid_field"))

    c = chain(4)
    c[1]["format_version"] = 99
    add("unknown_format_version", "§2.2: never guessed", c, broken(1, "unknown_format"))
    c = chain(4)
    c[1]["run_id"] = "run-1"
    add("v3_entry_carrying_run_id", "§2.2: v3 binds neither run_id nor sequence_num", c,
        broken(1, "format_field_misuse"))

    # §5: tombstones.
    c = chain(5)
    tombstone(c[2])
    add("tombstone", "§5.1: an erased entry is not a break; its stored chain hash is carried forward", c,
        {**INTACT, "tombstones_found": 1, "last_tombstone": 2})

    c = chain(5)
    c[2]["content_hash"] = "TOMBSTONE:" + "ab" * 32
    add("tombstone_content_hash_on_an_ordinary_entry",
        "§5.5: the content hash alone does not make a tombstone; the entry is recomputed and does not match",
        c, broken(2, "hash_mismatch"))

    c = chain(5)
    tombstone(c[2])
    c[2]["content_hash"] = "TOMBSTONE:BADDATA"
    add("tombstone_with_a_malformed_content_hash", "§5", c,
        broken(2, "invalid_tombstone", tombstones_found=1, last_tombstone=2))

    c = chain(5)
    tombstone(c[2])
    c[2]["chain_hash"] = "a|b"
    add("tombstone_with_a_malformed_chain_hash", "§5.5: chain_hash is a digest on every entry, tombstones included",
        c, broken(2, "invalid_field"))

    c = chain(5)
    tombstone(c[2])
    c[2]["format_version"] = 99
    add("tombstone_with_an_unknown_format", "§5.5: what a tombstone declares is still checked", c,
        broken(2, "unknown_format", tombstones_found=1, last_tombstone=2))

    c = chain(5)
    tombstone(c[2])
    c[2]["run_id"] = "run-1"
    add("v3_tombstone_carrying_run_id", "§5.5", c,
        broken(2, "format_field_misuse", tombstones_found=1, last_tombstone=2))

    # The limitation, pinned (§5.5): entries before a tombstone can be replaced.
    c = chain(5)
    c[0]["content_hash"] = sha512_hex(b"forged 0")
    c[1]["content_hash"] = sha512_hex(b"forged 1")
    relinked = relink(copy.deepcopy(c[:2]))
    c[0], c[1] = relinked[0], relinked[1]
    tombstone(c[2])
    add("entries_before_a_tombstone_rewritten",
        "§5.5, THE LIMITATION: this chain was tampered with and verifies. A verifier cannot detect it and "
        "MUST report last_tombstone so the caller knows entries 0 to 2 are not verified", c,
        {**INTACT, "tombstones_found": 1, "last_tombstone": 2})

    # A tombstone's timestamp is not checked: its hash is never recomputed, and
    # the row was rewritten by whatever erased it.
    c = chain(5)
    tombstone(c[2])
    c[2]["timestamp"] = "2026-10-12T09:00:02Z"
    add("tombstone_with_another_timestamp_spelling",
        "§5.5: the only checks on a tombstone are its chain hash shape, its content hash format, its "
        "declared format and global_seq", c, {**INTACT, "tombstones_found": 1, "last_tombstone": 2})

    c = chain(4)
    c[1]["timestamp"] = "2026-02-30T09:00:01.000000Z"
    add("timestamp_that_is_not_a_real_instant", "§4: the right shape, and no such day", c,
        broken(1, "invalid_timestamp"))

    # Two defects in one entry: the first break reported is the same everywhere.
    c = chain(4)
    c[1]["timestamp"] = "2026-10-12T09:00:01Z"
    c[1]["content_hash"] = "not|a|hash"
    add("two_defects_timestamp_before_field_shape",
        "§5.5: the timestamp is judged before the other field shapes", c, broken(1, "invalid_timestamp"))
    c = chain(4)
    c[1]["chain_hash"] = "short"
    c[1]["timestamp"] = "yesterday"
    add("two_defects_chain_hash_shape_first", "§5.5: chain_hash is checked first on every entry", c,
        broken(1, "invalid_field"))
    c = chain(4)
    c[1]["format_version"] = 99
    c[1]["content_hash"] = "not|a|hash"
    add("two_defects_unknown_format_before_field_shape",
        "§5.5: an entry of an unknown format has no field shapes to judge", c, broken(1, "unknown_format"))

    c = chain(4)
    add("segment_with_its_predecessor_hash", "a segment links from the hash supplied", c[2:], INTACT,
        previous_hash=c[1]["chain_hash"])
    add("segment_without_its_predecessor_hash", "and from nothing, it does not", chain(4)[2:],
        broken(0, "hash_mismatch"))
    add("malformed_previous_hash", "§5.5: the supplied predecessor hash is a digest", chain(4)[2:],
        broken(0, "invalid_field"), previous_hash="abc")
    return cases


def entries_text_cases() -> list:
    good = json.dumps(chain(1)[0], separators=(",", ":"))
    two = [json.dumps(e, separators=(",", ":")) for e in chain(2)]
    out = [
        {"name": "array", "text": "[" + ",".join(two) + "]", "expected": "entries"},
        {"name": "jsonl", "text": "\n".join(two) + "\n", "expected": "entries"},
        {"name": "an_unknown_member", "text": "[" + good.replace("{", '{"producer":"x",', 1) + "]",
         "expected": "entries"},
        {"name": "only_the_required_members",
         "text": json.dumps([{k: chain(1)[0][k] for k in ("entry_id", "timestamp", "content_hash", "chain_hash")}]),
         "expected": "entries"},
    ]
    for name, text in [
        ("empty", "  \n"),
        ("an_empty_object", "{}"),
        ("null", "null"),
        ("an_empty_array", "[]"),
        ("an_array_of_null", "[null]"),
        ("an_export_bundle", '{"format":"aleutian.proof.bundle.v1","chains":[]}'),
        ("an_anchor", '{"version":6,"subject":"s","chain_hash":"aa","entry_count":1}'),
        ("a_member_twice", good.replace('"global_seq":', '"global_seq":7,"global_seq":', 1)),
        ("a_member_in_another_case", good.replace('"chain_hash":', '"CHAIN_HASH":', 1)),
        ("no_chain_hash", good.replace('"chain_hash":', '"other":', 1)),
        ("a_member_of_another_type", good.replace('"global_seq":0', '"global_seq":"0"', 1)),
        ("two_objects_on_one_line", good + good),
        ("an_array_that_is_not_json", "[" + good),
    ]:
        out.append({"name": name, "text": text, "expected": "not_entries"})
    return out


def anchor_for(entries: list, prev_hash: str = SEED_ANCHOR_HASH, prev_id: str = SEED_ANCHOR_ID) -> dict:
    first, last = entries[0], entries[-1]
    return {
        "subject": SUBJECT, "version": 6,
        "anchor_id": "anchor_11111111-1111-1111-1111-111111111111",
        "chain_hash": anchor_chain_hash(prev_hash, SUBJECT, first["entry_id"], last["entry_id"], last["chain_hash"]),
        "range": {"start_entry_id": first["entry_id"], "end_entry_id": last["entry_id"]},
        "entry_count": len(entries), "signature": "", "signing_key_id": "vector-key",
        "created_at_ms": 1791795600000, "previous_anchor_id": prev_id, "verified_through": len(entries),
    }


def anchor_text_cases() -> list:
    good = json.dumps(anchor_for(chain(3)), separators=(",", ":"))
    out = [{"name": "well_formed_v6", "text": good, "expected": "parses"}]
    for name, text in [
        ("an_unknown_member", good.replace('"version":', '"root_hash":"aa","version":', 1)),
        ("a_member_in_another_case", good.replace('"entry_count":', '"ENTRY_COUNT":', 1)),
        ("a_member_twice", good.replace('"entry_count":', '"entry_count":1,"entry_count":', 1)),
        ("v6_with_the_legacy_subject_name", good.replace('"subject":', '"company_id":', 1)),
        ("both_subject_names", good.replace('"subject":', '"company_id":"vector-subject","subject":', 1)),
        ("an_unknown_member_in_range", good.replace('"start_entry_id":', '"extra":1,"start_entry_id":', 1)),
        ("a_range_member_twice", good.replace('"end_entry_id":', '"end_entry_id":"x","end_entry_id":', 1)),
        ("trailing_data", good + "{}"),
        ("not_an_object", "[]"),
        ("v4_with_the_new_subject_name", '{"version":4,"subject":"vector-subject"}'),
    ]:
        out.append({"name": name, "text": text, "expected": "refused"})
    return out


def bind_cases() -> list:
    """Keyless binds (BindAnchor): no signature is checked."""
    cases = []
    c = chain(5)

    def add(name, why, entries, anchor, prev_hash, expected):
        cases.append({"name": name, "why": why, "entries": entries, "anchor": anchor,
                      "previous_anchor_hash": prev_hash, "expected": expected})

    def outcome(o, bound=False, tombstones=0, not_bound=0):
        return {"error": False, "outcome": o, "bound": bound, "tombstones": tombstones, "entries_not_bound": not_bound}

    add("bound", "§9.7", c, anchor_for(c), SEED_ANCHOR_HASH, outcome("bound", True))

    edited = copy.deepcopy(c)
    edited[2]["content_hash"] = sha512_hex(b"something else")
    add("chain_broken", "the chain does not verify, so nothing is bound", edited, anchor_for(c),
        SEED_ANCHOR_HASH, outcome("chain_broken"))

    kept = relink([dict(e, global_seq=i) for i, e in enumerate(copy.deepcopy(c[1:]))])
    add("truncated_from_the_front_and_relinked",
        "the remainder verifies on its own; the anchor's committed first entry is gone", kept, anchor_for(c),
        SEED_ANCHOR_HASH, outcome("range_start_mismatch"))
    add("truncated_from_the_end", "", c[:4], anchor_for(c), SEED_ANCHOR_HASH, outcome("range_end_mismatch"))

    a = anchor_for(c)
    a["entry_count"], a["verified_through"] = 4, 4
    add("height_mismatch", "entry_count is not the chain's length", c, a, SEED_ANCHOR_HASH,
        outcome("height_mismatch"))

    add("wrong_predecessor_hash", "§9.4: the predecessor's hash is inside the anchor's own",
        c, anchor_for(c, "ab" * 64, "anchor_22222222-2222-2222-2222-222222222222"), "cd" * 64,
        outcome("head_mismatch"))

    a = anchor_for(c)
    a["previous_anchor_id"] = "anchor_22222222-2222-2222-2222-222222222222"
    add("first_anchor_naming_a_predecessor", "§9.8: the seed hash goes with the seed id only", c, a,
        SEED_ANCHOR_HASH, outcome("predecessor_mismatch"))
    add("later_anchor_naming_the_seed", "§9.8", c, anchor_for(c, "ab" * 64, SEED_ANCHOR_ID), "ab" * 64,
        outcome("predecessor_mismatch"))

    grown = chain(7)
    add("chain_grown_since_the_anchor",
        "§9.7: a bind is over exactly the entries given. The caller passes the prefix the anchor covers; "
        "given the grown chain, the anchor's last entry is not the last entry",
        grown, anchor_for(grown[:5]), SEED_ANCHOR_HASH, outcome("range_end_mismatch"))

    broken_with_tombstone = copy.deepcopy(c)
    tombstone(broken_with_tombstone[1])
    broken_with_tombstone[3]["content_hash"] = sha512_hex(b"something else")
    add("chain_broken_after_a_tombstone",
        "the counts are what the walk saw, whatever the outcome", broken_with_tombstone, anchor_for(c),
        SEED_ANCHOR_HASH, outcome("chain_broken", tombstones=1, not_bound=2))

    a = anchor_for(c)
    a["previous_anchor_id"] = "anchor_22222222-2222-2222-2222-222222222222"
    a["chain_hash"] = "ef" * 64
    add("predecessor_checked_before_the_head",
        "§9.8: two defects, a first anchor naming a predecessor and a wrong head; the predecessor is reported",
        c, a, SEED_ANCHOR_HASH, outcome("predecessor_mismatch"))

    a = anchor_for(c)
    a["verified_through"] = 0
    add("v6_without_verified_through", "§9.3: refused as malformed", c, a, SEED_ANCHOR_HASH, {"error": True})

    a = anchor_for(c)
    a["verified_through"] = 999999
    add("verified_through_above_entry_count", "§9.8: refused as a malformed anchor, not reported as an outcome",
        c, a, SEED_ANCHOR_HASH, {"error": True})
    a = anchor_for(c)
    a["created_at_ms"] = -5
    add("created_before_the_epoch", "§9.8", c, a, SEED_ANCHOR_HASH, {"error": True})

    # The tombstone on the anchor's last entry changes its id, so tombstone a
    # middle entry: the anchor still binds, and the result says what it leaves unbound.
    erased = copy.deepcopy(c)
    tombstone(erased[2])
    add("bound_over_a_tombstone",
        "§5.5: a lawful erasure does not break the anchor, and the result reports that entries 0 to 2 are not bound",
        erased, anchor_for(c), SEED_ANCHOR_HASH, outcome("bound", True, tombstones=1, not_bound=3))

    forged = copy.deepcopy(c)
    forged[0]["content_hash"] = sha512_hex(b"forged 0")
    forged[1]["content_hash"] = sha512_hex(b"forged 1")
    r = relink(copy.deepcopy(forged[:2]))
    forged[0], forged[1] = r[0], r[1]
    tombstone(forged[2])
    add("entries_before_a_tombstone_rewritten",
        "§5.5, THE LIMITATION: tampered, and it binds. entries_not_bound is what tells the caller",
        forged, anchor_for(c), SEED_ANCHOR_HASH, outcome("bound", True, tombstones=1, not_bound=3))

    forged = copy.deepcopy(c)
    for e in forged[:4]:
        e["content_hash"] = sha512_hex(b"forged " + e["entry_id"].encode())
    r = relink(copy.deepcopy(forged[:4]))
    forged[:4] = r
    forged[4]["content_hash"] = "TOMBSTONE:" + "00" * 32
    add("last_entry_given_a_tombstone_content_hash",
        "§5.5: one tombstone rule in every path. The last entry keeps its chain hash and takes a TOMBSTONE: "
        "content hash, with every other entry replaced; it is not a tombstone, and the chain is broken",
        forged, anchor_for(c), SEED_ANCHOR_HASH, outcome("chain_broken"))
    return cases


# ---------------------------------------------------------------------------
# Chain format v4 and anchor v7 (format-spec §2.0, §2.5, §5.0, §9.7).
# ---------------------------------------------------------------------------

def u32(n: int) -> bytes:
    return n.to_bytes(4, "big")


def leaf_v4(entry_id: str, entry_type: str, content: str, salt: str) -> str:
    """format-spec §2.0."""
    i, t = entry_id.encode(), entry_type.encode()
    return sha512_hex(b"aleutian.chain.leaf.v4:" + u32(len(i)) + i + u32(len(t)) + t
                      + content.encode() + salt.encode())


def chain_v4(prev: str, seq: int, ts_: str, leaf: str) -> str:
    """format-spec §2.0."""
    return sha512_hex(f"aleutian.chain.v4:{prev}|{seq}|{ts_}|{leaf}".encode())


def anchor_chain_hash_v7(prev: str, subject: str, start: int, end: int, tip: str) -> str:
    """format-spec §9.4, v7."""
    sb = subject.encode()
    return sha512_hex(b"aleutian.anchor.v7:" + prev.encode() + b"|" + u32(len(sb)) + sb + b"|"
                      + f"{start}|{end}|{tip}".encode())


def salt(i: int) -> str:
    return hashlib.sha256(f"verdict v4 salt {i}".encode()).hexdigest()


def v4_entry(i: int, seq: int, prev: str) -> dict:
    content = sha512_hex(f"evidence {i}".encode())
    e = {"entry_id": f"ent_{i:02d}", "entry_type": "event", "timestamp": ts(i), "format_version": 4,
         "global_seq": seq, "content_hash": content, "salt": salt(i)}
    e["leaf_hash"] = leaf_v4(e["entry_id"], e["entry_type"], content, e["salt"])
    e["chain_hash"] = chain_v4(prev, seq, e["timestamp"], e["leaf_hash"])
    return e


def v4_chain(n: int, prefix: list = None) -> list:
    """n v4 entries; after prefix (v2/v3 entries) when given, continuing it (§2.5)."""
    out = copy.deepcopy(prefix or [])
    prev = out[-1]["chain_hash"] if out else ""
    seq = out[-1]["global_seq"] + 1 if out else 0
    for i in range(n):
        e = v4_entry(len(out), seq + i, prev)
        out.append(e)
        prev = e["chain_hash"]
    return out


def erase(e: dict) -> dict:
    """format-spec §5.0: id, type, content hash and salt removed; the rest kept."""
    for k in ("entry_id", "entry_type", "content_hash", "salt"):
        del e[k]
    e["erased"] = True
    return e


def relink_mixed(entries: list) -> list:
    """Recompute every hash from the entries' current fields, v3 or v4, as
    someone with write access to the store would after an edit."""
    prev = ""
    for e in entries:
        if e.get("format_version") == 4:
            # A malformed entry may lack a field; hash what it has, so that the
            # only defect left is the one the case names.
            if all(k in e for k in ("entry_id", "entry_type", "content_hash", "salt")):
                leaf = leaf_v4(e["entry_id"], e["entry_type"], e["content_hash"], e["salt"])
                if "leaf_hash" in e:
                    e["leaf_hash"] = leaf
            else:
                leaf = e["leaf_hash"]
            e["chain_hash"] = chain_v4(prev, e["global_seq"], e["timestamp"], leaf)
        elif e.get("entry_type") != "tombstone":
            e["chain_hash"] = chain_v3(prev, e["global_seq"], e["timestamp"], e["content_hash"])
        prev = e["chain_hash"]
    return entries


V4_INTACT = {**INTACT, "erased_found": 0}


def v4_broken(at: int, kind: str, **more) -> dict:
    return {**V4_INTACT, "verdict": "BROKEN", "first_break": at, "first_break_type": kind, **more}


# ---------------------------------------------------------------------------
# A walk of format-spec §5.5, written from its text: steps 1 to 8 for v2, v3
# and v4 entries. It is a second derivation of every v4 chain case. The
# hand-written expected verdict of each case is checked against it, and it
# alone supplies expected.breaks, the number of breaks a walk reports (a count
# that cascades, and that no one should be asked to write by hand).
# ---------------------------------------------------------------------------

import re as _re
from datetime import datetime as _dt

_HEX128 = _re.compile(r"[0-9a-f]{128}")
_HEX64 = _re.compile(r"[0-9a-f]{64}")
_TS = _re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")
_TOMB = _re.compile(r"TOMBSTONE:[0-9a-f]{64}")
_LIVE_V4 = {"entry_id", "entry_type", "timestamp", "format_version", "global_seq", "content_hash", "salt",
            "leaf_hash", "chain_hash"}
_ERASED_V4 = {"timestamp", "format_version", "global_seq", "leaf_hash", "chain_hash", "erased"}


def _instant(ts_: str) -> bool:
    if not _TS.fullmatch(ts_):
        return False
    try:
        _dt.strptime(ts_, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return False
    return True


def _leaf_text(v) -> bool:
    if not isinstance(v, str):
        return False
    b = v.encode("utf-8", "surrogatepass")
    return 1 <= len(b) <= 256 and not any(c < 0x20 or c == 0x7F for c in b)


def chain_v2(prev: str, run_id: str, seq_num: int, ts_: str, content: str) -> str:
    """format-spec §2.3."""
    return sha512_hex(f"aleutian.chain.v2:{prev}|{run_id}|{seq_num}|{ts_}|{content}".encode())


def spec_walk(entries: list, previous_hash: str = "") -> dict:
    """format-spec §5.5 over entries as an export carries them."""
    out = {**V4_INTACT}
    breaks = []

    def brk(i, kind):
        breaks.append((i, kind))

    prev, prev_seq, seen_v4 = previous_hash, None, False
    for i, e in enumerate(entries):
        fmt = e.get("format_version", 2)
        is_v4 = fmt == 4
        stored = e.get("chain_hash")
        # 1. Recorded; the checks go on.
        if i > 0 and e["global_seq"] != prev_seq + 1:
            brk(i, "sequence_gap")
        prev_seq = e["global_seq"]
        was_v4, seen_v4 = seen_v4, seen_v4 or is_v4
        # 2.
        if not isinstance(stored, str) or not _HEX128.fullmatch(stored):
            brk(i, "invalid_field")
            prev = stored
            continue
        if is_v4 and e.get("erased") is True:
            out["erased_found"] += 1
        # 3.
        tomb_shape = (e.get("entry_type") == "tombstone" or str(e.get("entry_id", "")).startswith("tomb_")
                      or str(e.get("content_hash", "")).startswith("TOMBSTONE:"))
        if (not is_v4 and was_v4) or (not is_v4 and any(k in e for k in ("salt", "leaf_hash", "erased"))) \
                or (is_v4 and ("run_id" in e or "sequence_num" in e)) or (is_v4 and tomb_shape):
            brk(i, "format_field_misuse")
            prev = stored
            continue
        # An entry after one whose chain_hash failed step 2 is unlinked: checked
        # through step 7, never recomputed, and the walk resumes from its own
        # stored hash. A malformed supplied predecessor is the first entry's
        # step-7 break.
        unlinked = i > 0 and not (isinstance(prev, str) and _HEX128.fullmatch(prev))
        bad_supplied = i == 0 and prev != "" and not _HEX128.fullmatch(prev)
        # 4. A v2 or v3 tombstone: its own checks, the first that fails its one
        # break, and then nothing else.
        if not is_v4 and e.get("entry_type") == "tombstone" and str(e.get("entry_id", "")).startswith("tomb_"):
            out["tombstones_found"] += 1
            out["last_tombstone"] = i
            if not _TOMB.fullmatch(e.get("content_hash", "")):
                brk(i, "invalid_tombstone")
            elif fmt not in (2, 3):
                brk(i, "unknown_format")
            elif fmt == 3 and (e.get("run_id", "") != "" or e.get("sequence_num", 0) != 0):
                brk(i, "format_field_misuse")
            elif e["global_seq"] < 0 or bad_supplied:
                brk(i, "invalid_field")
            prev = stored
            continue
        # 5.
        if not _instant(e["timestamp"]):
            brk(i, "invalid_timestamp")
            prev = stored
            continue
        # 6.
        if fmt not in (2, 3, 4):
            brk(i, "unknown_format")
            prev = stored
            continue
        if fmt == 3 and (e.get("run_id", "") != "" or e.get("sequence_num", 0) != 0):
            brk(i, "format_field_misuse")
            prev = stored
            continue
        # 7.
        bad = bad_supplied or e["global_seq"] < 0
        if is_v4:
            keys = set(e)
            if e.get("erased") is True:
                bad = bad or keys != _ERASED_V4 or not _HEX128.fullmatch(e["leaf_hash"])
            else:
                bad = bad or keys != _LIVE_V4 or not _leaf_text(e.get("entry_id")) \
                    or not _leaf_text(e.get("entry_type")) or not _HEX128.fullmatch(e.get("content_hash", "")) \
                    or not _HEX64.fullmatch(e.get("salt", "")) or not _HEX128.fullmatch(e.get("leaf_hash", ""))
            has_predecessor = unlinked or prev != ""
            bad = bad or has_predecessor == (e["global_seq"] == 0)
        else:
            bad = bad or not _HEX128.fullmatch(e.get("content_hash", ""))
            if fmt == 2:
                bad = bad or e.get("run_id", "") == "" or e.get("sequence_num", 0) < 0
        if bad:
            brk(i, "invalid_field")
            prev = stored
            continue
        if unlinked:
            prev = stored
            continue
        # 8.
        if is_v4:
            erased = e.get("erased") is True
            leaf = e["leaf_hash"] if erased else leaf_v4(e["entry_id"], e["entry_type"], e["content_hash"], e["salt"])
            expected = chain_v4(prev, e["global_seq"], e["timestamp"], leaf)
            if not erased and leaf != e["leaf_hash"]:
                brk(i, "hash_mismatch")
            elif expected != stored:
                brk(i, "hash_mismatch")
        else:
            expected = (chain_v3(prev, e["global_seq"], e["timestamp"], e["content_hash"]) if fmt == 3 else
                        chain_v2(prev, e["run_id"], e["sequence_num"], e["timestamp"], e["content_hash"]))
            if expected != stored:
                brk(i, "hash_mismatch")
        prev = expected
    if breaks:
        out.update(verdict="BROKEN", first_break=breaks[0][0], first_break_type=breaks[0][1])
    out["breaks"] = len(breaks)
    return out


def with_breaks(cases: list) -> list:
    """Check every hand-written verdict against spec_walk, and add its breaks."""
    for c in cases:
        got = spec_walk(c["entries"], c["previous_hash"])
        for k, v in c["expected"].items():
            if got[k] != v:
                raise SystemExit(f"{c['name']}: {k} is {v!r} by construction and {got[k]!r} by the §5.5 walk")
        c["expected"]["breaks"] = got["breaks"]
    return cases


def v4_chain_cases() -> list:
    cases = []

    def add(name, why, entries, expected, previous_hash=""):
        cases.append({"name": name, "why": why, "previous_hash": previous_hash,
                      "entries": entries, "expected": expected})

    add("intact", "§2.0: four live v4 entries", v4_chain(4), V4_INTACT)

    c = v4_chain(5)
    erase(c[2])
    add("erased_entry", "§5.0: an erased entry is recomputed from its leaf hash; not a break", c,
        {**V4_INTACT, "erased_found": 1})
    c = v4_chain(5)
    erase(c[0])
    erase(c[4])
    add("first_and_last_erased", "§5.0", c, {**V4_INTACT, "erased_found": 2})

    # Round 1, finding 1, against v4: rewrite everything before an erased entry
    # and relink it, leaving the erased entry and what follows as stored.
    c = v4_chain(5)
    erase(c[2])
    for e in c[:2]:
        e["content_hash"] = sha512_hex(b"forged " + e["entry_id"].encode())
    c[:2] = relink_mixed(copy.deepcopy(c[:2]))
    add("entries_before_an_erased_entry_rewritten",
        "§5.0: the attack v3 cannot detect. The erased entry is recomputed from the forged predecessor, "
        "so it no longer matches", c, v4_broken(2, "hash_mismatch", erased_found=1))

    c = v4_chain(5)
    erase(c[2])
    for e in c[:2]:
        e["content_hash"] = sha512_hex(b"forged " + e["entry_id"].encode())
    relink_mixed(c)
    add("entries_before_an_erased_entry_rewritten_and_everything_relinked",
        "§5.0: with the whole chain relinked it is consistent again, and the head changed: only an anchor "
        "catches it (see bind case rewritten_and_relinked)", c, {**V4_INTACT, "erased_found": 1})

    c = v4_chain(4)
    c[1]["entry_id"] = "ent_other"
    add("entry_id_changed", "§2.0: the id is in the leaf hash", c, v4_broken(1, "hash_mismatch"))
    c = v4_chain(4)
    c[1]["entry_type"] = "other"
    add("entry_type_changed", "§2.0: the type is in the leaf hash", c, v4_broken(1, "hash_mismatch"))
    c = v4_chain(4)
    c[1]["salt"] = salt(99)
    add("salt_changed", "§2.0", c, v4_broken(1, "hash_mismatch"))
    c = v4_chain(4)
    c[1]["leaf_hash"] = sha512_hex(b"another leaf")
    add("stored_leaf_hash_wrong", "§5.0: a live entry's leaf hash is recomputed and compared", c,
        v4_broken(1, "hash_mismatch"))
    c = v4_chain(4)
    erase(c[1])
    c[1]["leaf_hash"] = sha512_hex(b"another leaf")
    add("erased_leaf_hash_replaced", "§5.0: the chain hash is recomputed from the leaf hash", c,
        v4_broken(1, "hash_mismatch", erased_found=1))

    c = v4_chain(4)
    erase(c[1])
    add("erased_without_the_right_to",
        "verification-model, Who may erase: THE PROPERTY. An erasure is not authenticated by the chain; "
        "this chain verifies whoever erased the entry", c, {**V4_INTACT, "erased_found": 1})

    # Shapes (§2.0, §5.5). Each chain is relinked, so the hashes agree.
    def shaped(name, why, mutate, expected_at, kind, erased_found=0):
        c = v4_chain(4)
        mutate(c[1])
        add(name, why, relink_mixed(c), v4_broken(expected_at, kind, erased_found=erased_found))

    shaped("salt_uppercase", "§5.5", lambda e: e.update(salt=e["salt"].upper()), 1, "invalid_field")
    shaped("salt_short", "§5.5", lambda e: e.update(salt=e["salt"][:62]), 1, "invalid_field")
    shaped("salt_missing", "§2.0: a live entry carries its salt", lambda e: e.pop("salt"), 1, "invalid_field")
    shaped("leaf_hash_missing", "§2.0", lambda e: e.pop("leaf_hash"), 1, "invalid_field")
    shaped("entry_id_empty", "§5.5", lambda e: e.update(entry_id=""), 1, "invalid_field")
    shaped("entry_id_control_character", "§5.5", lambda e: e.update(entry_id="a\nb"), 1, "invalid_field")
    shaped("entry_id_257_bytes", "§5.5", lambda e: e.update(entry_id="x" * 257), 1, "invalid_field")
    shaped("erased_with_entry_id_kept", "§2.0: an erased entry carries no id",
           lambda e: (erase(e), e.update(entry_id="ent_01")), 1, "invalid_field", 1)
    shaped("erased_with_salt_kept", "§2.0", lambda e: (erase(e), e.update(salt=salt(1))), 1, "invalid_field", 1)
    shaped("erased_false", "§2.0: a live entry carries no erased member", lambda e: e.update(erased=False),
           1, "invalid_field")
    shaped("tombstone_type", "§2.0: v4 has no tombstones", lambda e: e.update(entry_type="tombstone"),
           1, "format_field_misuse")
    shaped("tomb_id", "§2.0", lambda e: e.update(entry_id="tomb_00000000-0000-0000-0000-000000000000"),
           1, "format_field_misuse")
    shaped("tombstone_type_and_id", "§2.0: the v3 tombstone shape, in a v4 entry",
           lambda e: e.update(entry_type="tombstone", entry_id="tomb_00000000-0000-0000-0000-000000000000",
                              content_hash="TOMBSTONE:" + "ab" * 32), 1, "format_field_misuse")
    shaped("run_id_member", "§2.0: absent, not empty", lambda e: e.update(run_id=""), 1, "format_field_misuse")
    shaped("sequence_num_member", "§2.0", lambda e: e.update(sequence_num=0), 1, "format_field_misuse")

    c = v4_chain(3)
    for e in c:
        e["global_seq"] += 1
    add("first_entry_not_at_zero", "§2.0: a v4 entry with no predecessor has global_seq 0", relink_mixed(c),
        v4_broken(0, "invalid_field"))

    # §2.5: continued chains.
    v3 = chain(3, start=1)
    add("continued_from_v3", "§2.5: a v3 chain from global_seq 1, continued in v4", v4_chain(3, v3), V4_INTACT)
    c = v4_chain(3, chain(4))
    tombstone(c[1])
    add("continued_after_a_v3_tombstone", "§2.5: the v3 prefix keeps exactly its guarantee", c,
        {**V4_INTACT, "tombstones_found": 1, "last_tombstone": 1})

    c = v4_chain(3, chain(4))
    for e in c[:1]:
        e["content_hash"] = sha512_hex(b"forged 0")
    c[:1] = relink(copy.deepcopy(c[:1]))
    tombstone(c[1])
    add("continued_v3_prefix_rewritten_before_its_tombstone",
        "§2.5, §5.5: the v3 limitation stays in the prefix, and is reported; the v4 entries add nothing to it",
        c, {**V4_INTACT, "tombstones_found": 1, "last_tombstone": 1})

    c = v4_chain(2, chain(2))
    nxt = entry(9, c[-1]["global_seq"] + 1, c[-1]["chain_hash"])
    c.append(nxt)
    add("v3_entry_after_v4", "§2.5: never back from v4", c, v4_broken(4, "format_field_misuse"))
    c = v4_chain(2, chain(2))
    nxt = tombstone(entry(9, c[-1]["global_seq"] + 1, c[-1]["chain_hash"]))
    c.append(nxt)
    add("v3_tombstone_after_v4",
        "§2.5: the load-bearing case. A v3 tombstone's chain hash would be taken as stored and unlink "
        "everything before it", c, v4_broken(4, "format_field_misuse"))

    c = v4_chain(5)
    erase(c[1])
    c[3]["entry_id"] = "ent_changed"
    erase(c[4])
    add("erased_entries_after_a_break_are_counted", "§5.5: every entry walked is counted, after the first break too",
        c, v4_broken(3, "hash_mismatch", erased_found=2))
    c = v4_chain(4)
    erase(c[1])
    c[1]["chain_hash"] = "short"
    add("erased_entry_with_a_malformed_chain_hash_is_not_counted",
        "§5.5: an entry is counted only once its chain_hash is in shape (step 2)", c,
        v4_broken(1, "invalid_field"))
    c = v4_chain(1, chain(2))
    c[2]["chain_hash"] = "short"
    c.append(tombstone(entry(9, c[-1]["global_seq"] + 1, c[-1]["chain_hash"])))
    add("v3_tombstone_after_a_v4_entry_broken_at_step_2",
        "§2.5, §5.5: never back from v4 goes by the declared format, even after a v4 entry that broke at "
        "step 2, so the v3 tombstone after it is refused at step 3 and not counted", c,
        v4_broken(2, "invalid_field"))
    c = v4_chain(4)
    c[2]["run_id"] = ""
    c[2]["timestamp"] = "yesterday"
    add("misuse_before_timestamp", "§5.5: step 3 before step 5", c, v4_broken(2, "format_field_misuse"))
    c = v4_chain(4)
    c[2]["timestamp"] = "2026-10-12T09:00:02Z"
    c[2].pop("salt")
    add("timestamp_before_shape", "§5.5: step 5 before step 7", c, v4_broken(2, "invalid_timestamp"))
    c = v4_chain(4)
    c[2]["global_seq"] = 9
    c[2]["chain_hash"] = "short"
    add("sequence_gap_first", "§5.5: step 1", c, v4_broken(2, "sequence_gap"))

    c = v4_chain(4)
    add("segment_with_its_predecessor_hash", "§2.0: a segment links from the hash supplied", c[2:], V4_INTACT,
        previous_hash=c[1]["chain_hash"])
    c = v4_chain(4)
    add("segment_without_its_predecessor_hash",
        "§2.0: the first entry's global_seq is above 0, so it has a predecessor and this is a segment; "
        "walked from nothing, it breaks the first-entry rule",
        c[2:], v4_broken(0, "invalid_field"))
    c = v4_chain(4)
    add("predecessor_hash_supplied_to_a_first_entry",
        "§2.0: an entry with a predecessor has global_seq above 0", c, v4_broken(0, "invalid_field"),
        previous_hash=sha512_hex(b"some predecessor"))

    # Break counting (§5.0, §5.5): at most one break per entry from steps 2 to 8.
    c = v4_chain(4)
    c[1]["leaf_hash"] = sha512_hex(b"another leaf")
    c[1]["chain_hash"] = sha512_hex(b"another chain hash")
    add("leaf_and_chain_hash_both_wrong",
        "§5.0: a leaf mismatch is the entry's one break, and its stored chain_hash is not compared; the walk "
        "goes on from the hash the recomputed leaf gives, so entry 2 links", c, v4_broken(1, "hash_mismatch"))
    c = v4_chain(4)
    c[1]["timestamp"] = c[1]["timestamp"].replace(".000000Z", "Z")
    add("timestamp_in_another_spelling",
        "§4, §5.5: the same instant spelled otherwise is invalid_timestamp, and the walk goes on from the stored "
        "chain hash: one break, not a mismatch here and after", c, v4_broken(1, "invalid_timestamp"))
    c = v4_chain(4)
    c[1]["timestamp"] = c[1]["timestamp"].replace(".000000Z", "Z")
    c[1]["chain_hash"] = sha512_hex(b"another chain hash")
    add("timestamp_in_another_spelling_and_chain_hash_wrong",
        "§5.5: step 5 ends the entry's checks; the next entries are judged from its stored (wrong) chain hash",
        c, v4_broken(1, "invalid_timestamp"))
    c = v4_chain(4)
    erase(c[1])
    c[1]["timestamp"] = "yesterday"
    add("erased_entry_with_a_bad_timestamp", "§5.5: an erased entry's timestamp is checked like any other", c,
        v4_broken(1, "invalid_timestamp", erased_found=1))
    c = v4_chain(4)
    erase(c[1])
    c[1]["entry_type"] = "tombstone"
    add("erased_entry_with_a_tombstone_type",
        "§5.5: step 3 (a tombstone shape) comes before step 7 (an erased entry carries no type)", c,
        v4_broken(1, "format_field_misuse", erased_found=1))
    c = v4_chain(2)
    c.append(entry(9, 2, c[-1]["chain_hash"]))
    c.append(v4_entry(10, 3, c[-1]["chain_hash"]))
    add("v4_then_v3_then_v4", "§2.5: never back from v4; the v4 entry after it is judged on its own", c,
        v4_broken(2, "format_field_misuse"))
    c = v4_chain(4)
    c[1]["leaf_hash"] = c[1]["leaf_hash"].upper()
    add("live_leaf_hash_uppercase", "§5.5: a shape break (step 7), before the leaf is compared", c,
        v4_broken(1, "invalid_field"))
    c = v4_chain(3, chain(4))
    tombstone(c[1])
    c[2]["content_hash"] = sha512_hex(b"forged 2")
    prev = c[1]["chain_hash"]
    for e in c[2:4]:
        e["chain_hash"] = chain_v3(prev, e["global_seq"], e["timestamp"], e["content_hash"])
        prev = e["chain_hash"]
    add("continued_v3_entry_after_its_tombstone_rewritten",
        "§2.5: v3 binds the entries after its last tombstone, and the first v4 entry links from the v3 head, "
        "so rewriting a v3 entry after the tombstone and relinking the v3 part breaks at the first v4 entry", c,
        v4_broken(4, "hash_mismatch", tombstones_found=1, last_tombstone=1))
    c = v4_chain(2, chain(3))
    tombstone(c[1])
    c[1]["content_hash"] = "TOMBSTONE:" + "AB" * 32
    c[1]["run_id"] = "run_x"
    add("v3_tombstone_with_two_defects",
        "§5.5 step 4: a tombstone's checks in order, the first its one break: the content hash before the run "
        "fields", c, v4_broken(1, "invalid_tombstone", tombstones_found=1, last_tombstone=1))
    c = v4_chain(4)
    add("malformed_supplied_previous_hash",
        "§5.5 step 7: the first entry's break; the next links from its stored hash", c[2:],
        v4_broken(0, "invalid_field"), previous_hash="ab" * 63 + "|x")
    c = v4_chain(4)
    c[1]["entry_id"] = "a\u0085b\u00a0c"
    add("nel_and_nbsp_in_entry_id", "§2.0: U+0085 and U+00A0 are not control characters there", relink_mixed(c),
        V4_INTACT)
    return with_breaks(cases)


def anchor_v7_for(entries: list, start: int = None, end: int = None, subject: str = SUBJECT,
                  prev_hash: str = SEED_ANCHOR_HASH, prev_id: str = SEED_ANCHOR_ID) -> dict:
    start = entries[0]["global_seq"] if start is None else start
    end = entries[-1]["global_seq"] if end is None else end
    tip = next(e["chain_hash"] for e in entries if e["global_seq"] == end)
    return {
        "version": 7, "anchor_id": "anchor_77777777-7777-7777-7777-777777777777", "subject": subject,
        "chain_hash": anchor_chain_hash_v7(prev_hash, subject, start, end, tip),
        "range": {"start_seq": str(start), "end_seq": str(end)}, "entry_count": str(end - start + 1),
        "previous_anchor_hash": prev_hash, "previous_anchor_id": prev_id,
        "signing_key_id": "vector-key", "created_at_ms": 1791795600000, "signature": "",
    }


def v7_bind_cases() -> list:
    """Keyless binds of v7 anchors (§9.7). expect is what the caller passes:
    subject and previous_anchor_hash, each empty when not given."""
    cases = []
    c = v4_chain(5)

    def add(name, why, entries, anchor, expected, subject=SUBJECT, previous_anchor_hash="", previous_hash=""):
        cases.append({"name": name, "why": why, "entries": entries, "anchor": anchor, "previous_hash": previous_hash,
                      "expect": {"subject": subject, "previous_anchor_hash": previous_anchor_hash},
                      "expected": expected})

    def outcome(o, bound=False, tombstones=0, not_bound=0, subject_checked=True):
        return {"error": False, "outcome": o, "bound": bound, "tombstones": tombstones,
                "entries_not_bound": not_bound, "subject_checked": subject_checked}

    add("bound", "§9.7", c, anchor_v7_for(c), outcome("bound", True))
    for name, idx in [("first_entry_erased", [0]), ("last_entry_erased", [4]), ("first_and_last_erased", [0, 4])]:
        e = copy.deepcopy(c)
        for i in idx:
            erase(e[i])
        add(name, "§5.0, §9.4: erasure changes nothing the anchor binds; a v6 anchor broke here", e,
            anchor_v7_for(c), outcome("bound", True))

    forged = copy.deepcopy(c)
    erase(forged[2])
    for e in forged[:2]:
        e["content_hash"] = sha512_hex(b"forged " + e["entry_id"].encode())
    relink_mixed(forged)
    add("rewritten_and_relinked",
        "§5.0: before an erased entry, rewritten and the whole chain relinked; it verifies alone, and the "
        "anchor's head no longer matches", forged, anchor_v7_for(c), outcome("head_mismatch"))

    add("other_subject_expected", "§9.7: a genuine anchor for another subject", c, anchor_v7_for(c),
        outcome("tenant_mismatch"), subject="another-subject")
    a = anchor_v7_for(c)
    a["chain_hash"] = "ef" * 64
    add("subject_checked_before_the_head",
        "§9.7: two defects, a wrong head and another expected subject; the subject is step 5, the head step 6",
        c, a, outcome("tenant_mismatch"), subject="another-subject")
    add("predecessor_checked_before_the_subject",
        "§9.7: two defects, another expected predecessor and another expected subject; step 4 is reported",
        c, anchor_v7_for(c), outcome("predecessor_mismatch"), subject="another-subject",
        previous_anchor_hash="ab" * 64)
    broken_c = copy.deepcopy(c)
    broken_c[3]["content_hash"] = sha512_hex(b"something else")
    add("chain_broken", "§9.7 step 1: the chain is walked first; a break is chain_broken whatever else differs",
        broken_c, anchor_v7_for(c), outcome("chain_broken"), subject="another-subject")
    add("no_subject_expected", "§9.7: bound, and the result says the subject was not checked", c,
        anchor_v7_for(c), outcome("bound", True, subject_checked=False), subject="")
    add("other_predecessor_expected", "§9.7: the caller expected another previous anchor", c, anchor_v7_for(c),
        outcome("predecessor_mismatch"), previous_anchor_hash="ab" * 64)
    add("expected_predecessor_matches", "§9.7", c, anchor_v7_for(c), outcome("bound", True),
        previous_anchor_hash=SEED_ANCHOR_HASH)
    add("later_anchor_naming_the_seed_id", "§9.3: the seed id goes with the seed hash only", c,
        anchor_v7_for(c, prev_hash="ab" * 64), {"error": True})

    grown = v4_chain(8)
    add("chain_grown_since_the_anchor",
        "§9.7: the tip is the entry at end_seq; entries after it are not the anchor's business",
        grown, anchor_v7_for(grown[:5]), outcome("bound", True))
    add("truncated_from_the_end", "§9.7: no entry at end_seq", c[:4], anchor_v7_for(c), outcome("height_mismatch"))

    kept = copy.deepcopy(c[1:])
    for i, e in enumerate(kept):
        e["global_seq"] = i
    relink_mixed(kept)
    add("truncated_from_the_front_and_relinked",
        "§9.7: renumbered from 0 it is a whole chain again, one entry short; the tip it names is not "
        "the one signed", kept, anchor_v7_for(c), outcome("height_mismatch"))

    a = anchor_v7_for(c)
    a["chain_hash"] = "ef" * 64
    add("head_mismatch", "§9.4", c, a, outcome("head_mismatch"))

    add("over_a_segment", "§9.8: an anchor is not bound to entries verified from a predecessor hash", c[2:],
        anchor_v7_for(c), {"error": True}, previous_hash=c[1]["chain_hash"])

    a = anchor_v7_for(c)
    a["entry_count"] = "4"
    add("entry_count_not_range_length", "§9.3", c, a, {"error": True})

    v3 = chain(3, start=1)
    cont = v4_chain(3, v3)
    add("continued_chain_from_seq_1", "§2.5, §9.7: start_seq is the chain's first global_seq", cont,
        anchor_v7_for(cont), outcome("bound", True))
    add("range_not_from_the_first_entry", "§9.7: start_seq names the chain's first entry", cont,
        anchor_v7_for(cont, start=2), outcome("range_start_mismatch"))

    cont = v4_chain(3, chain(4))
    tombstone(cont[1])
    add("continued_after_a_v3_tombstone", "§2.5: the v3 prefix up to its last tombstone is reported unbound", cont,
        anchor_v7_for(cont), outcome("bound", True, tombstones=1, not_bound=2))

    forged = v4_chain(3, chain(4))
    forged[0]["content_hash"] = sha512_hex(b"forged 0")
    forged[:1] = relink(copy.deepcopy(forged[:1]))
    tombstone(forged[1])
    add("continued_v3_prefix_rewritten_before_its_tombstone",
        "§2.5: the frozen v3 limitation, against a v7 anchor. It binds, and entries_not_bound is what tells "
        "the caller", forged, anchor_v7_for(cont), outcome("bound", True, tombstones=1, not_bound=2))
    return cases


def v4_entries_text_cases() -> list:
    """format-spec §2.0, §5.5: what a reader of a v4 entries file refuses
    before any check. text is the file as UTF-8; text_base64, where given, is
    the file's exact bytes (they are not UTF-8, so JSON cannot carry them)."""
    import base64
    live = json.dumps(v4_chain(1)[0], separators=(",", ":"), ensure_ascii=False)
    c = v4_chain(3)
    erase(c[1])
    gone = json.dumps(c[1], separators=(",", ":"))
    eid = '"entry_id":"ent_00"'
    out = []

    def add(name, why, text, expected):
        out.append({"name": name, "why": why, "text": text, "expected": expected})

    add("live_entry", "§2.0", "[" + live + "]", "entries")
    add("erased_entry", "§2.0", "[" + gone + "]", "entries")
    add("surrogate_pair_escape", "§2.0: a pair is one character, read as it",
        "[" + live.replace(eid, '"entry_id":"\\ud83d\\ude00"') + "]", "entries")
    add("lone_high_surrogate_escape", "§2.0: a reader never repairs text",
        "[" + live.replace(eid, '"entry_id":"a\\ud800"') + "]", "not_entries")
    add("lone_low_surrogate_escape", "§2.0", "[" + live.replace(eid, '"entry_id":"\\udfffa"') + "]", "not_entries")
    add("high_surrogate_then_not_low", "§2.0",
        "[" + live.replace(eid, '"entry_id":"\\ud800\\u0041"') + "]", "not_entries")
    raw = ("[" + live.replace(eid, '"entry_id":"a\x00b"') + "]").encode().replace(b"\x00", b"\xff")
    out.append({"name": "invalid_utf8_byte", "why": "§2.0: a reader never repairs text", "text": "",
                "text_base64": base64.b64encode(raw).decode(), "expected": "not_entries"})
    raw = ("[" + live.replace(eid, '"entry_id":"a\x00b"') + "]").encode().replace(b"\x00", b"\xed\xa0\x80")
    out.append({"name": "surrogate_encoded_in_utf8", "why": "§2.0: not UTF-8 (CESU-8)", "text": "",
                "text_base64": base64.b64encode(raw).decode(), "expected": "not_entries"})
    for name, old, new, base in [
        ("salt_in_another_spelling", '"salt":', '"\u017falt":', live),
        ("leaf_hash_in_another_spelling", '"leaf_hash":', '"leaf_ha\u017fh":', gone),
        ("erased_in_another_spelling", '"erased":', '"era\u017fed":', gone),
        ("erased_null", '"erased":true', '"erased":null', gone),
        ("erased_as_a_string", '"erased":true', '"erased":"true"', gone),
        ("entry_id_null", eid, '"entry_id":null', live),
        ("salt_null", '"salt":', '"salt":null,"x":', live),
        ("timestamp_null", '"timestamp":', '"timestamp":null,"x":', live),
        ("global_seq_minus_zero", '"global_seq":0', '"global_seq":-0', live),
        ("global_seq_with_a_fraction", '"global_seq":0', '"global_seq":0.0', live),
        ("global_seq_with_an_exponent", '"global_seq":0', '"global_seq":0e0', live),
        ("format_version_as_a_string", '"format_version":4', '"format_version":"4"', live),
    ]:
        assert old in base, name
        add(name, "§5.5: one spelling and one JSON type per member, null for none",
            "[" + base.replace(old, new, 1) + "]", "not_entries")
    return out


def write_v4() -> None:
    obj = {
        "_comment": "Verifier verdict vectors for chain format v4, continued chains and v7 anchors. Written by "
                    "scripts/verdict-vectors.py from docs/format-spec.md (§2.0, §2.5, §5.0, §9.3, §9.7) and "
                    "never by an implementation under test. chain_cases: as in verify_verdict_vectors.json, "
                    "and expected.erased_found counts v4 erased entries. bind_cases: a keyless bind of a v7 "
                    "anchor to entries (linked from previous_hash when given) with the caller's expect "
                    "(subject, previous_anchor_hash; empty means not given); expected.error true means the "
                    "anchor or the bind is refused; otherwise compare outcome, bound, tombstones, "
                    "entries_not_bound and subject_checked. expected.breaks in chain_cases is how many breaks a walk "
                    "reports, every one collected. entries_text_cases: text (or, for bytes that are not UTF-8, "
                    "text_base64) is an entries file; \"entries\" if it reads, \"not_entries\" if the reader "
                    "refuses it (an error, never a broken chain). No case needs a key.",
        "seed_anchor_hash": SEED_ANCHOR_HASH,
        "seed_anchor_id": SEED_ANCHOR_ID,
        "chain_cases": v4_chain_cases(),
        "entries_text_cases": v4_entries_text_cases(),
        "bind_cases": v7_bind_cases(),
    }
    name = "verify_verdict_v4_vectors.json"
    raw = (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode()
    with open(os.path.join(TESTDATA, name), "wb") as f:
        f.write(raw)
    mpath = os.path.join(ROOT, "fixtures", "MANIFEST.json")
    manifest = json.load(open(mpath))
    manifest["vectors"][name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    manifest["vectors"] = dict(sorted(manifest["vectors"].items()))
    with open(mpath, "w") as f:
        f.write(json.dumps(manifest, indent=2) + "\n")
    n = len(obj["chain_cases"]) + len(obj["entries_text_cases"]) + len(obj["bind_cases"])
    print(f"wrote {name} ({len(raw)} bytes, {n} cases)")


def main() -> None:
    obj = {
        "_comment": FROZEN + "Verifier verdict vectors. Written by scripts/verdict-vectors.py from docs/format-spec.md "
                    "(§4, §5.5, §9.4, §9.8) and never by an implementation under test. Each case is a valid "
                    "chain with one stated defect; `why` cites the rule. chain_cases: verify the entries "
                    "(linking the first from previous_hash, empty for a whole chain) and compare verdict, the "
                    "index and type of the FIRST break (-1 and \"\" when intact), tombstones_found and "
                    "last_tombstone. entries_text_cases: text is the content of an entries file; \"entries\" "
                    "means it decodes, \"not_entries\" that it is refused as not being entries (an error, "
                    "never a broken chain). anchor_text_cases: text is an anchor's JSON; \"parses\" or "
                    "\"refused\". bind_cases: a keyless bind of anchor to entries with previous_anchor_hash; "
                    "expected.error true means the anchor is refused as malformed; otherwise compare "
                    "outcome, bound, tombstones and entries_not_bound. No case needs a key.",
        "seed_anchor_hash": SEED_ANCHOR_HASH,
        "seed_anchor_id": SEED_ANCHOR_ID,
        "chain_cases": chain_cases(),
        "entries_text_cases": entries_text_cases(),
        "anchor_text_cases": anchor_text_cases(),
        "bind_cases": bind_cases(),
    }
    name = "verify_verdict_vectors.json"
    raw = (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode()
    with open(os.path.join(TESTDATA, name), "wb") as f:
        f.write(raw)
    mpath = os.path.join(ROOT, "fixtures", "MANIFEST.json")
    manifest = json.load(open(mpath))
    manifest["vectors"][name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    manifest["vectors"] = dict(sorted(manifest["vectors"].items()))
    with open(mpath, "w") as f:
        f.write(json.dumps(manifest, indent=2) + "\n")
    n = sum(len(obj[k]) for k in ("chain_cases", "entries_text_cases", "anchor_text_cases", "bind_cases"))
    print(f"wrote {name} ({len(raw)} bytes, {n} cases)")
    write_v4()


if __name__ == "__main__":
    main()
