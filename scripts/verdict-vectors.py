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

writes fixtures/testdata/verify_verdict_vectors.json and its entry in
fixtures/MANIFEST.json. Standard library only: no case needs a signature.
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


def main() -> None:
    obj = {
        "_comment": "Verifier verdict vectors. Written by scripts/verdict-vectors.py from docs/format-spec.md "
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


if __name__ == "__main__":
    main()
