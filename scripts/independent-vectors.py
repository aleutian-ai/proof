#!/usr/bin/env python3
# Copyright 2026 Aleutian AI
# SPDX-License-Identifier: Apache-2.0
"""Independent reference computation for four conformance vector files.

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
    fixtures/testdata/record_v1_vectors.json         sink record-signing envelope
                                                     (docs/sink-format.md, Record signatures)
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


# ---------------------------------------------------------------------------
# Sink record-signing envelope aleutian.proof.record.v1:
#   "aleutian.proof.record.v1" 0x00 ‖ field(1, chain_id) ‖ field(2, entry_id)
#   ‖ field(3, entry_type) ‖ field(4, global_seq) ‖ field(5, previous_hash)
#   ‖ field(6, timestamp) ‖ field(7, content_hash) ‖ field(8, signing_key_id)
#   field(tag, v) = tag (1 byte) ‖ len(v) (uint32 big-endian) ‖ v
# Every value is ASCII, in the string encoding format-spec gives that field.
# previous_hash is empty exactly when global_seq is 0.
# ---------------------------------------------------------------------------

RECORD_ORDER = ["chain_id", "entry_id", "entry_type", "global_seq",
                "previous_hash", "timestamp", "content_hash", "signing_key_id"]


def record_v1(f: dict) -> bytes:
    out = b"aleutian.proof.record.v1\x00"
    for tag, name in enumerate(RECORD_ORDER, start=1):
        v = f[name].encode("ascii")
        out += bytes([tag]) + len(v).to_bytes(4, "big") + v
    return out


def timestamp_from_unix_ns(ns: int) -> str:
    """format-spec §4 from an instant: UTC, six digits, TRUNCATED (floor)."""
    import datetime
    secs, rem = divmod(ns, 1_000_000_000)
    micros = rem // 1000
    d = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=secs)
    return d.strftime("%Y-%m-%dT%H:%M:%S") + ".%06dZ" % micros


def record_v1_file() -> dict:
    prev = sha512_hex(b"record v1 previous entry")
    event = {
        "chain_id": "payments.0123456789abcdef0123456789abcdef",
        "entry_id": "sink-fedcba9876543210fedcba9876543210",
        "entry_type": "sink.event",
        "global_seq": "41",
        "previous_hash": prev,
        "timestamp": "2026-09-30T12:00:00.123456Z",
        "content_hash": sha512_hex(b"record v1 content"),
        "signing_key_id": "3fb85abc3e8bae42952ee9194ae1f615",
    }
    record = b'{"erased":"every earlier event on this chain","through_global_seq":"41"}'
    # 2026-09-30T12:00:00.123456789Z as an instant: the formatting is computed
    # here, independently, so an implementation that rounds (…457) fails.
    instant_ns = 1790769600 * 1_000_000_000 + 123_456_789
    cases = [
        ("event", {}, None),
        ("erasure", {"entry_type": "sink.erasure", "global_seq": "42",
                     "entry_id": "sink-00000000000000000000000000000042",
                     "content_hash": sha512_hex(b"aleutian.sink.erasure.v1:" + record)}, None),
        ("first_entry_seq_0_no_previous", {"global_seq": "0", "previous_hash": ""}, None),
        ("seq_2_pow_63_minus_1", {"global_seq": str(2**63 - 1)}, None),
        ("longest_class", {"chain_id": "a" * 31 + ".0123456789abcdef0123456789abcdef"}, None),
        ("zero_microseconds", {"timestamp": "2026-01-01T00:00:00.000000Z"}, None),
        ("nanoseconds_truncated", {"timestamp": timestamp_from_unix_ns(instant_ns)}, instant_ns),
    ]
    vectors = []
    for name, override, ns in cases:
        f = dict(event, **override)
        env = record_v1(f)
        v = {"name": name, "fields": f, "envelope_hex": env.hex(),
             "envelope_sha512": sha512_hex(env)}
        if ns is not None:
            v["timestamp_unix_ns"] = str(ns)
        vectors.append(v)
    # Field values a signer MUST refuse and a verifier MUST report unverifiable.
    reject = [
        ("chain_id_upper_case", {"chain_id": "Payments.0123456789abcdef0123456789abcdef"}),
        ("entry_id_not_sink", {"entry_id": "ent_000"}),
        ("entry_type_unknown", {"entry_type": "tombstone"}),
        ("global_seq_leading_zero", {"global_seq": "041"}),
        ("global_seq_plus_sign", {"global_seq": "+41"}),
        ("global_seq_negative", {"global_seq": "-1"}),
        ("previous_hash_empty_after_first", {"previous_hash": ""}),
        ("previous_hash_on_first", {"global_seq": "0"}),
        ("previous_hash_upper_case", {"previous_hash": prev.upper()}),
        ("timestamp_not_utc", {"timestamp": "2026-09-30T14:00:00.123456+02:00"}),
        ("timestamp_millis", {"timestamp": "2026-09-30T12:00:00.123Z"}),
        ("timestamp_year_0", {"timestamp": "0000-01-01T00:00:00.000000Z"}),
        ("content_hash_upper_case", {"content_hash": sha512_hex(b"x").upper()}),
        ("content_hash_tombstone", {"content_hash": "TOMBSTONE:" + "0" * 64}),
        ("key_id_short", {"signing_key_id": "3fb85abc"}),
    ]
    return {
        "_comment": "Sink record-signing envelope aleutian.proof.record.v1: the exact bytes "
                    "an ML-DSA-65 record signature covers (empty ML-DSA context). Domain "
                    "\"aleutian.proof.record.v1\" then 0x00, then eight fields in fixed order, "
                    "each tag (1 byte) || length (uint32 big-endian) || ASCII value. Values use "
                    "format-spec's own encodings (global_seq decimal, previous_hash hex or empty "
                    "exactly at global_seq 0, timestamp per §4). timestamp_unix_ns, where "
                    "present, is the instant the timestamp was formatted from (truncated, not "
                    "rounded). reject lists field values that must be refused. regression_signature "
                    "is NOT independent (Python has no ML-DSA): a deterministic ML-DSA-65 "
                    "signature by proof's Go signer, pinned so another implementation can check "
                    "it verifies and a change in proof is noticed. Computed in Python "
                    "(scripts/independent-vectors.py). See docs/sink-format.md §9.",
        "version": 1,
        "vectors": vectors,
        "reject": [{"name": n, "fields": dict(event, **o)} for n, o in reject],
        "regression_signature": REGRESSION_SIGNATURE,
    }


# A deterministic signature of vector "event" by the ML-DSA-65 key whose seed is
# 32 bytes of 0x07, produced by proof's Go signer (sink.MLDSA65RecordSigner).
# NOT an independent value; see the file comment. Regenerate only deliberately.
REGRESSION_SIGNATURE = {
    "vector": "event",
    "seed_hex": "07" * 32,
    "public_key_hex": "37584a6e4279aecee130eea890904536acf4553249923d4f0eba42de40472cce3349845612808d0e506b04e4fe1781b1c2aae0d61666c55401e81c7a97fa96806ffe1b720a40e33a11769b141aa0af327a7c2ba390d14185dd554bbd46f919d43c7586438fd284f7495ae584ee953852ea411facf2a6e1b95619f399dac5117149c8473d700e6905661b76d7918ec0a8db24e91ecd52ab2e75774d555ad3e28e2e946dcf0f45e6312b26d362776f5d55054978c3b241486535451b889ae3a6cb249a23cff2a99b9c1ee40430fb4628a5f2818bf94513c0e11061a2fbc9f4b0a76855b380a765812427657cef12cffb5e1c92e62b2f0ad2b42876e90669b4563ea609ff141cbe8ce9738353812fe2747a72e42eb6da23efa362bddbab852b087dfc2da6f4ee3207b1337ee15ce98942f0f14c176170548203b3786d68b49bed1ff1b7004fe86b35f2569190312d5a96e56a440b1cdf4749a8d72db60fcbb4533bfc08e9edd0414950eb2764c11d5055489aef5a2b9c432a6f71704d9c2d5a4adc8c77cf4bba50f002c7c169b865484c8ab2a96075b2a7e9935a4e4bc018aa7c07066488fd31e50372c1132f46440dc51f2e5f0561a28f5e4ca9a8b5b25c405fd626a7b86e6f4ce5e2b0baad4a83ebe197ea9e0a599dea31af1961adfff5c04ccdc5e917dd647baf5d3d0675d8cb84c74fd42c3a8e9af622b73af6135981220178aa49ed6f7ba7f15e2b469702fadb8cdbf82dc472e505d7ce9a108470815ec6a8ecf5148d7f12cf3ddbebde919fdeebf1836cb82038e5a167a58774ff2dfe4f8091d2b6b69f8620928df11312d45bd9125b8fef54d81c69c438d547b1304a390613b4c59063df93044455555e924843658f6943410359178cf66b886629be697a5fdfad5dd43a0e5f2249590f6063a431c3ef4f5c06f1726e144b041a882165515a82401eeb1cece050c5c211cdd6997d27e452681aab514b5635c3000d7ff2f8ab83f472fa2476be4461f51bef28c48a12dce04e28018885af938cce33e9af7fa77b99708ee7198fe4e0ef0d294828dc51f74a62469d1880967367b56cf470314dea7966ab9fe7fb36424d5642214e85d3e1f18250be8016c91b55fd6e6dc5cb55f67725ea5205945c8f1f833e4de81858a2afbb577aad41ebf74a4586dacd9bf3f85c9117d91a438cf0ff0ea7f94d0aeb960aa89959a661eee6883c3bff9eebc6df57ce0d5c8dd10c568c4149568768b3782bd05612146f850e2dbe7e67e5d1f1df19f2e61f3524422a587ae1f0515e8c54cf388c9bd005ac870600b547e6c58d2b8188da9424fc265883df0ff6a1440067b5e9dd7e7de3aff619a17091b40496661c70d2182a2e18bd665da0098594a91874c1fee87813db053faa183283aa1cdf32b0bd6c89b031810bc7a6e58ac9bcd607d24583e9ff9938a85b866d30bee6714e68001f5332775443094366b52db5d52791aaaff45697a8ced12c942eaa35d93e5685ad4567c5fb04ab85254d5f08fc3d484870bf8fe8682dcb1162417a892b9f564885aa9e207b8f3d44e48d4be8316bb9436ff0cb1dcfc3ddcee914dd03352d963013bab8235536ab6a72b786e6ca10f41830ae1893607e3b0fac7edcd95c4ca3002429821773f7d1a1468d98eb477d90c8c67cb9826d18d7b1a1a3d77878eacfe983a97ebf0aab885072e1b4c937f384baef44889cb4009fb527eed4b7d1a74c2fe362f97e64f5b8126db8cd3dcff538b3e58b67068858f954f457c8cb48831c2154378f964de777b6dbb4154d524922818ed3308ff607fa9f0300b4735c9014714d00758323af4b1e258a1fd9a52ee5117836bfca2162b0fe3665e252c55a4fddbccc8c0059758a30d6d22d0774fc57d898d321bf7874ff5b949ee3e7e6b1b6704a135baa299602d633ae8dcee4288fe0d48b14d4f0bc2e4579a56bf69ed7d2186d2da52730ef752743c52cd2e801d4c1e029994e23a98250911fc8b3d4a0cc6a9b4522767719c73c69a6189c8865a7a37c00540bc74ca1c5bc6c978fda8eca285858b844f2596cb19d83ea77f064734f6739edeb042516617759544729cc9255115bb70ffee2976824ddeeff8b5397fc91f1d75ad1d5e5d39b2b89e9d6fbce2ce3566960cdaf99107f58a6675fa5fb8ff45c14ec5dd75d4589e430551cc37ad75c034233093f4b08c9d62b271fcc9b1c4b48cac5b83d34d5e40a37a94ed5c79ab0dedf6c7d2cba5126b4d4f1025048160f9dc39919f827906413e9b0f2eb1f7aabe2b38f8cb63e51660bdf1b374a6b77a4a1d6f12801dc37fbcd50d5286cb6ebcbb7322c819757917245475aa930a97e5089f78f5cedef586c866c886fa7feebb53449a78e4789a4c17d938b8a980d3bb8c1021e96a8f28c39ffd73961bc8167b5fc65f746d72b8037ebb48f050cb017c5926a7eca3c73935ab7961b5e3998b2e0e218da9b8db376fabf666f7683b9bfd250fcaa7f3dce3587aa10ffaa641ea7037834256ac897702fb65d589d66e8b9ef53b9f377791a409b23f6dfa925eddb1b9de2b1cca56f9f39f0c308700731dd9d651533d2c07dee1c09637ad646cfa04815b25052156af2a130c9e822b12d93f001369aee447f81cb120b2df5a3af64fbd5b8b942d5758fe4486fddb2ea81ed9b7141bbf9a546c87ce494c537bc330e05e364e2663d9d64bf92da3016a26f6840852376e199759cc3d6cc90369200a18805fb6bfb43336fe64d370c8837b0cb4d53ec03c6cf376257d4c4",
    "signature_hex": "81eb0e1cd50a495580666941c07a5c9aabdfab0b410c359a4294066cd79f8de5a7e5816557559ef6c5ea0e7e2ad899291946c20d2451db89a79d7a8bb31bc3ac61e7b513d31a19a5c956d96caa3c2b5ad3e36e977c39fec87ad31bcf6f9fe359ac98ca3c5935e3919140a2a7ca51b6ae7e8801b96542f4d590a893bccb35933486da276c7a3d74c8645364d1712f41d270c76fbdfee55182e270ed4167ea429dde232237a308dbba6cebd67de8fb530104f91db1cf9b6807f8c79e7ace030e24bc49ffbb0fae889e7649e6c2989c564674864249b9ab0f66ae7e7090c7100b031c86da5dd1ddebed15570280b821f8ef00ba717926fb796c80c6725363a74fe0aee54656b18a59fcf6cc35f951df1aef36d99a9d1c0e27dfc97c48139d96ac51de1c01191af1dae8a2868cd747e48aac0a4340839de1a1bde7e10d196ed435f620713527103be00b74127cb2c106b800a5794fffa9c61104f21a974d3c3d2de29e5da378c7db758eb3b5e65aa0b56d7dda10772d5b3585ad3dd37eb0ee8cfea590f29a898e9856b9727a341e6242248916307a1385a3cf9caa08c880158002b30ef995e8564554949728d66bef23b5bd4b1ccf15c481328772178aa272b2e6e08a81a32abb402202900c0d3692b034db4e936c1cc4a288bb2a315781a3442bc4e36dbddfc8777e8761ef04aee12d48986de93026b3dae960a8accdcaa473ff2f4895dfbece6f5216359bd8db35866d0abe13752df16c0360a135434764c9cb5ea3001ccef2d7112490cc993e65d5fea0ceb7c7da6eb7fb507604fefed00836a8941d2f03f6ce5cce0e7365b5a10e2e8197c802d77aea363b99e4b8aeaa0dc4dcc5871059a4dea21ee50d34048a2cb36d484b7bd9974c76a735ca8141816bf2f77e00ae8a4f5402fd455c8af274e7940ecaaa1f167723003693e83a43a94a08928aa1be81d2e52534ff6aad438721bc6fe85bdf4b1819dab03dd8cb40dcdb8d05c59b0dc2d8a1ce7a4c0f21e90a2331847fd9b9b9eab330fbfe5c94d55f99b85dd2b1b7a85181e8afb483fb52e6858f70917ac0997f9b49c3814f599710fca1a65acb2635676397b8859b56d3318e06f4daaecd4dd0d61674c92427e36b89c147e6d6dc080cd3098d1974aae513ab9121bca86a3b351906377ce09b06466f8ac0faf42d17a8b4ee492815af7bd8af2d16a52671b1aec1e6e5422ad4b321f0c5ce599acc8fb98aaaa68503c551261b1c3c444a6fa1e1c643c98936fa9a30ec5ef3913edd629590de99ed4257db41581bcd36abfaf54bb0bdf356a1bfd3320eb2ca60c31dea9ff6707d7b4f144c270ac43a38e615bab92e33ee2bbca182cbdeb3fe5874b7b7de9f458fa2e85ee5d7e48ca6bdcc67d190fa1a943e8e45c2c06b78f7182e9d780a63ff5bac19f212ad885aa537e8209063fd4a2aa3cc1329eee19b3e29fea4ce624cffb9dc454a2ef595df3cad0dd0d28786f39ce940837b1222c746c62ad6d4a01e7c2f9e0b1d70709e8897f6ff5f69db9935cad7e46783c6207e3c2e0fc5029fe118cd9b84444da0b8e95d64a391da2f59d7f4c70c6d8cd07959846d25b0f08717fba1263ad2da68b98aea3d1b3d35edc59e3cce929926dd45a3df3ff5915a8f485ce1f790b90b02c6012bc010dda72ad5cc839507bc82800c3d2df0b0690a7431198869d86b899704123f9b8a036514d5b050b52018f0f051a1383eb07de36d07e6d5a153a304a265801db8aa3db483f34cd5166a2c5d26934d7fcab9c5ce6d6a72116687cd49e713cb91251e6c69f4428638bacbe8e7c7edbc58845b90078b08cced7fa14d71b0b92f05668be4627ac29be659732b1e1b592334c4373805ea5211cf2379b48841c602d36ca0394b65de61635e457beabd556a211cfa7ad79e7176f83e29baf07b212b38e67f490554180be216caa25d47fda8344bd778076522a47371b058fb04a49733bfdb30d742417cc94ba32a09d7969e48834f28135d025a73c8cfffb7c1422c9e1a0d8481b979747ceac170714fd17c68b883076172ac9265a04e3b4c13911d6c5650aa5df4a9c85b9cdf79b71165979199dca2c67801d2294528184b9d61d4cf188f53db16703bc0db47b1052e865f489c5f40f6ab995735ce550f32f5724f833eca6aa2623e51288dcaa90d6d49cd87c97233b2b43e1e817725defa54a936fbdb3308642c6358def6b37fbf68b433ebed0bb27c99016f57d2f9a3bc5d2e9f21985ae9e344f708f8b94fe7a4b09743bfd9567c646bc356ca11db32b08650e7308d93484cab923c0749e3d68761d82d3d5a7a27b68e41c6f5a2a8d58c57c3cf5ac7135cc7fd579c6b6a1edda7c0a1aefd8f5771ef2f042fffd94805adcf5d3c8786a4f9a1ae92c13971a7b4b58109b1e1e4c766bc093ecdcef4c1872d252fb1c4e89fac1c181192a2e5f21722dc6c61e4e1d58881997f237bc20d2c83cb4faa08bfa61e6cacdc6765b7318b0604cc11c5ae0567da52b511cabb50b751284a3154ce52cf8c584768a4568479853ebb088e702b3a45b6e894871fb7ede2c7f2f489078c0c0507519ef883b8ebd7509910b2dcf3f9d43edd03c002382694e4d58763706c3e4cfd29e4940ff282ddecbd852da143d5e7d793d6349b5efd004a65d3b08aab4e7852677447b9a1291596e88adc8dbd932d28cf751ad729834106bbe72df14104c624460b6de4c889340c618eb2468c16afedf005aea34b29004fae8af2251ef50f9f94c9a51bbdd53b74ab46c01790651300f314e6e6f41659ef589fa6451f1b8d284e2a61faaa32919cdaf545746d5012a906e119fdd836dd18dcb26d7936310e03ceb688e12ff3567cb7e135f850d1d25bb4aee6ed6fd1bd9baf278503b127d009bcdc54d0690cbf109040a2a0fd11152b17dd42ef4e92ddc6ee1f719acd53f0ee436a053bb440364a04a75f053309abc7d5b14fa1121217103b53a64b328db6e03e89e827225ccfb6a4dfd28df02af64cc13fc1d508d08761f938a3650b471f2c0416d76abf3a57290c77b67906f7163b99e8f5a911d70dd985183558a3be8d316b740162c8e515d2d34b80489a855eb003dba42eb837cdc650603b0faffa83d4ed58713a2e5b4699eb548ed11e6324a0277d6216638f7bd5f52165011f8c14347e2ae70a98ea50a9f0b50ca5390af3887e650b11245d3c7b5a755a087346e27571f9fd9080b59f11187243d8fb4ca69b1df64504da45ba5cb968ee1d248a96a3c77bc64d7c96eac838e659f38dbf31a3ba8874807fef1e0af0cac4f1d0211ae030c5346231b0844c17bab4cce9339fa05d8aa702eb7066e9a5bbc9de2bbe532544da95434563a1071f012be3e0de045271a429f7fa8f6e6dce209cfeef766017b79e55a59f5e3b607f0b6a2849f1fef16ca52414964d392b0a52df575c109a65b0be02340722273a1e506e6026d11c11fc4c5c33f851e7388b4ec44ee755f3d7da2519157a5e36cd82904cac264db209619cbedc6fe1023be28997f83aa9da3e25fac0fdfb3887a9cf1cf2f477f34e1e125cabf482e3516fb12a38400c0f0138a6551e79450b711cd83d6c97bfd2458e6b666ed2eb04d10daf5ad512c58b7e3418d0de0863a650e6788420b7aa89c0e96f3c38d37e600ff3b521379ff1af9f184c56d1a058e06617c215d392e153cf36d5cd63996d804022b074b5e9b88770c704ded82d678f8be12b8651e973da0b118f86f6a84518ddd3fdf87bfadf82bb4f5dad97ec9a846c2fd1b2c7bb1a401e460be215bff975ea5e149121b11df4cb9b671f1c4bb3cc3a781ce4781b39dd7e2f6b83e0147a5f542dd71833db7b47ca30c839422037a8283313d702b3dc939e59790b55ba315723d194bcc2accc4da08f9917234665fd8f980dab809bb5371ff1a7149830fb57db09b9680e13170bb37b26617a574e2cac81bc991efa9260fde685fab5f09fd8da5c8ac184171799ae9896c2d8b6f1590f9dcde11e856b1d0ae65007ea04c8f65094ecda36a0055f64a6fb78b1f79ca356abd2714a52ff510648de869077721aad94404dadddef5929ec3a00e77015e4d465c554e5fe462f0873d0f2d8f9ad7fdb18c362aa207ae8f115e4b3a93273956639ed73c7db601a987afa3d9e046d6a410523e9212b0cf2833c9828d01f2175e7623d81cb29fea92c1ce6230448c9d2aa38d04f05a95c15b94ded952ace211898fff929e9d502ad025c732a0242b10a9ec999cd92b150b44b0288a6ae12984905518461515129fafde6224881e0b18294c60438fea1b9ff781ae79f5be01971ddbcc7dd9ac97932c1f8177f87bb9472553df03d2f70b90a3c0c319762ae499e21df5a10492cf89d710b800c77037c98e6fd645738dac8d4b50b2d6ddb2c7bfce555fca6bff67b205bac12e986bce17c480a4475774cdfe15306aa3e2ac246193381b62bf7972ab6554ba8e3d752a6fd68dcc854579311a4415f69c19b981afc8660b9fc7bd1e79a3c44ef235dc30693c16be57f8aac5a9d4397494daa574bc669e110d6182f60d0d48edd9c9105d620bac0e349de2442c52a8cb1c127fe52443fa8b58edfa752d7dd0d773709b3ea0291122bc4ac33469aed2141528fa1c5d2d31f2c30377f919ad4d8f4030d62b951626377c1dde9f0f60000000000000000000000000000000000000000040c15161a23",
}


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
    write("record_v1_vectors.json", record_v1_file(), manifest)
    manifest["vectors"] = dict(sorted(manifest["vectors"].items()))
    with open(mpath, "w") as f:
        f.write(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
