# mldsa testdata — provenance

`acvp_keygen.json.gz` holds NIST **ACVP** (Automated Cryptographic Validation
Program) ML-DSA key-generation vectors for FIPS 204 — the data used to validate
ML-DSA implementations. They are external: agreeing with them means agreeing
with the standard, not with this code.

- **Source:** `sign/mldsa/testdata/ML-DSA-keyGen-FIPS204` in
  github.com/cloudflare/circl v1.6.3, which redistributes the NIST ACVP vectors.
- **Extracted:** `tcId`, `parameterSet`, `seed`, `pk` only. The secret keys in
  the original `expectedResults` are dropped — this package derives public keys
  from seeds, so `sk` is not needed.
- **Trimmed:** the first 10 vectors per parameter set (30 of 75), to keep the
  module small. All 75 were run against this implementation on 2026-09-22 and
  every one matched.

## What this does NOT cover

ACVP's signature vectors (`ML-DSA-sigGen-FIPS204`) drive `Sign_internal` from an
expanded signing key with no context prefix. This package signs from a SEED
using pure ML-DSA with an empty context, so those vectors cannot be run through
its public API. Signature stability is therefore covered by a self-generated
known-answer digest in `mldsa_test.go` — which detects drift, not conformance.
Key derivation, the part these vectors do cover, is genuine conformance.
