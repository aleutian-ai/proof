# mlkem testdata — provenance

`acvp_keygen.json.gz` holds NIST **ACVP** ML-KEM key-generation vectors for
FIPS 203 — the data used to validate ML-KEM implementations. External evidence:
matching them means matching the standard, not this code.

- **Source:** `kem/mlkem/testdata/ML-KEM-keyGen-FIPS203` in
  github.com/cloudflare/circl v1.6.3, which redistributes the NIST vectors.
- **Shape:** each vector's `d` and `z` are concatenated into the 64-byte `seed`
  this package and RFC 9935 use. The expected `ek` is the encapsulation key.
- **Trimmed:** first 10 vectors per parameter set (20 total). ML-KEM-512
  vectors are omitted — this package does not implement that set (see `_34`).

## What this does NOT cover

NIST's encapsulation/decapsulation vectors (`ML-KEM-encapDecap-FIPS203`) drive
those operations from an expanded decapsulation key, and `crypto/mlkem` builds
keys only from a seed, so they cannot be run through this API. Encapsulation is
also randomised with no derandomised variant, so its output cannot be pinned to
a vector at all. Those paths are covered by round-trip and implicit-rejection
tests instead — behaviour, not conformance. Key derivation, which these vectors
do cover, is genuine conformance.
