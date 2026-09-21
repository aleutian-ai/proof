# Canonical encoder cross-language corpus

This directory is the **single source of truth** for the canonical-JSON
encoder corpus exercised by:

- **Go**:     `internal/canonical/golden_vectors_test.go::TestGoldenVectors`
- **Python**: `sdk/verification-python/tests/test_canonical_json.py::CORPUS`
- **JS/TS**:  `sdk/verification-js/test/canonicalJson.test.ts::CORPUS`

When a fixture is added to one port's CORPUS list, the other two MUST be
updated in the same change set, and `UPDATE_GOLDEN=1 go test
-run TestGoldenVectors ./internal/canonical/` MUST be re-run to refresh
the `*.json` files here.

## Fixtures

| Fixture | Purpose |
|---|---|
| `ascii_basic.json` | Headline: alphabetical key sort |
| `html_chars.json` | `<`, `>`, `&` survive verbatim |
| `line_separators.json` | U+2028 / U+2029 escaped (Go default; ports match) |
| `emoji_supplementary.json` | UTF-8 4-byte sequences pass through |
| `int64_extremes.json` | INT64_MIN / INT64_MAX preserved as integers |
| `empty_collections.json` | `{}` / `null` / `""` / `[]` distinctions |
| `nested_3_levels.json` | Recursive key sort holds |
| `array_order_preserved.json` | Arrays do NOT sort |
| `mixed_array.json` | Heterogeneous arrays |
| `forward_slash.json` (Batch A L14) | `/` unescaped |
| `control_chars.json` (Batch A L14) | ``..``, `\t`, `\n`, `\r` |
| `del_unescaped.json` (Batch A L14) | U+007F NOT escaped |
| `non_bmp_key_sort.json` (Batch A C1) | UTF-8 byte sort across BMP boundary |

## Reject cases (no JSON artifact)

- `float_rejected`: `ValueError` (Python) / `CanonicalEncodingError` (JS) / `ErrFloatNotAllowed` (Go)
- `max_depth_exceeded`: same trio
- `lone_surrogate` (Batch A C2): `ErrLoneSurrogate` (Go)
- `non_nfc` (Batch A H7): `ErrNotNFC` (Go) / `ValueError` (Python) / `CanonicalEncodingError` (JS)

## Cross-port drift detection

CI runs each port's parity test against THIS directory. Any byte
mismatch fails the build. To regenerate (only when an encoder change
legitimately requires it):

```sh
UPDATE_GOLDEN=1 go test -run TestGoldenVectors ./internal/canonical/
```

## Adding a new fixture

1. Add the case to all 3 ports' CORPUS lists (Go test + Python + JS).
2. Run `UPDATE_GOLDEN=1` to write the new pinned JSON file here.
3. Update this README's table.

The "shared JSON manifest" approach was considered (one machine-readable
file all three ports load); rejected because: (a) the input shape needs
language-native types (int64 → `json.Number` in Go, `int` in Python,
`bigint` in JS), and (b) keeping the input as code in each port's test
file makes drift visible at code-review time.
