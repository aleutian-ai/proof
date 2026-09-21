# Canonical JSON golden vectors

These files are the byte-stable expected output of
`internal/canonical.MarshalJSON` for the corpus in
`internal/canonical/golden_vectors_test.go`.

**Cross-language parity gate**: the Python (`sdk/verification-python/`)
and JS (`sdk/verification-js/`) canonical encoders MUST produce
byte-identical output for the same logical input. The corpus is
defined in `golden_vectors_test.go`; the SDK parity tests should
reproduce the same input shapes and compare against these files.

## Regenerating

```sh
UPDATE_GOLDEN=1 go test -run TestGoldenVectors ./internal/canonical/
```

This regenerates every `*.json` file in this directory from the Go
encoder. **Only regenerate when a legitimate encoder change requires
updating the pins**; if the Go output drifts unexpectedly, the right
fix is to figure out why, NOT to re-pin.

## Why these specific fixtures

| Fixture | Tests |
|---|---|
| `ascii_basic.json` | Headline rule: alphabetical key sort |
| `html_chars.json` | E1 H1: `<`, `>`, `&` survive verbatim (no `<` etc.) |
| `line_separators.json` | U+2028 / U+2029 — Go default escapes these in `json.Marshal`, our encoder must not |
| `emoji_supplementary.json` | UTF-8 supplementary plane (4-byte sequences) |
| `int64_extremes.json` | INT64_MIN / INT64_MAX preserved as integers, not coerced to float |
| `empty_collections.json` | `{}` vs `null` vs `""` vs `[]` distinctions |
| `nested_3_levels.json` | Recursive key sort holds across nesting |
| `array_order_preserved.json` | Arrays do NOT sort; declaration order kept |
| `mixed_array.json` | Heterogeneous arrays (numbers + strings + bools + nulls + objects) |

## Reject cases (no `*.json` artifact)

- `float_rejected` — `ErrFloatNotAllowed` (per E1 L4)
- `max_depth_exceeded` — `ErrMaxDepthExceeded` (per E1 H2)

Tested via `TestGoldenVectors_Rejects`.
