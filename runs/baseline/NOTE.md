# Baseline pipeline check

The baseline uses `fuzzer/strategies/baseline.py`. It generates random Unicode
text between 0 and 200 characters and has no knowledge of XML.

```bash
.venv/bin/python -m fuzzer.campaign baseline -n 500 -o runs/baseline
```

This run checks the whole path from generation to serialization, harness
execution, classification, and saved results.

## Saved result

The current `summary.json` records:

| measurement | result |
|---|---:|
| inputs | 500 |
| wall time | 2.65 seconds |
| rejected | 498 |
| parsed cleanly | 1 |
| parsed with a diagnostic | 1 |
| acceptance | 0.4% |
| inputs starting with `<` | 0.6% |
| tracked features | 7/27 |
| maximum parsed depth | 1 |
| distinct diagnostics | 4 |
| crashes | 0 |

Almost every input was rejected near the start of the parser. That is expected
for random text and confirms that the baseline is not already acting like an XML
generator.

The three-seed coverage check is stored in
`runs/analysis/baseline_coverage_trials.json`. It averaged 13.21% parser
coverage with a 4.68-point standard deviation.

## Problems found while checking the pipeline

The baseline exposed several measurement problems:

1. A newline inside an mxml diagnostic could split the harness line protocol.
   The harness now escapes control bytes.
2. Diagnostic normalization could rewrite its own placeholders or leave a quote
   behind. Regression tests cover both cases.
3. mxml could truncate or corrupt a diagnostic when it formatted a decoded
   Unicode code point with `%c`. This became PR #357 and was fixed upstream.
4. The serializer originally changed surrogateescape byte markers. It now
   preserves those raw bytes and uses `surrogatepass` only for other lone
   surrogates.

The complete self-test suite has 101 assertions. The harness smoke suite has 20
checks, including a known sanitizer failure and a similar non-crashing input.
