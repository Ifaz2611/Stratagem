# Stratagem — Design Decisions

This file records the main engineering choices behind the Stratagem agentic fuzzing framework. These decisions were made during development of the Mini-XML fuzzing campaign and represent the design rationale for the current implementation. Each decision is labeled (D1, D2, etc.) for easy reference.

## D1. Target: mxml v4.0.4

I chose mxml because it is small, maintained, and gives detailed parser errors
through `mxmlOptionsSetErrorCallback`. Those messages provide useful blackbox
feedback. A parser that returns only success or failure would give the agentic
loop much less information.

XML also has recursive structure, so the generator has a real reason to use
`st.recursive` and `@composite`. mxml parses iteratively and tracks parent
pointers, so deep XML does not directly mean deep C call stacks.

The target is pinned to commit
`0d5afc4278d7a336d554602b951c2979c3f8f296`, the mxml v4.0.4 release.
`scripts/fetch_target.sh` checks the commit after checkout. This keeps the test
target stable.

## D2. Blackbox boundary

The design deliberately excludes coverage-guided mutation and instrumentation
beyond sanitizers. The loop uses only generated-input properties, process
results, and diagnostics returned through mxml's public callback.

I did not give the loop a list of the 40 `_mxml_error()` sites from mxml source.
Such a list would reveal which error sites were still missing and would act like
a coverage map.

Gcov and source-level error-site counts are used only after a campaign. They
evaluate the strategy but do not affect later generations.

## D3. UBSan stops the process

The build uses `-fno-sanitize-recover=all` and sets
`UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1`.

Without those settings, UBSan can print a runtime error and still exit with code
0. The fuzzer could then record undefined behavior as a clean parse. An
integer-overflow control confirms that the configured build exits with SIGABRT.

## D4. Leak detection uses a separate pass

The main campaigns run with `ASAN_OPTIONS=detect_leaks=0`. A separate replay
enables LeakSanitizer.

mxml leaks on the `<a a>` error path, and 8.2% of the historical corpus reaches
that path. If leak detection stayed enabled during every campaign, the same
known leak would dominate the crash records. The separate pass keeps leak
results without mixing them with fatal memory errors.

## D5. Acceptance uses a range

The prompt targets an acceptance range of roughly 40% to 70%. Very low
acceptance means most inputs stop near the parser entrance. Very high acceptance
leaves little exercise of error handling. The hard validation gate is
deliberately wider (10% to 95%): it rejects only strategies that clearly fail
one way or the other, and leaves borderline cases to refinement.

The summary also reports acceptance by input class. A single overall percentage
can hide a missing class. For example, a strategy may have reasonable total
acceptance while producing almost no malformed input.

## D6. Gcov is for evaluation

A separate build uses `--coverage`. I run it after the agentic campaigns to
compare saved strategies and feedback signals. Coverage is never included in an
LLM prompt.

This separation lets the report check whether the blackbox signals were useful
without turning the loop into a coverage-guided fuzzer.

## D7. Fixed stack size

`run.sh` sets the stack limit to 8 MiB. A fixed limit makes any stack-related
failure easier to reproduce across machines. No such failure appeared because
mxml parses nested elements iteratively.

## D8. Positive and negative controls

The smoke test includes upstream issue #350, a known memory error in
`mxmlIndexNew`. The sanitizer build detects it. A similar input that does
not trigger the bug is checked as well.

These controls show that the harness can detect a real sanitizer failure without
classifying every nearby input as a crash. The indexing path is enabled only by
the harness's `--index` option. Normal fuzzing calls the parse path and does not
claim issue #350 as a new finding.

## D9. Reproducibility uses recorded bytes

Each campaign writes the exact payloads to
`iterations/iter-N/corpus.jsonl.gz`. The payloads are base64 encoded because
they may contain NULs or invalid text bytes.

`scripts/verify_replay.sh` sends those bytes through the harness again and
compares classifications and corpus digests. It also rebuilds each generated
strategy from the saved LLM transcript. Both five-iteration runs replay all
2,500 classifications, and their strategy files match byte for byte.

This replay reproduces the original inputs and
classifications. It does not generate a new LLM response, and it does not apply
new validation rules to an old run.

Hypothesis's example database is disabled for campaign measurement. Otherwise,
cached examples from an earlier iteration could appear in a later sample.
Minimization enables the database because replay and shrinking are useful there.

## D10. Input features are measured from the output

`fuzzer/features.py` scans generated documents for 27 grammar and mxml-specific
features. Generated strategies do not call a reporting helper while drawing
data.

Scanning keeps the strategy interface small:
`documents() -> SearchStrategy[str]`. It also measures the baseline and every
generated strategy with the same code.

Malformed documents are difficult to scan accurately. The first scanner treated
parts of comments, CDATA, processing instructions, and declarations as XML
elements. This created false feature counts and incorrect nesting depth. The
scanner now masks those regions first, and regression tests cover the cases.

Byte features are checked on the serialized payload. A UTF-16 byte-order mark or
invalid UTF-8 sequence may not exist as normal Python text.

## D11. Evaluation uses three fixed seeds

The agentic loop runs one batch of 500 inputs per iteration. That batch is the
historical campaign record.

For later comparison, each saved strategy is run again at Hypothesis seeds 11,
22, and 33. Each seed still uses 500 inputs. The report gives the mean and sample
standard deviation of those three runs. These extra trials do not use LLM budget
and are not fed back into the loop.

The repeated trials matter because input sampling is noisy. The first run C
strategy ranged from 40.94% to 43.34% coverage across the three seeds. Two
separately generated v2 Sonnet strategies also differed by 2.12 points. Fixed
seeds reduce sampling uncertainty, but they do not remove variation between LLM
generations.

The corrected random-text baseline is stored separately in
`runs/analysis/baseline_coverage_trials.json`. It averaged 13.21% coverage with
a 4.68-point standard deviation.

## D12. Input-class checks live in validation

`agent/validate.py` checks the smoke sample against these bounds:

- `well_formed >= 35%`
- `near_miss >= 15%`
- `byte_hostile` between 15% and 45%

A seven-point sampling margin is applied to the 50-input validation batch.
Strategies outside the allowed range receive a repair request before a full
campaign starts.

Earlier prompts only described the desired class mix. The generated strategies
often ignored it or traded one class for another. Moving the check into
validation made the mix more predictable. The available runs do not prove that
this gate improves parser coverage.

## D13. Raw bytes through a string strategy

Generated strategies return Python `str`, while mxml receives bytes. Some
important parser paths start before text decoding, including byte-order mark
detection and malformed UTF handling.

The strategies use Python's surrogateescape convention for raw bytes. A code
point from U+DC80 to U+DCFF represents one byte from `0x80` to `0xff`.
`fuzzer/campaign.py` converts those markers back to their original bytes.
Other lone surrogates use `surrogatepass`, which produces intentionally invalid
UTF-8 sequences.

The first serializer used `surrogatepass` for both cases. As a result, intended
raw bytes changed before reaching mxml. The historical corpora preserve that old
behavior and still replay correctly. The corrected coverage study reruns the
saved strategy code through the fixed serializer.

Rare raw-byte branches are now covered by
`fuzzer/strategies/byte_probe.py`. It contains eight fixed cases that run every
time. Fixed probes are more reliable than random sampling for rare inputs that
matter to the evaluation.
