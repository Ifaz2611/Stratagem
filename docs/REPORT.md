# Stratagem: Agentic Grammar Fuzzing of Mini-XML

**Target:** Mini-XML (mxml) `v4.0.4` at commit `0d5afc42`.

## Executive Summary

This project demonstrates using Large Language Models (LLMs) to drive grammar-based fuzzing of a C XML parser. An agent writes Hypothesis strategies in Python, tests them against Mini-XML, receives blackbox feedback, and iteratively refines the strategy. The framework is entirely blackbox—no code coverage signals are provided to the LLM, only parser results and input properties.

**Key Results:**
- Cost: $4.51 for a 5-iteration campaign (500 inputs per iteration)
- Coverage: Grammar-based strategies achieved 38-45% parser coverage vs 13% random baseline
- Findings: Fixed one upstream bug (PR #357), reproduced one known leak (issue #354)
- Crashes: No memory-safety crashes or timeouts found in 10,000 tested inputs
- Correlation: Distinct diagnostic count showed +0.76 correlation with coverage

## Overview

This project tests a C XML parser with inputs generated from a formal grammar.
The generator is a Hypothesis strategy written by an LLM. After each batch, the
LLM receives a summary of the results and revises the strategy. The reported
run used five iterations of 500 inputs and cost $4.51.

The fuzzer is blackbox. AddressSanitizer and UndefinedBehaviorSanitizer detect
memory errors, but the agentic loop does not receive code coverage. The loop
works from parser results and properties of the generated inputs.

## Design

I used `XMLParser.g4` and `XMLLexer.g4` from ANTLR's `grammars-v4`
repository. Both files are pinned by source URL and checksum. I also tested
where mxml differs from that grammar.

The most important difference concerns close tags. The grammar can draw the
opening and closing names independently, so it can produce `<a></b>`. mxml
rejects that document. This is not a fault in the grammar. "The close tag must
match the open tag" is not a context-free property, so no context-free grammar
can state it. The generated strategy therefore reuses the opening name when it
writes the close tag. Putting that one rule in the seed prompt is why the first
strategy reached about 30% acceptance instead of near zero. The adaptation notes
also cover mxml features such as unquoted attributes, rootless comments, and
empty element names.

A small C harness passes stdin or file data to `mxmlLoadString`. Its exit codes
separate four outcomes:

- 0: parsed without a diagnostic
- 3: parsed and reported a diagnostic
- 1: rejected
- 2: harness error

Code 3 is separate because mxml can report an error and still return a tree.
Classifying on whether the error callback fired would count those documents as
rejected and distort the acceptance rate, which several results depend on.

A fatal signal, sanitizer report, or five-second timeout counts as a crash.
UBSan is built with `-fno-sanitize-recover=all`, so undefined behavior stops
the process. The smoke test also checks a known mxml bug, upstream issue #350.
This confirms that the sanitizer build can detect a real failure. A similar
non-crashing input is included as a control.

Each loop iteration follows the same steps: validate the generated Python,
sample 50 documents, run 500 documents through the harness, summarize the
results, and request a revision. The campaign code enforces the 500-input and
ten-minute limits. Validation also checks that the strategy produces a useful
mix of well-formed, near-valid, and byte-oriented inputs.

The main feedback signal is the number of distinct parser diagnostics. Each
message comes from a specific error site, so a new message is evidence that the
input reached a different parser branch. The summary also contains acceptance
rate, 27 grammar and mxml-specific input features, nesting depth, input sizes,
timing, and crash signatures.

I measured gcov coverage only after the campaigns. It was used to evaluate the
feedback signals, never to guide the LLM.

## Findings

The saved campaigns contain 10,000 historical inputs from 19 generated
strategies and one random-text baseline. They produced no memory-safety crash
and no timeout.

The work did find a diagnostic defect. mxml formatted a decoded Unicode code
point with `%c`. Some values truncated the error message, while others produced
invalid UTF-8. I reported the problem in
[PR #357](https://github.com/michaelrsweet/mxml/pull/357) and stated that it came
from fuzzing. The maintainer fixed it in commit `d986100` by printing code
points as `U+XXXX`.

The campaign also reproduced a leak on the `<a a>` error path. This matches
upstream issue #354. Across the 10,000 historical inputs, 820 triggered the same
leak signature. I treat this as an independent rediscovery, not a new upstream
bug.

For the coverage study, I reran every saved strategy three times with seeds 11,
22, and 33. Each trial used 500 inputs. The corrected random-text baseline
averaged 13.2% parser coverage, with a standard deviation of 4.7 points. The
first grammar-based strategies averaged 38.7% to 44.9%.

The reported run C changed as follows:

| iteration | diagnostics | parser coverage |
|---|---:|---:|
| 0 | 15.3 | 41.82% |
| 1 | 16.7 | 43.30% |
| 2 | 17.7 | 43.74% |
| 3 | 16.7 | 43.22% |
| 4 | 16.3 | 43.06% |

Iteration 2 was better than the final strategy. Run A showed the same pattern.
The loop always kept the latest strategy, even when an earlier one measured
better.

Across the longer runs, final coverage improved by 0.84 points in A and 1.24
points in C. Exploratory run F improved by 1.60 points, but it cost $5.45. I
exclude F from the budget-compliant result.

Distinct diagnostic count had correlations of +0.95, +0.96, and +0.83 with
coverage in runs A, C, and F. The pooled correlation across all 19 generated
strategies was +0.76. Production count was much weaker because most strategies
already covered almost all 27 tracked features.

## Challenges and limitations

The hardest problem was the measurement code. The first serializer did not
preserve surrogateescape byte markers. A strategy could request raw UTF-16 or
malformed bytes, but different bytes reached mxml. The saved corpora still
replay exactly, but they record the old behavior.

I fixed the serializer and reran the saved strategy code for the coverage
study. This corrected evaluation does not recreate the original agentic loop.
The historical LLM revisions were based on the measurements available at that
time. The repository keeps the old and corrected results in separate folders.

Sampling also adds substantial noise. Two strategies produced from the same
prompt and model differed by 2.12 coverage points. Several refinement gains are
smaller than that. Three trials reduce input-sampling noise, but they do not
measure variation between new LLM generations.

Rare byte cases were another gap. The final strategy included raw UTF-16 cases,
but none appeared in 1,500 corrected draws. I added a fixed eight-input byte
probe so those cases run every time. A fixed probe is more reliable for rare
inputs that are important enough to test every time.

With more time, I would generate several strategies for each prompt condition.
I would also keep the best measured strategy instead of always keeping the
latest one, and add real XML samples to reach more semantic parser behavior.

## Conclusion

The project produced a reproducible blackbox fuzzing pipeline, found and
disclosed a real mxml defect, demonstrated an upstream fix, and showed that
measurement correctness is essential to interpreting agentic fuzzing results.
