# Comparing the generated strategies

The primary evaluation is one agentic fuzzing run, reported as `runs/loop-c`.
I ran several other configurations to study three questions:

1. How much does the first prompt affect the strategy?
2. Do later iterations improve the strategy?
3. Do the blackbox feedback signals track parser coverage?

I used line coverage of `mxml-file.c` as an evaluation measure. The file has
833 measured lines. Coverage was collected after the fuzzing runs and was never
shown to the LLM.

## Runs

| run | prompt set | model | iterations | cost | role |
|---|---|---|---:|---:|---|
| A, `runs/loop` | v1 | Sonnet | 5 | $2.01 | comparison |
| B, `runs/loop-b` | v2 | Opus | 2 | $1.84 | model comparison |
| C, `runs/loop-c` | v2 | Sonnet | 5 | $4.51 | reported run |
| D, `runs/loop-d` | v3 | Sonnet | 1 | $4.18 | prompt check |
| E, `runs/loop-e` | v4 | Sonnet | 1 | $4.22 | validation check |
| F, `runs/loop-f` | v5 | Sonnet | 4 | $5.45 | exploratory, over budget |
| `ablation-v2-sonnet` | v2 | Sonnet | 1 | $0.44 | second v2 generation |

Runs A and C completed five iterations within $5. Run C is the reported run.
Runs B, D, and E stopped early when the backend reached an account usage limit.
Run F exceeded the spend cap because the old budget check ran only
between iterations. Its measurements are kept for analysis, but I do not use it
as evidence that the reported run met the budget.

Prompt set v1 reports acceptance, diagnostic count, and generated input
features. V2 adds marginal feedback, input classes, and a different refinement
request for each round. Later prompt sets add size boundaries and move the input
class rules into validation.

## Measurement method

A Hypothesis strategy produces a different sample on each run. A single sample
was too unstable for comparison. For example, the first strategy from run C
gave the following results:

| seed | coverage | acceptance |
|---:|---:|---:|
| 11 | 41.18% | 17.8% |
| 22 | 43.34% | 23.4% |
| 33 | 40.94% | 24.2% |

The same strategy differed by 2.40 coverage points across those seeds. I
therefore ran every strategy at seeds 11, 22, and 33, with 500 inputs per seed.
The tables report the mean and sample standard deviation.
`scripts/coverage_trials.py` produces the data in
`runs/analysis/coverage_trials.json`.

The historical corpora were generated before a serializer correction. They
replay the original campaign exactly, but some byte markers were encoded
incorrectly at the time. The coverage comparison therefore reruns the saved
strategy code through the corrected serializer. It does not use the historical
corpora. Old measurements are kept under
`runs/analysis/pre-serializer-fix/` so they are not confused with the current
table.

The corrected random-text baseline was measured with the same three seeds. It
averaged 13.21% coverage with a 4.68-point standard deviation. This baseline is
quite noisy because almost every random string is rejected near the start of the
parser.

## R1. Prompt and model effects

| first strategy | parser coverage |
|---|---:|
| v1, Sonnet, run A | 38.66% ± 0.55 |
| v2, Sonnet, run C | 41.82% ± 1.32 |
| v2, Sonnet, ablation | 43.94% ± 1.07 |
| v2, Opus, run B | 44.90% ± 0.67 |

The two v2 Sonnet generations differ by 2.12 points even though their setup is
the same. This is direct evidence of model-generation variance.

The mean of the two v2 Sonnet cells is 42.88%. Compared with run A, the v2
prompt is associated with a 4.22-point increase. Opus is 2.02 points above that
v2 Sonnet mean. The prompt difference is larger than the observed same-setup
gap. The model difference is about the same size as that gap, so this experiment
does not separate the model effect from generation variance.

## R2. Later iterations

| run | first | final | change | best |
|---|---:|---:|---:|---|
| A, 5 iterations | 38.66% | 39.50% | +0.84 | 40.18% at iteration 2 |
| C, 5 iterations | 41.82% | 43.06% | +1.24 | 43.74% at iteration 2 |
| F, 4 iterations | 39.94% | 41.54% | +1.60 | 41.54% at iteration 3 |

All three final strategies measured above their first strategy. The gains are
small compared with the first grammar-based generation, which reached about
39% to 45% coverage.

The evidence is limited. Each sequence of LLM revisions happened once, and run
F is over budget. Runs A and C are the two complete, budget-compliant
five-iteration sequences. They improved by less than 1.3 points.

In both A and C, iteration 2 measured better than iteration 4. The loop keeps the
newest strategy, so it does not preserve the best earlier result. Saving the
best measured strategy would improve the final selection without another LLM
call.

## R3. Feedback signals

I compared each feedback signal with corrected line coverage inside the three
longer runs.

| signal | A | C | F | same direction? |
|---|---:|---:|---:|---|
| distinct diagnostics | +0.95 | +0.96 | +0.83 | yes |
| acceptance rate | +0.52 | +0.76 | +0.78 | yes |
| well-formed share | +0.46 | +0.72 | +0.42 | yes |
| productions found | +0.05 | +0.16 | -0.26 | no |
| byte-oriented share | -0.35 | +0.72 | -0.02 | no |

Distinct diagnostic count had the strongest and most consistent relationship
with coverage. In run C, both values reached their maximum at iteration 2:

| iteration | diagnostics | coverage |
|---:|---:|---:|
| 0 | 15.3 | 41.82% |
| 1 | 16.7 | 43.30% |
| 2 | 17.7 | 43.74% |
| 3 | 16.7 | 43.22% |
| 4 | 16.3 | 43.06% |

There are only four or five points in each run, so the individual correlations
are uncertain. Across all 19 generated strategies, the pooled correlation
between diagnostic count and coverage is +0.76. At 19 observations that clears
p < 0.05, where chance alone gives a correlation above 0.46 less than 5% of the
time. The pooled figure is what makes this result supportable rather than
suggestive.

The diagnostic count is still an approximation. Variable text is normalized, but
mxml truncates its own messages in two ways, and each shifts the count a little
(`docs/findings.md`). A message cut short by the `%c` defect adds one extra
template for a site already counted. A message that fills mxml's 1024-byte
buffer loses the text naming its site, so several sites collapse into one.

Production count did not behave the same way. Across the 19 strategies it ranged
from 22.7 to 26.7 of the 27 tracked features, and 14 of them sat at 25 or above,
leaving little room for the value to change. It also
measures the generated documents, not the parser's behavior. A document can
contain many tracked features and still be rejected early.

Acceptance had a positive relationship with coverage in all three longer runs.
This makes sense for mxml because accepted documents reach more of the parser.
The result does not support maximizing acceptance. Rejected documents are still
useful for exercising error handling.

## Budget

Run C used five iterations and six calls, including one repair call. Its final
cost was $4.51. The second LLM call brought the cumulative cost to $1.06, while
the last iteration raised it from $2.32 to $4.51. Later prompts were more
expensive because they included a growing strategy and more history.

Run F reached $5.45. The budget check has since been changed so a call is refused
when the remaining budget cannot cover the running average call cost.

## Related work

Zest separates syntactic and semantic parser stages and reports that invalid
inputs can reach bugs missed by generator-only testing. This motivated the mix
of valid, near-valid, and byte-oriented documents.

Klees et al. show that fuzzing comparisons need repeated trials and enough time.
They also warn that stack-based crash hashes do not always match true root
causes. Those points motivated the three-seed measurements and the cautious
language around crash grouping.

Fuzz4All changes its generation request across rounds, while FunFuzz rewards
new coverage. Prompt v2 adapts both ideas without sending coverage to the loop.
Run C improved slightly more than run A, but the difference is too small to
credit either change.

## Limits of the comparison

- Each LLM revision sequence was generated once. The three seeds resample a
  saved strategy; they do not repeat the LLM generation.
- The two v2 Sonnet strategies differ by 2.12 points. Most iteration gains are
  smaller than that.
- Runs B, D, and E are too short to show a refinement trend.
- Run F is exploratory because it exceeded the $5 limit.
- The corrected evaluation reruns strategy code, while the original LLM saw
  measurements from the older serializer.
- Coverage is an evaluation measure, not the main goal. None of the strategies
  found a memory-safety crash.
- These results cover one XML parser. Other parsers may behave differently.

## Conclusion

The grammar-based first strategy produced the largest improvement over random
text. Later revisions gave smaller gains. In the two complete, budget-compliant
runs, the final improvement was 0.84 and 1.24 coverage points.

Distinct parser diagnostics were the most useful feedback signal in this study.
Production count was almost flat and did not track parser coverage well. More
LLM generations are needed before assigning precise effects to prompt or model
changes.
