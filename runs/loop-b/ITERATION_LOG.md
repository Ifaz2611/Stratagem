# Iteration log: loop-b

Backend `cli`, model `(backend default)`, 500 examples per iteration.

> This log keeps the measurements recorded with the campaign at that time. The
> serializer was corrected later, so the current three-seed strategy evaluation
> is reported in `docs/comparison.md` and `runs/analysis/coverage_trials.json`.

Every metric is the **mean of 3 independent trials** (Hypothesis seeds 11/22/33, 500 examples each), with the observed range in brackets. Single-trial numbers are not reliable here: re-sampling the same strategy moved acceptance by up to 15 points. The shipped corpus in each `iterations/iter-N/` is the canonical trial.

| iter | acceptance % | productions | max depth | distinct diagnostics | crashes | cum. cost |
|---|---|---|---|---|---|---|
| 0 | 47.2 [42-52] | 27.0 | 130 [96-186] | 15.3 [14-16] | 0 | $1.20 |
| 1 | 50.3 [45-54] | 26.7 [26-27] | 728 [582-904] | 14.3 [14-15] | 0 | $1.84 |

## Which movements are real?

| metric | span across iterations | within-strategy stdev | ratio | monotonic |
|---|---|---|---|---|
| acceptance % | 3.1 | 4.9 | **0.6x** | True |
| distinct diagnostics | 1.0 | 0.9 | **1.2x** | False |
| max depth | 598.0 | 106.0 | **5.6x** | True |

## Budget

- LLM calls: **2**
- Prompt tokens billed (incl. backend overhead): 44,776
- Prompt tokens authored by us (est.): 9,009
- Output tokens: 92,548
- Cost: **$1.84** of $2.50 cap
