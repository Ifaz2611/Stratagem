# Iteration log: loop

Backend `cli`, model `claude-sonnet-5`, 500 examples per iteration.

> This log keeps the measurements recorded with the campaign at that time. The
> serializer was corrected later, so the current three-seed strategy evaluation
> is reported in `docs/comparison.md` and `runs/analysis/coverage_trials.json`.

Every metric is the **mean of 3 independent trials** (Hypothesis seeds 11/22/33, 500 examples each), with the observed range in brackets. Single-trial numbers are not reliable here: re-sampling the same strategy moved acceptance by up to 15 points. The shipped corpus in each `iterations/iter-N/` is the canonical trial.

| iter | acceptance % | productions | max depth | distinct diagnostics | crashes | cum. cost |
|---|---|---|---|---|---|---|
| baseline | 0.2 [0-0] | 5.3 [5-6] | 0.3 [0-1] | 3.3 [3-4] | 0 | $0 |
| 0 | 32.0 [30-36] | 23.7 [23-24] | 37.0 [36-38] | 11.7 [11-12] | 0 | $0.44 |
| 1 | 36.3 [33-41] | 21.7 [21-22] | 4.7 [4-5] | 13.3 [12-14] | 0 | $0.76 |
| 2 | 39.2 [35-43] | 22.7 [22-24] | 93.7 [73-124] | 15.0 [14-16] | 0 | $1.19 |
| 3 | 46.1 [41-51] | 24.0 | 90.3 [54-150] | 13.3 [12-15] | 0 | $1.66 |
| 4 | 45.5 [41-53] | 23.0 | 98.0 [67-132] | 14.0 [13-15] | 0 | $2.01 |

## Which movements are real?

| metric | span across iterations | within-strategy stdev | ratio | monotonic |
|---|---|---|---|---|
| acceptance % | 14.1 | 4.6 | **3.1x** | False |
| distinct diagnostics | 3.3 | 1.1 | **3.2x** | False |
| max depth | 93.3 | 22.6 | **4.1x** | False |

## Budget

- LLM calls: **5**
- Prompt tokens billed (incl. backend overhead): 117,266
- Prompt tokens authored by us (est.): 27,041
- Output tokens: 171,307
- Cost: **$2.01** of $5.00 cap
