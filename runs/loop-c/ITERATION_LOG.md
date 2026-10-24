# Iteration log: loop-c

Backend `cli`, model `(backend default)`, 500 examples per iteration.

> This log keeps the measurements recorded with the campaign at that time. The
> serializer was corrected later, so the current three-seed strategy evaluation
> is reported in `docs/comparison.md` and `runs/analysis/coverage_trials.json`.

Every metric is the **mean of 3 independent trials** (Hypothesis seeds 11/22/33, 500 examples each), with the observed range in brackets. Single-trial numbers are not reliable here: re-sampling the same strategy moved acceptance by up to 15 points. The shipped corpus in each `iterations/iter-N/` is the canonical trial.

| iter | acceptance % | productions | max depth | distinct diagnostics | crashes | cum. cost |
|---|---|---|---|---|---|---|
| 0 | 21.9 [16-27] | 26.0 | 2.3 [2-3] | 14.0 [12-15] | 0 | $0.61 |
| 1 | 36.7 [29-41] | 26.3 [26-27] | 9.3 [3-13] | 15.3 [14-17] | 0 | $1.06 |
| 2 | 41.7 [38-46] | 25.7 [25-26] | 8.3 [5-14] | 14.0 [13-15] | 0 | $1.71 |
| 3 | 44.2 [42-47] | 26.0 [25-27] | 10.3 [4-21] | 16.3 [15-17] | 0 | $2.32 |
| 4 | 42.1 [41-43] | 26.3 [25-27] | 340 [294-377] | 15.7 [14-18] | 0 | $4.51 |

## Which movements are real?

| metric | span across iterations | within-strategy stdev | ratio | monotonic |
|---|---|---|---|---|
| acceptance % | 22.3 | 4.0 | **5.6x** | False |
| distinct diagnostics | 2.3 | 1.5 | **1.6x** | False |
| max depth | 337.7 | 12.5 | **27.0x** | False |

## Budget

- LLM calls: **6**
- Prompt tokens billed (incl. backend overhead): 387,325
- Prompt tokens authored by us (est.): 51,325
- Output tokens: 352,375
- Cost: **$4.51** of $5.00 cap
