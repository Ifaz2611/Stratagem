# Iteration log: loop-e

Backend `cli`, model `(backend default)`, 500 examples per iteration.

> This log keeps the measurements recorded with the campaign at that time. The
> serializer was corrected later, so the current three-seed strategy evaluation
> is reported in `docs/comparison.md` and `runs/analysis/coverage_trials.json`.

| iter | accept | productions | max depth | diagnostics | crashes | cum. cost |
|---|---|---|---|---|---|---|
| baseline | 0.2% | 5.3/27 | 0.3 | 3.3 | 0 | $0 |
| 0 | 50.0% | 26/27 | 3000 | 15 | 0 | $3.07 |

## Budget

- LLM calls: **5**
- Prompt tokens billed (incl. backend overhead): 368,742
- Prompt tokens we authored (est.): 22,681
- Output tokens: 319,270
- Cost: **$4.22** of $5.00 cap
