# Iteration log: loop-d

Backend `cli`, model `(backend default)`, 500 examples per iteration.

> This log keeps the measurements recorded with the campaign at that time. The
> serializer was corrected later, so the current three-seed strategy evaluation
> is reported in `docs/comparison.md` and `runs/analysis/coverage_trials.json`.

| iter | accept | productions | max depth | diagnostics | crashes | cum. cost |
|---|---|---|---|---|---|---|
| baseline | 0.2% | 5.3/27 | 0.3 | 3.3 | 0 | $0 |
| 0 | 36.6% | 27/27 | 5000 | 15 | 0 | $4.18 |

## Budget

- LLM calls: **3**
- Prompt tokens billed (incl. backend overhead): 269,898
- Prompt tokens we authored (est.): 9,409
- Output tokens: 344,011
- Cost: **$4.18** of $5.00 cap
