# Iteration log: loop-f

Backend `cli`, model `(backend default)`, 500 examples per iteration.

> This log keeps the measurements recorded with the campaign at that time. The
> serializer was corrected later, so the current three-seed strategy evaluation
> is reported in `docs/comparison.md` and `runs/analysis/coverage_trials.json`.

| iter | accept | productions | max depth | diagnostics | crashes | cum. cost |
|---|---|---|---|---|---|---|
| baseline | 0.2% | 5.3/27 | 0.3 | 3.3 | 0 | $0 |
| 0 | 43.8% | 26/27 | 3500 | 12 | 0 | $1.34 |
| 1 | 38.8% | 25/27 | 5000 | 13 | 0 | $2.40 |
| 2 | 42.4% | 27/27 | 17000 | 15 | 0 | $3.02 |
| 3 | 63.4% | 25/27 | 16500 | 15 | 0 | $5.45 |

## Budget

- LLM calls: **7**
- Prompt tokens billed (incl. backend overhead): 308,121
- Prompt tokens we authored (est.): 48,958
- Output tokens: 477,912
- Cost: **$5.45** of $5.00 cap
