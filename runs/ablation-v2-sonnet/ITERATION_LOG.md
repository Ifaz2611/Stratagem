# Iteration log: ablation-v2-sonnet

Backend `cli`, model `(backend default)`, 500 examples per iteration.

> This log keeps the measurements recorded with the campaign at that time. The
> serializer was corrected later, so the current three-seed strategy evaluation
> is reported in `docs/comparison.md` and `runs/analysis/coverage_trials.json`.

| iter | accept | productions | max depth | diagnostics | crashes | cum. cost |
|---|---|---|---|---|---|---|
| baseline | 0.2 | 5.3/27 | 0.3 | 3.3 | 0 | $0 |
| 0 | 47.2% | 26/27 | 4 | 13 | 0 | $0.44 |

## Budget

- LLM calls: **1**
- Prompt tokens billed (incl. backend overhead): 18,625
- Prompt tokens we authored (est.): 2,569
- Output tokens: 36,078
- Cost: **$0.44** of $0.60 cap
