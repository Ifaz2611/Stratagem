#!/usr/bin/env python3
"""Build ITERATION_LOG.md from a run's summaries plus its variance study.

Reports each metric as a multi-trial mean with range rather than a single
number. Re-sampling the same strategy moves acceptance by up to 15 points, so a
single trial is not a reliable measurement; Klees et al. (CCS 2018) require
multiple trials for this reason.
"""
from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from fuzzer.timeutil import utc_iso  # noqa: E402


def cell(vals: list[float] | list[int]) -> str:
    if not vals:
        return "-"
    m = statistics.mean(vals)
    lo, hi = min(vals), max(vals)
    fmt = f"{m:.1f}" if m < 100 else f"{m:.0f}"
    return f"{fmt} [{lo:.0f}-{hi:.0f}]" if lo != hi else f"{fmt}"


def main(run_id: str = "loop") -> int:
    out = REPO / "runs" / run_id
    var = {}
    vf = out / "variance_study.json"
    if vf.exists():
        for r in json.loads(vf.read_text(encoding="utf-8")):
            var[str(r["iteration"])] = r

    loop_summary = json.loads((out / "loop_summary.json").read_text(encoding="utf-8"))
    costs = {r["iteration"]: r.get("cost_usd_cumulative") for r in loop_summary["iterations"]}

    lines = [
        f"# Iteration log: {run_id}", "",
        f"_Generated {utc_iso()} (UTC)._", "",
        f"Backend `{loop_summary.get('backend')}`, model `{loop_summary.get('model')}`, "
        f"{loop_summary.get('max_examples')} examples per iteration.", "",
        "Every metric is the **mean of 3 independent trials** (Hypothesis seeds "
        "11/22/33, 500 examples each), with the observed range in brackets. "
        "Single-trial numbers are not reliable here: re-sampling the same "
        "strategy moved acceptance by up to 15 points. The shipped corpus in "
        "each `iterations/iter-N/` is the canonical trial.", "",
        "| iter | acceptance % | productions | max depth | distinct diagnostics | crashes | cum. cost |",
        "|---|---|---|---|---|---|---|",
    ]

    def row(label: str, key: str, cost: str) -> str | None:
        v = var.get(key)
        if not v:
            return None
        crashes = 0
        d = out / "iterations" / f"iter-{key}" if key != "baseline" else REPO / "runs" / "baseline"
        sf = d / "summary.json"
        if sf.exists():
            crashes = json.loads(sf.read_text(encoding="utf-8")).get("crash_count", 0)
        return (f"| {label} | {cell(v['acceptance_pct'])} | {cell(v['productions'])} | "
                f"{cell(v['max_depth'])} | {cell(v['diagnostics'])} | {crashes} | {cost} |")

    r = row("baseline", "baseline", "$0")
    if r:
        lines.append(r)
    for i in range(10):
        if str(i) not in var:
            continue
        c = costs.get(i)
        lines.append(row(f"{i}", str(i), f"${c:.2f}" if c is not None else "n/a"))

    # Signal vs noise, so a reader can judge which movements are real.
    lines += ["", "## Which movements are real?", "",
              "| metric | span across iterations | within-strategy stdev | ratio | monotonic |",
              "|---|---|---|---|---|"]
    iters = [var[str(i)] for i in range(10) if str(i) in var]
    for label, key in (("acceptance %", "acceptance_pct"),
                       ("distinct diagnostics", "diagnostics"),
                       ("max depth", "max_depth")):
        means = [statistics.mean(v[key]) for v in iters]
        noise = statistics.mean([statistics.stdev(v[key]) for v in iters])
        span = max(means) - min(means)
        mono = all(b >= a for a, b in zip(means, means[1:]))
        ratio = span / noise if noise else float("inf")
        lines.append(f"| {label} | {span:.1f} | {noise:.1f} | **{ratio:.1f}x** | {mono} |")

    b = loop_summary["budget"]
    lines += ["", "## Budget", "",
              f"- LLM calls: **{b['llm_calls']}**",
              f"- Prompt tokens billed (incl. backend overhead): {b['billable_input_tokens']:,}",
              f"- Prompt tokens authored by us (est.): {b['authored_prompt_tokens_est']:,}",
              f"- Output tokens: {b['output_tokens']:,}",
              f"- Cost: **${b['cost_usd']:.2f}** of ${b['max_usd']:.2f} cap"]

    (out / "ITERATION_LOG.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {out}/ITERATION_LOG.md")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "loop"))
