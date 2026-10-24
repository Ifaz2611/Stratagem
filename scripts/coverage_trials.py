"""Line coverage of each recorded strategy, regenerated and measured N times.

Evaluation only. The coverage build never runs inside the agentic loop and no
coverage number reaches the model (docs/design-decisions.md D2 and D6).

Why this exists alongside coverage_from_corpus.py. That script replays the bytes
a run recorded, which is the right tool for reproducing what a run did. It is
the wrong tool once the serializer changes, because the recorded bytes were
produced by the old one. This script re-runs the strategy itself, so the
documents reaching the parser are the ones the strategy actually describes.

Each strategy is drawn at several Hypothesis seeds and reported as a mean with
its standard deviation, because a single draw moves parser coverage by more than
a point (D11).

Usage:
    python scripts/coverage_trials.py loop-c loop
    python scripts/coverage_trials.py --all
"""

from __future__ import annotations

import argparse
import json
import shutil
import statistics as stats
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from fuzzer.campaign import Campaign  # noqa: E402
from fuzzer.corpus import read_corpus  # noqa: E402
from scripts.coverage_study import (  # noqa: E402
    COV_HARNESS, PARSER_FILE, read_coverage, reset_counters,
)

SEEDS = (11, 22, 33)
SCRATCH_MODULE = "_cov_trial"


def measure(strategy: Path, seed: int, out: Path, examples: int) -> dict:
    """Draw one trial from a strategy and return its coverage and proxies."""
    dest = REPO / "fuzzer" / "strategies" / f"{SCRATCH_MODULE}.py"
    shutil.copy(strategy, dest)
    try:
        c = Campaign(SCRATCH_MODULE, examples, out, mode="survey")
        c.random_seed = seed
        s = c.run()
    finally:
        dest.unlink(missing_ok=True)

    reset_counters()
    for payload in read_corpus(out / "corpus.jsonl.gz"):
        subprocess.run([str(COV_HARNESS)], input=payload, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=15)
    cov = read_coverage()[PARSER_FILE]
    b = s["buckets"]
    return {
        "seed": seed,
        "parser_pct": cov["pct"],
        "parser_lines_covered": cov["covered"],
        "acceptance": round(s["acceptance_rate"], 4),
        "diagnostics": s["distinct_diagnostic_templates"],
        "productions": s["structure"]["productions_hit"],
        "crashes": s["crash_count"],
        **{k: round(b.get(k, {}).get("share", 0.0), 4)
           for k in ("well_formed", "near_miss", "byte_hostile")},
    }


def cells(run: str) -> list[tuple[str, Path]]:
    base = REPO / "runs" / run
    if (base / "summary.json").exists() and not (base / "iterations").exists():
        strat = REPO / "fuzzer" / "strategies" / "baseline.py"
        return [(f"{run}/baseline", strat)] if strat.exists() else []
    out = []
    for d in sorted(base.glob("iterations/iter-*")):
        if (d / "strategy.py").exists() and (d / "summary.json").exists():
            out.append((f"{run}/{d.name}", d / "strategy.py"))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("runs", nargs="*")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("-n", "--examples", type=int, default=500)
    ap.add_argument("-o", "--out", default="runs/analysis/coverage_trials.json")
    args = ap.parse_args()

    if not COV_HARNESS.exists():
        sys.exit("coverage build missing; run ./harness/build.sh cov")

    runs = args.runs
    if args.all or not runs:
        runs = sorted({p.parents[2].name
                       for p in REPO.glob("runs/*/iterations/*/strategy.py")
                       if not p.parents[2].name.endswith("-replay")})

    scratch = REPO / "runs" / ".cov-trials"
    rows = []
    for run in runs:
        for label, strat in cells(run):
            trials = [measure(strat, s, scratch / label.replace("/", "_") / f"s{s}",
                              args.examples)
                      for s in SEEDS]
            pct = [t["parser_pct"] for t in trials]
            row = {"cell": label, "seeds": list(SEEDS), "trials": trials,
                   "parser_pct_mean": round(stats.mean(pct), 2),
                   "parser_pct_stdev": round(stats.stdev(pct), 2),
                   "parser_pct_min": min(pct), "parser_pct_max": max(pct),
                   "crashes": sum(t["crashes"] for t in trials)}
            rows.append(row)
            print(f"  {label:22} {row['parser_pct_mean']:6.2f}% "
                  f"+-{row['parser_pct_stdev']:.2f}  "
                  f"[{min(pct):.2f}, {max(pct):.2f}]  crashes={row['crashes']}",
                  flush=True)

    out = REPO / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    shutil.rmtree(scratch, ignore_errors=True)
    print(f"\n  wrote {out}")


if __name__ == "__main__":
    main()
