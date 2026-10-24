"""Line coverage of a recorded corpus, measured on the gcov build.

Evaluation only. The coverage build never runs inside the agentic loop and no
coverage number reaches the model, so every steering decision comes from the
blackbox signals alone (docs/design-decisions.md D2 and D6).

Inputs come from each iteration's corpus.jsonl.gz rather than being regenerated
from the strategy, so this measures exactly what a run fed the harness. That
makes it the right tool for reproducing a past run and the wrong one for judging
a strategy, because corpora recorded before the serializer fix do not contain the
documents their strategies describe (D13). For a strategy's coverage use
scripts/coverage_trials.py, which re-runs it.

gcov counters accumulate, so .gcda files are cleared before each cell to measure
that cell alone and not a running union.

Usage:
    python scripts/coverage_from_corpus.py loop-c/iter-0 loop-d/iter-0
    python scripts/coverage_from_corpus.py --all
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from fuzzer.corpus import read_corpus  # noqa: E402
from scripts.coverage_study import (  # noqa: E402
    COV_HARNESS, PARSER_FILE, read_coverage, reset_counters,
)


def cells(spec: str) -> list[tuple[str, Path]]:
    """Expand "loop-c/iter-0" or "loop-c" into (label, iteration dir) pairs."""
    run, _, it = spec.partition("/")
    base = REPO / "runs" / run / "iterations"
    dirs = sorted(base.glob(it or "iter-*"), key=lambda p: p.name)
    return [(f"{run}/{d.name}", d) for d in dirs if (d / "corpus.jsonl.gz").exists()]


def run_corpus(iteration_dir: Path) -> int:
    payloads = read_corpus(iteration_dir / "corpus.jsonl.gz")
    for payload in payloads:
        subprocess.run([str(COV_HARNESS)], input=payload,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=15)
    return len(payloads)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("specs", nargs="*", help='e.g. loop-c/iter-0 or loop-d')
    ap.add_argument("--all", action="store_true", help="every run with a corpus")
    ap.add_argument("-o", "--out", default="runs/analysis/coverage_by_corpus.json")
    args = ap.parse_args()

    if not COV_HARNESS.exists():
        sys.exit("coverage build missing; run ./harness/build.sh cov")

    specs = args.specs
    if args.all or not specs:
        # verify_replay.sh writes runs/<id>-replay/ as regenerable output; it is
        # not a campaign and has no meaningful coverage.
        specs = sorted({p.parents[2].name
                        for p in REPO.glob("runs/*/iterations/*/corpus.jsonl.gz")
                        if not p.parents[2].name.endswith("-replay")})

    targets: list[tuple[str, Path]] = []
    for spec in specs:
        targets.extend(cells(spec))
    if not targets:
        sys.exit(f"no corpora matched {specs}")

    rows = []
    for label, d in targets:
        reset_counters()
        n = run_corpus(d)
        cov = read_coverage()
        s = json.loads((d / "summary.json").read_text(encoding="utf-8"))
        st = s.get("structure", {})
        parser = cov.get(PARSER_FILE, {})
        rows.append({
            "cell": label,
            "documents": n,
            "parser_pct": parser.get("pct"),
            "parser_lines_covered": parser.get("covered"),
            "parser_lines_total": parser.get("lines"),
            "all_pct": cov["_total"]["pct"],
            "acceptance_rate": s.get("acceptance_rate"),
            "productions_hit": st.get("productions_hit"),
            "distinct_diagnostics": s.get("distinct_diagnostic_templates"),
            "boundaries": st.get("boundaries"),
            "per_file": cov,
        })
        print(f"  {label:18} docs={n:<4} parser={parser.get('pct'):>5.2f}% "
              f"({parser.get('covered')}/{parser.get('lines')})  "
              f"all={cov['_total']['pct']:>5.2f}%  |  "
              f"accept={s.get('acceptance_rate', 0):.1%} "
              f"prod={st.get('productions_hit')}/{st.get('productions_total')}")

    out = REPO / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(f"\n  wrote {out}")


if __name__ == "__main__":
    main()
