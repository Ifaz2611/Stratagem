"""Measure whether the blackbox proxy signals track real line coverage.

Evaluation only. The coverage build is never executed inside the agentic loop
and no coverage number is ever fed back to the model, so every steering decision
is made from the blackbox signals alone (docs/design-decisions.md D2 and D6).
This runs afterwards to answer whether those signals were worth steering by.

Method. The generated documents are regenerated from each iteration's saved
strategy and replayed through the gcov-instrumented build. gcov counters
accumulate, so .gcda files are deleted before each iteration's batch to measure
that iteration alone rather than a running union.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from hypothesis import HealthCheck, given, settings

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fuzzer.campaign import _encode  # noqa: E402
from fuzzer.features import PRODUCTIONS  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
COV_DIR = REPO / "build" / "cov"
COV_HARNESS = COV_DIR / "harness"
# The parser is the file the loop was trying to reach. Others are reported too,
# but mxml-file.c is the headline.
PARSER_FILE = "mxml-file.c"
MXML_FILES = ("mxml-file.c", "mxml-node.c", "mxml-attr.c", "mxml-options.c",
              "mxml-private.c", "mxml-get.c", "mxml-set.c", "mxml-search.c",
              "mxml-index.c")

_RE_COV = re.compile(r"Lines executed:([\d.]+)% of (\d+)")


def reset_counters() -> None:
    for f in COV_DIR.rglob("*.gcda"):
        f.unlink()


def read_coverage() -> dict:
    """Per-file and aggregate line coverage from gcov."""
    out, tot_cov, tot_lines = {}, 0, 0
    for name in MXML_FILES:
        p = subprocess.run(["gcov", "-n", name], cwd=COV_DIR,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        text = p.stdout.decode("utf-8", "replace")
        block = text.split(f"File '{name}'")
        if len(block) < 2:
            continue
        m = _RE_COV.search(block[1])
        if not m:
            continue
        pct, lines = float(m.group(1)), int(m.group(2))
        covered = round(pct / 100.0 * lines)
        out[name] = {"pct": pct, "lines": lines, "covered": covered}
        tot_cov += covered
        tot_lines += lines
    out["_total"] = {"covered": tot_cov, "lines": tot_lines,
                     "pct": round(100.0 * tot_cov / tot_lines, 2) if tot_lines else 0.0}
    return out


def replay(strategy_path: Path, n: int) -> int:
    """Regenerate a strategy's documents and run them through the gcov build."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("cov_strategy", strategy_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    count = 0

    @settings(max_examples=n, deadline=None, database=None, derandomize=True,
              suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large,
                                     HealthCheck.filter_too_much,
                                     HealthCheck.large_base_example])
    @given(mod.documents())
    def _go(doc: str) -> None:
        nonlocal count
        count += 1
        # Same serialiser the campaign uses. Encoding with surrogatepass here
        # instead (the bug this replaced) turned the U+DC80..U+DCFF raw-byte
        # sentinels into three-byte UTF-8 sequences, so the bytes measured were
        # not the bytes the strategy described.
        subprocess.run([str(COV_HARNESS)], input=_encode(doc),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)

    _go()
    return count


def main() -> None:
    if not COV_HARNESS.exists():
        sys.exit("coverage build missing; run ./harness/build.sh cov")

    targets = [("baseline", REPO / "fuzzer" / "strategies" / "baseline.py",
                REPO / "runs" / "baseline" / "summary.json")]
    for i in range(5):
        d = REPO / "runs" / "loop" / "iterations" / f"iter-{i}"
        targets.append((f"iter-{i}", d / "strategy.py", d / "summary.json"))

    rows = []
    for name, strat, summ in targets:
        if not strat.exists():
            continue
        reset_counters()
        n = replay(strat, 500)
        cov = read_coverage()
        s = json.loads(summ.read_text(encoding="utf-8")) if summ.exists() else {}
        st = s.get("structure", {})
        row = {
            "run": name,
            "documents": n,
            "parser_pct": cov.get(PARSER_FILE, {}).get("pct"),
            "parser_lines_covered": cov.get(PARSER_FILE, {}).get("covered"),
            "parser_lines_total": cov.get(PARSER_FILE, {}).get("lines"),
            "all_pct": cov["_total"]["pct"],
            "all_lines_covered": cov["_total"]["covered"],
            # the blackbox proxy signals, for correlation
            "acceptance_rate": s.get("acceptance_rate"),
            "productions_hit": st.get("productions_hit"),
            "distinct_diagnostics": s.get("distinct_diagnostic_templates"),
            "max_depth": st.get("max_depth_seen"),
            "per_file": cov,
        }
        rows.append(row)
        print(f"  {name:9} docs={n:<4} parser={row['parser_pct']:>5.2f}% "
              f"({row['parser_lines_covered']}/{row['parser_lines_total']})  "
              f"all={row['all_pct']:>5.2f}%  |  accept={s.get('acceptance_rate', 0):.1%} "
              f"prod={st.get('productions_hit')}/{st.get('productions_total', len(PRODUCTIONS))} "
              f"diag={s.get('distinct_diagnostic_templates')}")

    out = REPO / "runs" / "loop" / "coverage_study.json"
    out.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(f"\n  wrote {out}")


if __name__ == "__main__":
    main()
