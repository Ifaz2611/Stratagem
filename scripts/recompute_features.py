#!/usr/bin/env python3
"""Re-measure a recorded run with the current analyser, from its corpus.

No campaigns are re-run and the harness is not re-invoked: outcomes come from
the recorded results.jsonl and the exact inputs come from corpus.jsonl.gz. Only
the analysis changes.

Because the corpus is recorded, a run can be re-measured whenever the analyser
changes, instead of being stranded on the vocabulary it was first scored with.
This is what keeps runs comparable across analyser versions.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fuzzer import corpus, diagnostics, features  # noqa: E402


def recompute(iter_dir: Path) -> dict | None:
    cf = iter_dir / corpus.CORPUS_NAME
    rf = iter_dir / "results.jsonl"
    sf = iter_dir / "summary.json"
    if not (cf.exists() and rf.exists() and sf.exists()):
        return None

    payloads = corpus.read_corpus(cf)
    results = [json.loads(x) for x in rf.read_text(encoding="utf-8").splitlines() if x.strip()]
    if len(payloads) != len(results):
        print(f"  {iter_dir.name}: corpus/results length mismatch, skipped")
        return None

    summary = json.loads(sf.read_text(encoding="utf-8"))
    feats = []
    for pay, rec in zip(payloads, results):
        f = features.analyze(pay.decode("utf-8", "replace"), pay)
        feats.append(f)
        rec["structure"] = f.to_json()

    n = len(results)
    buckets: dict[str, dict] = {}
    for rec in results:
        b = rec["structure"]["bucket"]
        e = buckets.setdefault(b, {"n": 0, "accepted": 0})
        e["n"] += 1
        if rec["outcome"] in ("parsed_clean", "parsed_diag"):
            e["accepted"] += 1
    for e in buckets.values():
        e["share"] = round(e["n"] / n, 3)
        e["acceptance_rate"] = round(e["accepted"] / e["n"], 3) if e["n"] else 0.0

    all_diags = [d for r in results for d in r.get("diagnostics", [])]
    summary["structure"] = features.coverage(feats)
    summary["buckets"] = buckets
    summary["diagnostic_templates"] = diagnostics.histogram(all_diags)
    summary["distinct_diagnostic_templates"] = len(summary["diagnostic_templates"])

    rf.write_text("\n".join(json.dumps(r) for r in results) + "\n", encoding="utf-8")
    sf.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> int:
    runs = sys.argv[1:] or ["baseline", "loop", "loop-b"]
    root = Path(__file__).resolve().parent.parent / "runs"
    for run in runs:
        base = root / run
        dirs = ([base] if (base / "results.jsonl").exists()
                else sorted(base.glob("iterations/iter-*")))
        for d in dirs:
            s = recompute(d)
            if not s:
                continue
            st = s["structure"]
            bk = "  ".join(f"{b}={e['share']:.0%}" for b, e in sorted(s["buckets"].items()))
            print(f"  {run}/{d.name:8} accept={s['acceptance_rate']:6.1%} "
                  f"prod={st['productions_hit']}/{st['productions_total']} "
                  f"diag={s['distinct_diagnostic_templates']:3d}  {bk}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
