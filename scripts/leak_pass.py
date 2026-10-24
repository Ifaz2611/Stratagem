"""Leak pass over every recorded corpus.

The fuzzing runs set detect_leaks=0, because mxml leaks on a large minority of
inputs and, left on, those reports bury real crashes and swamp deduplication
(docs/design-decisions.md D4). Leaks are a real bug class, so they get this
separate pass instead of being dropped.

Inputs come from the recorded corpora rather than being regenerated, so the rate
below is measured over exactly the documents the campaigns ran.

Usage:  python scripts/leak_pass.py [run ...]        (default: every run)
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from fuzzer.corpus import read_corpus  # noqa: E402
from fuzzer.triage import parse_report  # noqa: E402

HARNESS = REPO / "build" / "asan" / "harness"
ENV = {
    "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=0:symbolize=1:print_stacktrace=1",
    "UBSAN_OPTIONS": "halt_on_error=1:abort_on_error=1:print_stacktrace=1",
    "PATH": "/usr/bin:/bin",
}
_BYTES = re.compile(r"SUMMARY: AddressSanitizer: (\d+) byte")


def scan(payload: bytes) -> tuple[bool, str, int]:
    p = subprocess.run([str(HARNESS)], input=payload, stdout=subprocess.DEVNULL,
                       stderr=subprocess.PIPE, env=ENV, timeout=15)
    err = p.stderr.decode("utf-8", "replace")
    if "LeakSanitizer: detected memory leaks" not in err:
        return False, "", 0
    m = _BYTES.search(err)
    report = parse_report(err)
    sig = "|".join(report.signature_frames[:3]) or "unknown"
    return True, sig, int(m.group(1)) if m else 0


def main() -> None:
    if not HARNESS.exists():
        sys.exit("asan build missing; run ./harness/build.sh asan")

    runs = sys.argv[1:] or sorted({p.parents[2].name
                                   for p in REPO.glob("runs/*/iterations/*/corpus.jsonl.gz")
                                   if not p.parents[2].name.endswith("-replay")}
                                  | {"baseline"})
    total = leaked = 0
    sigs: dict[str, int] = {}
    per_run = {}
    for run in runs:
        base = REPO / "runs" / run
        dirs = ([base] if (base / "corpus.jsonl.gz").exists()
                else sorted(base.glob("iterations/iter-*")))
        n = k = 0
        for d in dirs:
            cf = d / "corpus.jsonl.gz"
            if not cf.exists():
                continue
            for payload in read_corpus(cf):
                n += 1
                hit, sig, _ = scan(payload)
                if hit:
                    k += 1
                    sigs[sig] = sigs.get(sig, 0) + 1
        if n:
            per_run[run] = {"documents": n, "leaking": k, "rate": round(k / n, 4)}
            print(f"  {run:22} {k:5d}/{n:<5d} = {k / n:5.1%}", flush=True)
            total += n
            leaked += k

    print(f"\n  {'TOTAL':22} {leaked:5d}/{total:<5d} = {leaked / total:5.1%}")
    print(f"  distinct leak signatures: {len(sigs)}")
    for s, c in sorted(sigs.items(), key=lambda kv: -kv[1]):
        print(f"    {c:5d}  {s}")

    out = REPO / "runs" / "analysis" / "leak_pass.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"per_run": per_run, "total_documents": total,
                               "leaking_documents": leaked,
                               "rate": round(leaked / total, 4),
                               "signatures": sigs}, indent=2), encoding="utf-8")
    print(f"\n  wrote {out}")


if __name__ == "__main__":
    main()
