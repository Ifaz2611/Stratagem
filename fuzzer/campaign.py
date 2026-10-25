"""Run one strategy through the harness for a bounded number of examples.

This is the "run" and "summarise" stages of the agentic loop, and it doubles as
the end-to-end pipeline proof: generate -> serialize -> run harness -> classify
-> log.

Two modes, because the project wants two different things from Hypothesis:

  survey  The test body never raises, so Hypothesis runs the full example
          budget and we collect statistics over all of it. This is what the
          loop needs: acceptance rate, diagnostic diversity, structural spread.
          A body that failed on the first crash would abort the run and leave
          the summary blind to the other 400-odd inputs.

  hunt    The test body asserts "no crash", so a crash makes the test fail and
          Hypothesis's shrinker runs automatically. This is what minimisation
          needs: Hypothesis's own shrinking, rather than keeping the first
          crashing example that happened to be drawn.

Hypothesis settings worth explaining, since the defaults actively fight a
subprocess-based harness:

  deadline=None            Default is 200ms per example. Spawning a process
                           under ASan can exceed that, and a DeadlineExceeded
                           error is not a bug in the target. Left on, it would
                           manufacture false findings.
  database=None            Hypothesis normally caches interesting examples on
                           disk and replays them on the next run. Across loop
                           iterations that leaks inputs from the previous
                           strategy into the next one's statistics, so each
                           iteration would no longer measure only its own
                           generator. Minimisation re-enables it, where replay
                           is the point.
  derandomize=True         Fixed input sequence for a given strategy, so a run
                           can be repeated exactly.
  suppress_health_check    too_slow / data_too_large fire on a slow external
                           harness and on large documents, both of which are
                           expected here rather than symptomatic.
"""
from __future__ import annotations

import argparse
import importlib
import json
import signal
import statistics
import time
from dataclasses import dataclass
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import seed as hyp_seed
from hypothesis import strategies as st

from fuzzer import corpus, diagnostics, features, triage
from fuzzer.runner import DEFAULT_HARNESS, Outcome, run_one

REPO_ROOT = Path(__file__).resolve().parent.parent

# Campaign limits. Keep these in the execution layer, not only in CLI help,
# so programmatic callers cannot accidentally exceed the same budget.
MAX_EXAMPLES_PER_ITERATION = 500
MAX_WALL_CLOCK_S = 10 * 60


class CampaignWallClockExceeded(BaseException):
    """Raised by the process-level campaign watchdog.

    BaseException is deliberate. Hypothesis treats ordinary exceptions as test
    failures and tries to shrink them, which would spend more time after the
    campaign budget has already expired.
    """

SUPPRESSED = [
    HealthCheck.too_slow,
    HealthCheck.data_too_large,
    HealthCheck.filter_too_much,
    HealthCheck.large_base_example,
]


def _encode(doc: str | bytes) -> bytes:
    """Serialise a generated document to the bytes the harness will read.

    U+DC80..U+DCFF is reserved as the standard surrogateescape representation
    of raw bytes 0x80..0xFF. Generated strategies use that convention to carry
    UTF-16 BOMs and deliberately malformed UTF-8 through a str-only interface.

    Other lone surrogates use surrogatepass, which still gives the baseline a
    way to exercise UTF-8 encodings of surrogate code points. Handling the two
    cases character by character is necessary: one document can contain both,
    and neither codec handles the other's case. surrogateescape raises on
    U+D800; surrogatepass writes U+DCFF as the three bytes ed b3 bf rather than
    as the byte ff. See docs/design-decisions.md D13.

    Batching the ordinary runs is only for speed. UTF-8 encodes each code point
    independently, so per-character encoding gives identical bytes.
    """
    if isinstance(doc, bytes):
        return doc
    out = bytearray()
    ordinary: list[str] = []

    def flush() -> None:
        if ordinary:
            out.extend("".join(ordinary).encode("utf-8", "surrogatepass"))
            ordinary.clear()

    for ch in doc:
        cp = ord(ch)
        if 0xDC80 <= cp <= 0xDCFF:
            flush()
            out.append(cp - 0xDC00)
        else:
            ordinary.append(ch)
    flush()
    return bytes(out)


@dataclass
class Campaign:
    strategy_name: str
    max_examples: int
    out_dir: Path
    harness: Path = DEFAULT_HARNESS
    mode: str = "survey"
    # Extra harness flags. Used only to reach the positive-control bug behind
    # --index; the real fuzzing configuration passes nothing here.
    extra_args: tuple[str, ...] = ()
    # Fixed Hypothesis seed for an independent trial of the same strategy.
    # None keeps derandomize=True, giving one canonical sequence. Set it to draw
    # a different sample, which is how a metric's variance is measured; Klees et
    # al. (CCS 2018) require multiple trials for a valid evaluation.
    random_seed: int | None = None
    wall_clock_cap_s: float = MAX_WALL_CLOCK_S
    target: Any = "mxml"

    def run(self) -> dict:
        if not 1 <= self.max_examples <= MAX_EXAMPLES_PER_ITERATION:
            raise ValueError(
                f"max_examples must be 1..{MAX_EXAMPLES_PER_ITERATION}, "
                f"got {self.max_examples}")
        if self.wall_clock_cap_s <= 0 or self.wall_clock_cap_s > MAX_WALL_CLOCK_S:
            raise ValueError(
                f"wall_clock_cap_s must be in (0, {MAX_WALL_CLOCK_S}], "
                f"got {self.wall_clock_cap_s}")
        # Strategy modules are written to disk at run time by the agentic loop,
        # so the import system's cached directory listing must be dropped or a
        # freshly written module is reported as not found.
        importlib.invalidate_caches()
        mod = importlib.import_module(f"fuzzer.strategies.{self.strategy_name}")
        mod = importlib.reload(mod)
        strat = mod.documents()

        from fuzzer.targets import get_target
        target_obj = get_target(self.target)

        self.out_dir.mkdir(parents=True, exist_ok=True)
        crash_dir = self.out_dir / "crashes"
        results: list[dict] = []
        # Every payload is retained so the exact inputs ship as an artifact and
        # replay does not depend on regenerating them.
        payloads: list[bytes] = []
        feats: list[Any] = []
        crash_records: list[dict] = []
        crash_inputs: list[tuple[str, bytes, str]] = []
        started = time.monotonic()

        _settings = settings(
            max_examples=self.max_examples,
            deadline=None,
            database=None,
            derandomize=self.random_seed is None,
            suppress_health_check=SUPPRESSED,
        )

        def _body(doc):
            payload = _encode(doc)
            payloads.append(payload)
            r = target_obj.run(payload, extra_args=self.extra_args)

            text = doc if isinstance(doc, str) else doc.decode("utf-8", "replace")
            f = target_obj.analyze_features(text, payload)
            feats.append(f)

            rec = r.to_json()
            is_valid_shape = target_obj.is_valid_shape(payload)
            rec["starts_lt"] = is_valid_shape
            rec["valid_shape"] = is_valid_shape
            rec["structure"] = f.to_json()
            results.append(rec)

            if r.outcome.is_crash:
                crash_inputs.append((r.input_sha256, payload, r.stderr))
                crash_records.append({
                    "sha": r.input_sha256,
                    "stderr": r.stderr,
                    "outcome": r.outcome.value,
                    "rc": r.returncode,
                    "signal": r.signal_name,
                    "productions": sorted(f.productions),
                })
            if self.mode == "hunt":
                # Raising here is what hands control to Hypothesis's shrinker.
                assert not r.outcome.is_crash, (
                    f"{r.outcome.value} rc={r.returncode} sig={r.signal_name}"
                )

        # Compose the decorators explicitly so a seed can be applied only when
        # one was requested, keeping the default path byte-identical to before.
        probe = _settings(given(strat)(_body))
        if self.random_seed is not None:
            probe = hyp_seed(self.random_seed)(probe)

        shrunk_failure = None
        hit_wall_clock_cap = False

        # The ten-minute cap is on the whole iteration, not on one
        # target invocation. A timer around the probe enforces that independently
        # of how quickly or slowly the generated strategy produces examples.
        old_handler = None
        armed = False
        if hasattr(signal, "setitimer"):
            old_handler = signal.getsignal(signal.SIGALRM)

            def _deadline(_signum, _frame):
                raise CampaignWallClockExceeded()

            signal.signal(signal.SIGALRM, _deadline)
            signal.setitimer(signal.ITIMER_REAL, self.wall_clock_cap_s)
            armed = True
        try:
            probe()
        except AssertionError as exc:
            # hunt mode only: Hypothesis has already shrunk before raising.
            shrunk_failure = str(exc)
        except CampaignWallClockExceeded:
            hit_wall_clock_cap = True
        finally:
            if armed:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, old_handler)

        elapsed = time.monotonic() - started

        # Persist crashing inputs. These are the artifacts triage works from, so
        # the exact bytes and the full sanitizer report both have to survive.
        if crash_inputs:
            crash_dir.mkdir(parents=True, exist_ok=True)
            for sha, payload, stderr in crash_inputs:
                (crash_dir / f"{sha[:16]}.xml").write_bytes(payload)
                (crash_dir / f"{sha[:16]}.stderr.txt").write_text(stderr, encoding="utf-8")

        manifest = corpus.write_corpus(self.out_dir / corpus.CORPUS_NAME, payloads)

        with (self.out_dir / "results.jsonl").open("w", encoding="utf-8") as fh:
            for rec in results:
                fh.write(json.dumps(rec) + "\n")

        summary = self._summarize(results, feats, crash_records, elapsed, shrunk_failure, target_obj)
        summary["wall_clock_cap_s"] = self.wall_clock_cap_s
        summary["wall_clock_cap_reached"] = hit_wall_clock_cap
        summary["corpus"] = manifest
        (self.out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return summary

    def _summarize(self, results: list[dict], feats: list[Any],
                   crash_records: list[dict], elapsed: float,
                   shrunk: str | None, target_obj: Any = None) -> dict:
        if target_obj is None:
            from fuzzer.targets import get_target
            target_obj = get_target(self.target)
        n = len(results)
        counts: dict[str, int] = {}
        for r in results:
            counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1

        accepted = counts.get("parsed_clean", 0) + counts.get("parsed_diag", 0)

        # Acceptance per bucket. A generator can sit inside a healthy global
        # band while having abandoned one bucket entirely, which the global
        # number cannot show.
        buckets: dict[str, dict] = {}
        for r in results:
            b = r.get("structure", {}).get("bucket", "unknown")
            e = buckets.setdefault(b, {"n": 0, "accepted": 0})
            e["n"] += 1
            if r["outcome"] in ("parsed_clean", "parsed_diag"):
                e["accepted"] += 1
        for b, e in buckets.items():
            e["share"] = round(e["n"] / n, 3) if n else 0.0
            e["acceptance_rate"] = round(e["accepted"] / e["n"], 3) if e["n"] else 0.0
        crashes = counts.get("crash", 0) + counts.get("timeout", 0)

        all_diags = [d for r in results for d in r.get("diagnostics", [])]
        lengths = [r["len"] for r in results] or [0]
        durs = [r["dur_ms"] for r in results] or [0.0]

        diag_counts: dict[str, int] = {}
        for d in all_diags:
            norm = target_obj.normalize_diagnostic(d)
            diag_counts[norm] = diag_counts.get(norm, 0) + 1
        diag_hist = dict(sorted(diag_counts.items(), key=lambda kv: (-kv[1], kv[0])))

        return {
            "target": target_obj.name,
            "target_category": target_obj.category,
            "strategy": self.strategy_name,
            "mode": self.mode,
            "random_seed": self.random_seed,
            "examples": n,
            "wall_clock_s": round(elapsed, 2),
            "outcomes": counts,
            "acceptance_rate": round(accepted / n, 4) if n else 0.0,
            "buckets": buckets,
            "crash_count": crashes,
            "unique_crash_inputs": len({r["sha"] for r in results
                                        if r["outcome"] in ("crash", "timeout")}),
            "shape_rate": round(
                sum(1 for r in results if r.get("valid_shape", r.get("starts_lt"))) / n, 4) if n else 0.0,
            "xml_shaped_rate": round(
                sum(1 for r in results if r.get("starts_lt")) / n, 4) if n else 0.0,
            "diagnostic_templates": diag_hist,
            "distinct_diagnostic_templates": len(diag_hist),
            "input_len": {
                "min": min(lengths), "max": max(lengths),
                "mean": round(statistics.mean(lengths), 1),
                "median": round(statistics.median(lengths), 1),
            },
            "duration_ms": {
                "mean": round(statistics.mean(durs), 2),
                "max": max(durs),
            },
            "structure": target_obj.summarize_structure(feats),
            "crash_groups": triage.group(crash_records),
            "shrunk_failure": shrunk,
        }


def main() -> None:
    ap = argparse.ArgumentParser(description="Run one strategy through the harness.")
    ap.add_argument("strategy", help="module name under fuzzer/strategies/")
    ap.add_argument("-n", "--max-examples", type=int, default=500,
                    help="cap is 500 per iteration")
    ap.add_argument("-o", "--out", default=None, help="output directory")
    ap.add_argument("--mode", choices=("survey", "hunt"), default="survey")
    ap.add_argument("--seed", type=int, default=None,
                    help="Hypothesis seed for an independent reproducible trial")
    ap.add_argument("--harness", default=str(DEFAULT_HARNESS))
    ap.add_argument("--target", default="mxml",
                    choices=("mxml", "libxml2", "expat", "tinyxml2", "json", "http", "dns", "smtp"),
                    help="Target parser or protocol (default: mxml)")
    ap.add_argument("--index", action="store_true",
                    help="pass --index to the harness (positive control only)")
    args = ap.parse_args()

    out = Path(args.out) if args.out else REPO_ROOT / "runs" / f"{args.strategy}-{args.target}-{args.mode}"
    c = Campaign(args.strategy, args.max_examples, out, Path(args.harness), args.mode,
                 extra_args=("--index",) if args.index else (),
                 random_seed=args.seed,
                 target=args.target)
    s = c.run()

    print(f"target     : {s.get('target', 'mxml')} ({s.get('target_category', 'xml')})")
    print(f"strategy   : {s['strategy']}  ({s['mode']} mode)")
    print(f"examples   : {s['examples']}  in {s['wall_clock_s']}s")
    print(f"outcomes   : {s['outcomes']}")
    print(f"accept rate: {s['acceptance_rate']:.1%}")
    print(f"valid shape: {s.get('shape_rate', s['xml_shaped_rate']):.1%}")
    print(f"crashes    : {s['crash_count']} ({s['unique_crash_inputs']} unique inputs)")
    st_ = s["structure"]
    print(f"productions: {st_.get('productions_hit', 0)}/{st_.get('productions_total', 0)}"
          f"   missing: {', '.join(st_.get('missing', [])) or 'none'}")
    if "depth_histogram" in st_:
        print(f"depth      : {st_['depth_histogram']}  max={st_.get('max_depth_seen', 0)}")
    print(f"diag templates reached: {s['distinct_diagnostic_templates']}")
    for tpl, cnt in list(s["diagnostic_templates"].items())[:10]:
        print(f"   {cnt:5d}  {tpl}")
    if s["crash_groups"]:
        print(f"crash groups: {len(s['crash_groups'])}")
        for sig, b in s["crash_groups"].items():
            print(f"   {sig}  x{b['count']:<4} {b['label']}")
    print(f"input len  : {s['input_len']}")
    print(f"output     : {out}")


if __name__ == "__main__":
    main()
