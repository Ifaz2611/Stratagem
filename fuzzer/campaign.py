"""Run one strategy through the harness for a bounded number of examples.

This is the "run" and "summarise" stages of the agentic loop, and it doubles as
the end-to-end pipeline proof: generate -> serialize -> run harness -> classify
-> log.

Features:
  * Parallel fuzzing (run multiple campaigns concurrently)
  * Adaptive batch sizing based on strategy performance
  * Intelligent corpus management (deduplication, coverage-guided distillation)
  * Timeout detection and slow input isolation
  * Incremental campaign persistence and checkpoint resumption
"""
from __future__ import annotations

import argparse
import importlib
import json
import signal
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import seed as hyp_seed
from hypothesis import strategies as st

from fuzzer import corpus, diagnostics, features, triage
from fuzzer.batching import (
    AdaptiveBatchConfig,
    AdaptiveBatchController,
    extract_batch_metrics,
)
from fuzzer.runner import (
    DEFAULT_HARNESS,
    DEFAULT_SLOW_THRESHOLD_S,
    PER_RUN_TIMEOUT_S,
    Outcome,
    run_one,
)
from agent.progress import make_progress

REPO_ROOT = Path(__file__).resolve().parent.parent

MAX_EXAMPLES_PER_ITERATION = 500
MAX_WALL_CLOCK_S = 10 * 60


class CampaignWallClockExceeded(BaseException):
    """Raised by the process-level campaign watchdog."""


class CampaignTimeoutStreakExceeded(Exception):
    """Raised when excessive consecutive timeouts stall the fuzzer."""


SUPPRESSED = [
    HealthCheck.too_slow,
    HealthCheck.data_too_large,
    HealthCheck.filter_too_much,
    HealthCheck.large_base_example,
]


def _encode(doc: str | bytes) -> bytes:
    """Serialise a generated document to the bytes the harness will read."""
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
    extra_args: tuple[str, ...] = ()
    random_seed: int | None = None
    wall_clock_cap_s: float = MAX_WALL_CLOCK_S
    target: Any = "mxml"
    timeout_s: float = PER_RUN_TIMEOUT_S
    slow_threshold_s: float = DEFAULT_SLOW_THRESHOLD_S
    max_timeout_streak: int = 5
    adaptive_batch: bool = False
    batch_config: AdaptiveBatchConfig | None = None
    checkpoint_interval: int = 50
    resume: bool = False
    incremental_flush: bool = True
    generate_reproducers: bool = True
    # auto = only when stderr is a terminal; on = also emit milestone lines in
    # CI logs; off = silent. The campaign never writes to stdout, so callers
    # can still parse its summary.
    progress: str | bool = "auto"
    progress_stream: Any = None

    def run(self) -> dict:
        if not 1 <= self.max_examples <= MAX_EXAMPLES_PER_ITERATION:
            raise ValueError(
                f"max_examples must be 1..{MAX_EXAMPLES_PER_ITERATION}, "
                f"got {self.max_examples}"
            )
        if self.wall_clock_cap_s <= 0 or self.wall_clock_cap_s > MAX_WALL_CLOCK_S:
            raise ValueError(
                f"wall_clock_cap_s must be in (0, {MAX_WALL_CLOCK_S}], "
                f"got {self.wall_clock_cap_s}"
            )

        importlib.invalidate_caches()
        mod = importlib.import_module(f"fuzzer.strategies.{self.strategy_name}")
        mod = importlib.reload(mod)
        strat = mod.documents()

        from fuzzer.targets import get_target
        target_obj = get_target(self.target)

        self.out_dir.mkdir(parents=True, exist_ok=True)
        crash_dir = self.out_dir / "crashes"
        timeout_dir = self.out_dir / "timeouts"
        slow_dir = self.out_dir / "slow_inputs"
        checkpoint_file = self.out_dir / "checkpoint.json"
        results_file = self.out_dir / "results.jsonl"

        results: list[dict] = []
        payloads: list[bytes] = []
        feats: list[Any] = []
        crash_records: list[dict] = []
        crash_inputs: list[tuple[str, bytes, str]] = []
        timeout_inputs: list[tuple[str, bytes, str, float]] = []
        slow_inputs: list[tuple[str, bytes, float]] = []
        corpus_mgr = corpus.CorpusManager()

        # Resumption support
        if self.resume and checkpoint_file.exists():
            try:
                cp = json.loads(checkpoint_file.read_text(encoding="utf-8"))
                if results_file.exists():
                    for line in results_file.read_text(encoding="utf-8").splitlines():
                        if line.strip():
                            rec = json.loads(line)
                            results.append(rec)
                corpus_path = self.out_dir / corpus.CORPUS_NAME
                if corpus_path.exists():
                    payloads = corpus.read_corpus(corpus_path)
                    for p in payloads:
                        corpus_mgr.add(p)
                if len(results) >= self.max_examples:
                    summary_path = self.out_dir / "summary.json"
                    if summary_path.exists():
                        return json.loads(summary_path.read_text(encoding="utf-8"))
            except Exception:
                pass

        results_fh = results_file.open("a", encoding="utf-8")
        started = time.monotonic()
        bar = make_progress(
            self.max_examples,
            desc=f"{target_obj.name}:{self.strategy_name}",
            enabled=self.progress,
            stream=self.progress_stream,
            unit="input",
            initial=len(results),
        )
        consecutive_timeouts = 0
        hit_wall_clock_cap = False
        shrunk_failure = None
        interrupted = False

        def _save_checkpoint(is_interrupted: bool = False) -> None:
            """Save incremental checkpoint to disk."""
            elapsed_now = time.monotonic() - started
            manifest = corpus.write_corpus(self.out_dir / corpus.CORPUS_NAME, payloads)
            cp_data = {
                "strategy": self.strategy_name,
                "target": target_obj.name,
                "examples_completed": len(results),
                "target_examples": self.max_examples,
                "wall_clock_elapsed_s": round(elapsed_now, 2),
                "crashes": len(crash_records),
                "unique_crashes": len({r["sha"] for r in results if r["outcome"] in ("crash", "timeout")}),
                "timeouts": len(timeout_inputs),
                "slow_inputs": len(slow_inputs),
                "interrupted": is_interrupted,
                "timestamp": time.time(),
                "corpus_manifest": manifest,
            }
            checkpoint_file.write_text(json.dumps(cp_data, indent=2), encoding="utf-8")

        def _process_one(doc: str | bytes) -> None:
            nonlocal consecutive_timeouts
            payload = _encode(doc)
            payloads.append(payload)

            r = target_obj.run(
                payload,
                timeout_s=self.timeout_s,
                extra_args=self.extra_args,
                slow_threshold_s=self.slow_threshold_s,
            )

            text = doc if isinstance(doc, str) else doc.decode("utf-8", "replace")
            f = target_obj.analyze_features(text, payload)
            feats.append(f)

            rec = r.to_json()
            is_valid_shape = target_obj.is_valid_shape(payload)
            rec["starts_lt"] = is_valid_shape
            rec["valid_shape"] = is_valid_shape
            rec["structure"] = f.to_json()
            results.append(rec)

            # Incremental persistence to results.jsonl
            results_fh.write(json.dumps(rec) + "\n")
            if self.incremental_flush:
                results_fh.flush()

            # Intelligent corpus registration
            corpus_mgr.add(
                payload=payload,
                outcome=r.outcome.value,
                diagnostics=r.diagnostics,
                productions=f.productions if hasattr(f, "productions") else [],
                duration_ms=r.duration_s * 1000,
            )

            # Timeout handling
            if r.outcome == Outcome.TIMEOUT:
                consecutive_timeouts += 1
                timeout_inputs.append((r.input_sha256, payload, r.stderr, r.duration_s))
                timeout_dir.mkdir(parents=True, exist_ok=True)
                (timeout_dir / f"{r.input_sha256[:16]}.bin").write_bytes(payload)
                (timeout_dir / f"{r.input_sha256[:16]}.meta.json").write_text(
                    json.dumps({
                        "sha": r.input_sha256,
                        "duration_s": round(r.duration_s, 3),
                        "timeout_threshold_s": self.timeout_s,
                        "stderr": r.stderr,
                    }, indent=2),
                    encoding="utf-8",
                )
                if consecutive_timeouts >= self.max_timeout_streak:
                    raise CampaignTimeoutStreakExceeded(
                        f"Reached {consecutive_timeouts} consecutive timeouts"
                    )
            else:
                consecutive_timeouts = 0

            # Slow input tracking
            if r.is_slow and r.outcome != Outcome.TIMEOUT:
                slow_inputs.append((r.input_sha256, payload, r.duration_s))
                slow_dir.mkdir(parents=True, exist_ok=True)
                (slow_dir / f"{r.input_sha256[:16]}.bin").write_bytes(payload)
                (slow_dir / f"{r.input_sha256[:16]}.meta.json").write_text(
                    json.dumps({
                        "sha": r.input_sha256,
                        "duration_s": round(r.duration_s, 3),
                        "slow_threshold_s": self.slow_threshold_s,
                        "outcome": r.outcome.value,
                    }, indent=2),
                    encoding="utf-8",
                )

            # Crash handling and immediate persistence
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
                crash_dir.mkdir(parents=True, exist_ok=True)
                (crash_dir / f"{r.input_sha256[:16]}.xml").write_bytes(payload)
                (crash_dir / f"{r.input_sha256[:16]}.stderr.txt").write_text(
                    r.stderr, encoding="utf-8"
                )

            # Checkpoint check
            if (
                self.checkpoint_interval > 0
                and len(results) % self.checkpoint_interval == 0
            ):
                _save_checkpoint()

            bar.update(1)
            bar.set_postfix(crashes=len(crash_records),
                            timeouts=len(timeout_inputs))

            if self.mode == "hunt":
                assert not r.outcome.is_crash, (
                    f"{r.outcome.value} rc={r.returncode} sig={r.signal_name}"
                )

        # Set up watchdog timer
        old_handler = None
        armed = False
        if hasattr(signal, "setitimer"):
            old_handler = signal.getsignal(signal.SIGALRM)

            def _deadline(_signum, _frame):
                raise CampaignWallClockExceeded()

            signal.signal(signal.SIGALRM, _deadline)
            signal.setitimer(signal.ITIMER_REAL, self.wall_clock_cap_s)
            armed = True

        # Signal handler for graceful termination
        orig_sigint = signal.getsignal(signal.SIGINT)

        def _handle_sigint(signum, frame):
            nonlocal interrupted
            interrupted = True
            _save_checkpoint(is_interrupted=True)
            if callable(orig_sigint) and orig_sigint != _handle_sigint:
                orig_sigint(signum, frame)
            else:
                raise KeyboardInterrupt()

        try:
            signal.signal(signal.SIGINT, _handle_sigint)
        except (ValueError, AttributeError):
            pass

        batch_history: dict[str, Any] | None = None

        try:
            if self.adaptive_batch:
                # Adaptive batch execution
                cfg = self.batch_config or AdaptiveBatchConfig(
                    initial_batch_size=min(50, self.max_examples),
                    max_batch_size=self.max_examples,
                )
                batch_ctrl = AdaptiveBatchController(cfg)
                seen_prods: set[str] = set()
                seen_diags: set[str] = set()
                seen_crashes: set[str] = set()
                batch_idx = 0

                while len(results) < self.max_examples:
                    remaining_budget = self.max_examples - len(results)
                    curr_size = min(batch_ctrl.current_batch_size, remaining_budget)
                    if curr_size <= 0:
                        break

                    b_started = time.monotonic()
                    prev_len = len(results)

                    b_settings = settings(
                        max_examples=curr_size,
                        deadline=None,
                        database=None,
                        derandomize=False,
                        suppress_health_check=SUPPRESSED,
                    )
                    b_probe = b_settings(given(strat)(_process_one))
                    batch_seed = (self.random_seed or 0) + (batch_idx * 10007) + 1
                    b_probe = hyp_seed(batch_seed)(b_probe)

                    try:
                        b_probe()
                    except AssertionError as exc:
                        shrunk_failure = str(exc)
                        break

                    b_elapsed = time.monotonic() - b_started
                    batch_res = results[prev_len:]
                    batch_f = feats[prev_len:]

                    metrics, seen_prods, seen_diags, seen_crashes = extract_batch_metrics(
                        batch_index=batch_idx,
                        batch_results=batch_res,
                        batch_feats=batch_f,
                        seen_productions=seen_prods,
                        seen_diagnostics=seen_diags,
                        seen_crashes=seen_crashes,
                        duration_s=b_elapsed,
                    )
                    batch_ctrl.record_and_adapt(metrics)
                    _save_checkpoint()
                    batch_idx += 1

                batch_history = batch_ctrl.summary()

            else:
                # Monolithic batch execution
                remaining_examples = self.max_examples - len(results)
                if remaining_examples > 0:
                    _settings = settings(
                        max_examples=remaining_examples,
                        deadline=None,
                        database=None,
                        derandomize=self.random_seed is None,
                        suppress_health_check=SUPPRESSED,
                    )
                    probe = _settings(given(strat)(_process_one))
                    if self.random_seed is not None:
                        probe = hyp_seed(self.random_seed)(probe)

                    probe()

        except AssertionError as exc:
            shrunk_failure = str(exc)
        except CampaignWallClockExceeded:
            hit_wall_clock_cap = True
        except CampaignTimeoutStreakExceeded:
            pass
        except KeyboardInterrupt:
            interrupted = True
        finally:
            if armed:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, old_handler)
            try:
                signal.signal(signal.SIGINT, orig_sigint)
            except (ValueError, AttributeError):
                pass
            results_fh.close()
            bar.close()

        elapsed = time.monotonic() - started

        # Final corpus management and distillation
        manifest = corpus.write_corpus(self.out_dir / corpus.CORPUS_NAME, payloads)
        distilled = corpus_mgr.distill()
        distilled_manifest = distilled.export_corpus(
            self.out_dir / corpus.DISTILLED_CORPUS_NAME
        )

        # Automatic Minimal Reproducer Generation
        reproducers_manifest: list[dict] = []
        if self.generate_reproducers and crash_inputs:
            from fuzzer.reproducer import create_reproducer_bundle
            repro_dir = self.out_dir / "reproducers"
            seen_sigs: set[str] = set()
            for c_sha, c_payload, c_stderr in crash_inputs:
                c_rep = triage.parse_report(c_stderr)
                c_sig = c_rep.signature if c_rep else "crash"
                if c_sig in seen_sigs:
                    continue
                seen_sigs.add(c_sig)
                try:
                    b_dir = repro_dir / c_sig
                    b_bundle = create_reproducer_bundle(
                        payload=c_payload,
                        target=target_obj,
                        out_dir=b_dir,
                        minimize_first=True,
                        signature=c_sig,
                    )
                    reproducers_manifest.append(b_bundle.to_json())
                except Exception:
                    pass

        summary = self._summarize(
            results, feats, crash_records, elapsed, shrunk_failure, target_obj
        )
        summary["wall_clock_cap_s"] = self.wall_clock_cap_s
        summary["wall_clock_cap_reached"] = hit_wall_clock_cap
        summary["interrupted"] = interrupted
        summary["corpus"] = manifest
        summary["corpus_stats"] = corpus_mgr.stats()
        summary["distilled_corpus"] = distilled_manifest
        summary["distilled_stats"] = distilled.stats()
        summary["timeout_count"] = len(timeout_inputs)
        summary["slow_input_count"] = len(slow_inputs)
        summary["slow_threshold_s"] = self.slow_threshold_s
        summary["timeout_threshold_s"] = self.timeout_s
        summary["reproducers"] = reproducers_manifest

        if batch_history:
            summary["batch_history"] = batch_history

        # Finalize checkpoint
        _save_checkpoint(is_interrupted=interrupted)
        (self.out_dir / "summary.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8"
        )
        return summary

    def _summarize(
        self,
        results: list[dict],
        feats: list[Any],
        crash_records: list[dict],
        elapsed: float,
        shrunk: str | None,
        target_obj: Any = None,
    ) -> dict:
        if target_obj is None:
            from fuzzer.targets import get_target
            target_obj = get_target(self.target)
        n = len(results)
        counts: dict[str, int] = {}
        for r in results:
            counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1

        accepted = counts.get("parsed_clean", 0) + counts.get("parsed_diag", 0)

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

        # Find top slowest inputs
        sorted_by_dur = sorted(results, key=lambda r: r.get("dur_ms", 0.0), reverse=True)
        slowest = [
            {"sha": r.get("sha", ""), "dur_ms": r.get("dur_ms", 0.0), "outcome": r.get("outcome", "")}
            for r in sorted_by_dur[:10]
        ]

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
            "unique_crash_inputs": len(
                {r["sha"] for r in results if r["outcome"] in ("crash", "timeout")}
            ),
            "shape_rate": round(
                sum(1 for r in results if r.get("valid_shape", r.get("starts_lt"))) / n, 4
            ) if n else 0.0,
            "xml_shaped_rate": round(
                sum(1 for r in results if r.get("starts_lt")) / n, 4
            ) if n else 0.0,
            "diagnostic_templates": diag_hist,
            "distinct_diagnostic_templates": len(diag_hist),
            "input_len": {
                "min": min(lengths),
                "max": max(lengths),
                "mean": round(statistics.mean(lengths), 1),
                "median": round(statistics.median(lengths), 1),
            },
            "duration_ms": {
                "mean": round(statistics.mean(durs), 2),
                "max": max(durs),
            },
            "slowest_inputs": slowest,
            "structure": target_obj.summarize_structure(feats),
            "crash_groups": triage.group(crash_records),
            "clusters": [c.to_json() for c in triage.cluster_crashes(crash_records)],
            "triage_summary": triage.triage_summary(crash_records),
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
    ap.add_argument("--timeout", type=float, default=PER_RUN_TIMEOUT_S,
                    help=f"Per-input timeout in seconds (default: {PER_RUN_TIMEOUT_S})")
    ap.add_argument("--slow-threshold", type=float, default=DEFAULT_SLOW_THRESHOLD_S,
                    help=f"Threshold in seconds for slow input detection (default: {DEFAULT_SLOW_THRESHOLD_S})")
    ap.add_argument("--adaptive-batch", action="store_true",
                    help="Enable adaptive batch sizes based on strategy performance")
    ap.add_argument("--checkpoint-interval", type=int, default=50,
                    help="Save checkpoint every N inputs (default: 50)")
    ap.add_argument("--resume", action="store_true",
                    help="Resume from existing checkpoint in output directory")
    ap.add_argument("--progress", choices=("auto", "on", "off"), default="auto",
                    help="Progress bar: auto (TTY only), on, or off")
    ap.add_argument("--parallel", action="store_true",
                    help="Run across targets in parallel")
    ap.add_argument("--targets", nargs="+", default=None,
                    help="Targets for parallel execution")
    ap.add_argument("-w", "--workers", type=int, default=None,
                    help="Parallel workers count")
    args = ap.parse_args()

    if args.parallel:
        from fuzzer.parallel import run_parallel_targets
        target_list = args.targets or [args.target, "json", "http"]
        base_out = Path(args.out) if args.out else REPO_ROOT / "runs" / f"parallel-{args.strategy}"
        print(f"Running parallel campaigns across targets: {target_list}...")
        summary = run_parallel_targets(
            strategy=args.strategy,
            targets=target_list,
            max_examples=args.max_examples,
            base_out_dir=base_out,
            max_workers=args.workers,
            mode=args.mode,
            adaptive_batch=args.adaptive_batch,
        )
        print("\n=== Parallel Run Complete ===")
        print(f"Completed: {summary.completed_campaigns}/{summary.total_campaigns} in {summary.total_wall_clock_s:.2f}s")
        print(f"Total examples: {summary.total_examples} ({summary.throughput_eps:.1f} ex/s)")
        print(f"Total crashes : {summary.total_crashes} ({summary.unique_crashes} unique)")
        return

    out = Path(args.out) if args.out else REPO_ROOT / "runs" / f"{args.strategy}-{args.target}-{args.mode}"
    c = Campaign(
        strategy_name=args.strategy,
        max_examples=args.max_examples,
        out_dir=out,
        harness=Path(args.harness),
        mode=args.mode,
        extra_args=("--index",) if args.index else (),
        random_seed=args.seed,
        target=args.target,
        timeout_s=args.timeout,
        slow_threshold_s=args.slow_threshold,
        adaptive_batch=args.adaptive_batch,
        checkpoint_interval=args.checkpoint_interval,
        resume=args.resume,
        progress=args.progress,
    )
    s = c.run()

    print(f"target     : {s.get('target', 'mxml')} ({s.get('target_category', 'xml')})")
    print(f"strategy   : {s['strategy']}  ({s['mode']} mode)")
    print(f"examples   : {s['examples']}  in {s['wall_clock_s']}s")
    print(f"outcomes   : {s['outcomes']}")
    print(f"accept rate: {s['acceptance_rate']:.1%}")
    print(f"valid shape: {s.get('shape_rate', s['xml_shaped_rate']):.1%}")
    print(f"crashes    : {s['crash_count']} ({s['unique_crash_inputs']} unique inputs)")
    print(f"timeouts   : {s.get('timeout_count', 0)}")
    print(f"slow inputs: {s.get('slow_input_count', 0)}")
    if "corpus_stats" in s:
        cs = s["corpus_stats"]
        ds = s.get("distilled_stats", {})
        print(f"corpus     : {cs.get('count', 0)} total, {ds.get('count', 0)} distilled ({cs.get('duplicates_rejected', 0)} dups filtered)")
    if "batch_history" in s:
        bh = s["batch_history"]
        print(f"batches    : {bh.get('batches_evaluated', 0)} batches, size: {bh.get('initial_size')} -> {bh.get('final_size')}")
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
