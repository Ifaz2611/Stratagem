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
import heapq
import json
import signal
import statistics
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import seed as hyp_seed

from fuzzer import corpus, triage
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
)
from fuzzer.result_cache import ResultCache, cache_enabled_by_env
from fuzzer.strategy_loader import StrategyLoader, get_default_loader
from fuzzer.timeutil import utc_iso
from agent.progress import make_progress

REPO_ROOT = Path(__file__).resolve().parent.parent

MAX_EXAMPLES_PER_ITERATION = 500
MAX_WALL_CLOCK_S = 10 * 60
# Reproducers are generated once per distinct sanitizer signature, so retaining
# every crashing payload only wastes memory in a long campaign. The cap bounds
# the artifact pass without changing what is written to disk (each crash is
# persisted as soon as it happens).
MAX_REPRODUCER_INPUTS = 64


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
    """Serialise a generated document to the bytes the harness will read.

    Three conventions meet here:

    * ``bytes``/``bytearray``/``memoryview`` already are the payload;
    * U+DC80..U+DCFF are the ``surrogateescape`` sentinels for raw bytes
      0x80..0xFF (the strategies use this to describe non-UTF-8 input);
    * ordinary text is UTF-8.

    Valid surrogate pairs (U+D800..U+DBFF followed by U+DC00..U+DFFF) are the
    one ambiguous case: Python can hold a pair either as one astral code point
    or as two surrogate code points. Encoding the pair element-wise with
    ``surrogatepass`` yields CESU-8 (six bytes), which is not the UTF-8 the
    generator meant. Combine a *valid* pair into its scalar first; a lone
    surrogate still takes the documented ``surrogatepass`` path.
    """
    if isinstance(doc, (bytes, bytearray, memoryview)):
        return bytes(doc)
    if not isinstance(doc, str):
        raise TypeError(
            f"document must be str or bytes-like, not {type(doc).__name__}")

    out = bytearray()
    ordinary: list[str] = []

    def flush() -> None:
        if ordinary:
            out.extend("".join(ordinary).encode("utf-8", "surrogatepass"))
            ordinary.clear()

    i = 0
    n = len(doc)
    while i < n:
        ch = doc[i]
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDBFF and i + 1 < n:
            low = ord(doc[i + 1])
            if 0xDC00 <= low <= 0xDFFF:
                flush()
                scalar = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00)
                out.extend(chr(scalar).encode("utf-8"))
                i += 2
                continue
        if 0xDC80 <= cp <= 0xDCFF:
            flush()
            out.append(cp - 0xDC00)
            i += 1
            continue
        ordinary.append(ch)
        i += 1
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
    # Performance features. All default to the pre-existing behaviour: the
    # bytecode cache is transparent, result caching is opt-in, and corpus
    # trimming only happens when a ceiling is requested.
    use_result_cache: bool = False
    result_cache_dir: Path | str | None = None
    result_cache_size: int | None = 200_000
    result_cache_ttl_s: float | None = None
    max_corpus_entries: int | None = None
    strategy_loader: StrategyLoader | None = None
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

        loader = self.strategy_loader or get_default_loader()
        loaded = loader.load(self.strategy_name)
        strat = loaded.documents()

        from fuzzer.targets import get_target
        target_obj = get_target(self.target)

        self.out_dir.mkdir(parents=True, exist_ok=True)
        crash_dir = self.out_dir / "crashes"
        timeout_dir = self.out_dir / "timeouts"
        slow_dir = self.out_dir / "slow_inputs"
        checkpoint_file = self.out_dir / "checkpoint.json"
        results_file = self.out_dir / "results.jsonl"
        corpus_path = self.out_dir / corpus.CORPUS_NAME

        results: list[dict] = []
        feats: list[Any] = []
        crash_records: list[dict] = []
        crash_inputs: list[tuple[str, bytes, str]] = []
        crash_signatures: set[str] = set()
        # Counters rather than payload lists: a timeout or slow input has
        # already been written to its artifact directory, and only the total is
        # reported. Keeping the bytes here made a long campaign retain one copy
        # of every slow input for no consumer.
        timeout_count = 0
        slow_input_count = 0
        corpus_mgr = corpus.CorpusManager(max_entries=self.max_corpus_entries)

        # Result caching is opt-in (or enabled by environment for operators),
        # and only for outcomes that a deterministic target reproduces.
        cache: ResultCache | None = None
        cache_context: dict[str, Any] | None = None
        if self.use_result_cache or cache_enabled_by_env():
            cache_root = (Path(self.result_cache_dir) if self.result_cache_dir
                          else REPO_ROOT / "runs" / ".result_cache")
            cache = ResultCache(
                cache_root / "results.sqlite3",
                max_entries=(self.result_cache_size or None),
                ttl_s=self.result_cache_ttl_s,
            )
            cache_context = cache.context(
                target_obj,
                harness=self.harness,
                extra_args=self.extra_args,
                timeout_s=self.timeout_s,
                slow_threshold_s=self.slow_threshold_s,
            )

        # Resumption support. Existing corpus records are streamed into the
        # manager and folded into the writer's digest, so a resumed campaign
        # appends to the same file instead of keeping a second payload list.
        existing_count = 0
        existing_raw_bytes = 0
        existing_digest = None
        if self.resume and checkpoint_file.exists():
            try:
                checkpoint = json.loads(checkpoint_file.read_text(encoding="utf-8"))
                if not isinstance(checkpoint, dict):
                    raise ValueError("checkpoint is not an object")
                if results_file.exists():
                    for line in results_file.read_text(encoding="utf-8").splitlines():
                        if line.strip():
                            rec = json.loads(line)
                            results.append(rec)
                if corpus_path.exists():
                    import hashlib
                    existing_digest = hashlib.sha256()
                    for p in corpus.iter_corpus(corpus_path):
                        corpus_mgr.add(p)
                        existing_count += 1
                        existing_raw_bytes += len(p)
                        existing_digest.update(hashlib.sha256(p).digest())
                if len(results) >= self.max_examples:
                    summary_path = self.out_dir / "summary.json"
                    if summary_path.exists():
                        return json.loads(summary_path.read_text(encoding="utf-8"))
            except Exception:
                # A partially written checkpoint or corpus is not a reason to
                # fail the run; start the corpus over rather than mixing a
                # partial digest with fresh records.
                existing_count = 0
                existing_raw_bytes = 0
                existing_digest = None

        writer = corpus.CorpusWriter(
            corpus_path,
            append=existing_count > 0,
            start_count=existing_count,
            initial_raw_bytes=existing_raw_bytes,
            initial_digest=existing_digest,
        )

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
            manifest = writer.manifest()
            cp_data = {
                "strategy": self.strategy_name,
                "target": target_obj.name,
                "examples_completed": len(results),
                "target_examples": self.max_examples,
                "wall_clock_elapsed_s": round(elapsed_now, 2),
                "crashes": len(crash_records),
                "unique_crashes": len({r["sha"] for r in results if r["outcome"] in ("crash", "timeout")}),
                "timeouts": timeout_count,
                "slow_inputs": slow_input_count,
                "interrupted": is_interrupted,
                "timestamp": time.time(),
                "timestamp_utc": utc_iso(),
                "corpus_manifest": manifest,
            }
            checkpoint_file.write_text(json.dumps(cp_data, indent=2), encoding="utf-8")

        def _process_one(doc: str | bytes) -> None:
            nonlocal consecutive_timeouts, timeout_count, slow_input_count
            if time.monotonic() - started >= self.wall_clock_cap_s:
                raise CampaignWallClockExceeded()
            payload = _encode(doc)
            writer.add(payload)

            r = self._run_payload(payload, target_obj, cache, cache_context)

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
                timeout_count += 1
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
                slow_input_count += 1
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
                record = triage.parse_report(r.stderr)
                crash_sig = (record.signature if record
                             else f"unparsed-{r.signal_name or r.returncode}")
                # Reproducers are deduplicated by signature later; retaining
                # every payload until the end only grows the process. Keep the
                # first input for each signature, up to a fixed bound. The
                # crash itself is still written to disk below.
                if (crash_sig not in crash_signatures
                        and len(crash_inputs) < MAX_REPRODUCER_INPUTS):
                    crash_signatures.add(crash_sig)
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
                            timeouts=timeout_count)

            if self.mode == "hunt":
                assert not r.outcome.is_crash, (
                    f"{r.outcome.value} rc={r.returncode} sig={r.signal_name}"
                )

        # Signal handlers only work in the main thread of the main interpreter.
        is_main_thread = (
            hasattr(threading, "current_thread")
            and hasattr(threading, "main_thread")
            and threading.current_thread() is threading.main_thread()
        )

        # Set up watchdog timer
        old_handler = None
        armed = False
        orig_sigint = None

        if is_main_thread:
            if hasattr(signal, "setitimer") and hasattr(signal, "SIGALRM"):
                try:
                    old_handler = signal.getsignal(signal.SIGALRM)

                    def _deadline(_signum, _frame):
                        raise CampaignWallClockExceeded()

                    signal.signal(signal.SIGALRM, _deadline)
                    signal.setitimer(signal.ITIMER_REAL, self.wall_clock_cap_s)
                    armed = True
                except (ValueError, AttributeError, OSError):
                    pass

            # Signal handler for graceful termination
            try:
                orig_sigint = signal.getsignal(signal.SIGINT)

                def _handle_sigint(signum, frame):
                    nonlocal interrupted
                    interrupted = True
                    _save_checkpoint(is_interrupted=True)
                    if callable(orig_sigint) and orig_sigint != _handle_sigint:
                        orig_sigint(signum, frame)
                    else:
                        raise KeyboardInterrupt()

                signal.signal(signal.SIGINT, _handle_sigint)
            except (ValueError, AttributeError, OSError):
                orig_sigint = None

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
            if armed and is_main_thread:
                try:
                    signal.setitimer(signal.ITIMER_REAL, 0)
                    signal.signal(signal.SIGALRM, old_handler)
                except (ValueError, AttributeError, OSError):
                    pass
            if orig_sigint is not None and is_main_thread:
                try:
                    signal.signal(signal.SIGINT, orig_sigint)
                except (ValueError, AttributeError, OSError):
                    pass
            results_fh.close()
            bar.close()
            manifest = writer.close()

        elapsed = time.monotonic() - started

        # Final corpus management and distillation. The raw corpus has already
        # been streamed to disk; the manager is the deduplicated view used for
        # distillation and coverage statistics.
        if self.max_corpus_entries is not None:
            corpus_mgr.trim(self.max_corpus_entries)
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
        summary["timeout_count"] = timeout_count
        summary["slow_input_count"] = slow_input_count
        summary["slow_threshold_s"] = self.slow_threshold_s
        summary["timeout_threshold_s"] = self.timeout_s
        summary["reproducers"] = reproducers_manifest
        summary["strategy_load"] = {
            "name": loaded.name,
            "from_cache": loaded.from_cache,
            "compile_ms": loaded.compile_ms,
            **loader.stats(),
        }
        if self.max_corpus_entries is not None:
            summary["corpus_memory"] = corpus_mgr.memory_stats()
        if cache is not None:
            summary["result_cache"] = cache.stats()

        if batch_history:
            summary["batch_history"] = batch_history

        # Finalize checkpoint
        _save_checkpoint(is_interrupted=interrupted)
        (self.out_dir / "summary.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8"
        )
        return summary

    def _run_payload(
        self,
        payload: bytes,
        target_obj: Any,
        cache: ResultCache | None,
        cache_context: dict[str, Any] | None,
    ) -> Any:
        """Run one payload, consulting the deterministic cache when enabled.

        A cache failure is contained inside :class:`ResultCache`; this helper
        always returns a real or cached :class:`RunResult`.
        """
        key = None
        if cache is not None and cache_context is not None:
            key = cache.key(cache_context, payload)
            hit = cache.get(key)
            if hit is not None:
                return hit
        result = target_obj.run(
            payload,
            timeout_s=self.timeout_s,
            extra_args=self.extra_args,
            slow_threshold_s=self.slow_threshold_s,
        )
        if cache is not None and key is not None:
            cache.put(key, result)
        return result

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
        buckets: dict[str, dict] = {}
        lengths: list[int] = []
        durs: list[float] = []
        diag_counts: dict[str, int] = {}
        unique_crash_shas: set[str] = set()
        shaped = 0
        xml_shaped = 0

        # One pass over the result log. At corpus scale the old version built a
        # separate list of every diagnostic and then walked the results again
        # for each aggregate; this keeps only the counters that are reported.
        for r in results:
            outcome = r["outcome"]
            counts[outcome] = counts.get(outcome, 0) + 1

            bucket = r.get("structure", {}).get("bucket", "unknown")
            entry = buckets.setdefault(bucket, {"n": 0, "accepted": 0})
            entry["n"] += 1
            if outcome in ("parsed_clean", "parsed_diag"):
                entry["accepted"] += 1

            lengths.append(r["len"])
            durs.append(r["dur_ms"])
            for diagnostic in r.get("diagnostics", []):
                norm = target_obj.normalize_diagnostic(diagnostic)
                diag_counts[norm] = diag_counts.get(norm, 0) + 1
            if outcome in ("crash", "timeout"):
                unique_crash_shas.add(r["sha"])
            if r.get("valid_shape", r.get("starts_lt")):
                shaped += 1
            if r.get("starts_lt"):
                xml_shaped += 1

        accepted = counts.get("parsed_clean", 0) + counts.get("parsed_diag", 0)
        for entry in buckets.values():
            entry["share"] = round(entry["n"] / n, 3) if n else 0.0
            entry["acceptance_rate"] = (
                round(entry["accepted"] / entry["n"], 3) if entry["n"] else 0.0)
        crashes = counts.get("crash", 0) + counts.get("timeout", 0)

        lengths = lengths or [0]
        durs = durs or [0.0]
        diag_hist = dict(sorted(diag_counts.items(), key=lambda kv: (-kv[1], kv[0])))

        # heapq.nlargest avoids sorting the entire result list just to report
        # the ten slowest inputs.
        sorted_by_dur = heapq.nlargest(
            10, results, key=lambda r: r.get("dur_ms", 0.0))
        slowest = [
            {"sha": r.get("sha", ""), "dur_ms": r.get("dur_ms", 0.0), "outcome": r.get("outcome", "")}
            for r in sorted_by_dur
        ]

        return {
            "target": target_obj.name,
            "target_category": target_obj.category,
            "strategy": self.strategy_name,
            "mode": self.mode,
            "random_seed": self.random_seed,
            "generated_at_utc": utc_iso(),
            "examples": n,
            "wall_clock_s": round(elapsed, 2),
            "outcomes": counts,
            "acceptance_rate": round(accepted / n, 4) if n else 0.0,
            "buckets": buckets,
            "crash_count": crashes,
            "unique_crash_inputs": len(unique_crash_shas),
            "shape_rate": round(shaped / n, 4) if n else 0.0,
            "xml_shaped_rate": round(xml_shaped / n, 4) if n else 0.0,
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
    ap.add_argument("--cache-results", action="store_true",
                    help="Reuse harness results for identical inputs; only for "
                         "deterministic targets (also STRATAGEM_RESULT_CACHE=1)")
    ap.add_argument("--cache-dir", default=None,
                    help="Directory for the result cache database")
    ap.add_argument("--cache-size", type=int, default=200_000,
                    help="Maximum cached results (0 = unlimited, default: 200000)")
    ap.add_argument("--cache-ttl", type=float, default=None,
                    help="Discard cached results older than this many seconds")
    ap.add_argument("--max-corpus-entries", type=int, default=None,
                    help="Trim the in-memory corpus to this many entries")
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
            use_result_cache=args.cache_results,
            result_cache_dir=args.cache_dir,
            result_cache_size=(args.cache_size or None),
            result_cache_ttl_s=args.cache_ttl,
            max_corpus_entries=args.max_corpus_entries,
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
        use_result_cache=args.cache_results,
        result_cache_dir=args.cache_dir,
        result_cache_size=(args.cache_size or None),
        result_cache_ttl_s=args.cache_ttl,
        max_corpus_entries=args.max_corpus_entries,
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
