"""Comprehensive test suite for Fuzzer Improvements:
  1. Parallel fuzzing (multiple campaigns running simultaneously)
  2. Adaptive batch sizes based on strategy performance
  3. Intelligent corpus management (deduplication, coverage-guided selection, prioritization)
  4. Timeout detection and handling for slow inputs
  5. Incremental campaign persistence for long-running tests
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

from fuzzer.batching import (
    AdaptiveBatchConfig,
    AdaptiveBatchController,
    BatchMetrics,
    extract_batch_metrics,
)
from fuzzer.campaign import Campaign, CampaignTimeoutStreakExceeded
from fuzzer.corpus import (
    CORPUS_NAME,
    DISTILLED_CORPUS_NAME,
    CorpusEntry,
    CorpusManager,
    read_corpus,
    write_corpus,
)
from fuzzer.parallel import (
    CampaignTask,
    ParallelCampaignRunner,
    run_parallel_seeds,
    run_parallel_strategies,
    run_parallel_targets,
)
from fuzzer.runner import DEFAULT_HARNESS, Outcome, RunResult, run_one

_passed = 0
_failed: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    global _passed
    if cond:
        _passed += 1
    else:
        _failed.append(f"{name}{(': ' + detail) if detail else ''}")


# =====================================================================
# 1. Parallel Fuzzing Tests
# =====================================================================
def test_parallel_fuzzing() -> None:
    with tempfile.TemporaryDirectory() as td:
        base_out = Path(td) / "parallel_test"

        # Test parallel runner with CampaignTask
        tasks = [
            CampaignTask(
                name="c1_mxml",
                strategy_name="baseline",
                target="mxml",
                max_examples=10,
                mode="survey",
            ),
            CampaignTask(
                name="c2_json",
                strategy_name="baseline",
                target="json",
                max_examples=10,
                mode="survey",
            ),
            CampaignTask(
                name="c3_http",
                strategy_name="baseline",
                target="http",
                max_examples=10,
                mode="survey",
            ),
        ]

        runner = ParallelCampaignRunner(tasks, max_workers=3, base_out_dir=base_out)
        summary = runner.run()

        check("parallel/completed_all", summary.completed_campaigns == 3, f"got {summary.completed_campaigns}")
        check("parallel/failed_zero", summary.failed_campaigns == 0, str(summary.failures))
        check("parallel/total_examples", summary.total_examples == 30, f"got {summary.total_examples}")
        check("parallel/throughput", summary.throughput_eps > 0)
        check("parallel/campaigns_recorded", len(summary.campaigns) == 3)
        check("parallel/summary_file_exists", (base_out / "parallel_summary.json").exists())

        # Test run_parallel_targets
        t_summary = run_parallel_targets(
            strategy="baseline",
            targets=["mxml", "json"],
            max_examples=5,
            base_out_dir=base_out / "targets_test",
            max_workers=2,
        )
        check("parallel/targets_completed", t_summary.completed_campaigns == 2)
        check("parallel/targets_examples", t_summary.total_examples == 10)

        # Test run_parallel_seeds
        s_summary = run_parallel_seeds(
            strategy="baseline",
            target="mxml",
            seeds=[42, 43],
            max_examples=5,
            base_out_dir=base_out / "seeds_test",
            max_workers=2,
        )
        check("parallel/seeds_completed", s_summary.completed_campaigns == 2)
        check("parallel/seeds_examples", s_summary.total_examples == 10)


# =====================================================================
# 2. Adaptive Batch Sizing Tests
# =====================================================================
def test_adaptive_batch_sizing() -> None:
    cfg = AdaptiveBatchConfig(
        initial_batch_size=50,
        min_batch_size=10,
        max_batch_size=200,
        growth_factor=1.5,
        decay_factor=0.6,
    )
    ctrl = AdaptiveBatchController(cfg)
    check("batching/initial_size", ctrl.current_batch_size == 50)

    # 1. Growth on new crash
    m_crash = BatchMetrics(
        batch_index=0,
        batch_size=50,
        new_crashes=1,
        valid_shape_rate=1.0,
        acceptance_rate=0.5,
    )
    next_size = ctrl.record_and_adapt(m_crash)
    check("batching/grows_on_crash", next_size > 50, f"got {next_size}")

    # 2. Growth on new productions
    m_prod = BatchMetrics(
        batch_index=1,
        batch_size=next_size,
        new_productions=3,
        valid_shape_rate=1.0,
        acceptance_rate=0.5,
    )
    next_size2 = ctrl.record_and_adapt(m_prod)
    check("batching/grows_on_productions", next_size2 > next_size, f"got {next_size2} vs {next_size}")

    # 3. Decay on invalid / malformed shapes
    m_malformed = BatchMetrics(
        batch_index=2,
        batch_size=next_size2,
        valid_shape_rate=0.1,  # below min_shape_rate
        acceptance_rate=0.0,
    )
    next_size3 = ctrl.record_and_adapt(m_malformed)
    check("batching/decays_on_malformed", next_size3 < next_size2, f"got {next_size3} vs {next_size2}")

    # 4. Decay on timeouts
    m_timeout = BatchMetrics(
        batch_index=3,
        batch_size=next_size3,
        timeouts=2,
        valid_shape_rate=1.0,
        acceptance_rate=0.5,
    )
    next_size4 = ctrl.record_and_adapt(m_timeout)
    check("batching/decays_on_timeout", next_size4 < next_size3, f"got {next_size4} vs {next_size3}")

    # 5. Clamping bounds check
    for _ in range(10):
        ctrl.record_and_adapt(
            BatchMetrics(
                batch_index=4,
                batch_size=10,
                valid_shape_rate=0.0,
                acceptance_rate=0.0,
            )
        )
    check("batching/clamped_to_min", ctrl.current_batch_size == cfg.min_batch_size, f"got {ctrl.current_batch_size}")

    for _ in range(15):
        ctrl.record_and_adapt(
            BatchMetrics(
                batch_index=5,
                batch_size=200,
                new_crashes=2,
                new_productions=5,
                valid_shape_rate=1.0,
                acceptance_rate=0.5,
            )
        )
    check("batching/clamped_to_max", ctrl.current_batch_size == cfg.max_batch_size, f"got {ctrl.current_batch_size}")

    # Campaign integration test with adaptive batching
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "adaptive_campaign"
        c = Campaign(
            strategy_name="baseline",
            max_examples=30,
            out_dir=out,
            adaptive_batch=True,
            batch_config=AdaptiveBatchConfig(
                initial_batch_size=10, min_batch_size=5, max_batch_size=25
            ),
        )
        s = c.run()
        check("batching/campaign_runs", s["examples"] == 30, f"got {s['examples']}")
        check("batching/summary_has_history", "batch_history" in s)
        bh = s["batch_history"]
        check("batching/multiple_batches", bh["batches_evaluated"] > 1, f"batches: {bh['batches_evaluated']}")
        check("batching/progression_tracked", len(bh["size_progression"]) > 1)


# =====================================================================
# 3. Intelligent Corpus Management Tests
# =====================================================================
def test_corpus_management() -> None:
    mgr = CorpusManager()

    # Exact deduplication
    p1 = b"<root>hello</root>"
    p2 = b"<root>world</root>"
    check("corpus/add_new", mgr.add(p1, outcome="parsed_clean", productions=["elem"]))
    check("corpus/reject_exact_dup", not mgr.add(p1, outcome="parsed_clean"), "expected duplicate reject")
    check("corpus/add_second", mgr.add(p2, outcome="parsed_clean", productions=["elem"]))
    check("corpus/count_is_2", len(mgr) == 2)
    check("corpus/duplicates_tracked", mgr.duplicates_rejected == 1)

    # Semantic deduplication
    p3 = b"<root>duplicate_semantics</root>"
    # Same outcome, same diagnostics, same productions as p1
    added_sem = mgr.add(
        p3,
        outcome="parsed_clean",
        productions=["elem"],
        deduplicate_semantic=True,
    )
    check("corpus/reject_semantic_dup", not added_sem)

    # Coverage-guided selection (Set Cover)
    # Entry A covers: p1, p2
    # Entry B covers: p2, p3
    # Entry C covers: p4
    # Entry D covers: p1 (redundant)
    mgr_coverage = CorpusManager()
    e_a = CorpusEntry(payload=b"short", productions=["p1", "p2"], diagnostics=["d1"], length=5, duration_ms=2.0)
    e_b = CorpusEntry(payload=b"med_len", productions=["p2", "p3"], length=7, duration_ms=3.0)
    e_c = CorpusEntry(payload=b"c", productions=["p4"], length=1, duration_ms=1.0)
    e_d = CorpusEntry(payload=b"long_redundant_input", productions=["p1"], length=25, duration_ms=10.0)
    e_crash = CorpusEntry(payload=b"crash!", outcome="crash", productions=["p1"], length=6)

    for e in (e_a, e_b, e_c, e_d, e_crash):
        mgr_coverage.add_entry(e)

    check("corpus/coverage_init_count", len(mgr_coverage) == 5)
    selected = mgr_coverage.select_coverage_guided(features_to_cover=("productions", "diagnostics"))

    # Selected must cover p1, p2, p3, p4, d1 and the crash
    covered_prods = {p for e in selected for p in e.productions}
    check("corpus/all_prods_covered", {"p1", "p2", "p3", "p4"}.issubset(covered_prods))
    check("corpus/distillation_smaller", len(selected) < 5, f"selected: {len(selected)}")
    check("corpus/redundant_omitted", e_d not in selected)
    check("corpus/crash_preserved", e_crash in selected)

    # Distill
    distilled_mgr = mgr_coverage.distill()
    check("corpus/distill_is_manager", isinstance(distilled_mgr, CorpusManager))
    check("corpus/distill_size", len(distilled_mgr) == len(selected))

    # Prioritization / Energy scoring
    scored = mgr_coverage.prioritize()
    check("corpus/prioritize_returns_all", len(scored) == 5)
    check("corpus/scores_assigned", all(e.score > 0 for e in scored))
    # Crashes or rare productions get high priority
    check("corpus/crash_high_rank", scored[0].outcome == "crash" or scored[0].score >= scored[-1].score)

    # Merging
    mgr_other = CorpusManager()
    mgr_other.add(b"<unique>input</unique>", productions=["p5"])
    mgr_other.add(p1)  # already in mgr
    added_count = mgr.merge(mgr_other)
    check("corpus/merge_added_unique_only", added_count == 1, f"added: {added_count}")

    # Export / Import persistence
    with tempfile.TemporaryDirectory() as td:
        exp_path = Path(td) / "test_corpus.jsonl.gz"
        manifest = mgr.export_corpus(exp_path)
        check("corpus/export_file_exists", exp_path.exists())
        check("corpus/manifest_count", manifest["count"] == len(mgr))

        # Backward compatibility with read_corpus
        read_payloads = read_corpus(exp_path)
        check("corpus/read_corpus_compatible", len(read_payloads) == len(mgr))
        check("corpus/read_corpus_bytes_match", read_payloads[0] == mgr.payloads()[0])

        # Import into fresh manager
        imported_mgr = CorpusManager()
        imp_count = imported_mgr.import_corpus(exp_path)
        check("corpus/import_count", imp_count == len(mgr))


# =====================================================================
# 4. Timeout Detection and Slow Input Handling Tests
# =====================================================================
def test_timeout_and_slow_inputs() -> None:
    # 1. Slow input detection in RunResult
    res_slow = RunResult(
        outcome=Outcome.PARSED_CLEAN,
        returncode=0,
        duration_s=1.5,
        is_slow=True,
        slow_threshold_s=1.0,
    )
    j = res_slow.to_json()
    check("timeout/runresult_has_is_slow", j.get("is_slow") is True)

    # 2. run_one with slow threshold
    # A fast execution should not be marked slow
    r_fast = run_one(b"<r/>", target="mxml", slow_threshold_s=5.0)
    check("timeout/fast_not_slow", not r_fast.is_slow)

    # With very low threshold (0.0s), it should be marked slow
    r_slow = run_one(b"<r/>", target="mxml", slow_threshold_s=0.0)
    check("timeout/marked_slow_on_threshold", r_slow.is_slow)

    # 3. Campaign slow input persistence
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "slow_campaign"
        c = Campaign(
            strategy_name="baseline",
            max_examples=10,
            out_dir=out,
            slow_threshold_s=0.0,  # forces all to be marked as slow
        )
        s = c.run()
        check("timeout/slow_inputs_counted", s["slow_input_count"] == 10)
        slow_dir = out / "slow_inputs"
        check("timeout/slow_dir_exists", slow_dir.exists())
        bins = list(slow_dir.glob("*.bin"))
        metas = list(slow_dir.glob("*.meta.json"))
        check("timeout/slow_files_persisted", len(bins) > 0 and len(metas) > 0)

        # 4. Timeout handling & artifact persistence
        res_timeout = RunResult(
            outcome=Outcome.TIMEOUT,
            returncode=-9,
            signal_name="TIMEOUT",
            duration_s=5.1,
            is_slow=True,
        )
        check("timeout/to_json_has_timeout", res_timeout.to_json().get("timeout") is True)
        check("timeout/is_crash_includes_timeout", res_timeout.outcome.is_crash is True)


# =====================================================================
# 5. Incremental Persistence Tests
# =====================================================================
def test_incremental_persistence() -> None:
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "incremental_campaign"

        # Run campaign with small checkpoint interval
        c = Campaign(
            strategy_name="baseline",
            max_examples=25,
            out_dir=out,
            checkpoint_interval=10,
            incremental_flush=True,
        )
        s = c.run()

        # Verify results.jsonl and checkpoint.json exist
        results_file = out / "results.jsonl"
        checkpoint_file = out / "checkpoint.json"
        check("persistence/results_jsonl_exists", results_file.exists())
        check("persistence/checkpoint_json_exists", checkpoint_file.exists())

        lines = results_file.read_text(encoding="utf-8").splitlines()
        check("persistence/all_results_streamed", len(lines) == 25)

        cp = json.loads(checkpoint_file.read_text(encoding="utf-8"))
        check("persistence/checkpoint_completed", cp["examples_completed"] == 25)
        check("persistence/checkpoint_target", cp["target_examples"] == 25)
        check("persistence/checkpoint_has_manifest", "corpus_manifest" in cp)

        # Distilled corpus artifact
        distilled_file = out / DISTILLED_CORPUS_NAME
        check("persistence/distilled_corpus_saved", distilled_file.exists())
        check("persistence/summary_has_distilled_stats", "distilled_stats" in s)

        # Resumption test:
        # Simulate partial run by creating a checkpoint at 15 examples
        resume_out = Path(td) / "resume_campaign"
        resume_out.mkdir(parents=True, exist_ok=True)
        # Run first 15 examples
        c_part = Campaign(
            strategy_name="baseline",
            max_examples=15,
            out_dir=resume_out,
            checkpoint_interval=5,
        )
        c_part.run()

        # Now resume with target max_examples = 25
        c_resume = Campaign(
            strategy_name="baseline",
            max_examples=25,
            out_dir=resume_out,
            checkpoint_interval=5,
            resume=True,
        )
        s_resumed = c_resume.run()
        check("persistence/resumed_completed_target", s_resumed["examples"] == 25, f"got {s_resumed['examples']}")
        resumed_lines = (resume_out / "results.jsonl").read_text(encoding="utf-8").splitlines()
        check("persistence/resumed_results_count", len(resumed_lines) == 25)


def main() -> int:
    print("Running Fuzzer Improvements Test Suite...")
    test_parallel_fuzzing()
    test_adaptive_batch_sizing()
    test_corpus_management()
    test_timeout_and_slow_inputs()
    test_incremental_persistence()

    print(f"passed={_passed} failed={len(_failed)}")
    for f in _failed:
        print(f"  FAIL {f}")
    return 1 if _failed else 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
