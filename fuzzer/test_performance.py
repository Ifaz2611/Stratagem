"""Hermetic tests for the performance layer.

These tests do not need a sanitizer build, an LLM, or a network. Campaign
integration uses a counting in-process target so the assertions are about the
cache and corpus machinery, not about parser behaviour.

Run:  .venv/bin/python -m fuzzer.test_performance
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from fuzzer.campaign import Campaign
from fuzzer.corpus import (
    CorpusEntry,
    CorpusManager,
    CorpusWriter,
    corpus_digest,
    iter_corpus,
    read_corpus,
    write_corpus,
)
from fuzzer.distributed import (
    _claim_next,
    merge_results,
    plan_shards,
    run_local,
    run_worker,
    status,
)
from fuzzer.result_cache import ResultCache
from fuzzer.runner import Outcome, RunResult
from fuzzer.strategy_loader import StrategyError, StrategyLoader
from fuzzer.targets.base import BaseTarget

_passed = 0
_failed: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    global _passed
    if cond:
        _passed += 1
    else:
        _failed.append(f"{name}{(': ' + detail) if detail else ''}")


# ---------------------------------------------------------------------------
# 1. Strategy bytecode loader
# ---------------------------------------------------------------------------
_STRATEGY_SOURCE = '''\
from hypothesis import strategies as st

NAME = "demo"
DESCRIPTION = "a demo strategy"
LOAD_COUNT = globals().get("LOAD_COUNT", 0) + 1


def documents():
    return st.just("<demo/>")
'''


def test_strategy_loader() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        strategies = root / "strategies"
        cache = root / "cache"
        strategies.mkdir()
        (strategies / "demo.py").write_text(_STRATEGY_SOURCE, encoding="utf-8")

        loader = StrategyLoader(strategies_dir=strategies, cache_dir=cache)
        first = loader.load("demo")
        check("loader/first_compiles", not first.from_cache)
        check("loader/code_file_written",
              first.code_path is not None and first.code_path.exists())
        check("loader/fresh_module_state",
              first.module.LOAD_COUNT == 1,
              f"got {first.module.LOAD_COUNT}")
        docs = first.documents()
        from hypothesis import strategies as st
        check("loader/documents_returns_strategy",
              isinstance(docs, st.SearchStrategy))

        second = loader.load("demo")
        check("loader/second_from_cache", second.from_cache)
        check("loader/state_resets_per_load",
              second.module.LOAD_COUNT == 1,
              f"got {second.module.LOAD_COUNT}")

        # Package prefix resolution
        prefixed = loader.load("fuzzer.strategies.demo")
        check("loader/package_prefix_resolved", prefixed.from_cache)
        stats = loader.stats()
        check("loader/compiled_once", stats["compiled"] == 1,
              f"got {stats['compiled']}")
        check("loader/hit_counted", stats["cache_hits"] >= 1,
              f"got {stats['cache_hits']}")
        check("loader/executes_each_time", stats["executions"] == 3,
              f"got {stats['executions']}")

        # A changed source must invalidate the content-addressed entry.
        (strategies / "demo.py").write_text(
            _STRATEGY_SOURCE.replace('NAME = "demo"', 'NAME = "demo2"'),
            encoding="utf-8")
        changed = loader.load("demo")
        check("loader/source_change_recompiles", not changed.from_cache)
        check("loader/source_change_visible",
              changed.module.NAME == "demo2",
              f"got {changed.module.NAME}")

        # A corrupt cache file is a miss, not a failed campaign.
        assert changed.code_path is not None
        changed.code_path.write_bytes(b"not a cache file")
        fresh_loader = StrategyLoader(strategies_dir=strategies, cache_dir=cache)
        recovered = fresh_loader.load("demo")
        check("loader/corrupt_cache_recovers",
              not recovered.from_cache and recovered.module.NAME == "demo2")

        try:
            loader.load("../escape")
            rejected = False
        except StrategyError:
            rejected = True
        check("loader/rejects_path_traversal", rejected)

        try:
            loader.load("missing")
            missing_rejected = False
        except StrategyError:
            missing_rejected = True
        check("loader/rejects_missing", missing_rejected)

        documents, loaded = loader.load_documents("demo")
        check("loader/load_documents", isinstance(documents, st.SearchStrategy)
              and loaded.name == "demo")


# ---------------------------------------------------------------------------
# 2. Deterministic result cache
# ---------------------------------------------------------------------------
def _clean(payload: bytes = b"<r/>", *, duration_s: float = 0.01) -> RunResult:
    return RunResult(
        outcome=Outcome.PARSED_CLEAN,
        returncode=0,
        diagnostics=[],
        stderr="",
        duration_s=duration_s,
        input_sha256=hashlib.sha256(payload).hexdigest(),
        input_len=len(payload),
    )


def test_result_cache() -> None:
    with tempfile.TemporaryDirectory() as td:
        db = Path(td) / "results.sqlite3"
        cache = ResultCache(db)
        context = cache.context(
            target="mxml", timeout_s=1.0, slow_threshold_s=0.5)
        payload = b"<r/>"
        key = cache.key(context, payload)

        check("result_cache/miss", cache.get(key) is None)
        result = _clean(payload)
        check("result_cache/store", cache.put(key, result))
        hit = cache.get(key)
        check("result_cache/hit", hit is not None and hit.cached)
        check("result_cache/hit_preserves_outcome",
              hit is not None and hit.outcome == Outcome.PARSED_CLEAN)
        check("result_cache/hit_preserves_duration",
              hit is not None and hit.duration_s == result.duration_s)
        check("result_cache/key_changes_with_payload",
              cache.key(context, b"<x/>") != key)
        check("result_cache/key_changes_with_timeout",
              cache.key(cache.context(target="mxml", timeout_s=2.0), payload)
              != key)

        # Timeouts and harness errors are not deterministic enough to cache.
        timeout = RunResult(
            outcome=Outcome.TIMEOUT, returncode=-1, signal_name="TIMEOUT",
            duration_s=1.0, input_sha256="a" * 64, input_len=3)
        check("result_cache/does_not_store_timeout",
              not cache.put(cache.key(context, b"slow"), timeout))
        check("result_cache/does_not_store_harness_error",
              not cache.put(cache.key(context, b"bad"), RunResult(
                  outcome=Outcome.HARNESS_ERROR, returncode=2,
                  input_sha256="b" * 64, input_len=3)))

        # A corrupt value is a miss and is contained.
        conn = sqlite3.connect(db)
        try:
            with conn:
                conn.execute(
                    "UPDATE results SET value = ? WHERE key = ?",
                    ("not-json", key))
        finally:
            conn.close()
        check("result_cache/corrupt_value_is_miss", cache.get(key) is None)
        check("result_cache/corrupt_value_counted", cache.errors >= 1)

        # TTL and pruning.
        cache2 = ResultCache(Path(td) / "ttl.sqlite3", ttl_s=-1.0)
        ctx2 = cache2.context(target="mxml", timeout_s=1.0)
        k2 = cache2.key(ctx2, b"<ttl/>")
        cache2.put(k2, _clean(b"<ttl/>"))
        check("result_cache/ttl_expiry", cache2.get(k2) is None)

        cache3 = ResultCache(Path(td) / "small.sqlite3", max_entries=2)
        ctx3 = cache3.context(target="mxml", timeout_s=1.0)
        for i in range(4):
            p = f"<{i}/>".encode()
            cache3.put(cache3.key(ctx3, p), _clean(p))
        removed = cache3.prune()
        check("result_cache/prune_removes", removed >= 2,
              f"removed {removed}")
        check("result_cache/prune_limit", cache3.entries() <= 2,
              f"entries {cache3.entries()}")


# ---------------------------------------------------------------------------
# 3. Corpus memory behaviour and streaming writer
# ---------------------------------------------------------------------------
@dataclass
class _FakeFeatures:
    productions: list[str]

    def to_json(self) -> dict:
        return {"bucket": "well_formed"}


class _CountingTarget(BaseTarget):
    name = "counting"
    category = "xml"
    harness_binary = None

    def __init__(self) -> None:
        self.calls = 0

    def run(self, payload: bytes, timeout_s: float = 5.0,
            extra_args: tuple[str, ...] = (),
            slow_threshold_s: float | None = None,
            sanitizers=None, sanitizer_env=None) -> RunResult:
        self.calls += 1
        outcome = (Outcome.PARSED_CLEAN if payload.startswith(b"<")
                   else Outcome.REJECTED)
        return RunResult(
            outcome=outcome,
            returncode=0 if outcome == Outcome.PARSED_CLEAN else 1,
            duration_s=0.001,
            input_sha256=hashlib.sha256(payload).hexdigest(),
            input_len=len(payload),
            slow_threshold_s=slow_threshold_s,
        )

    def is_valid_shape(self, payload: bytes) -> bool:
        return payload.startswith(b"<")

    def normalize_diagnostic(self, message: str) -> str:
        return message

    def analyze_features(self, text: str, payload: bytes = b"") -> _FakeFeatures:
        return _FakeFeatures(["elem"] if text.startswith("<") else [])

    def summarize_structure(self, feature_list: list) -> dict:
        return {
            "productions_hit": 1 if feature_list else 0,
            "productions_total": 1,
            "missing": [],
        }


def test_corpus_memory() -> None:
    entry = CorpusEntry(payload=b"<r/>")
    check("corpus/slots_enabled", not hasattr(entry, "__dict__"))

    mgr = CorpusManager()
    mgr.add(b"<a/>", outcome="parsed_clean", productions=["elem"])
    check("corpus/signatures_lazy", mgr._sig_set is None)
    duplicate = mgr.add(
        b"<b/>", outcome="parsed_clean", productions=["elem"],
        deduplicate_semantic=True)
    check("corpus/semantic_dedup_after_lazy_init", not duplicate)
    check("corpus/signatures_tracked_after_use", mgr._sig_set is not None)

    # A ceiling trims in batches and never loses a crash.
    capped = CorpusManager(max_entries=3, evict_batch=1)
    for i in range(12):
        capped.add(f"<n{i}/>".encode(), outcome="parsed_clean",
                   productions=["elem"])
    capped.add(b"crash", outcome="crash", productions=["boom"])
    check("corpus/auto_eviction_bounded",
          len(capped) <= capped.max_entries + capped.evict_batch,
          f"len={len(capped)}")
    capped.trim(3)
    check("corpus/trim_respects_limit", len(capped) == 3,
          f"len={len(capped)}")
    check("corpus/trim_preserves_crash",
          any(e.outcome == "crash" for e in capped),
          "crash entry was dropped")
    check("corpus/evicted_counted", capped.evicted > 0)

    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "corpus.jsonl.gz"
        payloads = [b"<a/>", b"<b/>", b"\x00\xff"]
        writer = CorpusWriter(path)
        for p in payloads:
            writer.add(p)
        manifest = writer.close()
        check("corpus/writer_count", manifest["count"] == 3,
              f"got {manifest['count']}")
        check("corpus/writer_roundtrip", read_corpus(path) == payloads)
        check("corpus/writer_digest_matches",
              manifest["corpus_digest"] == corpus_digest(payloads),
              f"{manifest['corpus_digest']} != {corpus_digest(payloads)}")
        check("corpus/iter_matches_read",
              list(iter_corpus(path)) == payloads)

        second = Path(td) / "second.jsonl.gz"
        m2 = write_corpus(second, iter(payloads))
        check("corpus/write_iterable", m2["corpus_digest"] == manifest["corpus_digest"])

        digest = hashlib.sha256()
        for p in payloads:
            digest.update(hashlib.sha256(p).digest())
        appender = CorpusWriter(path, append=True, start_count=3,
                                initial_raw_bytes=manifest["raw_bytes"],
                                initial_digest=digest)
        appender.add(b"<c/>")
        m3 = appender.close()
        check("corpus/append_count", m3["count"] == 4, f"got {m3['count']}")
        check("corpus/append_roundtrip", read_corpus(path) == payloads + [b"<c/>"])
        check("corpus/append_digest", m3["corpus_digest"] == corpus_digest(payloads + [b"<c/>"]))


# ---------------------------------------------------------------------------
# 4. Campaign integration: cache hits and streaming corpus
# ---------------------------------------------------------------------------
def test_campaign_cache_integration() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        cache_dir = root / "cache"
        target = _CountingTarget()

        first = Campaign(
            strategy_name="byte_probe",
            max_examples=4,
            out_dir=root / "first",
            target=target,
            random_seed=11,
            progress="off",
            use_result_cache=True,
            result_cache_dir=cache_dir,
            max_corpus_entries=3,
        ).run()
        check("campaign/cache_first_misses",
              first.get("result_cache", {}).get("stores", 0) > 0,
              f"stats={first.get('result_cache')}")
        calls_after_first = target.calls
        check("campaign/first_run_executes", calls_after_first == 4,
              f"calls={calls_after_first}")

        second = Campaign(
            strategy_name="byte_probe",
            max_examples=4,
            out_dir=root / "second",
            target=target,
            random_seed=11,
            progress="off",
            use_result_cache=True,
            result_cache_dir=cache_dir,
            max_corpus_entries=3,
        ).run()
        check("campaign/cache_second_hits",
              second.get("result_cache", {}).get("hits", 0) == 4,
              f"stats={second.get('result_cache')}")
        check("campaign/cache_avoids_execution",
              target.calls == calls_after_first,
              f"calls={target.calls}")
        records = [
            json.loads(line)
            for line in (root / "second" / "results.jsonl")
            .read_text(encoding="utf-8").splitlines() if line.strip()
        ]
        check("campaign/cached_marked", all(r.get("cached") for r in records))
        check("campaign/corpus_streamed",
              (root / "second" / "corpus.jsonl.gz").exists())
        check("campaign/corpus_trimmed",
              second["corpus_stats"]["count"] <= 3,
              f"count={second['corpus_stats']['count']}")
        check("campaign/loader_stats_present",
              second["strategy_load"]["executions"] >= 1)


# ---------------------------------------------------------------------------
# 5. Distributed sharding
# ---------------------------------------------------------------------------
class _FakeCampaign:
    def __init__(self, task) -> None:
        self.task = task

    def run(self) -> dict:
        clean = self.task.examples if self.task.task_id.endswith("000") else 0
        return {
            "examples": self.task.examples,
            "outcomes": {"parsed_clean": clean,
                         "rejected": self.task.examples - clean},
            "acceptance_rate": (clean / self.task.examples
                                if self.task.examples else 0.0),
            "crash_count": 0,
            "unique_crash_inputs": 0,
            "wall_clock_s": 0.05,
            "crash_groups": {},
        }


def test_distributed() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        plan = plan_shards(
            root, strategies=["baseline"], targets=["json"],
            examples=10, shards=3, seed=5)
        check("distributed/task_count", len(plan.tasks) == 3)
        check("distributed/examples_sum",
              sum(t.examples for t in plan.tasks) == 10)
        check("distributed/deterministic_seeds",
              [t.seed for t in plan.tasks] == [5, 6, 7])
        check("distributed/unique_out_dirs",
              len({t.out_dir for t in plan.tasks}) == 3)

        # Claims are exclusive across workers.
        first = _claim_next(plan, "worker-a", lease_s=600)
        second = _claim_next(plan, "worker-b", lease_s=600)
        check("distributed/claim_exclusive",
              first is not None and second is not None
              and first.task_id != second.task_id)
        if first is not None:
            plan.claim_path(first).unlink()
        reclaimed = _claim_next(plan, "worker-b", lease_s=600)
        check("distributed/released_claim_reusable",
              reclaimed is not None and reclaimed.task_id == first.task_id)

        # A stale claim is reclaimed after its lease.
        stale = plan.tasks[2]
        plan.claim_path(stale).write_text(json.dumps({
            "worker_id": "dead",
            "claimed_at": time.time() - 100,
        }), encoding="utf-8")
        taken = _claim_next(plan, "worker-c", lease_s=10)
        check("distributed/stale_claim_reclaimed",
              taken is not None and taken.task_id == stale.task_id)

        # Clear all claims so the worker test starts clean.
        for task in plan.tasks:
            try:
                plan.claim_path(task).unlink()
            except OSError:
                pass

        worker = run_worker(
            root, "worker-1", poll_s=0.01, idle_timeout_s=2.0, lease_s=600,
            campaign_factory=lambda task, work: _FakeCampaign(task))
        check("distributed/worker_completed_all", worker["completed"] == 3,
              f"completed={worker['completed']} failed={worker['failed']}")
        current = status(root)
        check("distributed/status_complete", current["complete"])
        check("distributed/status_done", current["done"] == 3)

        merged = merge_results(root)
        check("distributed/merge_examples", merged["examples"] == 10,
              f"got {merged['examples']}")
        check("distributed/merge_outcomes",
              merged["outcomes"].get("parsed_clean", 0) > 0)
        check("distributed/merge_complete", merged["complete"])
        check("distributed/merge_written",
              (root / "distributed_summary.json").exists())

        # A worker records a failure instead of dying.
        fail_plan = plan_shards(
            root / "failing", strategies=["baseline"], targets=["json"],
            examples=4, shards=2, seed=0)

        def factory(task, work):
            if task.task_id.endswith("001"):
                raise RuntimeError("boom")
            return _FakeCampaign(task)

        fail_worker = run_worker(
            root / "failing", "worker-f", poll_s=0.01, idle_timeout_s=2.0,
            lease_s=600, campaign_factory=factory)
        check("distributed/failure_isolated",
              fail_worker["completed"] == 1 and fail_worker["failed"] == 1,
              f"stats={fail_worker}")
        failed_merge = merge_results(root / "failing")
        check("distributed/failure_reported",
              len(failed_merge["failures"]) == 1)
        check("distributed/failure_plan_ids",
              set(failed_merge["failures"]) == {fail_plan.tasks[1].task_id})

        # Local worker runner can drain a plan without a broker.
        local_root = root / "local"
        plan_shards(local_root, strategies=["baseline"], targets=["json"],
                    examples=6, shards=3, seed=0)
        local = run_local(
            local_root, workers=2, idle_timeout_s=2.0,
            campaign_factory=lambda task, work: _FakeCampaign(task))
        check("distributed/local_completes",
              local["completed"] == 3 and local["failed"] == 0,
              f"local={local}")

        # Plan files round-trip.
        loaded = plan_shards(
            root / "roundtrip", strategies=["baseline"], targets=["mxml"],
            examples=4, shards=2, seed=3)
        from fuzzer.distributed import DistributedPlan
        reloaded = DistributedPlan.load(root / "roundtrip")
        check("distributed/plan_roundtrip",
              [t.to_dict() for t in reloaded.tasks]
              == [t.to_dict() for t in loaded.tasks])


# ---------------------------------------------------------------------------
def main() -> int:
    test_strategy_loader()
    test_result_cache()
    test_corpus_memory()
    test_campaign_cache_integration()
    test_distributed()

    print(f"performance checks: {_passed} passed, {len(_failed)} failed")
    for failure in _failed:
        print(f"  FAIL: {failure}")
    return 0 if not _failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
