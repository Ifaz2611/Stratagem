"""Comprehensive tests for the agentic loop.

Coverage is organised around the loop's decisions rather than its lines:

  * budget accounting and the pre-call overrun guard
  * configuration validation
  * prompt construction (seed and refine)
  * transcript recording, iteration attribution and resume restoration
  * strategy acquisition: first pass, repair, truncation resend, budget stop
  * campaign repair after a gate pass
  * end-to-end runs, early stops, ensemble voting and cache reuse

No LLM, harness, network or committed run directory is required: the backend
and campaign are test doubles, and every run lives under a temporary root.

Run with pytest::

    python -m pytest agent/test_loop.py -q

or without pytest::

    python -m agent.test_loop
"""
from __future__ import annotations

import contextlib
import json
import tempfile
import traceback
from pathlib import Path
from unittest.mock import patch

from agent import llm
from agent import loop as loopmod
from agent.loop import MAX_ITERATIONS, MAX_REPAIRS, Budget, Loop
from agent.validate import Validation

VALID_CODE = (
    "```python\n"
    "NAME = 'test'\n"
    "DESCRIPTION = 'test strategy'\n"
    "def documents():\n"
    "    from hypothesis import strategies as st\n"
    "    return st.just('<a/>')\n"
    "```\n"
)


# --------------------------------------------------------------------- helpers
def make_summary(
    *,
    strategy: str = "gen_iter0",
    examples: int = 20,
    acceptance: float = 0.50,
    productions: int = 5,
    productions_total: int = 27,
    diag: int = 3,
    crashes: int = 0,
    depth: int = 4,
) -> dict:
    return {
        "target": "mxml",
        "target_category": "xml",
        "strategy": strategy,
        "mode": "survey",
        "examples": examples,
        "wall_clock_s": 0.5,
        "outcomes": {"parsed_clean": int(examples * acceptance),
                     "rejected": examples - int(examples * acceptance)},
        "acceptance_rate": acceptance,
        "buckets": {
            "well_formed": {"n": examples, "share": 0.5,
                            "acceptance_rate": acceptance},
            "near_miss": {"n": max(1, examples // 2), "share": 0.3,
                          "acceptance_rate": 0.4},
            "byte_hostile": {"n": max(1, examples // 4), "share": 0.2,
                             "acceptance_rate": 0.2},
        },
        "crash_count": crashes,
        "unique_crash_inputs": crashes,
        "shape_rate": 0.8,
        "xml_shaped_rate": 0.8,
        "diagnostic_templates": {f"diag-{i}": 2 for i in range(diag)},
        "distinct_diagnostic_templates": diag,
        "input_len": {"min": 1, "max": 40, "mean": 12.0, "median": 10.0},
        "duration_ms": {"mean": 0.5, "max": 2.0},
        "slowest_inputs": [],
        "structure": {
            "productions_hit": productions,
            "productions_total": productions_total,
            "missing": [f"p{i}" for i in range(productions, productions_total)],
            "max_depth_seen": depth,
            "hit": {f"p{i}": 1 for i in range(productions)},
            "depth_histogram": {"0": 1, "1": 2},
            "boundaries": {},
        },
        "crash_groups": (
            {f"sig{i}": {"count": 1, "label": "crash"} for i in range(crashes)}
            if crashes else {}
        ),
        "clusters": [],
        "triage_summary": {},
        "shrunk_failure": None,
    }


def _write_results(out_dir: Path, examples: int) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = [
        {
            "sha": f"{i:064x}", "len": 4, "dur_ms": 0.1 + i / 100,
            "outcome": "parsed_clean" if i % 2 else "rejected",
            "diagnostics": ["DIAG a"] if i % 3 == 0 else [],
            "structure": {"max_depth": i % 5, "bucket": "well_formed"},
        }
        for i in range(examples)
    ]
    (out_dir / "results.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


class FakeCampaign:
    """Campaign double that writes the artifacts the loop reads."""

    fail_times = 0
    production_hits: list[int] = []
    instances: list["FakeCampaign"] = []

    def __init__(self, strategy_name, max_examples, out_dir, mode="survey",
                 target="mxml", **kwargs):
        self.strategy_name = strategy_name
        self.max_examples = max_examples
        self.out_dir = Path(out_dir)
        self.mode = mode
        self.target = target
        self.kwargs = kwargs
        type(self).instances.append(self)

    def run(self) -> dict:
        if type(self).fail_times > 0:
            type(self).fail_times -= 1
            raise RuntimeError("simulated campaign failure")
        prod = (type(self).production_hits.pop(0)
                if type(self).production_hits else 5)
        _write_results(self.out_dir, self.max_examples)
        summary = make_summary(strategy=self.strategy_name,
                               examples=self.max_examples,
                               productions=prod)
        (self.out_dir / "summary.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8")
        return summary

    @classmethod
    def reset(cls) -> None:
        cls.fail_times = 0
        cls.production_hits = []
        cls.instances = []


class FakeBackend:
    """Deterministic backend with optional failures."""

    name = "mock"

    def __init__(self, texts: list[str] | None = None,
                 fail_times: int = 0, cost_usd: float = 0.01):
        self.texts = list(texts or [])
        self.fail_times = fail_times
        self.cost_usd = cost_usd
        self.calls: list[dict] = []

    def complete(self, system: str, user: str, stream: bool = False,
                 on_chunk=None) -> llm.LLMResponse:
        self.calls.append({"system": system, "user": user})
        if self.fail_times:
            self.fail_times -= 1
            raise llm.LLMError("simulated backend failure")
        text = self.texts.pop(0) if self.texts else VALID_CODE
        return llm.LLMResponse(text=text, backend="mock", model="fake",
                               input_tokens=100, output_tokens=50,
                               cost_usd=self.cost_usd)


@contextlib.contextmanager
def loop_env():
    """Redirect the loop's run and strategy roots into a temporary directory."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        strategies = root / "strategies"
        strategies.mkdir()
        with patch.object(loopmod, "REPO_ROOT", root), \
                patch.object(loopmod, "STRATEGY_DIR", strategies), \
                patch.object(loopmod, "_grammar_body",
                             return_value="<grammar body/>"):
            yield root, strategies


def make_loop(run_id: str = "test", **kwargs) -> Loop:
    kwargs.setdefault("max_examples", 20)
    kwargs.setdefault("max_iterations", 2)
    kwargs.setdefault("backend_kind", "cli")   # constructed lazily, never called
    kwargs.setdefault("progress_mode", "off")
    kwargs.setdefault("status_mode", "off")
    return Loop(run_id=run_id, **kwargs)


def attach(loop: Loop, backend: FakeBackend) -> FakeBackend:
    loop.backend = backend
    loop.backend_seed = backend
    loop.backend_refine = backend
    return backend


def good(code: str = VALID_CODE, acceptance: float = 0.5) -> Validation:
    return Validation(True, "ok", code=code, acceptance=acceptance)


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


# ----------------------------------------------------------------------- tests
def test_budget_accounting() -> None:
    b = Budget(max_iterations=3, max_usd=2.0)
    r = llm.LLMResponse(text="x", backend="mock", input_tokens=100,
                        output_tokens=20, cache_read_tokens=5,
                        cache_write_tokens=3, cost_usd=0.25)
    b.add(r, prompt_chars=400)
    expect(b.calls == 1, f"calls={b.calls}")
    expect(b.billable_input == 108, f"billable={b.billable_input}")
    expect(abs(b.cost_usd - 0.25) < 1e-9, f"cost={b.cost_usd}")
    expect(b.authored_chars == 400, f"authored={b.authored_chars}")
    expect(abs(b.mean_call_cost - 0.25) < 1e-9, "mean cost")
    data = b.to_json()
    expect(data["llm_calls"] == 1 and data["authored_prompt_tokens_est"] == 100,
           str(data))


def test_budget_overrun_guard() -> None:
    b = Budget(max_iterations=5, max_usd=1.0)
    expect(not b.would_overrun(), "first call must always be allowed")
    b.add(llm.LLMResponse(text="", backend="m", cost_usd=0.4), 0)
    expect(not b.would_overrun(), "remaining 0.60 covers mean 0.40")
    b.add(llm.LLMResponse(text="", backend="m", cost_usd=0.4), 0)
    expect(b.would_overrun(), "remaining 0.20 cannot cover mean 0.40")
    b.max_usd = 0.5
    expect(b.exhausted and b.would_overrun(), "spend above cap is exhausted")


def test_configuration_validation() -> None:
    cases = [
        {"max_examples": 0},
        {"max_examples": 501},
        {"max_iterations": 0},
        {"max_iterations": MAX_ITERATIONS + 1},
        {"max_usd": 0},
        {"resume_from": -1},
        {"ensemble_candidates": 9},
        {"screening_examples": 0},
        {"cache_similarity": 1.5},
        {"progress_mode": "sometimes"},
        {"status_mode": "sometimes"},
    ]
    with loop_env():
        for kwargs in cases:
            try:
                make_loop(**kwargs)
            except ValueError:
                continue
            raise AssertionError(f"expected ValueError for {kwargs}")


def test_seed_prompt_renders_all_placeholders() -> None:
    with loop_env():
        lp = make_loop()
        prompt = lp._seed_prompt()
        expect("<grammar body/>" in prompt, "grammar body not substituted")
        for placeholder in ("{grammar_commit}", "{parser_g4}", "{lexer_g4}",
                            "{productions}"):
            expect(placeholder not in prompt,
                   f"placeholder {placeholder} left in seed prompt")
        expect("document" in prompt.lower(), "production list missing")


def test_refine_prompt_carries_measured_feedback() -> None:
    with loop_env():
        lp = make_loop()
        summary = make_summary(productions=2, diag=1)
        results = [{"dur_ms": 4.0, "len": 10, "outcome": "parsed_clean",
                    "structure": {"max_depth": 2}}]
        lp.union_diagnostics = {"old"}
        lp.union_productions = {"p0"}
        prompt = lp._refine_prompt(2, "SOURCE = 42\n", summary, results,
                                   directive_override="deepen nesting")
        expect("deepen nesting" in prompt, "directive not rendered")
        expect("SOURCE = 42" in prompt, "strategy source not rendered")
        expect("50.0%" in prompt or "0.5" in prompt, "acceptance not rendered")
        expect("document" in prompt.lower(), "partial summary not tolerated")


def test_call_records_transcript_and_budget() -> None:
    with loop_env():
        lp = make_loop()
        backend = attach(lp, FakeBackend([VALID_CODE]))
        r = lp._call("hello", "seed", iteration=0)
        expect(r.text == VALID_CODE, "response text")
        call = lp.out / "transcript" / "call-1"
        for name in ("system.md", "user.md", "meta.json", "response.json"):
            expect((call / name).exists(), f"{name} not recorded")
        meta = json.loads((call / "meta.json").read_text(encoding="utf-8"))
        rec = json.loads((call / "response.json").read_text(encoding="utf-8"))
        expect(meta == {"tag": "seed", "call": 1, "iteration": 0}, str(meta))
        expect(rec["tag"] == "seed" and rec["iteration"] == 0, str(rec))
        expect(rec["elapsed_s"] >= 0, "elapsed not recorded")
        expect(lp.budget.calls == 1 and len(backend.calls) == 1, "budget/calls")


def test_call_iteration_attribution() -> None:
    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "call-7"
        d.mkdir()
        response = d / "response.json"
        expect(loopmod.Loop._call_iteration(response, {"iteration": 3}) == 3,
               "explicit iteration field")
        expect(loopmod.Loop._call_iteration(response, {"tag": "seed"}) == 0,
               "seed tag")
        expect(loopmod.Loop._call_iteration(
            response, {"tag": "refine-repair1"}) is None, "unknown tag")
        (d / "user.md").write_text(
            "prefix\n## Current strategy (iteration 4)\n", encoding="utf-8")
        expect(loopmod.Loop._call_iteration(
            response, {"tag": "refine"}) == 4, "prompt fallback")


def test_grouped_calls_and_iteration_costs() -> None:
    with loop_env():
        lp = make_loop()
        backend = attach(lp, FakeBackend([VALID_CODE, VALID_CODE, VALID_CODE]))
        lp._call("seed", "seed", iteration=0)
        lp._call("repair", "seed-repair1", iteration=0)
        lp._call("refine", "refine", iteration=1)
        groups = lp._grouped_calls()
        expect([len(g) for g in groups] == [2, 1], str([len(g) for g in groups]))
        expect(lp._calls_per_iteration() == {0: 2, 1: 1},
               str(lp._calls_per_iteration()))
        costs = lp._iteration_costs()
        expect(abs(costs[0] - 0.02) < 1e-9 and abs(costs[1] - 0.03) < 1e-9,
               str(costs))
        expect(len(backend.calls) == 3, "unexpected call count")


def _write_recorded_call(run_dir: Path, n: int, *, cost: float = 0.5,
                         iteration: int = 0, tag: str = "seed") -> None:
    d = run_dir / "transcript" / f"call-{n}"
    d.mkdir(parents=True)
    (d / "system.md").write_text("sys", encoding="utf-8")
    (d / "user.md").write_text("user", encoding="utf-8")
    (d / "meta.json").write_text(json.dumps(
        {"tag": tag, "call": n, "iteration": iteration}), encoding="utf-8")
    (d / "response.json").write_text(json.dumps({
        "text": VALID_CODE, "backend": "replay", "model": "old",
        "input_tokens": 100, "output_tokens": 50, "cache_read_tokens": 0,
        "cache_write_tokens": 0, "cost_usd": cost, "elapsed_s": 1.0,
        "tag": tag, "iteration": iteration,
    }), encoding="utf-8")


def _write_iteration(run_dir: Path, n: int) -> None:
    d = run_dir / "iterations" / f"iter-{n}"
    d.mkdir(parents=True)
    (d / "strategy.py").write_text("SOURCE = 1\n", encoding="utf-8")
    summary = make_summary(strategy=f"gen_iter{n}")
    (d / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    _write_results(d, 4)


def test_resume_restores_budget_and_feedback() -> None:
    with loop_env() as (root, _):
        run_dir = root / "runs" / "resume"
        _write_recorded_call(run_dir, 1, cost=0.5)
        _write_iteration(run_dir, 0)
        lp = make_loop(run_id="resume", backend_kind="replay",
                       max_iterations=2, resume_from=1)
        expect(lp.budget.calls == 1, f"calls={lp.budget.calls}")
        expect(abs(lp.budget.cost_usd - 0.5) < 1e-9,
               f"cost={lp.budget.cost_usd}")
        expect(lp._call_seq == 1, f"call numbering: {lp._call_seq}")
        expect(len(lp._prior_iterations()) == 1, "prior iteration table")
        expect(len(lp.union_diagnostics) == 3 and len(lp.union_productions) == 5,
               "feedback unions not restored")


def test_resume_requires_previous_artifacts() -> None:
    with loop_env():
        try:
            make_loop(run_id="resume-missing", backend_kind="replay",
                      max_iterations=2, resume_from=1)
        except ValueError as exc:
            text = str(exc)
            expect("strategy.py" in text and "summary.json" in text
                   and "results.jsonl" in text,
                   f"missing names not all reported: {text}")
            return
        raise AssertionError("resume without artifacts must fail before spending")


def test_obtain_single_accepts_first_candidate() -> None:
    with loop_env() as (_, strategies):
        lp = make_loop()
        backend = attach(lp, FakeBackend([VALID_CODE]))
        dest = strategies / "gen_iter0.py"
        with patch.object(loopmod.validate, "validate", return_value=good()):
            got = lp._obtain_single(0, "prompt", "seed", "gen_iter0", dest,
                                    backend, MAX_REPAIRS)
        expect(got == ("gen_iter0", VALID_CODE), str(got))
        expect(lp._last_gate_failures == 0, "no gate failures expected")
        expect(len(backend.calls) == 1, "one call expected")


def test_obtain_single_repairs_a_rejected_candidate() -> None:
    with loop_env() as (_, strategies):
        lp = make_loop()
        backend = attach(lp, FakeBackend([VALID_CODE, "corrected"]))
        dest = strategies / "gen_iter0.py"
        side_effect = [
            Validation(False, "syntax", error="bad indent", code="x"),
            good("corrected"),
        ]
        with patch.object(loopmod.validate, "validate",
                          side_effect=side_effect):
            got = lp._obtain_single(0, "prompt", "seed", "gen_iter0", dest,
                                    backend, MAX_REPAIRS)
        expect(got == ("gen_iter0", "corrected"), str(got))
        expect(lp._last_gate_failures == 1, str(lp._last_gate_failures))
        tags = [json.loads((lp.transcript / f"call-{i}" / "meta.json")
                           .read_text(encoding="utf-8"))["tag"] for i in (1, 2)]
        expect(tags == ["seed", "seed-repair1"], str(tags))
        second_prompt = backend.calls[1]["user"]
        expect("previous attempt was rejected" in second_prompt,
               "repair prompt not fed back")


def test_obtain_single_resends_truncated_transport() -> None:
    with loop_env() as (_, strategies):
        lp = make_loop()
        backend = attach(lp, FakeBackend([VALID_CODE, VALID_CODE]))
        dest = strategies / "gen_iter0.py"
        side_effect = [
            Validation(False, "truncated", code="fragment"),
            good(),
        ]
        with patch.object(loopmod.validate, "validate",
                          side_effect=side_effect):
            got = lp._obtain_single(0, "prompt", "seed", "gen_iter0", dest,
                                    backend, MAX_REPAIRS)
        expect(got is not None, "resend should recover")
        expect(lp._last_gate_failures == 0,
               "a transport truncation is not a gate failure")
        tags = [json.loads((lp.transcript / f"call-{i}" / "meta.json")
                           .read_text(encoding="utf-8"))["tag"] for i in (1, 2)]
        expect(tags == ["seed", "seed"], f"truncation must resend, not repair: {tags}")


def test_obtain_single_stops_when_budget_cannot_pay() -> None:
    with loop_env() as (_, strategies):
        lp = make_loop()
        backend = attach(lp, FakeBackend([VALID_CODE]))
        lp.budget.cost_usd = lp.max_usd
        got = lp._obtain_single(0, "prompt", "seed", "gen_iter0",
                                strategies / "gen_iter0.py", backend, MAX_REPAIRS)
        expect(got is None, "must not spend past the cap")
        expect(not backend.calls, "backend was called despite exhausted budget")


def test_campaign_repair_retries_on_campaign_failure() -> None:
    with loop_env():
        FakeCampaign.reset()
        FakeCampaign.fail_times = 1
        lp = make_loop()
        lp.max_examples = 10
        attach(lp, FakeBackend([VALID_CODE, VALID_CODE]))
        with patch.object(loopmod, "Campaign", FakeCampaign), \
                patch.object(loopmod.validate, "validate", return_value=good()):
            got = lp._repair_campaign(0, "prompt", "seed", "gen_iter0",
                                      RuntimeError("boom"), max_repairs=2,
                                      examples=10)
        expect(got is not None, "second campaign attempt should succeed")
        expect(len(FakeCampaign.instances) == 2,
               f"campaign attempts={len(FakeCampaign.instances)}")
        expect(got[2]["acceptance_rate"] == 0.5, "repaired summary")


def test_run_end_to_end_writes_artifacts() -> None:
    with loop_env():
        FakeCampaign.reset()
        lp = make_loop(max_iterations=2, max_examples=20)
        backend = attach(lp, FakeBackend([VALID_CODE, VALID_CODE]))
        with patch.object(loopmod, "Campaign", FakeCampaign), \
                patch.object(loopmod.validate, "validate", return_value=good()):
            final = lp.run()
        expect(len(final["iterations"]) == 2, str(final["iterations"]))
        expect(final["stopped_early"] is None, str(final["stopped_early"]))
        expect(final["budget"]["llm_calls"] == 2, str(final["budget"]))
        expect((lp.out / "loop_summary.json").exists(), "loop summary")
        expect((lp.out / "ITERATION_LOG.md").exists(), "iteration log")
        for i in (0, 1):
            idir = lp.out / "iterations" / f"iter-{i}"
            for name in ("strategy.py", "summary.json", "results.jsonl"):
                expect((idir / name).exists(), f"iter-{i}/{name} missing")
        log = (lp.out / "ITERATION_LOG.md").read_text(encoding="utf-8")
        expect("| 0 |" in log and "| 1 |" in log, "iteration rows missing")
        expect(len(backend.calls) == 2, "seed + one refine call expected")
        expect(final["target"] == "mxml", str(final.get("target")))
        expect(all(call.kwargs.get("progress") == "off"
                   for call in FakeCampaign.instances),
               "loop must pass its progress mode to campaigns")


def test_run_forwards_performance_settings() -> None:
    with loop_env():
        FakeCampaign.reset()
        lp = make_loop(max_iterations=1, max_examples=10)
        lp.use_result_cache = True
        lp.max_corpus_entries = 50
        attach(lp, FakeBackend([VALID_CODE]))
        with patch.object(loopmod, "Campaign", FakeCampaign), \
                patch.object(loopmod.validate, "validate", return_value=good()):
            lp.run()
        expect(len(FakeCampaign.instances) == 1, "expected 1 campaign")
        call = FakeCampaign.instances[0]
        expect(call.kwargs.get("use_result_cache") is True, "use_result_cache forwarded")
        expect(call.kwargs.get("max_corpus_entries") == 50, "max_corpus_entries forwarded")


def test_run_stops_on_exhausted_budget_without_calling_llm() -> None:
    with loop_env():
        FakeCampaign.reset()
        lp = make_loop(max_iterations=2)
        backend = attach(lp, FakeBackend([VALID_CODE]))
        lp.budget.cost_usd = 10.0
        lp.budget.max_usd = 0.5
        with patch.object(loopmod, "Campaign", FakeCampaign), \
                patch.object(loopmod.validate, "validate", return_value=good()):
            final = lp.run()
        expect(final["stopped_early"] == "budget exhausted",
               str(final["stopped_early"]))
        expect(not final["iterations"], "no iteration should have run")
        expect(not backend.calls, "LLM was called with an exhausted budget")


def test_run_preserves_completed_work_when_backend_fails() -> None:
    with loop_env():
        FakeCampaign.reset()
        lp = make_loop(max_iterations=2)
        attach(lp, FakeBackend(fail_times=1))
        with patch.object(loopmod, "Campaign", FakeCampaign), \
                patch.object(loopmod.validate, "validate", return_value=good()):
            final = lp.run()
        expect(final["stopped_early"] is not None
               and "LLMError" in final["stopped_early"],
               str(final["stopped_early"]))
        expect((lp.out / "loop_summary.json").exists(),
               "summary must still be written after a backend failure")
        expect(lp.budget.calls == 0,
               "a failed call must not be charged as a successful call")
        failed = lp.out / "transcript" / "call-1"
        expect(failed.exists() and not (failed / "response.json").exists(),
               "failed call must leave a prompt-only record")


def test_run_ensemble_screens_and_writes_winner() -> None:
    with loop_env():
        FakeCampaign.reset()
        FakeCampaign.production_hits = [22, 2]
        lp = make_loop(max_iterations=1, ensemble_candidates=2,
                       screening_examples=10)
        b1 = FakeBackend([VALID_CODE])
        b2 = FakeBackend([VALID_CODE])
        lp.ensemble_backends = [b1, b2]
        with patch.object(loopmod, "Campaign", FakeCampaign), \
                patch.object(loopmod.validate, "validate", return_value=good()):
            got = lp._ensemble_strategy(0, "prompt", "seed", MAX_REPAIRS)
        expect(got is not None, "ensemble should pick a winner")
        expect(lp._last_source_kind == "ensemble", lp._last_source_kind)
        report = lp.out / "iterations" / "iter-0" / "ensemble.json"
        expect(report.exists(), "ensemble report missing")
        data = json.loads(report.read_text(encoding="utf-8"))
        expect(data["winner"]["name"] == "gen_iter0_c0", str(data.get("winner")))
        expect((loopmod.STRATEGY_DIR / "gen_iter0.py").exists(),
               "winner not promoted to the iteration module")


def test_strategy_cache_reuse_records_provenance() -> None:
    with loop_env() as (root, _):
        from agent.strategy_cache import StrategyCache
        from fuzzer.targets import get_target
        cache_dir = root / "cache"
        cache = StrategyCache(cache_dir, min_similarity=0.0)
        cache.store("CACHED = 1\n", get_target("mxml"), make_summary(),
                    "old-run", 0)
        lp = make_loop(use_strategy_cache=True, cache_dir=str(cache_dir),
                       cache_similarity=0.0)
        with patch.object(loopmod.validate, "validate",
                          return_value=good("CACHED = 1\n")):
            got = lp._try_strategy_cache(0)
        expect(got == ("gen_iter0", "CACHED = 1\n"), str(got))
        expect(lp._last_source_kind == "cache", lp._last_source_kind)
        expect((lp.out / "iterations" / "iter-0" / "cache_hit.json").exists(),
               "cache provenance not recorded")


def test_debug_mode_writes_jsonl_events() -> None:
    with loop_env():
        FakeCampaign.reset()
        lp = make_loop(max_iterations=1, debug=True)
        attach(lp, FakeBackend([VALID_CODE]))
        with patch.object(loopmod, "Campaign", FakeCampaign), \
                patch.object(loopmod.validate, "validate", return_value=good()):
            lp.run()
        log = lp.out / "debug.jsonl"
        expect(log.exists(), "debug.jsonl missing")
        events = [json.loads(line) for line in
                  log.read_text(encoding="utf-8").splitlines() if line.strip()]
        names = {e["event"] for e in events}
        for expected in ("run_started", "iteration_started", "llm_call",
                         "gate_passed", "iteration_finished", "run_finished"):
            expect(expected in names, f"missing event {expected}: {sorted(names)}")


def test_loop_arg_parser() -> None:
    from agent.loop import _build_arg_parser
    parser = _build_arg_parser()
    args = parser.parse_args(["--run-id", "test-parse", "-n", "100", "-i", "3"])
    expect(args.run_id == "test-parse", args.run_id)
    expect(args.max_examples == 100, str(args.max_examples))
    expect(args.iterations == 3, str(args.iterations))
    expect(args.target == "mxml", args.target)



# --------------------------------------------------------------- standalone
def _run_all() -> int:
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    failed = []
    for name, fn in tests:
        try:
            fn()
        except Exception:
            failed.append(name)
            print(f"FAIL {name}")
            traceback.print_exc()
        else:
            print(f"ok   {name}")
    print(f"\n{len(tests) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
