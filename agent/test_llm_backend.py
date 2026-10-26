"""Exhaustive tests for LLM Backend enhancements:
  1. Streaming response handling & StreamAccumulator
  2. Circuit breaker state machine & fast-fail protection
  3. Multi-tier FallbackBackend failover & error logging
  4. PromptVersion loading, rendering, placeholder validation, and diffing
  5. PromptManager discovery, variant creation, and registration
  6. PromptABTester routing, outcome tracking, Welch's t-test / Mann-Whitney U / A12 effect size,
     Markdown reporting, and JSON persistence.
"""
from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock

from agent.llm import (
    AllBackendsFailedError,
    CircuitBreaker,
    CircuitOpenError,
    CircuitState,
    ClaudeCLIBackend,
    FallbackBackend,
    LLMError,
    LLMResponse,
    OpenAICompatBackend,
    ReplayBackend,
    StreamAccumulator,
    _chunk_text,
    make_backend,
)
from agent.prompt_manager import PromptABTester, PromptManager, PromptVersion


# -----------------------------------------------------------------------------
# 1. Streaming & Response Handling Tests
# -----------------------------------------------------------------------------

def test_llm_response_structure():
    resp = LLMResponse(
        text="def strategy(): pass",
        backend="test_backend",
        model="test-model",
        input_tokens=100,
        output_tokens=50,
        cache_read_tokens=20,
        cache_write_tokens=10,
        cost_usd=0.0025,
        streaming=True,
        duration_s=1.25,
        time_to_first_token_s=0.15,
        tokens_per_second=40.0,
        fallback_used=True,
        fallback_from="primary_backend",
    )
    assert resp.billable_input == 130
    d = resp.to_json()
    assert d["backend"] == "test_backend"
    assert d["model"] == "test-model"
    assert d["billable_input"] == 130
    assert d["streaming"] is True
    assert d["duration_s"] == 1.25
    assert d["time_to_first_token_s"] == 0.15
    assert d["tokens_per_second"] == 40.0
    assert d["fallback_used"] is True
    assert d["fallback_from"] == "primary_backend"


def test_stream_accumulator():
    chunks_received = []
    acc = StreamAccumulator(on_chunk=lambda c: chunks_received.append(c))

    assert acc.time_to_first_token_s is None
    assert acc.text == ""

    acc.add_chunk("hello ")
    ttft = acc.time_to_first_token_s
    assert ttft is not None
    assert ttft >= 0.0

    acc.add_chunk("world!")
    assert acc.text == "hello world!"
    assert chunks_received == ["hello ", "world!"]
    assert acc.duration_s >= 0.0
    assert acc.tokens_per_second >= 0.0


def test_chunk_text_utility():
    text = "abcdefghijklmnopqrstuvwxyz"
    chunks = list(_chunk_text(text, chunk_size=10))
    assert chunks == ["abcdefghij", "klmnopqrst", "uvwxyz"]
    assert "".join(chunks) == text


def test_replay_backend_streaming():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        call_dir = p / "call-1"
        call_dir.mkdir(parents=True)
        resp_data = {
            "text": "class CustomFuzzer:\n    pass\n",
            "model": "replay-model",
            "input_tokens": 120,
            "output_tokens": 30,
            "cache_read_tokens": 0,
            "cache_write_tokens": 0,
            "cost_usd": 0.001,
        }
        (call_dir / "response.json").write_text(json.dumps(resp_data), encoding="utf-8")

        rb = ReplayBackend(transcript_dir=p, start=0)

        streamed_chunks = []
        resp = rb.complete_stream(
            system="system prompt",
            user="user prompt",
            on_chunk=lambda c: streamed_chunks.append(c),
            chunk_size=10,
        )

        assert resp.streaming is True
        assert resp.text == resp_data["text"]
        assert "".join(streamed_chunks) == resp_data["text"]
        assert resp.time_to_first_token_s is not None
        assert resp.duration_s >= 0.0


def test_mock_openai_streaming():
    backend = OpenAICompatBackend.__new__(OpenAICompatBackend)
    backend.name = "openai"
    backend.model = "gpt-5"
    backend.max_tokens = 1000

    # Build mock streaming response chunks
    mock_chunk1 = MagicMock()
    mock_chunk1.model = "gpt-5-turbo"
    mock_chunk1.usage = None
    choice1 = MagicMock()
    choice1.finish_reason = None
    choice1.delta.content = "import "
    mock_chunk1.choices = [choice1]

    mock_chunk2 = MagicMock()
    mock_chunk2.model = "gpt-5-turbo"
    mock_chunk2.usage = None
    choice2 = MagicMock()
    choice2.finish_reason = None
    choice2.delta.content = "hypothesis\n"
    mock_chunk2.choices = [choice2]

    mock_chunk3 = MagicMock()
    mock_chunk3.model = "gpt-5-turbo"
    usage = MagicMock()
    usage.prompt_tokens = 85
    usage.completion_tokens = 22
    usage.prompt_tokens_details = None
    mock_chunk3.usage = usage
    choice3 = MagicMock()
    choice3.finish_reason = "stop"
    choice3.delta.content = None
    mock_chunk3.choices = [choice3]

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = [mock_chunk1, mock_chunk2, mock_chunk3]
    backend._client = mock_client

    received = []
    resp = backend.complete_stream(
        system="system",
        user="user",
        on_chunk=lambda c: received.append(c),
    )

    assert resp.streaming is True
    assert resp.text == "import hypothesis\n"
    assert received == ["import ", "hypothesis\n"]
    assert resp.input_tokens == 85
    assert resp.output_tokens == 22
    assert resp.model == "gpt-5-turbo"
    assert resp.raw["finish_reason"] == "stop"


# -----------------------------------------------------------------------------
# 2. Circuit Breaker Tests
# -----------------------------------------------------------------------------

def test_circuit_breaker_closed_to_open_to_half_open_to_closed():
    cb = CircuitBreaker(
        name="test_cb",
        failure_threshold=2,
        recovery_timeout_s=0.05,
        half_open_successes=2,
    )
    assert cb.state == CircuitState.CLOSED
    assert cb.allow_request() is True

    # 1st failure: still closed
    cb.record_failure("timeout 1")
    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 1
    assert cb.allow_request() is True

    # 2nd failure: trips open
    cb.record_failure("timeout 2")
    assert cb.state == CircuitState.OPEN
    assert cb.failure_count == 2
    assert cb.allow_request() is False

    # Wait for cooldown period
    time.sleep(0.06)

    # Cooldown elapsed: transitions to HALF_OPEN
    assert cb.allow_request() is True
    assert cb.state == CircuitState.HALF_OPEN

    # In HALF_OPEN: 1st success
    cb.record_success()
    assert cb.state == CircuitState.HALF_OPEN

    # In HALF_OPEN: 2nd success -> closes circuit!
    cb.record_success()
    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0


def test_circuit_breaker_half_open_reopens_on_failure():
    cb = CircuitBreaker(
        name="test_cb2",
        failure_threshold=1,
        recovery_timeout_s=0.02,
        half_open_successes=1,
    )
    cb.record_failure("failure 1")
    assert cb.state == CircuitState.OPEN
    time.sleep(0.03)

    assert cb.allow_request() is True
    assert cb.state == CircuitState.HALF_OPEN

    # Fail during probe
    cb.record_failure("probe failed")
    assert cb.state == CircuitState.OPEN


def test_circuit_breaker_reset():
    cb = CircuitBreaker(name="test_reset", failure_threshold=1)
    cb.record_failure("err")
    assert cb.state == CircuitState.OPEN
    cb.reset()
    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0


# -----------------------------------------------------------------------------
# 3. Fallback Backend Tests
# -----------------------------------------------------------------------------

class MockSuccessBackend:
    def __init__(self, name="mock_success", model="model-a", text="success result"):
        self.name = name
        self.model = model
        self.text = text
        self.call_count = 0

    def complete(self, system, user, stream=False, on_chunk=None):
        self.call_count += 1
        return LLMResponse(
            text=self.text,
            backend=self.name,
            model=self.model,
            input_tokens=10,
            output_tokens=5,
        )

    def complete_stream(self, system, user, on_chunk=None):
        self.call_count += 1
        if on_chunk:
            on_chunk(self.text)
        return LLMResponse(
            text=self.text,
            backend=self.name,
            model=self.model,
            streaming=True,
            input_tokens=10,
            output_tokens=5,
        )


class MockFailingBackend:
    def __init__(self, name="mock_failing", model="model-fail", error_msg="Simulated failure"):
        self.name = name
        self.model = model
        self.error_msg = error_msg
        self.call_count = 0

    def complete(self, system, user, stream=False, on_chunk=None):
        self.call_count += 1
        raise LLMError(self.error_msg)

    def complete_stream(self, system, user, on_chunk=None):
        self.call_count += 1
        raise LLMError(self.error_msg)


def test_fallback_primary_success():
    primary = MockSuccessBackend(name="primary", model="gpt-5", text="primary ok")
    fallback = MockSuccessBackend(name="fallback", model="sonnet", text="fallback ok")

    fb = FallbackBackend(primary=primary, fallbacks=[fallback])
    resp = fb.complete("system", "user")

    assert resp.text == "primary ok"
    assert resp.fallback_used is False
    assert resp.backend == "primary"
    assert primary.call_count == 1
    assert fallback.call_count == 0


def test_fallback_failover_on_primary_error():
    primary = MockFailingBackend(name="primary", model="gpt-5", error_msg="429 RateLimitExceeded")
    fallback = MockSuccessBackend(name="secondary", model="sonnet", text="secondary ok")

    fallback_events = []
    fb = FallbackBackend(
        primary=primary,
        fallbacks=[fallback],
        on_fallback=lambda b_name, exc, next_b: fallback_events.append((b_name, str(exc), next_b)),
    )

    resp = fb.complete("system", "user")

    assert resp.text == "secondary ok"
    assert resp.fallback_used is True
    assert resp.fallback_from == "primary"
    assert resp.backend == "secondary"
    assert len(fallback_events) == 1
    assert fallback_events[0][0] == "primary"
    assert "429" in fallback_events[0][1]
    assert fallback_events[0][2] == "secondary"
    assert primary.call_count == 1
    assert fallback.call_count == 1


def test_fallback_circuit_breaker_skips_failed_backend():
    primary = MockFailingBackend(name="primary", error_msg="Outage")
    fallback = MockSuccessBackend(name="secondary", text="fallback response")

    fb = FallbackBackend(
        primary=primary,
        fallbacks=[fallback],
        circuit_breaker=True,
        failure_threshold=1,
        recovery_timeout_s=10.0,
    )

    # 1st call fails primary, succeeds on fallback, trips primary breaker
    resp1 = fb.complete("s", "u")
    assert resp1.fallback_used is True
    assert primary.call_count == 1

    # 2nd call: primary circuit breaker is OPEN, so it is skipped immediately!
    resp2 = fb.complete("s", "u")
    assert resp2.fallback_used is True
    # primary was not called a second time
    assert primary.call_count == 1
    assert fallback.call_count == 2


def test_fallback_all_backends_failed():
    primary = MockFailingBackend(name="p1", error_msg="Error 1")
    fb1 = MockFailingBackend(name="p2", error_msg="Error 2")
    fb = FallbackBackend(primary=primary, fallbacks=[fb1])

    try:
        fb.complete("s", "u")
        assert False, "Should have raised AllBackendsFailedError"
    except AllBackendsFailedError as exc:
        assert len(exc.errors) == 2


def test_make_backend_with_fallback_chain():
    primary = MockFailingBackend(name="mock_p")
    sec = MockSuccessBackend(name="mock_s")

    backend = make_backend("cli", fallbacks=[sec])
    assert isinstance(backend, FallbackBackend)
    assert len(backend.fallbacks) == 1


# -----------------------------------------------------------------------------
# 4. Prompt Versioning & Management Tests
# -----------------------------------------------------------------------------

def test_prompt_manager_discovery():
    mgr = PromptManager()
    versions = mgr.list_versions()
    assert "v1" in versions or "default" in versions
    assert "v2" in versions
    assert "v3" in versions
    assert "v4" in versions
    assert "v5" in versions


def test_prompt_version_rendering():
    mgr = PromptManager()
    v2 = mgr.get_version("v2")

    # Render system
    sys_txt = v2.render_system()
    assert isinstance(sys_txt, str)
    assert len(sys_txt) > 0

    # Render seed
    seed_txt = v2.render_seed(
        grammar_commit="abc1234",
        parser_g4="parser grammar",
        lexer_g4="lexer grammar",
        productions=["p1", "p2", "p3", "p4", "p5"],
    )
    assert "abc1234" in seed_txt
    assert "parser grammar" in seed_txt
    assert "lexer grammar" in seed_txt
    assert "p1" in seed_txt

    # Render refine
    refine_txt = v2.render_refine(
        it=2,
        source="class Strategy:\n    pass\n",
        summary={"examples": 100, "acceptance_rate": 0.52},
        directive="deepen",
    )
    assert "deepen" in refine_txt
    assert "52.0%" in refine_txt
    assert "class Strategy:" in refine_txt


def test_prompt_version_validation():
    v_good = PromptVersion(
        name="test_good",
        system_template="system prompt",
        seed_template="seed {grammar_commit} {parser_g4} {lexer_g4} {productions}",
        refine_template="refine {source} {acceptance_rate}",
    )
    assert v_good.validate() == []

    v_bad = PromptVersion(name="test_bad")
    issues = v_bad.validate()
    assert any("system_template is empty" in i for i in issues)
    assert any("seed_template is empty" in i for i in issues)
    assert any("refine_template is empty" in i for i in issues)


def test_prompt_version_diff():
    mgr = PromptManager()
    diffs = mgr.compare_versions("v2", "v5")
    assert "refine" in diffs
    assert len(diffs["refine"]) > 0


def test_prompt_manager_create_variant():
    mgr = PromptManager()
    variant = mgr.create_variant(
        base_version="v2",
        new_name="v2_special",
        system_override="Custom system prompt for special fuzzer",
        directives_override=["explore_boundary", "havoc"],
    )
    assert variant.name == "v2_special"
    assert variant.system_template == "Custom system prompt for special fuzzer"
    assert variant.directives == ["explore_boundary", "havoc"]
    assert "v2_special" in mgr.list_versions()


# -----------------------------------------------------------------------------
# 5. Prompt A/B Testing Tests
# -----------------------------------------------------------------------------

def test_prompt_ab_tester_routing():
    mgr = PromptManager()
    ab = PromptABTester(variants=["v4", "v5"], manager=mgr, routing="round_robin")

    v_a = ab.next_variant()
    v_b = ab.next_variant()
    v_c = ab.next_variant()

    assert v_a.name == "v4"
    assert v_b.name == "v5"
    assert v_c.name == "v4"

    # Seed hash routing (deterministic)
    ab_hash = PromptABTester(variants=["v4", "v5"], manager=mgr, routing="seed_hash")
    v1 = ab_hash.next_variant(iteration=1, seed=42)
    v2 = ab_hash.next_variant(iteration=1, seed=42)
    assert v1.name == v2.name


def test_prompt_ab_tester_observation_and_evaluation():
    mgr = PromptManager()
    ab = PromptABTester(variants=["v4", "v5"], manager=mgr)

    # Variant v4 trials (lower coverage)
    for i in range(12):
        ab.record_trial(
            variant="v4",
            trial_id=f"v4_{i}",
            metrics={
                "syntax_valid": True,
                "gate_passed": True,
                "productions_hit": 14 + (i % 3),
                "acceptance_rate": 0.40 + (i % 2) * 0.05,
                "tokens_used": 1200,
                "crashes": 0,
            },
        )

    # Variant v5 trials (significantly higher coverage)
    for i in range(12):
        ab.record_trial(
            variant="v5",
            trial_id=f"v5_{i}",
            metrics={
                "syntax_valid": True,
                "gate_passed": True,
                "productions_hit": 24 + (i % 3),
                "acceptance_rate": 0.65 + (i % 2) * 0.05,
                "tokens_used": 1400,
                "crashes": 1 if i == 5 else 0,
            },
        )

    # Evaluate productions_hit
    eval_res = ab.evaluate(variant_a="v4", variant_b="v5", metric="productions_hit")

    assert eval_res["variant_a"] == "v4"
    assert eval_res["variant_b"] == "v5"
    assert eval_res["winner"] == "v5"
    assert eval_res["statistically_significant"] is True
    assert eval_res["p_value_welch"] < 0.001
    assert eval_res["effect_size_a12"] == 1.0  # complete stochastic dominance
    assert eval_res["effect_magnitude"] == "large"
    assert eval_res["diff_pct"] > 50.0

    # Summary
    summ = ab.summary()
    assert summ["v4"]["trials"] == 12
    assert summ["v5"]["trials"] == 12
    assert summ["v5"]["total_crashes"] == 1
    assert summ["v5"]["productions_hit"]["mean"] > summ["v4"]["productions_hit"]["mean"]

    # Markdown Report
    report = ab.render_report(baseline="v4")
    assert "# Prompt A/B Testing Report" in report
    assert "| **v4** |" in report
    assert "| **v5** |" in report
    assert "YES" in report
    assert "**v5**" in report


def test_prompt_ab_tester_save_load():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "experiment.json"
        mgr = PromptManager()
        ab = PromptABTester(variants=["v4", "v5"], manager=mgr, name="test_exp")
        ab.record_trial("v4", 0, {"productions_hit": 18, "acceptance_rate": 0.5})
        ab.record_trial("v5", 0, {"productions_hit": 25, "acceptance_rate": 0.7})
        ab.save(p)

        loaded = PromptABTester.load(p, manager=mgr)
        assert loaded.name == "test_exp"
        assert len(loaded.get_trials("v4")) == 1
        assert len(loaded.get_trials("v5")) == 1
        assert loaded.get_trials("v5")[0]["productions_hit"] == 25


def run_all_tests():
    tests = [
        test_llm_response_structure,
        test_stream_accumulator,
        test_chunk_text_utility,
        test_replay_backend_streaming,
        test_mock_openai_streaming,
        test_circuit_breaker_closed_to_open_to_half_open_to_closed,
        test_circuit_breaker_half_open_reopens_on_failure,
        test_circuit_breaker_reset,
        test_fallback_primary_success,
        test_fallback_failover_on_primary_error,
        test_fallback_circuit_breaker_skips_failed_backend,
        test_fallback_all_backends_failed,
        test_make_backend_with_fallback_chain,
        test_prompt_manager_discovery,
        test_prompt_version_rendering,
        test_prompt_version_validation,
        test_prompt_version_diff,
        test_prompt_manager_create_variant,
        test_prompt_ab_tester_routing,
        test_prompt_ab_tester_observation_and_evaluation,
        test_prompt_ab_tester_save_load,
    ]
    passed = 0
    failed = []
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            import traceback
            failed.append((t.__name__, str(e), traceback.format_exc()))

    print(f"\n[test_llm_backend] {passed}/{len(tests)} tests passed")
    if failed:
        for name, err, tb in failed:
            print(f"FAILED: {name}: {err}\n{tb}")
        raise AssertionError(f"{len(failed)} tests failed")


if __name__ == "__main__":
    run_all_tests()
