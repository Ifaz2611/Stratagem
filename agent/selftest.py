"""Self-checks for the agent enhancements.

The five features are opt-in and manipulate run artifacts, so their failure
modes are quiet: a cached strategy from the wrong target, a vote that ranks a
crashing candidate last, a tuner that shrinks the example budget after a win.
These checks exercise the decision logic without an LLM, harness or network.

Run:  .venv/bin/python -m agent.selftest
"""
from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from typing import Any

from agent.ensemble import Candidate, vote_candidates
from agent.fewshot import FewShotLibrary
from agent.harness_gen import (HarnessSpec, extract_harness_code,
                               validate_harness_code)
from agent.scoring import score_summary
from agent.strategy_cache import StrategyCache, TargetProfile
from agent.tuning import HyperparameterTuner

_passed = 0
_failed: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    global _passed
    if cond:
        _passed += 1
    else:
        _failed.append(f"{name}{(': ' + detail) if detail else ''}")


def _summary(prod: int = 5, total: int = 27, diag: int = 2, acc: float = 0.5, crashes: int = 0,
             depth: int = 3, examples: int = 50, seconds: float = 0.5) -> dict[str, Any]:
    return {
        "acceptance_rate": acc,
        "distinct_diagnostic_templates": diag,
        "crash_count": crashes,
        "crash_groups": {f"g{i}": {"count": 1} for i in range(crashes)},
        "examples": examples,
        "wall_clock_s": seconds,
        "outcomes": {"parsed_clean": int(examples * acc)},
        "structure": {
            "productions_hit": prod,
            "productions_total": total,
            "max_depth_seen": depth,
            "hit": {f"p{i}": 1 for i in range(prod)},
            "missing": [],
        },
    }


# --------------------------------------------------------------------- scoring
def test_scoring() -> None:
    clean = _summary(crashes=0, prod=27, diag=40, acc=0.5)
    crash = _summary(crashes=1, prod=1, diag=1, acc=0.05)
    check("score/crash dominates coverage", score_summary(crash) > score_summary(clean),
          f"{score_summary(crash):.1f} vs {score_summary(clean):.1f}")
    check("score/acceptance band preferred",
          score_summary(_summary(acc=0.55)) > score_summary(_summary(acc=0.01)))
    check("score/partial summary tolerated", score_summary({}) == 0.0)


# -------------------------------------------------------------------- ensemble
def test_ensemble() -> None:
    candidates = [
        Candidate("clean", "m1", source="a", summary=_summary(prod=27, diag=30)),
        Candidate("crash", "m2", source="b", summary=_summary(prod=2, diag=2, crashes=1)),
        Candidate("broken", "m3", error="gate failed"),
    ]
    result = vote_candidates(candidates)
    check("ensemble/crash wins", result.winner is not None and result.winner.name == "crash",
          str([(c.name, c.votes) for c in result.ranked]))
    check("ensemble/broken excluded", result.ranked[0].name != "broken")
    check("ensemble/all ineligible", vote_candidates([candidates[2]]).winner is None)
    check("ensemble/votes recorded", result.votes.get("crash", 0) > 0)
    check("ensemble/report serialisable",
          json.dumps(result.to_json()).startswith("{"))


# ---------------------------------------------------------------------- tuning
def test_tuning() -> None:
    tuner = HyperparameterTuner(max_examples=500, directives=["a", "b"],
                                state_path=None)
    first = tuner.decide(0)
    check("tune/starts at cap", first.examples == 500 and first.directive is None,
          str(first))
    tuner.observe(0, 500, 20, 8, 1)
    check("tune/ema set", tuner.yield_ema > 0)
    tuner.observe(1, 500, 0, 0, 0)
    check("tune/shrinks after stall", tuner.examples < 500, str(tuner.examples))
    tuner.observe(2, tuner.examples, 30, 20, 2)
    check("tune/grows after win", tuner.examples > 64, str(tuner.examples))
    check("tune/directive explores untried", tuner.decide(3).directive == "a")
    tuner.observe(3, tuner.examples, 0, 0, 0, gate_failures=1)
    check("tune/repairs rise after gate failure", tuner.repairs >= 2, str(tuner.repairs))

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "tuning.json"
        t = HyperparameterTuner(max_examples=500, directives=["x"], state_path=p)
        t.observe(0, 500, 1, 0, 0)
        loaded = HyperparameterTuner.load(p, max_examples=500, directives=["x"])
        check("tune/state round-trip", loaded.history and loaded.examples == t.examples,
              f"{loaded.examples} vs {t.examples}")


# ----------------------------------------------------------------- cache
def test_cache() -> None:
    from fuzzer.targets import get_target
    mxml = TargetProfile.from_target(get_target("mxml"))
    expat = TargetProfile.from_target(get_target("expat"))
    jsonp = TargetProfile.from_target(get_target("json"))
    check("cache/xml neighbours similar", mxml.similarity(expat) >= 0.70,
          str(mxml.similarity(expat)))
    check("cache/xml vs json distinct", mxml.similarity(jsonp) < 0.5,
          str(mxml.similarity(jsonp)))

    with tempfile.TemporaryDirectory() as td:
        cache = StrategyCache(td, min_similarity=0.70)
        cache.store("SOURCE = 1\n", get_target("mxml"), _summary(), "run-a", 0)
        hit = cache.best(get_target("expat"))
        check("cache/finds neighbour", hit is not None and hit.entry.target.name == "mxml",
              str(hit))
        check("cache/rejects unrelated", cache.best(get_target("json")) is None)
        check("cache/stats", cache.stats()["entries"] == 1)
        cache.store("SOURCE = 1\n", get_target("mxml"), _summary(), "run-a", 0)
        check("cache/deduplicates same source+target", cache.stats()["entries"] == 1)


# -------------------------------------------------------------------- few-shot
def _write_run(root: Path, run_id: str, target: str, summary: dict,
               source: str, iteration: int = 0) -> None:
    d = root / run_id / "iterations" / f"iter-{iteration}"
    d.mkdir(parents=True, exist_ok=True)
    (d / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    (d / "strategy.py").write_text(source, encoding="utf-8")


def test_fewshot() -> None:
    from fuzzer.targets import get_target
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        good = _summary(prod=22, diag=12, crashes=1)
        good.update({"target": "mxml", "target_category": "xml"})
        _write_run(root, "old-xml", "mxml", good, "GOOD_XML_STRATEGY = 1\n")
        noisy = _summary(prod=2, diag=1)
        noisy.update({"target": "json", "target_category": "json"})
        _write_run(root, "old-json", "json", noisy, "JSON_STRATEGY = 1\n")
        current = _summary(prod=27, diag=50)
        current.update({"target": "mxml", "target_category": "xml"})
        _write_run(root, "current", "mxml", current, "CURRENT_STRATEGY = 1\n")

        lib = FewShotLibrary(root, k=3, budget_chars=5000, min_similarity=0.55)
        picked = lib.examples(get_target("expat"), exclude_run="current")
        names = [e.source for e in picked]
        check("fewshot/picks similar target", any("GOOD_XML_STRATEGY" in s for s in names),
              str(names))
        check("fewshot/filters unrelated target", all("JSON_STRATEGY" not in s for s in names))
        check("fewshot/excludes current run", all("CURRENT_STRATEGY" not in s for s in names))
        block = lib.render(get_target("expat"), exclude_run="current")
        check("fewshot/renders source", "GOOD_XML_STRATEGY" in block)
        check("fewshot/mentions metrics", "crashes 1" in block)
        check("fewshot/respects budget", len(block) <= 5000 + 200, str(len(block)))


# ---------------------------------------------------------------- harness
_VALID_HARNESS = r"""#include <stdio.h>
#include <stdlib.h>

int main(void) {
    unsigned char *buf = NULL;
    size_t cap = 0, len = 0;
    int c;
    while ((c = getchar()) != EOF) {
        if (len == cap) {
            cap = cap ? cap * 2 : 4096;
            unsigned char *grown = realloc(buf, cap);
            if (!grown) { free(buf); return 2; }
            buf = grown;
        }
        buf[len++] = (unsigned char)c;
    }
    if (len == 0) {
        printf("DIAG\tempty input\n");
        free(buf);
        return 1;
    }
    printf("DIAG\tparsed %zu bytes\n", len);
    free(buf);
    return 0;
}

/* Kept for the structural gate's exit-code check. */
int unused_exit_codes(void) {
    return 3;
}
"""


def test_harness() -> None:
    from fuzzer.targets import get_target
    spec = HarnessSpec.from_target(get_target("http"))
    v = validate_harness_code(_VALID_HARNESS, spec)
    check("harness/valid sample", v.ok, f"{v.stage} {v.checks}")
    check("harness/extract fence",
          "int main" in (extract_harness_code("```c\n" + _VALID_HARNESS + "```") or ""))
    check("harness/missing main rejected",
          not validate_harness_code("int f(void) { return 0; }", spec).ok)
    bad = _VALID_HARNESS.replace("int main(void)", "int main(void) { system(\"x\"); } int old_main(void)")
    check("harness/forbidden call rejected", not validate_harness_code(bad, spec).ok)
    unbalanced = _VALID_HARNESS.replace("int main(void) {", "int main(void) {{")
    check("harness/unbalanced rejected", not validate_harness_code(unbalanced, spec).ok)
    mxml = HarnessSpec.from_target(get_target("mxml"))
    check("harness/header required",
          not validate_harness_code(_VALID_HARNESS, mxml).ok)


# ----------------------------------------------------------------- llm backend
def test_streaming() -> None:
    from agent.llm import LLMResponse, StreamAccumulator, _chunk_text
    chunks = []
    acc = StreamAccumulator(on_chunk=lambda c: chunks.append(c))
    acc.add_chunk("abc")
    acc.add_chunk("def")
    check("streaming/accumulator text", acc.text == "abcdef")
    check("streaming/accumulator chunks", chunks == ["abc", "def"])
    check("streaming/accumulator ttft", acc.time_to_first_token_s is not None and acc.time_to_first_token_s >= 0)

    split = list(_chunk_text("1234567890", chunk_size=4))
    check("streaming/chunk text", split == ["1234", "5678", "90"])

    resp = LLMResponse(text="hi", backend="mock", streaming=True, duration_s=0.5, time_to_first_token_s=0.1)
    d = resp.to_json()
    check("streaming/response to_json", d.get("streaming") is True and d.get("time_to_first_token_s") == 0.1)


def test_circuit_breaker() -> None:
    from agent.llm import CircuitBreaker, CircuitState
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout_s=0.01)
    check("circuit/initial closed", cb.state == CircuitState.CLOSED and cb.allow_request() is True)
    cb.record_failure("err 1")
    check("circuit/one failure still closed", cb.state == CircuitState.CLOSED)
    cb.record_failure("err 2")
    check("circuit/tripped open", cb.state == CircuitState.OPEN and cb.allow_request() is False)
    time.sleep(0.02)
    check("circuit/half open probe", cb.allow_request() is True and cb.state == CircuitState.HALF_OPEN)
    cb.record_success()
    check("circuit/recovered closed", cb.state == CircuitState.CLOSED and cb.failure_count == 0)


def test_fallback_backend() -> None:
    from agent.llm import FallbackBackend, LLMError, LLMResponse, AllBackendsFailedError
    class MockB:
        def __init__(self, name: str, fail: bool = False) -> None:
            self.name = name
            self.fail = fail
        def complete(self, s: str, u: str, stream: bool = False, on_chunk: Any = None) -> LLMResponse:
            if self.fail:
                raise LLMError(f"{self.name} failed")
            return LLMResponse(text=f"{self.name} ok", backend=self.name)

    primary = MockB("primary", fail=True)
    secondary = MockB("secondary", fail=False)
    fb = FallbackBackend(primary=primary, fallbacks=[secondary])
    r = fb.complete("sys", "usr")
    check("fallback/routes to secondary", r.backend == "secondary" and r.fallback_used is True)
    check("fallback/records origin", r.fallback_from == "primary")

    both_fail = FallbackBackend(primary=MockB("p", fail=True), fallbacks=[MockB("s", fail=True)])
    try:
        both_fail.complete("s", "u")
        check("fallback/raises on all failed", False)
    except AllBackendsFailedError:
        check("fallback/raises on all failed", True)


def test_prompt_versions() -> None:
    from agent.prompt_manager import PromptManager
    mgr = PromptManager()
    versions = mgr.list_versions()
    check("prompts/discovers versions", all(v in versions for v in ("v2", "v3", "v4", "v5")))

    v2 = mgr.get_version("v2")
    seed = v2.render_seed(grammar_commit="comm", parser_g4="p4", lexer_g4="l4", productions="prods")
    check("prompts/renders seed", "comm" in seed and "p4" in seed and "prods" in seed)
    refine = v2.render_refine(it=1, source="PASS_CODE = 1", directive="deepen")
    check("prompts/renders refine", "PASS_CODE = 1" in refine and "deepen" in refine)
    check("prompts/validates cleanly", len(v2.validate()) == 0)

    diffs = mgr.compare_versions("v2", "v5")
    check("prompts/diffs versions", "refine" in diffs and len(diffs["refine"]) > 0)


def test_prompt_ab() -> None:
    from agent.prompt_manager import PromptABTester
    ab = PromptABTester(["v4", "v5"], routing="round_robin")
    v1 = ab.next_variant()
    v2 = ab.next_variant()
    check("ab/round robin alternates", v1.name != v2.name)

    for i in range(10):
        ab.record_trial("v4", i, {"productions_hit": 10 + i % 2, "acceptance_rate": 0.3})
        ab.record_trial("v5", i, {"productions_hit": 25 + i % 2, "acceptance_rate": 0.7})

    ev = ab.evaluate("v4", "v5", "productions_hit")
    check("ab/evaluates winner", ev["winner"] == "v5" and ev["statistically_significant"] is True)
    check("ab/calculates effect size", ev["effect_size_a12"] == 1.0)
    rep = ab.render_report(baseline="v4")
    check("ab/renders report", "# Prompt A/B Testing Report" in rep and "YES" in rep)


def main() -> int:
    test_scoring()
    test_ensemble()
    test_tuning()
    test_cache()
    test_fewshot()
    test_harness()
    test_streaming()
    test_circuit_breaker()
    test_fallback_backend()
    test_prompt_versions()
    test_prompt_ab()
    print(f"{_passed} passed")
    if _failed:
        print(f"{len(_failed)} FAILED")
        for f in _failed:
            print(f"  - {f}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
