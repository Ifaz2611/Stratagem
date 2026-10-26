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
from pathlib import Path

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


def _summary(prod=5, total=27, diag=2, acc=0.5, crashes=0,
             depth=3, examples=50, seconds=0.5) -> dict:
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


def main() -> int:
    test_scoring()
    test_ensemble()
    test_tuning()
    test_cache()
    test_fewshot()
    test_harness()
    print(f"{_passed} passed")
    if _failed:
        print(f"{len(_failed)} FAILED")
        for f in _failed:
            print(f"  - {f}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
