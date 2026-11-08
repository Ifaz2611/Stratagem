"""Comprehensive test suite for Crash Discovery Effectiveness improvements:
  1. Control experiment (libFuzzer/AFL vs Stratagem on Mini-XML)
  2. Sanitizer build verification (ASan, UBSan, TSan, MSan flags & symbols)
  3. Differential testing across parser targets (mxml, expat, libxml2, tinyxml2)
  4. Structured callback diagnostics, differential feedback & novelty scoring
  5. Coverage shadow (offline post-hoc edge & state attribution)
  6. Byte-level mutations (bit flips, integer overflows, truncations, NUL injection)
  7. Adversarial bug-class generators (Billion Laughs, deep nesting, UTF-8/16 boundaries)
  8. Seed corpus management & cross-fertilization across parsers
  9. A/B experiment infrastructure (pure blackbox vs coverage-augmented)
 10. Agent loop integration with structured diagnostics and optional coverage guidance
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from fuzzer.ab_experiment import ABExperimentRunner
from fuzzer.adversarial import AdversarialXMLGenerator
from fuzzer.control_experiment import ControlExperimentRunner
from fuzzer.coverage_shadow import CoverageShadow
from fuzzer.differential import (
    DifferentialOracle,
    DivergenceSeverity,
    DivergenceType,
)
from fuzzer.mutations import (
    ByteMutator,
    flip_bit,
    flip_byte,
    inject_integer_overflow,
    inject_nul_bytes,
    truncate_bytes,
)
from fuzzer.sanitizer_verify import SAN_BUILD_FLAGS, verify_sanitizers
from fuzzer.seed_corpus import SeedCorpusManager
from fuzzer.structured_diagnostics import (
    DiagnosticProfile,
    NoveltyTracker,
    build_profile,
    compare_profiles,
    extract_structured_diagnostic,
)
from fuzzer.runner import Outcome, RunResult

_passed = 0
_failed: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    """Assert condition and record pass/failure."""
    global _passed
    if cond:
        _passed += 1
        return
    failure = f"{name}{(': ' + detail) if detail else ''}"
    _failed.append(failure)
    raise AssertionError(failure)


# =====================================================================
# 1. Control Experiment Tests
# =====================================================================
def test_control_experiment() -> None:
    runner = ControlExperimentRunner(target_name="mxml")

    # Simple deterministic generators
    def dummy_ctrl(i: int) -> bytes:
        return f"<root id='{i}'>control</root>".encode()

    def dummy_strat(i: int) -> bytes:
        return f"<root id='{i}'><child/></root>".encode()

    res = runner.run_control(dummy_ctrl, dummy_strat, budget=20)
    check("control/budget_matches", res.budget_examples == 20)
    check("control/target_clean", res.target_is_clean is True)
    check("control/total_tested", res.control_metrics.total_inputs == 20 and res.stratagem_metrics.total_inputs == 20)
    check("control/edges_recorded", len(res.control_metrics.edges_covered) > 0)
    check("control/json_export", "control" in res.to_json() and "stratagem" in res.to_json())

    md = res.generate_markdown_report()
    check("control/markdown_table", "| Traditional Control (libFuzzer/AFL) |" in md)
    check("control/markdown_clean_status", "CLEAN" in md)


# =====================================================================
# 2. Sanitizer Build Verification Tests
# =====================================================================
def test_sanitizer_verification() -> None:
    # Check flags recorded for all major sanitizers
    check("sanitizers/asan_flag", "-fsanitize=address,undefined" in SAN_BUILD_FLAGS["asan"])
    check("sanitizers/ubsan_halt", "-fno-sanitize-recover=all" in SAN_BUILD_FLAGS["asan"])
    check("sanitizers/tsan_flag", "-fsanitize=thread" in SAN_BUILD_FLAGS["tsan"])
    check("sanitizers/msan_flag", "-fsanitize=memory" in SAN_BUILD_FLAGS["msan"])
    check("sanitizers/cov_flag", "--coverage" in SAN_BUILD_FLAGS["cov"])

    results = verify_sanitizers()
    check("sanitizers/results_asan", "asan" in results)
    check("sanitizers/results_ubsan", "ubsan" in results)
    check("sanitizers/results_tsan", "tsan" in results)
    check("sanitizers/results_msan", "msan" in results)
    check("sanitizers/env_options_present", "ASAN_OPTIONS" in results["asan"].env_vars)


# =====================================================================
# 3. Differential Testing Tests
# =====================================================================
def test_differential_testing() -> None:
    oracle = DifferentialOracle(target_names=("mxml", "expat", "libxml2"))

    # 1. Perfectly valid XML should not diverge on outcome
    valid_xml = b"<root><child>value</child></root>"
    div_valid = oracle.test_input(valid_xml)
    check("diff/valid_no_crash_or_outcome_div", div_valid is None or div_valid.divergence_type != DivergenceType.CRASH_DIVERGENCE)

    # 2. Input that triggers outcome divergence (e.g., bare control char accepted by mxml with diag, rejected by expat)
    bad_ctrl_xml = b"<root>\x01</root>"
    div_ctrl = oracle.test_input(bad_ctrl_xml)
    check("diff/detects_divergence", div_ctrl is not None)
    if div_ctrl:
        check("diff/has_outcomes_dict", "mxml" in div_ctrl.outcomes and "expat" in div_ctrl.outcomes)

    # 3. Batch testing
    batch = [
        b"<root/>",
        b"<root><unclosed>",
        b"<a a>",
        b"not xml at all",
    ]
    report = oracle.run_batch(batch)
    check("diff/batch_total_tested", report.total_inputs_tested == 4)
    check("diff/report_json", "divergence_by_type" in report.to_json())
    md = report.generate_markdown_report()
    check("diff/report_markdown", "Differential Testing Report" in md)


# =====================================================================
# 4. Structured Diagnostics, Feedback & Novelty Tests
# =====================================================================
def test_structured_diagnostics() -> None:
    raw = "Missing close tag </item> under parent <root> on line 3."
    payload = b"<root>\n  <item>\n  content"

    diag = extract_structured_diagnostic(raw, payload)
    check("struct/extracted_line", diag.line == 3)
    check("struct/extracted_template", "</%s>" in diag.normalized_template)
    check("struct/extracted_phase", diag.failure_phase == "tag_close")
    check("struct/depth_calculated", diag.depth_reached > 0)
    check("struct/bytes_consumed", diag.bytes_consumed > 0)

    # Construct and compare profiles
    p_shallow = build_profile(
        sha="sha1",
        payload=b"<root>",
        outcome="rejected",
        diagnostics=["XML does not start with '<' on line 1."],
    )
    p_deep = build_profile(
        sha="sha2",
        payload=b"<root><sub1><sub2><item attr='val'/></sub2></sub1></root>",
        outcome="parsed_clean",
        diagnostics=[],
    )

    check("profile/deep_depth_higher", p_deep.max_depth_reached > p_shallow.max_depth_reached)
    check("profile/comparison_orders_deep", compare_profiles(p_deep, p_shallow) == 1)
    check("profile/comparison_orders_shallow", compare_profiles(p_shallow, p_deep) == -1)

    # Novelty tracker
    tracker = NoveltyTracker()
    score_first = tracker.score_input(p_shallow)
    check("novelty/initial_score_positive", score_first > 0)

    # Scoring p_deep brings depth novelty
    score_deep = tracker.score_input(p_deep)
    check("novelty/depth_novelty_awarded", score_deep > 0)

    # Re-scoring exact same profile produces 0 novelty
    score_repeat = tracker.score_input(p_shallow)
    check("novelty/repeat_zero_novelty", score_repeat == 0.0)

    # Fresh tracker batch evaluation
    batch_tracker = NoveltyTracker()
    batch_summary = batch_tracker.evaluate_batch("test_strategy", [p_shallow, p_deep])
    check("novelty/batch_summary_score", batch_summary["novelty_score"] > 0)
    check("novelty/batch_summary_phases", len(batch_summary["cumulative_phases"]) > 0)


# =====================================================================
# 5. Coverage Shadow Tests
# =====================================================================
def test_coverage_shadow() -> None:
    shadow = CoverageShadow(target_name="mxml")

    corpus_s1 = [
        b"<root><a/></root>",
        b"<root><b>text</b></root>",
        b"<!-- comment --><root/>",
    ]
    corpus_s2 = [
        b"<root><![CDATA[cdata block]]></root>",
        b"<!DOCTYPE r [<!ELEMENT r ANY>]><r/>",
    ]

    shadow.analyze_strategy_corpus("strat_1", corpus_s1)
    shadow.analyze_strategy_corpus("strat_2", corpus_s2)

    rep = shadow.compile_report()
    check("shadow/total_edges", rep.total_edges_discovered > 0)
    check("shadow/edges_by_strat_1", rep.edges_by_strategy["strat_1"] > 0)
    check("shadow/edges_by_strat_2", rep.edges_by_strategy["strat_2"] > 0)
    check("shadow/unique_attribution", "strat_2" in rep.unique_edges_by_strategy)

    md = rep.generate_markdown()
    check("shadow/markdown_header", "Coverage Shadow: Offline Post-Hoc Analysis" in md)


# =====================================================================
# 6. Byte-Level Mutation Tests
# =====================================================================
def test_byte_mutations() -> None:
    base = b"<root attr='100'>test content</root>"

    # 1. Bit flip changes exactly one bit
    flipped = flip_bit(base)
    check("mutations/bit_flip_diff", flipped != base)
    check("mutations/bit_flip_len_same", len(flipped) == len(base))

    # 2. Byte flip
    b_flipped = flip_byte(base)
    check("mutations/byte_flip_diff", b_flipped != base)
    check("mutations/byte_flip_len_same", len(b_flipped) == len(base))

    # 3. Truncate
    truncated = truncate_bytes(base)
    check("mutations/truncate_shorter", len(truncated) < len(base))
    check("mutations/truncate_prefix_matches", base.startswith(truncated))

    # 4. Integer overflow injection
    int_injected = inject_integer_overflow(base)
    check("mutations/int_injected_longer", len(int_injected) > len(base))

    # 5. NUL byte injection
    nul_injected = inject_nul_bytes(base)
    check("mutations/nul_injected", b"\x00" in nul_injected)

    # 6. ByteMutator pipeline
    mutator = ByteMutator(seed=1234)
    mutated = mutator.mutate(base, intensity=2)
    check("mutations/mutator_diff", mutated != base)
    many = mutator.mutate_many(base, count=5)
    check("mutations/mutator_many_count", len(many) == 5)


# =====================================================================
# 7. Adversarial Bug-Class Generator Tests
# =====================================================================
def test_adversarial_generators() -> None:
    # 1. Billion Laughs
    bomb = AdversarialXMLGenerator.billion_laughs(depth=3, expansion=5)
    check("adv/billion_laughs_has_entities", b"<!ENTITY lol" in bomb and b"&lol3;" in bomb)

    # 2. Quadratic Blowup
    quad = AdversarialXMLGenerator.quadratic_blowup(n_entities=10, size=50)
    check("adv/quadratic_entities", b"&e0;" in quad and b"&e9;" in quad)

    # 3. Deep Nesting
    nested = AdversarialXMLGenerator.deep_nesting(depth=50)
    check("adv/deep_nesting_depth", nested.count(b"<tag") == 50 and nested.count(b"</tag") == 50)

    # 4. Huge Attributes
    attrs = AdversarialXMLGenerator.huge_attributes(count=100)
    check("adv/huge_attrs_count", attrs.count(b"attr") == 100)

    # 5. Long element name
    long_el = AdversarialXMLGenerator.long_element_name(length=1200)
    check("adv/long_element_len", len(long_el) > 1200)

    # 6. UTF-8 & UTF-16 boundary cases
    utf8_cases = AdversarialXMLGenerator.utf8_boundary_cases()
    check("adv/utf8_cases_count", len(utf8_cases) >= 5)

    utf16_cases = AdversarialXMLGenerator.utf16_boundary_cases()
    check("adv/utf16_cases_count", len(utf16_cases) >= 3)

    # 7. Malformed DOCTYPE
    doctypes = AdversarialXMLGenerator.malformed_doctype()
    check("adv/doctypes_count", len(doctypes) >= 4)

    # 8. All combined
    all_cases = AdversarialXMLGenerator.all_adversarial_cases()
    check("adv/all_cases_count", len(all_cases) >= 15)


# =====================================================================
# 8. Seed Corpus & Cross-Fertilization Tests
# =====================================================================
def test_seed_corpus() -> None:
    mgr = SeedCorpusManager()
    check("seeds/initial_count", len(mgr.seeds) >= 5)

    # Real world seeds
    mxml_seeds = mgr.get_seeds_for_target("mxml", cross_fertilize=False)
    check("seeds/target_filtered", len(mxml_seeds) > 0)

    # Cross-fertilization retrieves seeds from other targets too
    cross_seeds = mgr.get_seeds_for_target("mxml", cross_fertilize=True)
    check("seeds/cross_fertilize_more", len(cross_seeds) >= len(mxml_seeds))

    # Export seeds
    with tempfile.TemporaryDirectory() as td:
        out_dir = Path(td) / "seeds"
        count = mgr.export_seeds(out_dir)
        check("seeds/exported_count", count == len(mgr.seeds))
        xmls = list(out_dir.glob("*.xml"))
        check("seeds/exported_xml_files", len(xmls) == count)


# =====================================================================
# 9. A/B Experiment Infrastructure Tests
# =====================================================================
def test_ab_experiment() -> None:
    runner = ABExperimentRunner(target_name="mxml")

    def bb_gen(i: int) -> bytes:
        return f"<root id='{i}'><item>blackbox</item></root>".encode()

    def cov_gen(i: int, seen_edges: set[str]) -> bytes:
        # Changes structure based on seen edges
        tag = "unseen_tag" if len(seen_edges) < 5 else "seen_tag"
        return f"<{tag} id='{i}'/>".encode()

    res = runner.run_experiment(bb_gen, cov_gen, budget=15)
    check("ab/budget_matches", res.budget_per_arm == 15)
    check("ab/blackbox_executed", res.blackbox_arm.total_inputs == 15)
    check("ab/coverage_executed", res.coverage_arm.total_inputs == 15)
    check("ab/edges_recorded", len(res.coverage_arm.covered_edges) > 0)
    check("ab/json_export", "blackbox" in res.to_json() and "coverage_augmented" in res.to_json())

    md = res.generate_markdown()
    check("ab/markdown_table", "| Arm A: Pure Blackbox (D2 Baseline) |" in md)
    check("ab/markdown_findings", "Key Findings" in md)


# =====================================================================
# 10. Agent Loop Integration Tests
# =====================================================================
def test_loop_integration() -> None:
    from agent.loop import Loop
    from agent.prompt_manager import PromptVersion
    from fuzzer.targets import get_target

    lp = Loop.__new__(Loop)
    lp.prompts = Path(__file__).resolve().parent.parent / "agent" / "prompts"
    lp.prompt_version = PromptVersion.from_dir(lp.prompts, name="v1")
    lp.target = "mxml"
    lp.target_obj = get_target("mxml")
    lp.union_diagnostics = set()
    lp.union_productions = set()
    lp.directives = ["improve"]
    lp.structured_diagnostics = True
    lp.coverage_guided = True
    lp.last_novelty_stats = {
        "novelty_score": 45.0,
        "max_depth": 8,
        "avg_depth": 3.2,
        "max_consumed": 250,
        "avg_consumed": 120.0,
        "cumulative_phases": ["tag_open", "attribute", "body"],
        "cumulative_templates": 12,
    }
    lp.last_coverage_stats = {
        "edges_count": 85,
        "new_edges": 14,
    }

    summary = {
        "examples": 5,
        "outcomes": {"parsed_clean": 3, "rejected": 2},
        "acceptance_rate": 0.6,
        "crash_count": 0,
        "xml_shaped_rate": 1.0,
        "distinct_diagnostic_templates": 2,
        "diagnostic_templates": {"error template 1": 2},
        "input_len": {"min": 10, "max": 100},
        "structure": {
            "productions_hit": 10,
            "productions_total": 27,
            "hit": {"p_element": 5},
            "missing": ["p_cdata"],
            "depth_histogram": {"1": 2, "2": 3},
            "max_depth_seen": 2,
            "boundaries": {},
        },
        "buckets": {},
    }

    refine_prompt = lp._refine_prompt(1, "SOURCE = 1\n", summary, [])
    check("loop/refine_has_structured_section", "### Structured Callback Diagnostics" in refine_prompt)
    check("loop/refine_has_novelty_score", "Novelty score: **45.0**" in refine_prompt)
    check("loop/refine_has_coverage_section", "### Coverage-Guided Signal" in refine_prompt)
    check("loop/refine_has_edges_count", "Cumulative branch / proxy edges reached: **85**" in refine_prompt)


def main() -> None:
    print("Running Crash Discovery Test Suite...")
    test_control_experiment()
    test_sanitizer_verification()
    test_differential_testing()
    test_structured_diagnostics()
    test_coverage_shadow()
    test_byte_mutations()
    test_adversarial_generators()
    test_seed_corpus()
    test_ab_experiment()
    test_loop_integration()

    print(f"passed={_passed} failed={len(_failed)}")
    if _failed:
        print("Failures:")
        for f in _failed:
            print(f"  * {f}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
