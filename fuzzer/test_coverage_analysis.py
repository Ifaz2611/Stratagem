"""Comprehensive test suite for Coverage & Analysis improvements:
  1. ThreadSanitizer & MemorySanitizer support
  2. Crash triage (bug clustering, deduplication, severity, stack similarity)
  3. Automatic minimal reproducer generation (DeltaDebugger, script generators, bundles)
  4. Statistical significance testing for coverage improvements (Welch, MWU, A12, CIs)
  5. Visual coverage reports (HTML / interactive dashboards, SVG charts)
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from fuzzer.reproducer import (
    DeltaDebugger,
    create_reproducer_bundle,
    generate_c_reproducer,
    generate_python_reproducer,
    generate_shell_reproducer,
)
from fuzzer.runner import (
    Outcome,
    RunResult,
    SanitizerType,
    detect_sanitizer,
    get_sanitizer_env,
)
from fuzzer.significance import (
    bootstrap_ci_difference,
    cohens_d,
    compare_cells,
    compare_samples,
    evaluate_campaign_progress,
    format_significance_table,
    hedges_g,
    mann_whitney_u_test,
    vargha_delaney_a12,
    welch_t_test,
)
from fuzzer.targets import get_target
from fuzzer.triage import (
    BugClusterer,
    Severity,
    calculate_stack_similarity,
    classify_severity,
    parse_report,
)
from fuzzer.visual_report import generate_html_dashboard

_passed = 0
_failed: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    global _passed
    if cond:
        _passed += 1
    else:
        _failed.append(f"{name}{(': ' + detail) if detail else ''}")


# =====================================================================
# 1. Sanitizer Support Tests (ThreadSanitizer, MemorySanitizer)
# =====================================================================
def test_sanitizers() -> None:
    # SanitizerType enum
    check("sanitizers/enum_asan", SanitizerType.ASAN.value == "asan")
    check("sanitizers/enum_tsan", SanitizerType.TSAN.value == "tsan")
    check("sanitizers/enum_msan", SanitizerType.MSAN.value == "msan")

    # Sanitizer env builder
    env_all = get_sanitizer_env()
    check("sanitizers/env_has_asan", "ASAN_OPTIONS" in env_all)
    check("sanitizers/env_has_ubsan", "UBSAN_OPTIONS" in env_all)
    check("sanitizers/env_has_tsan", "TSAN_OPTIONS" in env_all)
    check("sanitizers/env_has_msan", "MSAN_OPTIONS" in env_all)

    env_tsan = get_sanitizer_env(sanitizers=("tsan",))
    check("sanitizers/env_filtered_tsan", "TSAN_OPTIONS" in env_tsan and "ASAN_OPTIONS" not in env_tsan)

    # Detect sanitizer from stderr
    stderr_tsan = "WARNING: ThreadSanitizer: data race (pid=123)"
    stderr_msan = "WARNING: MemorySanitizer: use-of-uninitialized-value"
    stderr_asan = "==1==ERROR: AddressSanitizer: heap-buffer-overflow"
    stderr_ubsan = "runtime error: signed integer overflow"
    stderr_lsan = "==1==ERROR: LeakSanitizer: detected memory leaks"

    check("sanitizers/detect_tsan", detect_sanitizer(stderr_tsan) == "ThreadSanitizer")
    check("sanitizers/detect_msan", detect_sanitizer(stderr_msan) == "MemorySanitizer")
    check("sanitizers/detect_asan", detect_sanitizer(stderr_asan) == "AddressSanitizer")
    check("sanitizers/detect_ubsan", detect_sanitizer(stderr_ubsan) == "UndefinedBehaviorSanitizer")
    check("sanitizers/detect_lsan", detect_sanitizer(stderr_lsan) == "LeakSanitizer")
    check("sanitizers/detect_none", detect_sanitizer("regular output") is None)

    # RunResult with sanitizer annotation
    rr = RunResult(
        outcome=Outcome.CRASH,
        returncode=-1,
        stderr=stderr_tsan,
        sanitizer="ThreadSanitizer",
    )
    d = rr.to_json()
    check("sanitizers/run_result_json", d.get("sanitizer") == "ThreadSanitizer")

    # Target harness_for_sanitizer
    target = get_target("mxml")
    check("sanitizers/target_supported", "tsan" in target.supported_sanitizers and "msan" in target.supported_sanitizers)

    # Parsing TSan and MSan reports
    tsan_full = """
WARNING: ThreadSanitizer: data race (pid=12345)
  Write of size 8 at 0x7b5000000000 by thread T1:
    #0 worker_write /path/to/test.c:10 (harness+0x1234)
    #1 thread_start /path/to/test.c:20 (harness+0x1234)

  Previous read of size 8 at 0x7b5000000000 by thread T2:
    #0 worker_read /path/to/test.c:15 (harness+0x1234)
    #1 thread_start /path/to/test.c:22 (harness+0x1234)
"""
    rep_tsan = parse_report(tsan_full)
    check("sanitizers/tsan_parsed", rep_tsan is not None)
    if rep_tsan:
        check("sanitizers/tsan_tool", rep_tsan.tool == "ThreadSanitizer")
        check("sanitizers/tsan_bug_type", rep_tsan.bug_type == "data-race")
        check("sanitizers/tsan_access", rep_tsan.access == "WRITE")
        check("sanitizers/tsan_top_frame", rep_tsan.signature_frames[0] == "worker_write@test.c")

    msan_full = """
==12345==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x7f4e8c1 in check_val /path/to/parser.c:15
    #1 0x7f4e8d2 in parse_node /path/to/parser.c:45
"""
    rep_msan = parse_report(msan_full)
    check("sanitizers/msan_parsed", rep_msan is not None)
    if rep_msan:
        check("sanitizers/msan_tool", rep_msan.tool == "MemorySanitizer")
        check("sanitizers/msan_bug_type", rep_msan.bug_type == "use-of-uninitialized-value")
        check("sanitizers/msan_top_frame", rep_msan.signature_frames[0] == "check_val@parser.c")


# =====================================================================
# 2. Crash Triage & Bug Clustering Tests
# =====================================================================
def test_crash_triage() -> None:
    # Severity classification
    check("triage/sev_critical_oob_w", classify_severity("heap-buffer-overflow", "WRITE") == Severity.CRITICAL.value)
    check("triage/sev_critical_df", classify_severity("double-free") == Severity.CRITICAL.value)
    check("triage/sev_critical_uaf_w", classify_severity("use-after-free", "WRITE") == Severity.CRITICAL.value)
    check("triage/sev_high_oob_r", classify_severity("heap-buffer-overflow", "READ") == Severity.HIGH.value)
    check("triage/sev_high_tsan", classify_severity("data-race") == Severity.HIGH.value)
    check("triage/sev_medium_msan", classify_severity("use-of-uninitialized-value") == Severity.MEDIUM.value)
    check("triage/sev_medium_ubsan", classify_severity("signed-integer-overflow") == Severity.MEDIUM.value)
    check("triage/sev_low_leak", classify_severity("memory-leak") == Severity.LOW.value)
    check("triage/sev_info_timeout", classify_severity("timeout") == Severity.INFO.value)

    # Stack similarity
    stack_a = ["foo@a.c", "bar@b.c", "baz@c.c"]
    stack_b = ["foo@a.c", "bar@b.c", "other@d.c"]
    stack_c = ["diff@x.c", "other@y.c"]

    sim_ident = calculate_stack_similarity(stack_a, stack_a)
    sim_close = calculate_stack_similarity(stack_a, stack_b)
    sim_diff = calculate_stack_similarity(stack_a, stack_c)

    check("triage/similarity_identity", sim_ident == 1.0)
    check("triage/similarity_high_for_close", sim_close > 0.7, f"got {sim_close}")
    check("triage/similarity_low_for_diff", sim_diff < 0.2, f"got {sim_diff}")

    # BugClusterer
    crash1 = {
        "sha": "sha111",
        "stderr": "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\nWRITE of size 4\n    #0 0x1 in index_sort /src/mxml-index.c:10\n    #1 0x2 in mxmlIndexNew /src/mxml-index.c:20\n",
        "outcome": "crash",
    }
    # Same bug, reached from a different caller in mxml-index
    crash2 = {
        "sha": "sha222",
        "stderr": "==2==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\nWRITE of size 4\n    #0 0x1 in index_sort /src/mxml-index.c:10\n    #1 0x3 in mxmlIndexSort /src/mxml-index.c:50\n",
        "outcome": "crash",
    }
    # Different bug: use-after-free in node.c
    crash3 = {
        "sha": "sha333",
        "stderr": "==3==ERROR: AddressSanitizer: use-after-free on address 0x2\nREAD of size 8\n    #0 0x4 in mxmlDelete /src/mxml-node.c:100\n    #1 0x5 in mxml_free /src/mxml-node.c:120\n",
        "outcome": "crash",
    }
    # Timeout
    crash4 = {
        "sha": "sha444",
        "outcome": "timeout",
        "productions": ["p_element", "p_content"],
    }

    clusterer = BugClusterer()
    for c in (crash1, crash2, crash3, crash4):
        clusterer.add_crash(c)

    deduped = clusterer.deduplicate()
    check("triage/deduped_count", len(deduped) == 4)

    clusters = clusterer.cluster()
    check("triage/clusters_count", len(clusters) == 3, f"got {len(clusters)}")

    # Check that crash1 and crash2 merged into the index_sort cluster
    index_cluster = next((c for c in clusters if "index_sort" in c.root_cause_func), None)
    check("triage/cluster_merged_index_sort", index_cluster is not None)
    if index_cluster:
        check("triage/cluster_index_count", index_cluster.crash_count == 2)
        check("triage/cluster_index_sev", index_cluster.severity == Severity.CRITICAL.value)
        check("triage/cluster_unique_inputs", len(index_cluster.unique_inputs) == 2)

    # Triage summary & Markdown report
    summary = clusterer.triage_summary()
    check("triage/summary_total_clusters", summary["total_clusters"] == 3)
    check("triage/summary_severity_breakdown", summary["severity_breakdown"]["CRITICAL"] >= 1)

    md = clusterer.generate_markdown_report()
    check("triage/markdown_contains_table", "| Severity | Clusters |" in md)
    check("triage/markdown_contains_cluster_id", "cluster-01" in md)


# =====================================================================
# 3. Minimal Reproducer Generation Tests
# =====================================================================
def test_reproducer_generation() -> None:
    # 1. DeltaDebugger on string/bytes
    oracle = lambda b: b"<crash_tag>" in b
    dd = DeltaDebugger(oracle, timeout_s=5.0)

    heavy_input = b"""
<root>
  <header version="1.0">Unnecessary information</header>
  <metadata author="test">lots of padding bytes 1234567890</metadata>
  <data>
    <item id="1">item one</item>
    <crash_tag>TRIGGER</crash_tag>
    <item id="2">item two</item>
  </data>
</root>
"""
    shrunk = dd.minimize(heavy_input)
    check("reproducer/dd_minimized", len(shrunk) < len(heavy_input))
    check("reproducer/dd_triggers_oracle", oracle(shrunk))
    check("reproducer/dd_contains_crash_tag", b"<crash_tag>" in shrunk)

    # 2. Script generators
    py_code = generate_python_reproducer(b"<test/>", target_name="mxml", signature="sig123", label="heap-overflow")
    check("reproducer/python_has_b64", "base64.b64decode" in py_code)
    check("reproducer/python_has_target", "mxml" in py_code)
    check("reproducer/python_has_signature", "sig123" in py_code)

    c_code = generate_c_reproducer(b"<test/>", target_name="mxml", signature="sig123")
    check("reproducer/c_has_payload_array", "unsigned char payload[]" in c_code)
    check("reproducer/c_has_hex_bytes", "0x3c" in c_code)

    sh_code = generate_shell_reproducer("reproducer.bin")
    check("reproducer/sh_has_asan", "ASAN_OPTIONS" in sh_code)

    # 3. Full bundle generation
    with tempfile.TemporaryDirectory() as td:
        bundle_dir = Path(td) / "bundle_test"
        bundle = create_reproducer_bundle(
            payload=b"<root><child/></root>",
            target="mxml",
            out_dir=bundle_dir,
            minimize_first=False,
            verify_runs=2,
        )
        check("reproducer/bundle_returned", bundle is not None)
        check("reproducer/bundle_file_bin", (bundle_dir / "reproducer.bin").exists())
        check("reproducer/bundle_file_py", (bundle_dir / "reproduce.py").exists())
        check("reproducer/bundle_file_c", (bundle_dir / "reproduce.c").exists())
        check("reproducer/bundle_file_sh", (bundle_dir / "reproduce.sh").exists())
        check("reproducer/bundle_file_meta", (bundle_dir / "metadata.json").exists())

        meta = json.loads((bundle_dir / "metadata.json").read_text(encoding="utf-8"))
        check("reproducer/bundle_meta_target", meta["target"] == "mxml")
        check("reproducer/bundle_meta_runs", meta["verified_runs"] == 2)


# =====================================================================
# 4. Statistical Significance Testing Tests
# =====================================================================
def test_statistical_significance() -> None:
    # 1. Welch's t-test
    # Identical samples -> t=0, p=1.0
    s_same = [40.0, 41.0, 42.0, 43.0, 44.0]
    t, df, p = welch_t_test(s_same, s_same)
    check("stats/welch_same_p1", abs(p - 1.0) < 1e-4, f"p={p}")

    # Separated samples -> p < 0.05
    s_high = [50.0, 51.0, 52.0, 51.5, 50.5]
    s_low = [30.0, 31.0, 32.0, 31.5, 30.5]
    t_sep, df_sep, p_sep = welch_t_test(s_high, s_low)
    check("stats/welch_separated_significant", p_sep < 0.001, f"p={p_sep}")
    check("stats/welch_df_positive", df_sep > 0)

    # 2. Mann-Whitney U test
    u, p_mwu = mann_whitney_u_test(s_high, s_low)
    check("stats/mwu_u_zero", u == 0.0, f"u={u}")
    check("stats/mwu_significant", p_mwu < 0.05, f"p={p_mwu}")

    # 3. Vargha-Delaney A12 effect size
    a12_high, mag_high = vargha_delaney_a12(s_high, s_low)
    check("stats/a12_high_one", a12_high == 1.0, f"a12={a12_high}")
    check("stats/a12_large_mag", mag_high == "large", mag_high)

    a12_same, mag_same = vargha_delaney_a12(s_same, s_same)
    check("stats/a12_same_half", a12_same == 0.5, f"a12={a12_same}")
    check("stats/a12_same_mag", mag_same == "negligible", mag_same)

    # 4. Cohen's d & Hedges' g
    d = cohens_d(s_high, s_low)
    g = hedges_g(s_high, s_low)
    check("stats/cohens_d_large", d > 5.0, f"d={d}")
    check("stats/hedges_g_large", g > 5.0, f"g={g}")

    # 5. Bootstrap CI
    ci_low, ci_high = bootstrap_ci_difference(s_high, s_low)
    check("stats/ci_positive", ci_low > 15.0 and ci_high > 15.0, f"[{ci_low}, {ci_high}]")

    # 6. High-level compare_samples
    sig_res = compare_samples(s_high, s_low, metric="coverage_pct")
    check("stats/compare_samples_sig", sig_res.is_significant)
    check("stats/compare_samples_verdict", "Statistically significant improved" in sig_res.verdict)

    # 7. Testing real coverage_trials.json
    trials_path = Path("runs/analysis/coverage_trials.json")
    if trials_path.exists():
        data = json.loads(trials_path.read_text(encoding="utf-8"))
        res_cells = compare_cells(data, "loop/iter-4", "loop/iter-0")
        check("stats/compare_cells_parser_pct", "parser_pct" in res_cells)
        check("stats/compare_cells_acceptance", "acceptance" in res_cells)
        check("stats/compare_cells_acceptance_sig", res_cells["acceptance"].is_significant)

        # Campaign progression
        prog = evaluate_campaign_progress(data, baseline_cell="loop/iter-0", metric="parser_pct")
        check("stats/progression_list", len(prog) > 0)
        table = format_significance_table(res_cells)
        check("stats/format_table", "| `parser_pct` |" in table)


# =====================================================================
# 5. Visual Coverage Reports Tests
# =====================================================================
def test_visual_reports() -> None:
    trials_path = Path("runs/analysis/coverage_trials.json")
    loop_summary_path = Path("runs/loop/loop_summary.json")

    with tempfile.TemporaryDirectory() as td:
        out_html = Path(td) / "test_report.html"

        # 1. From coverage_trials.json
        if trials_path.exists():
            data = json.loads(trials_path.read_text(encoding="utf-8"))
            res_p = generate_html_dashboard(data, out_file=out_html, title="Unit Test Dashboard")
            check("visual/html_file_created", res_p.exists())
            html_text = res_p.read_text(encoding="utf-8")
            check("visual/html_has_title", "Unit Test Dashboard" in html_text)
            check("visual/html_has_svg_chart", "<svg" in html_text)
            check("visual/html_has_tabs", "tab-coverage" in html_text and "tab-significance" in html_text)
            check("visual/html_has_kpis", "Peak Line Coverage" in html_text)
            check("visual/html_offline_self_contained", "http://" not in html_text and "https://" not in html_text)

        # 2. From loop_summary.json
        if loop_summary_path.exists():
            out_loop_html = Path(td) / "loop_report.html"
            data_loop = json.loads(loop_summary_path.read_text(encoding="utf-8"))
            res_loop_p = generate_html_dashboard(data_loop, out_file=out_loop_html, title="Loop Summary Dashboard")
            check("visual/loop_html_created", res_loop_p.exists())
            loop_text = res_loop_p.read_text(encoding="utf-8")
            check("visual/loop_html_has_content", "Loop Summary Dashboard" in loop_text)


def main() -> None:
    print("Running Coverage & Analysis Test Suite...")
    test_sanitizers()
    test_crash_triage()
    test_reproducer_generation()
    test_statistical_significance()
    test_visual_reports()

    print(f"passed={_passed} failed={len(_failed)}")
    if _failed:
        print("Failures:")
        for f in _failed:
            print(f"  * {f}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
