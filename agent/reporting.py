"""Markdown and text report formatting for the agentic loop."""
from __future__ import annotations

from pathlib import Path

BASELINE = {"acceptance": "0.2%", "productions": "5.3/27", "depth": 0.3, "templates": 3.3}


def format_slowest(results: list[dict]) -> str:
    slowest = sorted(results, key=lambda r: -r["dur_ms"])[:3]
    return "\n".join(
        f"{r['dur_ms']:8.1f} ms  len={r['len']:<6} depth={r['structure']['max_depth']:<3} {r['outcome']}"
        for r in slowest) or "(none)"


def format_crashes(summary: dict) -> str:
    if summary.get("crash_groups"):
        return "### Crashes found\n\n```\n" + "\n".join(
            f"{sig}  x{b['count']}  {b['label']}"
            for sig, b in summary["crash_groups"].items()) + "\n```\n\n" + (
            "Keep whatever produced these and push harder on the same area.")
    return ("### Crashes found\n\nNone yet. Sanitizers are active and a "
            "known real bug is detected by this pipeline, so the "
            "absence is real, not a detection failure.")


def format_boundaries(boundaries: dict) -> str:
    return "\n".join(
        f"{k:20} max={v.get('max', 0):<8} p90={v.get('p90', 0):<8} "
        f"p50={v.get('p50', 0):<8} distinct values={v.get('distinct', 0)}"
        for k, v in boundaries.items()) or "(not measured)"


def format_buckets(buckets: dict) -> str:
    return "\n".join(
        f"{b:14} share={e['share']:6.1%}  acceptance={e['acceptance_rate']:6.1%}  n={e['n']}"
        for b, e in sorted(buckets.items())) or "(not measured)"


def format_diagnostics(summary: dict) -> str:
    return "\n".join(f"{c:5d}  {t}" for t, c in
                     list(summary.get("diagnostic_templates", {}).items())[:20]) or "(none)"


def format_structured_diagnostics(novelty_stats: dict | None) -> str:
    """Format structured diagnostic statistics into a markdown prompt block."""
    if not novelty_stats:
        return ""
    phases = ", ".join(novelty_stats.get("cumulative_phases", [])) or "none"
    return (
        "### Structured Callback Diagnostics\n\n"
        f"- Novelty score: **{novelty_stats.get('novelty_score', 0.0):.1f}**\n"
        f"- Max depth reached: **{novelty_stats.get('max_depth', 0)}** (avg {novelty_stats.get('avg_depth', 0.0):.1f})\n"
        f"- Consumed prefix before failure: **{novelty_stats.get('max_consumed', 0)} bytes** (avg {novelty_stats.get('avg_consumed', 0.0):.1f} bytes)\n"
        f"- Parser failure phases explored: `{phases}`\n"
        f"- Distinct diagnostic templates hit: {novelty_stats.get('cumulative_templates', 0)}\n\n"
        "Steer toward inputs that penetrate deeper (higher depth and prefix bytes) before rejection."
    )


def format_coverage_guidance(edge_stats: dict | None) -> str:
    """Format optional coverage-guided feedback into a markdown prompt block."""
    if not edge_stats:
        return ""
    return (
        "### Coverage-Guided Signal (Optional Evaluation Mode)\n\n"
        f"- Cumulative branch / proxy edges reached: **{edge_stats.get('edges_count', 0)}**\n"
        f"- New edges discovered this iteration: **{edge_stats.get('new_edges', 0)}**\n"
        "Target remaining uncovered branch edges by varying syntax structure and token combinations."
    )


def write_iteration_log(out_dir: Path, final: dict) -> None:
    rows = final["iterations"]
    lines = [
        f"# Iteration log: {final['run_id']}", "",
        f"Backend `{final['backend']}`, model `{final['model']}`, "
        f"{final['max_examples']} examples per iteration.", "",
        "| iter | source | examples | accept | productions | max depth | diagnostics | crashes | cum. cost |",
        "|---|---|---|---|---|---|---|---|---|",
        f"| baseline | - | - | {BASELINE['acceptance']} | {BASELINE['productions']} | "
        f"{BASELINE['depth']} | {BASELINE['templates']} | 0 | $0 |",
    ]
    for r in rows:
        cost_str = (f"${r['cost_usd_cumulative']:.2f} |"
                    if r.get("cost_usd_cumulative") is not None else "n/a |")
        lines.append(
            f"| {r['iteration']} | {r.get('source', 'llm')} | "
            f"{r.get('examples', final['max_examples'])} | "
            f"{r['acceptance_rate']:.1%} | "
            f"{r['productions_hit']}/{r['productions_total']} | {r['max_depth']} | "
            f"{r['distinct_diagnostic_templates']} | {r['crash_count']} | {cost_str}")
    b = final["budget"]
    lines += ["", "## Budget", "",
              f"- LLM calls: **{b['llm_calls']}**",
              f"- Prompt tokens billed (incl. backend overhead): {b['billable_input_tokens']:,}",
              f"- Prompt tokens we authored (est.): {b['authored_prompt_tokens_est']:,}",
              f"- Output tokens: {b['output_tokens']:,}",
              f"- Cost: **${b['cost_usd']:.2f}** of ${b['max_usd']:.2f} cap"]
    if not final.get("cost_cap_enforced", True):
        lines.append("- Cost cap: **advisory only** — this backend reports no "
                     "per-call price, so the cap cannot be enforced.")
    (out_dir / "ITERATION_LOG.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
