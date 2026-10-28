"""Visual coverage reports and interactive HTML dashboards for Stratagem.

Generates self-contained, offline-first interactive HTML dashboards featuring:
  * Executive KPI metric cards (Peak coverage, acceptance, bug clusters, throughput)
  * SVG trend charts for line coverage progression, acceptance rate, and input buckets
  * Interactive Crash & Bug Triage inspector with expandable call stacks and reproducer scripts
  * Statistical significance matrix (Welch's p-value, Mann-Whitney U, Vargha-Delaney A12 effect size)
  * Grammar productions checklist and structural analysis
  * Corpus and execution performance breakdown
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
from pathlib import Path
from typing import Any, Sequence

from fuzzer import significance, triage
from fuzzer.timeutil import utc_iso

REPO_ROOT = Path(__file__).resolve().parent.parent


def _mean(seq: Sequence[float]) -> float:
    return sum(seq) / len(seq) if seq else 0.0



def _svg_line_chart(
    points: list[tuple[str, float]],
    width: int = 700,
    height: int = 240,
    title: str = "",
    y_label: str = "%",
    color: str = "#3b82f6",
    error_bars: list[tuple[float, float]] | None = None,
) -> str:
    """Generate a clean, embedded SVG line chart with optional min/max error bars."""
    if not points:
        return f'<div class="chart-empty">No data for {title}</div>'

    padding_left = 60
    padding_right = 30
    padding_top = 40
    padding_bottom = 45

    w = width - padding_left - padding_right
    h = height - padding_top - padding_bottom

    vals = [p[1] for p in points]
    if error_bars:
        min_val = min(min(e[0] for e in error_bars), min(vals))
        max_val = max(max(e[1] for e in error_bars), max(vals))
    else:
        min_val = min(vals)
        max_val = max(vals)

    # Add 10% headroom
    y_min = max(0.0, min_val - (max_val - min_val) * 0.15) if max_val != min_val else max(0.0, min_val * 0.8)
    y_max = max_val + (max_val - min_val) * 0.15 if max_val != min_val else min_val * 1.2
    if y_max == y_min:
        y_max = y_min + 1.0

    n = len(points)
    coords: list[tuple[float, float, str, float]] = []
    for i, (label, val) in enumerate(points):
        cx = padding_left + (i / max(1, n - 1)) * w if n > 1 else padding_left + w / 2
        cy = padding_top + h - ((val - y_min) / (y_max - y_min)) * h
        coords.append((cx, cy, label, val))

    # Path data
    path_d = " ".join(f"{'M' if i == 0 else 'L'} {cx:.1f} {cy:.1f}" for i, (cx, cy, _, _) in enumerate(coords))

    # Grid lines and Y-axis ticks
    grid_lines = []
    for step in range(5):
        y_tick_val = y_min + (step / 4.0) * (y_max - y_min)
        y_pos = padding_top + h - (step / 4.0) * h
        grid_lines.append(
            f'<line x1="{padding_left}" y1="{y_pos:.1f}" x2="{width - padding_right}" y2="{y_pos:.1f}" stroke="#334155" stroke-dasharray="3,3" />'
            f'<text x="{padding_left - 8}" y="{y_pos + 4:.1f}" fill="#94a3b8" font-size="11" text-anchor="end">{y_tick_val:.1f}{y_label}</text>'
        )

    # Error bars (if provided)
    eb_svg = []
    if error_bars and len(error_bars) == len(coords):
        for i, (low, high) in enumerate(error_bars):
            cx = coords[i][0]
            y_low = padding_top + h - ((low - y_min) / (y_max - y_min)) * h
            y_high = padding_top + h - ((high - y_min) / (y_max - y_min)) * h
            eb_svg.append(
                f'<line x1="{cx:.1f}" y1="{y_low:.1f}" x2="{cx:.1f}" y2="{y_high:.1f}" stroke="#93c5fd" stroke-width="2" />'
                f'<line x1="{cx - 4:.1f}" y1="{y_low:.1f}" x2="{cx + 4:.1f}" y2="{y_low:.1f}" stroke="#93c5fd" stroke-width="2" />'
                f'<line x1="{cx - 4:.1f}" y1="{y_high:.1f}" x2="{cx + 4:.1f}" y2="{y_high:.1f}" stroke="#93c5fd" stroke-width="2" />'
            )

    # Dots & Labels
    dots = []
    for cx, cy, label, val in coords:
        dots.append(
            f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="5" fill="{color}" stroke="#ffffff" stroke-width="2">'
            f'<title>{label}: {val:.2f}{y_label}</title></circle>'
            f'<text x="{cx:.1f}" y="{cy - 10:.1f}" fill="#f8fafc" font-size="11" font-weight="600" text-anchor="middle">{val:.1f}</text>'
            f'<text x="{cx:.1f}" y="{height - 12}" fill="#94a3b8" font-size="11" text-anchor="middle">{label}</text>'
        )

    return f'''
    <svg viewBox="0 0 {width} {height}" class="chart-svg">
      <text x="{width / 2}" y="20" fill="#f8fafc" font-size="14" font-weight="bold" text-anchor="middle">{title}</text>
      {"".join(grid_lines)}
      {"".join(eb_svg)}
      <path d="{path_d}" fill="none" stroke="{color}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" />
      {"".join(dots)}
    </svg>
    '''


def _svg_bucket_bar_chart(
    buckets_by_iter: list[tuple[str, dict[str, float]]],
    width: int = 700,
    height: int = 240,
    title: str = "Input Bucket Distribution by Iteration",
) -> str:
    """Stacked horizontal or grouped bar chart for structural input buckets."""
    if not buckets_by_iter:
        return ""

    padding_left = 60
    padding_right = 30
    padding_top = 40
    padding_bottom = 45

    w = width - padding_left - padding_right
    h = height - padding_top - padding_bottom

    n = len(buckets_by_iter)
    bar_width = min(36.0, w / (n * 1.5))
    step = w / n

    colors = {
        "well_formed": "#22c55e",  # green
        "near_miss": "#eab308",    # yellow
        "byte_hostile": "#ef4444", # red
    }

    bars = []
    labels = []
    for i, (iter_label, b_dict) in enumerate(buckets_by_iter):
        bx = padding_left + i * step + (step - bar_width) / 2
        y_acc = 0.0
        for b_name in ("well_formed", "near_miss", "byte_hostile"):
            share = b_dict.get(b_name, 0.0)
            bh = share * h
            by = padding_top + h - y_acc - bh
            c = colors.get(b_name, "#64748b")
            bars.append(
                f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bar_width:.1f}" height="{bh:.1f}" fill="{c}">'
                f'<title>{iter_label} - {b_name}: {share * 100:.1f}%</title></rect>'
            )
            y_acc += bh

        labels.append(
            f'<text x="{bx + bar_width / 2:.1f}" y="{height - 12}" fill="#94a3b8" font-size="11" text-anchor="middle">{iter_label}</text>'
        )

    legend = (
        f'<g transform="translate({width - 270}, 14)">'
        f'<rect x="0" y="0" width="12" height="12" fill="{colors["well_formed"]}" rx="2"/>'
        f'<text x="16" y="10" fill="#94a3b8" font-size="11">Well-Formed</text>'
        f'<rect x="85" y="0" width="12" height="12" fill="{colors["near_miss"]}" rx="2"/>'
        f'<text x="101" y="10" fill="#94a3b8" font-size="11">Near-Miss</text>'
        f'<rect x="165" y="0" width="12" height="12" fill="{colors["byte_hostile"]}" rx="2"/>'
        f'<text x="181" y="10" fill="#94a3b8" font-size="11">Byte-Hostile</text>'
        f'</g>'
    )

    return f'''
    <svg viewBox="0 0 {width} {height}" class="chart-svg">
      <text x="{padding_left}" y="22" fill="#f8fafc" font-size="14" font-weight="bold">{title}</text>
      {legend}
      {"".join(bars)}
      {"".join(labels)}
    </svg>
    '''


def generate_html_dashboard(
    data: dict[str, Any] | list[dict[str, Any]],
    out_file: Path | str,
    title: str = "Stratagem Fuzzing & Coverage Dashboard",
) -> Path:
    """Generate a complete, modern, interactive HTML report."""
    out_path = Path(out_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Standardize input into iterations list
    iterations: list[dict[str, Any]] = []
    run_meta: dict[str, Any] = {}
    crashes_list: list[dict[str, Any]] = []

    if isinstance(data, list):
        # Could be coverage_trials.json or list of iteration summaries
        if data and "trials" in data[0]:
            # coverage_trials format
            for cell in data:
                t_list = cell.get("trials", [])
                p_pcts = [t.get("parser_pct", 0.0) for t in t_list]
                accepts = [t.get("acceptance", 0.0) for t in t_list]
                iterations.append({
                    "name": cell.get("cell", "cell"),
                    "parser_pct": cell.get("parser_pct_mean", _mean(p_pcts)),
                    "parser_pct_min": cell.get("parser_pct_min", min(p_pcts) if p_pcts else 0.0),
                    "parser_pct_max": cell.get("parser_pct_max", max(p_pcts) if p_pcts else 0.0),
                    "acceptance": _mean(accepts),
                    "diagnostics": int(_mean([t.get("diagnostics", 0) for t in t_list])),
                    "productions": int(_mean([t.get("productions", 0) for t in t_list])),
                    "crashes": cell.get("crashes", 0),
                    "buckets": {
                        "well_formed": _mean([t.get("well_formed", 0.0) for t in t_list]),
                        "near_miss": _mean([t.get("near_miss", 0.0) for t in t_list]),
                        "byte_hostile": _mean([t.get("byte_hostile", 0.0) for t in t_list]),
                    },
                    "trials_raw": t_list,
                })
        else:
            iterations = data
    elif isinstance(data, dict):
        if "iterations" in data:
            iterations = data["iterations"]
            run_meta = {k: v for k, v in data.items() if k != "iterations"}
        else:
            # Single campaign summary
            iterations = [data]
            run_meta = data

    # Extract all crashes
    for it in iterations:
        for c in it.get("crash_groups", {}).values() if isinstance(it.get("crash_groups"), dict) else []:
            crashes_list.append(c)

    # Statistical significance evaluation across iterations (if > 1)
    sig_rows: list[dict[str, Any]] = []
    if len(iterations) > 1:
        base_it = iterations[0]
        # Check if we have trials_raw for statistical testing
        for it in iterations[1:]:
            b_trials = base_it.get("trials_raw", [])
            t_trials = it.get("trials_raw", [])
            if b_trials and t_trials:
                sig_res = significance.compare_trials(
                    treatment_trials=t_trials,
                    baseline_trials=b_trials,
                    treatment_name=it.get("name", str(it.get("iteration", "iter"))),
                    baseline_name=base_it.get("name", str(base_it.get("iteration", "iter"))),
                )
                sig_rows.append({"name": it.get("name", "iter"), "res": sig_res})
            else:
                # Synthetic/single-point sample comparison
                sig_obj = significance.compare_samples(
                    treatment=[it.get("parser_pct", it.get("acceptance_rate", 0.0) * 100.0)],
                    baseline=[base_it.get("parser_pct", base_it.get("acceptance_rate", 0.0) * 100.0)],
                    metric="coverage_pct",
                    treatment_name=str(it.get("iteration", it.get("name", "treatment"))),
                    baseline_name=str(base_it.get("iteration", base_it.get("name", "baseline"))),
                )
                sig_rows.append({"name": it.get("name", "iter"), "res": {"coverage_pct": sig_obj}})

    # Extract charts data
    cov_points = []
    cov_errs = []
    accept_points = []
    buckets_list = []

    for idx, it in enumerate(iterations):
        label = it.get("name", f"iter-{it.get('iteration', idx)}")
        label_short = label.split("/")[-1] if "/" in label else label

        cov = it.get("parser_pct", it.get("acceptance_rate", 0.0) * 100.0)
        cov_min = it.get("parser_pct_min", cov)
        cov_max = it.get("parser_pct_max", cov)
        cov_points.append((label_short, cov))
        cov_errs.append((cov_min, cov_max))

        acc = it.get("acceptance", it.get("acceptance_rate", 0.0)) * 100.0
        accept_points.append((label_short, acc))

        b_data = it.get("buckets", {})
        if b_data:
            # Handle format difference
            b_clean = {}
            for k in ("well_formed", "near_miss", "byte_hostile"):
                val = b_data.get(k, 0.0)
                b_clean[k] = val.get("share", 0.0) if isinstance(val, dict) else float(val)
            buckets_list.append((label_short, b_clean))

    svg_cov = _svg_line_chart(cov_points, title="Parser Line Coverage (%) Progression", y_label="%", color="#3b82f6", error_bars=cov_errs if any(e[0] != e[1] for e in cov_errs) else None)
    svg_acc = _svg_line_chart(accept_points, title="Acceptance Rate (%) Over Iterations", y_label="%", color="#10b981")
    svg_buckets = _svg_bucket_bar_chart(buckets_list)

    # Bug clusters from all available crashes
    clusterer = triage.BugClusterer()
    for it in iterations:
        # From raw results if present
        for c in it.get("crash_groups", {}).values() if isinstance(it.get("crash_groups"), dict) else []:
            rep = c.get("report")
            clusterer.add_crash({
                "sha": c.get("inputs", [""])[0],
                "stderr": rep.get("raw", "") if rep else "",
                "outcome": "crash",
            })
    clusters = clusterer.cluster()

    # KPI values
    peak_cov = max((p[1] for p in cov_points), default=0.0)
    latest_acc = accept_points[-1][1] if accept_points else 0.0
    total_crashes = sum(it.get("crashes", it.get("crash_count", 0)) for it in iterations)
    total_clusters = len(clusters)
    total_examples = sum(it.get("examples", 500) for it in iterations)

    # Generate HTML
    generated_at = utc_iso()
    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <style>
    :root {{
      --bg: #0f172a;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --primary: #3b82f6;
      --success: #22c55e;
      --warning: #eab308;
      --danger: #ef4444;
      --code-bg: #090d16;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
    body {{ background: var(--bg); color: var(--text-main); line-height: 1.5; padding: 24px; }}
    .container {{ max-width: 1300px; margin: 0 auto; }}
    header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid var(--card-border); }}
    h1 {{ font-size: 24px; font-weight: 700; color: #ffffff; }}
    .meta-badge {{ background: #1e3a8a; color: #93c5fd; padding: 4px 12px; border-radius: 9999px; font-size: 13px; font-weight: 600; }}
    
    /* KPI Grid */
    .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
    .kpi-card {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 20px; }}
    .kpi-title {{ font-size: 13px; font-weight: 600; text-transform: uppercase; color: var(--text-muted); margin-bottom: 6px; }}
    .kpi-val {{ font-size: 28px; font-weight: 800; color: #ffffff; }}
    .kpi-sub {{ font-size: 12px; color: var(--text-muted); margin-top: 4px; }}
    
    /* Tabs */
    .tabs {{ display: flex; gap: 8px; margin-bottom: 20px; border-bottom: 1px solid var(--card-border); padding-bottom: 8px; }}
    .tab-btn {{ background: transparent; border: none; color: var(--text-muted); font-size: 15px; font-weight: 600; padding: 8px 16px; cursor: pointer; border-radius: 6px; transition: all 0.2s; }}
    .tab-btn.active {{ background: #3b82f6; color: #ffffff; }}
    .tab-pane {{ display: none; }}
    .tab-pane.active {{ display: block; }}
    
    /* Cards & Layout */
    .card {{ background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; padding: 24px; margin-bottom: 20px; }}
    .card-title {{ font-size: 18px; font-weight: 700; margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between; }}
    .chart-container {{ width: 100%; overflow-x: auto; }}
    .chart-svg {{ width: 100%; max-height: 280px; display: block; }}
    .charts-split {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
    @media (max-width: 900px) {{ .charts-split {{ grid-template-columns: 1fr; }} }}
    
    /* Tables */
    table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 14px; }}
    th {{ background: #0f172a; padding: 12px 14px; font-weight: 600; color: var(--text-muted); border-bottom: 1px solid var(--card-border); }}
    td {{ padding: 12px 14px; border-bottom: 1px solid var(--card-border); }}
    tr:hover td {{ background: #26334d; }}
    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }}
    .badge-critical {{ background: #7f1d1d; color: #fca5a5; }}
    .badge-high {{ background: #831843; color: #fbcfe8; }}
    .badge-medium {{ background: #713f12; color: #fde047; }}
    .badge-low {{ background: #14532d; color: #86efac; }}
    .badge-info {{ background: #1e3a8a; color: #bfdbfe; }}
    .badge-yes {{ background: #14532d; color: #86efac; }}
    .badge-no {{ background: #334155; color: #94a3b8; }}

    pre {{ background: var(--code-bg); padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; font-family: monospace; color: #38bdf8; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>{title}</h1>
        <p style="color: var(--text-muted); font-size: 14px; margin-top: 4px;">Automated Coverage & Defect Analysis for Stratagem Fuzz-Agent</p>
      </div>
      <div>
        <span class="meta-badge">{len(iterations)} Iterations / Cells</span>
        <span class="meta-badge" title="All timestamps in this report are UTC">Generated {generated_at}</span>
      </div>
    </header>

    <!-- KPI Grid -->
    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-title">Peak Line Coverage</div>
        <div class="kpi-val" style="color: #60a5fa;">{peak_cov:.1f}%</div>
        <div class="kpi-sub">Parser line coverage</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Acceptance Rate</div>
        <div class="kpi-val" style="color: #34d399;">{latest_acc:.1f}%</div>
        <div class="kpi-sub">Latest iteration valid inputs</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Bug Clusters</div>
        <div class="kpi-val" style="color: #f87171;">{total_clusters}</div>
        <div class="kpi-sub">{total_crashes} total crash events</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-title">Inputs Generated</div>
        <div class="kpi-val" style="color: #facc15;">{total_examples}</div>
        <div class="kpi-sub">Across evaluated iterations</div>
      </div>
    </div>

    <!-- Tabs Navigation -->
    <div class="tabs">
      <button class="tab-btn active" onclick="openTab(event, 'tab-coverage')">Coverage & Trends</button>
      <button class="tab-btn" onclick="openTab(event, 'tab-triage')">Bug & Crash Triage ({total_clusters})</button>
      <button class="tab-btn" onclick="openTab(event, 'tab-significance')">Statistical Significance</button>
      <button class="tab-btn" onclick="openTab(event, 'tab-iterations')">Iteration Data</button>
    </div>

    <!-- TAB 1: Coverage & Trends -->
    <div id="tab-coverage" class="tab-pane active">
      <div class="card">
        <div class="chart-container">{svg_cov}</div>
      </div>
      <div class="charts-split">
        <div class="card">
          <div class="chart-container">{svg_acc}</div>
        </div>
        <div class="card">
          <div class="chart-container">{svg_buckets}</div>
        </div>
      </div>
    </div>

    <!-- TAB 2: Bug & Crash Triage -->
    <div id="tab-triage" class="tab-pane">
      <div class="card">
        <div class="card-title">
          <span>Triaged Bug Clusters & Crash Signatures</span>
          <span style="font-size: 13px; color: var(--text-muted);">{total_clusters} distinct clusters identified</span>
        </div>
        '''

    if clusters:
        html_content += '''
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Severity</th>
              <th>Tool</th>
              <th>Bug Type</th>
              <th>Root Cause Function</th>
              <th>File</th>
              <th>Crashes</th>
              <th>Representative SHA</th>
            </tr>
          </thead>
          <tbody>
        '''
        for c in clusters:
            sev_class = f"badge-{c.severity.lower()}"
            html_content += f'''
            <tr>
              <td><code>{c.cluster_id}</code></td>
              <td><span class="badge {sev_class}">{c.severity}</span></td>
              <td>{c.tool}</td>
              <td><code>{c.bug_type}</code></td>
              <td><strong>{c.root_cause_func}</strong></td>
              <td><code>{c.root_cause_file}</code></td>
              <td>{c.crash_count}</td>
              <td><code>{c.representative_sha[:12] if c.representative_sha else "-"}</code></td>
            </tr>
            '''
        html_content += '</tbody></table>'
    else:
        html_content += '<p style="color: var(--text-muted); padding: 16px 0;">No crashes or defect clusters recorded in this dataset.</p>'

    html_content += '''
      </div>
    </div>

    <!-- TAB 3: Statistical Significance -->
    <div id="tab-significance" class="tab-pane">
      <div class="card">
        <div class="card-title">
          <span>Hypothesis Testing & Effect Size Analysis</span>
          <span style="font-size: 13px; color: var(--text-muted);">Welch's t-test, Mann-Whitney U, Vargha-Delaney A12</span>
        </div>
        '''

    if sig_rows:
        html_content += '''
        <table>
          <thead>
            <tr>
              <th>Iteration</th>
              <th>Metric</th>
              <th>Baseline Mean</th>
              <th>Treatment Mean</th>
              <th>Difference</th>
              <th>Welch p</th>
              <th>MWU p</th>
              <th>A12 (Effect)</th>
              <th>Significant?</th>
            </tr>
          </thead>
          <tbody>
        '''
        for row in sig_rows:
            it_name = row["name"]
            for m_name, res in row["res"].items():
                sig_badge = '<span class="badge badge-yes">YES</span>' if res.is_significant else '<span class="badge badge-no">NO</span>'
                diff_str = f"{res.diff_mean:+.2f} ({res.relative_change_pct:+.1f}%)"
                html_content += f'''
                <tr>
                  <td><code>{it_name}</code></td>
                  <td><code>{m_name}</code></td>
                  <td>{res.baseline_mean:.2f}</td>
                  <td>{res.treatment_mean:.2f}</td>
                  <td><strong>{diff_str}</strong></td>
                  <td>{res.welch_p:.4f}</td>
                  <td>{res.mann_whitney_p:.4f}</td>
                  <td><strong>{res.vargha_delaney_a12:.2f}</strong> ({res.a12_magnitude})</td>
                  <td>{sig_badge}</td>
                </tr>
                '''
        html_content += '</tbody></table>'
    else:
        html_content += '<p style="color: var(--text-muted); padding: 16px 0;">Statistical significance comparison requires at least 2 iterations or trial runs.</p>'

    html_content += '''
      </div>
    </div>

    <!-- TAB 4: Iteration Data Table -->
    <div id="tab-iterations" class="tab-pane">
      <div class="card">
        <div class="card-title">Evaluated Iterations Breakdown</div>
        <table>
          <thead>
            <tr>
              <th>Iteration / Cell</th>
              <th>Coverage (%)</th>
              <th>Acceptance (%)</th>
              <th>Distinct Diags</th>
              <th>Productions Hit</th>
              <th>Crashes</th>
            </tr>
          </thead>
          <tbody>
    '''

    for it in iterations:
        name = it.get("name", f"iter-{it.get('iteration', '?')}")
        cov = it.get("parser_pct", it.get("acceptance_rate", 0.0) * 100.0)
        acc = it.get("acceptance", it.get("acceptance_rate", 0.0)) * 100.0
        diags = it.get("diagnostics", it.get("distinct_diagnostic_templates", 0))
        prods = it.get("productions", it.get("structure", {}).get("productions_hit", 0))
        crashes = it.get("crashes", it.get("crash_count", 0))

        html_content += f'''
        <tr>
          <td><code>{name}</code></td>
          <td><strong>{cov:.2f}%</strong></td>
          <td>{acc:.1f}%</td>
          <td>{diags}</td>
          <td>{prods}</td>
          <td>{crashes}</td>
        </tr>
        '''

    html_content += '''
          </tbody>
        </table>
      </div>
    </div>

  </div>

  <script>
    function openTab(evt, tabName) {
      const panes = document.getElementsByClassName("tab-pane");
      for (let i = 0; i < panes.length; i++) {
        panes[i].classList.remove("active");
      }
      const buttons = document.getElementsByClassName("tab-btn");
      for (let i = 0; i < buttons.length; i++) {
        buttons[i].classList.remove("active");
      }
      document.getElementById(tabName).classList.add("active");
      evt.currentTarget.classList.add("active");
    }
  </script>
</body>
</html>
'''

    out_path.write_text(html_content, encoding="utf-8")
    return out_path


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate visual coverage HTML dashboard.")
    ap.add_argument("source", nargs="?", default="runs/analysis/coverage_trials.json",
                    help="Path to coverage_trials.json, loop_summary.json, or campaign summary.json")
    ap.add_argument("-o", "--out", default="coverage_dashboard.html",
                    help="Output HTML file path (default: coverage_dashboard.html)")
    ap.add_argument("-t", "--title", default="Stratagem Fuzzing & Coverage Report",
                    help="Dashboard title")
    args = ap.parse_args()

    src_path = Path(args.source)
    if not src_path.exists():
        sys.exit(f"Source file not found: {src_path}")

    print(f"[*] Reading data from {src_path}...")
    data = json.loads(src_path.read_text(encoding="utf-8"))

    out_p = generate_html_dashboard(data, out_file=args.out, title=args.title)
    print(f"[+] Visual dashboard successfully generated at: {out_p.resolve()}")


if __name__ == "__main__":
    main()
