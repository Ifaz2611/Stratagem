"""Statistical significance testing for fuzzing coverage improvements.

Provides mathematically rigorous, pure-Python statistical evaluation without
external scipy/numpy dependencies:
  * Welch's two-sample t-test (unequal variances, exact Student's t distribution via regularized incomplete beta)
  * Mann-Whitney U test (non-parametric rank-sum test with tie & continuity correction)
  * Vargha-Delaney A12 effect size (standard fuzzing benchmark effect magnitude)
  * Cohen's d and Hedges' g (standardized difference with small-sample bias correction)
  * Empirical bootstrap 95% confidence intervals for mean coverage difference
  * Cross-iteration progression evaluation & multi-metric hypothesis testing
"""
from __future__ import annotations

import json
import math
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


def _betacf(a: float, b: float, x: float, max_iter: int = 200, eps: float = 3.0e-12) -> float:
    """Continued fraction approximation for incomplete beta function."""
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < 1e-30:
        d = 1e-30
    d = 1.0 / d
    h = d

    for m in range(1, max_iter + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < 1e-30:
            d = 1e-30
        c = 1.0 + aa / c
        if abs(c) < 1e-30:
            c = 1e-30
        d = 1.0 / d
        h *= d * c

        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < 1e-30:
            d = 1e-30
        c = 1.0 + aa / c
        if abs(c) < 1e-30:
            c = 1e-30
        d = 1.0 / d
        del_val = d * c
        h *= del_val
        if abs(del_val - 1.0) < eps:
            break

    return h


def _ibeta(a: float, b: float, x: float) -> float:
    """Regularized incomplete beta function I_x(a, b)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    ln_beta = math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)
    bt = math.exp(math.log(x) * a + math.log(1.0 - x) * b - ln_beta)
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _betacf(a, b, x) / a
    else:
        return 1.0 - bt * _betacf(b, a, 1.0 - x) / b


def _student_t_p_value(t: float, df: float) -> float:
    """Two-tailed p-value for Student's t distribution with df degrees of freedom."""
    if df <= 0.0:
        return 1.0
    x = df / (df + t * t)
    return _ibeta(df / 2.0, 0.5, x)


def _mean(seq: Sequence[float]) -> float:
    return sum(seq) / len(seq) if seq else 0.0


def _variance(seq: Sequence[float], ddof: int = 1) -> float:
    n = len(seq)
    if n <= ddof:
        return 0.0
    m = _mean(seq)
    return sum((x - m) ** 2 for x in seq) / (n - ddof)


def _stdev(seq: Sequence[float], ddof: int = 1) -> float:
    return math.sqrt(_variance(seq, ddof))


def welch_t_test(treatment: Sequence[float], baseline: Sequence[float]) -> tuple[float, float, float]:
    """Perform Welch's two-sample t-test for unequal variances.

    Returns:
        (t_statistic, degrees_of_freedom, two_tailed_p_value)
    """
    n1, n2 = len(treatment), len(baseline)
    if n1 < 2 or n2 < 2:
        return 0.0, 1.0, 1.0

    m1, m2 = _mean(treatment), _mean(baseline)
    v1, v2 = _variance(treatment, 1), _variance(baseline, 1)

    se1 = v1 / n1
    se2 = v2 / n2
    denom = se1 + se2

    if denom <= 0.0:
        # Zero variance: identical samples or constant
        return (0.0, float(n1 + n2 - 2), 1.0) if m1 == m2 else (float("inf"), 1.0, 0.0)

    t = (m1 - m2) / math.sqrt(denom)

    # Welch-Satterthwaite equation for degrees of freedom
    num_df = (se1 + se2) ** 2
    den_df = (se1 ** 2) / (n1 - 1) + (se2 ** 2) / (n2 - 1)
    df = num_df / den_df if den_df > 0 else float(n1 + n2 - 2)

    p_value = _student_t_p_value(t, df)
    return t, df, p_value


def mann_whitney_u_test(treatment: Sequence[float], baseline: Sequence[float]) -> tuple[float, float]:
    """Perform two-tailed Mann-Whitney U test with tie correction and continuity correction.

    Returns:
        (u_statistic, two_tailed_p_value)
    """
    n1, n2 = len(treatment), len(baseline)
    if n1 == 0 or n2 == 0:
        return 0.0, 1.0

    # Combine and rank
    combined = [(val, 1) for val in treatment] + [(val, 2) for val in baseline]
    combined.sort(key=lambda item: item[0])

    N = n1 + n2
    ranks = [0.0] * N
    i = 0
    ties: list[int] = []

    while i < N:
        j = i
        while j < N and combined[j][0] == combined[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks[k] = avg_rank
        tie_count = j - i
        if tie_count > 1:
            ties.append(tie_count)
        i = j

    r1 = sum(ranks[k] for k in range(N) if combined[k][1] == 1)
    u1 = r1 - n1 * (n1 + 1) / 2.0
    u2 = n1 * n2 - u1
    u = min(u1, u2)

    mu_u = n1 * n2 / 2.0
    tie_corr = sum(t ** 3 - t for t in ties) / (N * (N - 1)) if N > 1 else 0.0
    var_u = (n1 * n2 / 12.0) * ((N + 1) - tie_corr)

    if var_u <= 0.0:
        return u, 1.0

    sd_u = math.sqrt(var_u)
    # Continuity correction
    z = (abs(u - mu_u) - 0.5) / sd_u
    p_value = math.erfc(abs(z) / math.sqrt(2.0))
    return u, min(1.0, max(0.0, p_value))


def vargha_delaney_a12(treatment: Sequence[float], baseline: Sequence[float]) -> tuple[float, str]:
    """Calculate the Vargha-Delaney A12 effect size statistic.

    A12 measures the probability that a random draw from treatment is greater than
    a random draw from baseline.
      * A12 = 0.5: No effect (identical)
      * A12 > 0.5: Treatment outperforms baseline
      * A12 < 0.5: Baseline outperforms treatment

    Returns:
        (a12_value, magnitude) where magnitude is one of:
        "negligible", "small", "medium", "large"
    """
    n1, n2 = len(treatment), len(baseline)
    if n1 == 0 or n2 == 0:
        return 0.5, "negligible"

    combined = [(val, 1) for val in treatment] + [(val, 2) for val in baseline]
    combined.sort(key=lambda item: item[0])

    N = n1 + n2
    ranks = [0.0] * N
    i = 0
    while i < N:
        j = i
        while j < N and combined[j][0] == combined[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks[k] = avg_rank
        i = j

    r1 = sum(ranks[k] for k in range(N) if combined[k][1] == 1)
    a12 = (r1 / n1 - (n1 + 1) / 2.0) / n2

    diff = abs(a12 - 0.5)
    if diff < 0.06:
        mag = "negligible"
    elif diff < 0.14:
        mag = "small"
    elif diff < 0.21:
        mag = "medium"
    else:
        mag = "large"

    return round(a12, 4), mag


def cohens_d(treatment: Sequence[float], baseline: Sequence[float]) -> float:
    """Calculate Cohen's d standardized effect size."""
    n1, n2 = len(treatment), len(baseline)
    if n1 < 2 or n2 < 2:
        return 0.0
    m1, m2 = _mean(treatment), _mean(baseline)
    v1, v2 = _variance(treatment, 1), _variance(baseline, 1)
    s_pooled = math.sqrt(((n1 - 1) * v1 + (n2 - 1) * v2) / (n1 + n2 - 2))
    return (m1 - m2) / s_pooled if s_pooled > 0 else 0.0


def hedges_g(treatment: Sequence[float], baseline: Sequence[float]) -> float:
    """Calculate Hedges' g (Cohen's d with small-sample bias correction)."""
    d = cohens_d(treatment, baseline)
    df = len(treatment) + len(baseline) - 2
    if df < 1:
        return d
    correction = 1.0 - (3.0 / (4.0 * df - 1.0))
    return round(d * correction, 4)


def bootstrap_ci_difference(
    treatment: Sequence[float],
    baseline: Sequence[float],
    n_bootstraps: int = 2000,
    ci: float = 0.95,
    seed: int = 42,
) -> tuple[float, float]:
    """Compute empirical bootstrap confidence interval for mean difference (treatment - baseline)."""
    if not treatment or not baseline:
        return 0.0, 0.0

    rng = random.Random(seed)
    diffs: list[float] = []
    n1, n2 = len(treatment), len(baseline)

    for _ in range(n_bootstraps):
        s1 = [treatment[rng.randrange(n1)] for _ in range(n1)]
        s2 = [baseline[rng.randrange(n2)] for _ in range(n2)]
        diffs.append(_mean(s1) - _mean(s2))

    diffs.sort()
    lower_idx = int(((1.0 - ci) / 2.0) * n_bootstraps)
    upper_idx = int(((1.0 + ci) / 2.0) * n_bootstraps)

    lower = diffs[max(0, lower_idx)]
    upper = diffs[min(n_bootstraps - 1, upper_idx)]
    return round(lower, 4), round(upper, 4)


@dataclass
class SignificanceResult:
    """Result of statistical significance testing between treatment and baseline."""
    metric: str
    baseline_name: str
    treatment_name: str
    baseline_mean: float
    baseline_stdev: float
    baseline_n: int
    treatment_mean: float
    treatment_stdev: float
    treatment_n: int
    diff_mean: float
    relative_change_pct: float
    welch_t: float
    welch_df: float
    welch_p: float
    mann_whitney_u: float
    mann_whitney_p: float
    vargha_delaney_a12: float
    a12_magnitude: str
    hedges_g: float
    ci_95_lower: float
    ci_95_upper: float
    alpha: float = 0.05

    @property
    def is_significant(self) -> bool:
        """Did the comparison achieve statistical significance (Welch or MWU p < alpha)?"""
        return (self.welch_p < self.alpha) or (self.mann_whitney_p < self.alpha)

    @property
    def verdict(self) -> str:
        """Human-readable verdict summarizing the statistical conclusion."""
        if not self.is_significant:
            return (
                f"No statistically significant difference in {self.metric} "
                f"(Welch p={self.welch_p:.4f}, MWU p={self.mann_whitney_p:.4f}, A12={self.vargha_delaney_a12:.2f})"
            )
        direction = "improved" if self.diff_mean > 0 else "degraded"
        return (
            f"Statistically significant {direction} in {self.metric}: "
            f"{self.baseline_mean:.2f} -> {self.treatment_mean:.2f} "
            f"({self.relative_change_pct:+.1f}%, p={min(self.welch_p, self.mann_whitney_p):.4f}, "
            f"{self.a12_magnitude} effect A12={self.vargha_delaney_a12:.2f})"
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "metric": self.metric,
            "baseline": {
                "name": self.baseline_name,
                "mean": round(self.baseline_mean, 3),
                "stdev": round(self.baseline_stdev, 3),
                "n": self.baseline_n,
            },
            "treatment": {
                "name": self.treatment_name,
                "mean": round(self.treatment_mean, 3),
                "stdev": round(self.treatment_stdev, 3),
                "n": self.treatment_n,
            },
            "diff_mean": round(self.diff_mean, 3),
            "relative_change_pct": round(self.relative_change_pct, 2),
            "welch_t_test": {
                "t_stat": round(self.welch_t, 3),
                "df": round(self.welch_df, 2),
                "p_value": round(self.welch_p, 5),
            },
            "mann_whitney_u_test": {
                "u_stat": round(self.mann_whitney_u, 2),
                "p_value": round(self.mann_whitney_p, 5),
            },
            "effect_size": {
                "vargha_delaney_a12": self.vargha_delaney_a12,
                "magnitude": self.a12_magnitude,
                "hedges_g": self.hedges_g,
            },
            "ci_95": [self.ci_95_lower, self.ci_95_upper],
            "is_significant": self.is_significant,
            "verdict": self.verdict,
        }


def compare_samples(
    treatment: Sequence[float],
    baseline: Sequence[float],
    metric: str = "coverage",
    alpha: float = 0.05,
    treatment_name: str = "treatment",
    baseline_name: str = "baseline",
) -> SignificanceResult:
    """Compare two measurement samples and run complete statistical battery."""
    m_base = _mean(baseline)
    s_base = _stdev(baseline)
    m_treat = _mean(treatment)
    s_treat = _stdev(treatment)

    diff = m_treat - m_base
    rel = (diff / m_base * 100.0) if m_base != 0.0 else 0.0

    t_stat, df, welch_p = welch_t_test(treatment, baseline)
    u_stat, mwu_p = mann_whitney_u_test(treatment, baseline)
    a12, a12_mag = vargha_delaney_a12(treatment, baseline)
    g = hedges_g(treatment, baseline)
    ci_low, ci_high = bootstrap_ci_difference(treatment, baseline)

    return SignificanceResult(
        metric=metric,
        baseline_name=baseline_name,
        treatment_name=treatment_name,
        baseline_mean=m_base,
        baseline_stdev=s_base,
        baseline_n=len(baseline),
        treatment_mean=m_treat,
        treatment_stdev=s_treat,
        treatment_n=len(treatment),
        diff_mean=diff,
        relative_change_pct=rel,
        welch_t=t_stat,
        welch_df=df,
        welch_p=welch_p,
        mann_whitney_u=u_stat,
        mann_whitney_p=mwu_p,
        vargha_delaney_a12=a12,
        a12_magnitude=a12_mag,
        hedges_g=g,
        ci_95_lower=ci_low,
        ci_95_upper=ci_high,
        alpha=alpha,
    )


def compare_trials(
    treatment_trials: list[dict],
    baseline_trials: list[dict],
    metrics: list[str] | None = None,
    alpha: float = 0.05,
    treatment_name: str = "treatment",
    baseline_name: str = "baseline",
) -> dict[str, SignificanceResult]:
    """Compare trials dictionaries across multiple metrics."""
    if metrics is None:
        metrics = [
            "parser_pct",
            "acceptance",
            "diagnostics",
            "productions",
            "crashes",
        ]

    out: dict[str, SignificanceResult] = {}
    for m in metrics:
        t_vals = [float(t[m]) for t in treatment_trials if m in t]
        b_vals = [float(b[m]) for b in baseline_trials if m in b]
        if t_vals and b_vals:
            out[m] = compare_samples(
                treatment=t_vals,
                baseline=b_vals,
                metric=m,
                alpha=alpha,
                treatment_name=treatment_name,
                baseline_name=baseline_name,
            )

    return out


def compare_cells(
    trials_data: list[dict],
    treatment_cell: str,
    baseline_cell: str,
    metrics: list[str] | None = None,
    alpha: float = 0.05,
) -> dict[str, SignificanceResult]:
    """Compare two cells directly from a loaded coverage_trials.json structure."""
    cell_map = {c["cell"]: c for c in trials_data if "cell" in c}
    if treatment_cell not in cell_map:
        raise KeyError(f"Treatment cell '{treatment_cell}' not found in trials data.")
    if baseline_cell not in cell_map:
        raise KeyError(f"Baseline cell '{baseline_cell}' not found in trials data.")

    return compare_trials(
        treatment_trials=cell_map[treatment_cell].get("trials", []),
        baseline_trials=cell_map[baseline_cell].get("trials", []),
        metrics=metrics,
        alpha=alpha,
        treatment_name=treatment_cell,
        baseline_name=baseline_cell,
    )


def evaluate_campaign_progress(
    trials_data: list[dict],
    baseline_cell: str | None = None,
    metric: str = "parser_pct",
) -> list[dict[str, Any]]:
    """Evaluate sequential progression across all cells/iterations against a baseline."""
    if not trials_data:
        return []

    if baseline_cell is None:
        baseline_cell = trials_data[0]["cell"]

    cell_map = {c["cell"]: c for c in trials_data if "cell" in c}
    baseline_trials = cell_map[baseline_cell].get("trials", [])
    b_vals = [float(t[metric]) for t in baseline_trials if metric in t]

    results: list[dict[str, Any]] = []
    for entry in trials_data:
        cell_name = entry["cell"]
        t_vals = [float(t[metric]) for t in entry.get("trials", []) if metric in t]
        if not t_vals:
            continue

        sig = compare_samples(
            treatment=t_vals,
            baseline=b_vals,
            metric=metric,
            treatment_name=cell_name,
            baseline_name=baseline_cell,
        )
        results.append({
            "cell": cell_name,
            "mean": round(sig.treatment_mean, 2),
            "diff_from_baseline": round(sig.diff_mean, 2),
            "rel_change_pct": round(sig.relative_change_pct, 1),
            "p_value": round(min(sig.welch_p, sig.mann_whitney_p), 4),
            "a12": sig.vargha_delaney_a12,
            "effect_size": sig.a12_magnitude,
            "significant": sig.is_significant,
        })

    return results


def format_significance_table(results: dict[str, SignificanceResult]) -> str:
    """Format dictionary of significance results as a Markdown table."""
    lines = [
        "| Metric | Baseline Mean (SD) | Treatment Mean (SD) | Diff (Rel %) | Welch p | MWU p | A12 (Effect) | 95% CI | Significant? |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    for m, r in results.items():
        sig_badge = "**YES**" if r.is_significant else "No"
        diff_str = f"{r.diff_mean:+.2f} ({r.relative_change_pct:+.1f}%)"
        base_str = f"{r.baseline_mean:.2f} (±{r.baseline_stdev:.2f})"
        treat_str = f"{r.treatment_mean:.2f} (±{r.treatment_stdev:.2f})"
        a12_str = f"{r.vargha_delaney_a12:.2f} ({r.a12_magnitude})"
        ci_str = f"[{r.ci_95_lower:+.2f}, {r.ci_95_upper:+.2f}]"
        lines.append(
            f"| `{m}` | {base_str} | {treat_str} | {diff_str} | {r.welch_p:.4f} | {r.mann_whitney_p:.4f} | {a12_str} | {ci_str} | {sig_badge} |"
        )
    return "\n".join(lines)


def main() -> None:
    """CLI for statistical significance evaluation."""
    import argparse

    ap = argparse.ArgumentParser(description="Statistical significance evaluation for fuzzing coverage.")
    ap.add_argument("trials_file", nargs="?", default="runs/analysis/coverage_trials.json",
                    help="Path to coverage_trials.json")
    ap.add_argument("--baseline", default=None, help="Baseline cell name (e.g., loop/iter-0)")
    ap.add_argument("--treatment", default=None, help="Treatment cell name (e.g., loop/iter-4)")
    ap.add_argument("-m", "--metric", default="parser_pct", help="Primary metric (default: parser_pct)")
    args = ap.parse_args()

    path = Path(args.trials_file)
    if not path.exists():
        raise SystemExit(f"File not found: {path}")

    data = json.loads(path.read_text(encoding="utf-8"))

    if args.baseline and args.treatment:
        print(f"\nComparing '{args.treatment}' vs baseline '{args.baseline}':\n")
        res = compare_cells(data, args.treatment, args.baseline)
        print(format_significance_table(res))
        print("\nVerdicts:")
        for r in res.values():
            print(f"  * {r.verdict}")
    else:
        base_cell = args.baseline or data[0]["cell"]
        print(f"\nEvaluating Campaign Progression against baseline '{base_cell}' ({args.metric}):\n")
        prog = evaluate_campaign_progress(data, baseline_cell=base_cell, metric=args.metric)
        print("| Cell | Mean | Diff | Rel Change | p-value | A12 | Effect | Significant? |")
        print("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
        for row in prog:
            sig = "**YES**" if row["significant"] else "No"
            print(f"| `{row['cell']}` | {row['mean']}% | {row['diff_from_baseline']:+.2f} | {row['rel_change_pct']:+.1f}% | {row['p_value']} | {row['a12']} | {row['effect_size']} | {sig} |")


if __name__ == "__main__":
    main()
