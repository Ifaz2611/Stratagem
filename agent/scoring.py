"""Shared scoring for campaign summaries.

Three features need to answer the same question: *was this strategy better?*
The ensemble vote, the strategy cache and the few-shot library must not each
invent their own answer, or a strategy could win an ensemble and then be ranked
last in the cache. This module is the single definition.

The score is deliberately dominated by crashes. A campaign that finds one crash
is worth more than one that reaches an extra parser diagnostic, because the
loop exists to find memory-safety bugs. Every other component is a tie-breaker
for the common case where neither campaign crashed.

All functions tolerate partial summaries. A replay of an old run, a screening
campaign that ended early, or a summary written by an earlier version of the
project must not raise here: a scoring crash would stop a run that is otherwise
healthy.
"""
from __future__ import annotations

import math
from typing import Any

# The acceptance band the loop steers toward. Outside this band a strategy is
# either bouncing off the parser's front door or never exercising error paths.
TARGET_ACCEPTANCE_LOW = 0.40
TARGET_ACCEPTANCE_HIGH = 0.70

# Weights for the scalar score. They are exposed as module constants so a
# report can explain the ranking, and so a future experiment can change them in
# one place rather than chasing literals through three modules.
WEIGHT_CRASH_GROUP = 50.0
WEIGHT_CRASH = 5.0
WEIGHT_PRODUCTION = 5.0
WEIGHT_DIAGNOSTIC = 1.0
WEIGHT_ACCEPTANCE = 4.0
WEIGHT_DEPTH = 0.2
WEIGHT_SHAPE = 0.5
WEIGHT_HARNESS_ERROR = -2.0
WEIGHT_TIMEOUT = -0.5


def _summary_structure(summary: dict) -> dict:
    st = summary.get("structure") or {}
    return st if isinstance(st, dict) else {}


def _number(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def acceptance_fit(rate: float) -> float:
    """How well an acceptance rate matches the band the loop is steering to.

    1.0 inside the band, falling linearly to 0.0 at the extremes. A strategy at
    0% and one at 100% are both uninformative, for opposite reasons.
    """
    if TARGET_ACCEPTANCE_LOW <= rate <= TARGET_ACCEPTANCE_HIGH:
        return 1.0
    if rate < TARGET_ACCEPTANCE_LOW:
        distance = TARGET_ACCEPTANCE_LOW - rate
        span = TARGET_ACCEPTANCE_LOW
    else:
        distance = rate - TARGET_ACCEPTANCE_HIGH
        span = 1.0 - TARGET_ACCEPTANCE_HIGH
    if span <= 0:
        return 0.0
    return max(0.0, 1.0 - distance / span)


def summary_components(summary: dict) -> dict[str, float]:
    """Raw, explainable components of a campaign summary.

    Kept separate from the scalar score so the ensemble can rank candidates on
    individual dimensions (a Borda vote) rather than on one opaque number.
    """
    st = _summary_structure(summary)
    crash_groups = summary.get("crash_groups") or {}
    if isinstance(crash_groups, dict):
        groups = len(crash_groups)
    elif isinstance(crash_groups, (list, tuple, set)):
        groups = len(crash_groups)
    else:
        groups = 0

    total_prods = _number(st.get("productions_total"), 0.0)
    hit_prods = _number(st.get("productions_hit"), 0.0)
    production_rate = hit_prods / total_prods if total_prods > 0 else 0.0

    acceptance = _number(summary.get("acceptance_rate"), 0.0)
    examples = _number(summary.get("examples"), 0.0)
    wall_clock = _number(summary.get("wall_clock_s"), 0.0)
    throughput = examples / wall_clock if wall_clock > 0 else 0.0

    return {
        "crash_groups": float(groups),
        "crash_count": _number(summary.get("crash_count"), 0.0),
        "productions": hit_prods,
        "production_rate": production_rate,
        "diagnostics": _number(summary.get("distinct_diagnostic_templates"), 0.0),
        "acceptance": acceptance,
        "acceptance_fit": acceptance_fit(acceptance),
        "max_depth": _number(st.get("max_depth_seen"), 0.0),
        "shape_rate": _number(summary.get("shape_rate",
                                           summary.get("xml_shaped_rate")), 0.0),
        "throughput": throughput,
        "harness_errors": _number((summary.get("outcomes") or {}).get("harness_error"), 0.0),
        "timeouts": _number(summary.get("timeout_count"), 0.0),
    }


def score_summary(summary: dict) -> float:
    """A single scalar fitness for a campaign summary.

    Higher is better. The crash term is dominant by three orders of magnitude,
    which is intentional: a crash is the objective, and every other signal is a
    proxy used to make progress between crashes.
    """
    c = summary_components(summary)
    return (
        WEIGHT_CRASH_GROUP * c["crash_groups"]
        + WEIGHT_CRASH * c["crash_count"]
        + WEIGHT_PRODUCTION * c["production_rate"]
        + WEIGHT_DIAGNOSTIC * c["diagnostics"]
        + WEIGHT_ACCEPTANCE * c["acceptance_fit"]
        + WEIGHT_DEPTH * math.log1p(max(0.0, c["max_depth"]))
        + WEIGHT_SHAPE * c["shape_rate"]
        + WEIGHT_HARNESS_ERROR * c["harness_errors"]
        + WEIGHT_TIMEOUT * c["timeouts"]
    )


def explain(summary: dict) -> dict[str, float]:
    """Components plus the final score, for reports and debugging."""
    c = summary_components(summary)
    c["score"] = round(score_summary(summary), 4)
    return {k: round(v, 4) for k, v in c.items()}
