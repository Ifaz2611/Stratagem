"""Adaptive batch size control based on strategy performance.

Dynamically modulates fuzzer batch sizes in response to feedback:
  * Scales UP when discovering crashes, new grammar productions, or novel diagnostics
  * Scales UP when operating within the healthy acceptance rate band
  * Scales DOWN when generating malformed / invalid shapes
  * Scales DOWN when suffering timeouts or latency stalls
  * Decays gradually when coverage plateaus
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class BatchMetrics:
    """Observed performance and coverage metrics for a single batch."""
    batch_index: int
    batch_size: int
    crashes: int = 0
    new_crashes: int = 0
    accepted: int = 0
    acceptance_rate: float = 0.0
    valid_shape_rate: float = 0.0
    new_productions: int = 0
    new_diagnostics: int = 0
    avg_duration_ms: float = 0.0
    timeouts: int = 0
    slow_inputs: int = 0
    throughput_eps: float = 0.0

    def to_dict(self) -> dict:
        return {
            "batch_index": self.batch_index,
            "batch_size": self.batch_size,
            "crashes": self.crashes,
            "new_crashes": self.new_crashes,
            "accepted": self.accepted,
            "acceptance_rate": round(self.acceptance_rate, 4),
            "valid_shape_rate": round(self.valid_shape_rate, 4),
            "new_productions": self.new_productions,
            "new_diagnostics": self.new_diagnostics,
            "avg_duration_ms": round(self.avg_duration_ms, 2),
            "timeouts": self.timeouts,
            "slow_inputs": self.slow_inputs,
            "throughput_eps": round(self.throughput_eps, 2),
        }


@dataclass
class AdaptiveBatchConfig:
    """Hyperparameters steering batch size adaptation."""
    initial_batch_size: int = 50
    min_batch_size: int = 10
    max_batch_size: int = 500
    growth_factor: float = 1.5
    decay_factor: float = 0.6
    target_acceptance_min: float = 0.20
    target_acceptance_max: float = 0.85
    min_shape_rate: float = 0.50
    reward_new_crash: float = 1.5
    reward_new_production: float = 1.25
    reward_new_diagnostic: float = 1.15
    penalty_timeout: float = 0.70
    plateau_decay: float = 0.90


class AdaptiveBatchController:
    """Manages adaptive batch sizing across fuzzer iterations or campaign phases."""

    def __init__(self, config: AdaptiveBatchConfig | None = None) -> None:
        self.config = config or AdaptiveBatchConfig()
        self.current_batch_size: int = self.config.initial_batch_size
        self.history: list[BatchMetrics] = []
        self.size_history: list[int] = [self.current_batch_size]

    def compute_next_batch_size(self, metrics: BatchMetrics) -> int:
        """Compute the next batch size given metrics from the latest batch."""
        size = float(self.current_batch_size)
        multiplier = 1.0

        # 1. Crash discovery reward
        if metrics.new_crashes > 0:
            multiplier *= (self.config.reward_new_crash ** min(metrics.new_crashes, 3))
        elif metrics.crashes > 0:
            multiplier *= 1.10

        # 2. Novelty rewards (new productions & new diagnostics)
        if metrics.new_productions > 0:
            multiplier *= (self.config.reward_new_production ** min(metrics.new_productions, 3))
        if metrics.new_diagnostics > 0:
            multiplier *= (self.config.reward_new_diagnostic ** min(metrics.new_diagnostics, 3))

        # 3. Shape & acceptance checks
        if metrics.valid_shape_rate < self.config.min_shape_rate:
            multiplier *= self.config.decay_factor
        elif (
            self.config.target_acceptance_min
            <= metrics.acceptance_rate
            <= self.config.target_acceptance_max
        ):
            # Healthy acceptance rate band bonus
            multiplier *= 1.10
        elif (
            metrics.acceptance_rate < self.config.target_acceptance_min
            and metrics.new_productions == 0
        ):
            multiplier *= self.config.decay_factor

        # 4. Timeout & slow input penalty
        if metrics.timeouts > 0:
            multiplier *= (self.config.penalty_timeout ** min(metrics.timeouts, 3))
        elif metrics.slow_inputs > max(1, metrics.batch_size * 0.20):
            multiplier *= 0.85

        # 5. Plateau decay (no crashes, no new productions, no new diagnostics)
        if (
            metrics.new_crashes == 0
            and metrics.new_productions == 0
            and metrics.new_diagnostics == 0
        ):
            multiplier *= self.config.plateau_decay

        new_size = int(round(size * multiplier))
        # Clamp strictly within bounds
        new_size = max(self.config.min_batch_size, min(self.config.max_batch_size, new_size))
        return new_size

    def record_and_adapt(self, metrics: BatchMetrics) -> int:
        """Record batch metrics and update current_batch_size. Returns the new batch size."""
        self.history.append(metrics)
        next_size = self.compute_next_batch_size(metrics)
        self.current_batch_size = next_size
        self.size_history.append(next_size)
        return next_size

    def summary(self) -> dict:
        """Return summary of batch progression."""
        return {
            "initial_size": self.config.initial_batch_size,
            "final_size": self.current_batch_size,
            "batches_evaluated": len(self.history),
            "size_progression": list(self.size_history),
            "min_size_seen": min(self.size_history) if self.size_history else self.current_batch_size,
            "max_size_seen": max(self.size_history) if self.size_history else self.current_batch_size,
            "batch_details": [m.to_dict() for m in self.history],
        }


def extract_batch_metrics(
    batch_index: int,
    batch_results: list[dict],
    batch_feats: list[Any],
    seen_productions: set[str],
    seen_diagnostics: set[str],
    seen_crashes: set[str],
    duration_s: float = 0.0,
) -> tuple[BatchMetrics, set[str], set[str], set[str]]:
    """Analyze a batch of results and compute its BatchMetrics while updating coverage sets."""
    n = len(batch_results)
    if n == 0:
        return (
            BatchMetrics(batch_index=batch_index, batch_size=0),
            seen_productions,
            seen_diagnostics,
            seen_crashes,
        )

    crashes = 0
    new_crashes = 0
    accepted = 0
    timeouts = 0
    slow_inputs = 0
    durs: list[float] = []

    current_prods: set[str] = set()
    current_diags: set[str] = set()
    current_crashes: set[str] = set()

    for r in batch_results:
        outcome = r.get("outcome", "")
        if outcome in ("parsed_clean", "parsed_diag"):
            accepted += 1
        if outcome in ("crash", "timeout"):
            crashes += 1
            sha = r.get("sha", "")
            current_crashes.add(sha)
            if sha not in seen_crashes:
                new_crashes += 1
        if outcome == "timeout":
            timeouts += 1
        if r.get("is_slow"):
            slow_inputs += 1
        durs.append(r.get("dur_ms", 0.0))
        for d in r.get("diagnostics", []):
            current_diags.add(d)

    for f in batch_feats:
        if hasattr(f, "productions"):
            current_prods.update(f.productions)

    new_prods = len(current_prods - seen_productions)
    new_diags = len(current_diags - seen_diagnostics)

    updated_productions = seen_productions | current_prods
    updated_diagnostics = seen_diagnostics | current_diags
    updated_crashes = seen_crashes | current_crashes

    shape_count = sum(1 for r in batch_results if r.get("valid_shape", r.get("starts_lt", False)))
    avg_dur = sum(durs) / len(durs) if durs else 0.0
    throughput = (n / duration_s) if duration_s > 0 else 0.0

    metrics = BatchMetrics(
        batch_index=batch_index,
        batch_size=n,
        crashes=crashes,
        new_crashes=new_crashes,
        accepted=accepted,
        acceptance_rate=accepted / n,
        valid_shape_rate=shape_count / n,
        new_productions=new_prods,
        new_diagnostics=new_diags,
        avg_duration_ms=avg_dur,
        timeouts=timeouts,
        slow_inputs=slow_inputs,
        throughput_eps=throughput,
    )

    return metrics, updated_productions, updated_diagnostics, updated_crashes
