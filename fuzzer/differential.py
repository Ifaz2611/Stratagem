"""Differential testing engine across parser targets.

Compares parser behavior on identical payloads across multiple targets
(e.g., Mini-XML, Expat, libxml2, TinyXML-2) to detect semantic divergences,
parsing discrepancies, and differential crashes that pure blackbox single-target
signals miss.
"""
from __future__ import annotations

import collections
import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from fuzzer.runner import Outcome, RunResult
from fuzzer.targets import BaseTarget, get_target


class DivergenceType(str, Enum):
    """Classification of differential divergence."""
    CRASH_DIVERGENCE = "crash_divergence"        # One target crashes/times out, others don't
    OUTCOME_DIVERGENCE = "outcome_divergence"    # Accept vs Reject divergence
    DIAGNOSTIC_DIVERGENCE = "diagnostic_divergence" # Divergent error templates
    STRUCTURAL_DIVERGENCE = "structural_divergence" # Discrepancy in parsed element tree / depth


class DivergenceSeverity(str, Enum):
    CRITICAL = "CRITICAL"  # Memory safety or denial-of-service disparity
    HIGH = "HIGH"          # Major semantic disagreement (e.g. valid document rejected)
    MEDIUM = "MEDIUM"      # Moderate error code or recovery disagreement
    LOW = "LOW"            # Minor formatting or diagnostic difference


@dataclass
class DivergenceRecord:
    """Record of a divergence observed on a single payload across targets."""
    input_sha256: str
    payload_len: int
    payload_snippet: str
    divergence_type: DivergenceType
    severity: DivergenceSeverity
    outcomes: dict[str, str]  # target_name -> outcome.value
    diagnostics: dict[str, list[str]]  # target_name -> diagnostics
    durations_ms: dict[str, float]  # target_name -> duration_ms
    details: str

    def to_json(self) -> dict[str, Any]:
        return {
            "sha": self.input_sha256[:16],
            "len": self.payload_len,
            "snippet": self.payload_snippet,
            "divergence_type": self.divergence_type.value,
            "severity": self.severity.value,
            "outcomes": self.outcomes,
            "diagnostics": self.diagnostics,
            "durations_ms": self.durations_ms,
            "details": self.details,
        }


@dataclass
class DifferentialReport:
    """Aggregated summary of differential testing run."""
    targets_tested: list[str]
    total_inputs_tested: int = 0
    divergence_count: int = 0
    divergence_by_type: dict[str, int] = field(default_factory=dict)
    divergence_by_severity: dict[str, int] = field(default_factory=dict)
    divergences: list[DivergenceRecord] = field(default_factory=list)
    duration_s: float = 0.0

    def to_json(self) -> dict[str, Any]:
        return {
            "targets_tested": self.targets_tested,
            "total_inputs_tested": self.total_inputs_tested,
            "divergence_count": self.divergence_count,
            "divergence_by_type": self.divergence_by_type,
            "divergence_by_severity": self.divergence_by_severity,
            "divergences": [d.to_json() for d in self.divergences],
            "duration_s": round(self.duration_s, 3),
        }

    def generate_markdown_report(self) -> str:
        lines = [
            "# Differential Testing Report",
            "",
            f"**Targets Compared:** {', '.join(f'`{t}`' for t in self.targets_tested)}  ",
            f"**Total Inputs:** {self.total_inputs_tested:,} | **Divergences Found:** {self.divergence_count:,}  ",
            "",
            "## Divergence Breakdown",
            "",
            "| Type | Count |",
            "|---|---|",
        ]
        for t, cnt in sorted(self.divergence_by_type.items()):
            lines.append(f"| `{t}` | {cnt} |")

        lines.extend([
            "",
            "| Severity | Count |",
            "|---|---|",
        ])
        for s, cnt in sorted(self.divergence_by_severity.items()):
            lines.append(f"| **{s}** | {cnt} |")

        if self.divergences:
            lines.extend([
                "",
                "## Notable Divergences",
                "",
                "| SHA | Type | Severity | Outcomes | Snippet |",
                "|---|---|---|---|---|",
            ])
            for d in self.divergences[:15]:
                out_summary = ", ".join(f"{k}:{v}" for k, v in d.outcomes.items())
                snip = d.payload_snippet.replace("\n", " ").replace("|", "\\|")[:30]
                lines.append(f"| `{d.input_sha256[:8]}` | `{d.divergence_type.value}` | **{d.severity.value}** | {out_summary} | `{snip}` |")

        return "\n".join(lines)


class DifferentialOracle:
    """Orchestrates differential execution and divergence detection across targets."""

    def __init__(self, target_names: tuple[str, ...] = ("mxml", "expat", "libxml2")):
        self.targets: list[BaseTarget] = [get_target(name) for name in target_names]

    def test_input(self, payload: bytes) -> DivergenceRecord | None:
        """Run a single input across all targets and detect any divergence."""
        results: dict[str, RunResult] = {}
        for target in self.targets:
            res = target.run(payload)
            results[target.name] = res

        sha = hashlib.sha256(payload).hexdigest()
        snippet = payload[:60].decode("utf-8", "replace")
        outcomes = {name: res.outcome.value for name, res in results.items()}
        diagnostics = {name: res.diagnostics for name, res in results.items()}
        durations = {name: round(res.duration_s * 1000, 2) for name, res in results.items()}

        # 1. Crash divergence check
        crashed_targets = [name for name, res in results.items() if res.outcome.is_crash]
        non_crashed_targets = [name for name, res in results.items() if not res.outcome.is_crash]
        if crashed_targets and non_crashed_targets:
            return DivergenceRecord(
                input_sha256=sha,
                payload_len=len(payload),
                payload_snippet=snippet,
                divergence_type=DivergenceType.CRASH_DIVERGENCE,
                severity=DivergenceSeverity.CRITICAL,
                outcomes=outcomes,
                diagnostics=diagnostics,
                durations_ms=durations,
                details=f"Target(s) {crashed_targets} crashed while {non_crashed_targets} survived safely.",
            )

        # 2. Outcome divergence check (accept vs reject)
        accepted_targets = [name for name, res in results.items() if res.outcome.is_accepted]
        rejected_targets = [name for name, res in results.items() if res.outcome == Outcome.REJECTED]
        if accepted_targets and rejected_targets:
            return DivergenceRecord(
                input_sha256=sha,
                payload_len=len(payload),
                payload_snippet=snippet,
                divergence_type=DivergenceType.OUTCOME_DIVERGENCE,
                severity=DivergenceSeverity.HIGH,
                outcomes=outcomes,
                diagnostics=diagnostics,
                durations_ms=durations,
                details=f"Accepted by {accepted_targets} but rejected by {rejected_targets}.",
            )

        # 3. Diagnostic divergence check
        diag_sets = {name: set(res.diagnostics) for name, res in results.items() if res.diagnostics}
        if len(set(frozenset(s) for s in diag_sets.values())) > 1 and len(diag_sets) >= 2:
            return DivergenceRecord(
                input_sha256=sha,
                payload_len=len(payload),
                payload_snippet=snippet,
                divergence_type=DivergenceType.DIAGNOSTIC_DIVERGENCE,
                severity=DivergenceSeverity.MEDIUM,
                outcomes=outcomes,
                diagnostics=diagnostics,
                durations_ms=durations,
                details=f"Targets produced divergent diagnostic sets: {diag_sets}",
            )

        return None

    def run_batch(self, payloads: Iterable[bytes]) -> DifferentialReport:
        """Run batch of inputs across targets and compile differential report."""
        start = time.monotonic()
        target_names = [t.name for t in self.targets]
        report = DifferentialReport(targets_tested=target_names)

        type_counts: dict[str, int] = collections.defaultdict(int)
        sev_counts: dict[str, int] = collections.defaultdict(int)

        for payload in payloads:
            report.total_inputs_tested += 1
            divergence = self.test_input(payload)
            if divergence:
                report.divergence_count += 1
                type_counts[divergence.divergence_type.value] += 1
                sev_counts[divergence.severity.value] += 1
                report.divergences.append(divergence)

        report.divergence_by_type = dict(type_counts)
        report.divergence_by_severity = dict(sev_counts)
        report.duration_s = time.monotonic() - start
        return report
