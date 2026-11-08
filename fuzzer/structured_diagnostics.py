"""Structured diagnostics, differential feedback profiles, and blackbox novelty tracking.

Extracts structured execution vectors from parser callback diagnostics:
  * callback type & failure phase
  * line & column position
  * bytes consumed before failure
  * parser depth reached

Provides:
  * Profile comparison (differential feedback favoring deeper penetration)
  * Per-strategy and per-input novelty scores (blackbox proxy for coverage)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from fuzzer.diagnostics import normalize


_RE_LINE = re.compile(r"\bon line (\d+)\b", re.IGNORECASE)
_RE_COL = re.compile(r"\b(col|column) (\d+)\b", re.IGNORECASE)

# Mapping of keywords in diagnostics to failure phases
_PHASE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(attribute|Missing value for attribute|Duplicate attribute)\b", re.IGNORECASE), "attribute"),
    (re.compile(r"\b(close tag|Missing close tag|Mismatched close tag)\b", re.IGNORECASE), "tag_close"),
    (re.compile(r"\b(open tag|does not start with '<'|Bare <)\b", re.IGNORECASE), "tag_open"),
    (re.compile(r"\b(entity|reference)\b", re.IGNORECASE), "entity"),
    (re.compile(r"\b(cdata)\b", re.IGNORECASE), "cdata"),
    (re.compile(r"\b(doctype|second root)\b", re.IGNORECASE), "doctype"),
    (re.compile(r"\b(control character|utf-8|utf-16|encoding)\b", re.IGNORECASE), "encoding"),
]

PHASE_DEPTH_WEIGHT: dict[str, int] = {
    "doctype": 1,
    "encoding": 2,
    "tag_open": 3,
    "attribute": 4,
    "entity": 5,
    "cdata": 6,
    "tag_close": 7,
    "body": 8,
    "unknown": 0,
}


@dataclass
class StructuredDiagnostic:
    """Deconstructed diagnostic with spatial and parser-state attributes."""
    raw_message: str
    normalized_template: str
    callback_name: str = "error"
    line: int | None = None
    column: int | None = None
    byte_offset: int = 0
    depth_reached: int = 0
    bytes_consumed: int = 0
    failure_phase: str = "unknown"

    def to_json(self) -> dict[str, Any]:
        return {
            "template": self.normalized_template,
            "callback": self.callback_name,
            "line": self.line,
            "col": self.column,
            "byte_offset": self.byte_offset,
            "depth_reached": self.depth_reached,
            "bytes_consumed": self.bytes_consumed,
            "failure_phase": self.failure_phase,
        }


def _determine_phase(message: str) -> str:
    for pat, phase in _PHASE_PATTERNS:
        if pat.search(message):
            return phase
    return "unknown"


def _estimate_spatial_metrics(payload: bytes, line_num: int | None) -> tuple[int, int, int]:
    """Estimate byte offset, depth reached, and bytes consumed from payload and line."""
    if not payload:
        return 0, 0, 0

    lines = payload.split(b"\n")
    if line_num is not None and 1 <= line_num <= len(lines):
        # Bytes up to the specified line
        consumed = sum(len(line) + 1 for line in lines[:line_num])
        consumed = min(consumed, len(payload))
        consumed_slice = payload[:consumed]
    else:
        # Default to full payload
        consumed = len(payload)
        consumed_slice = payload

    depth = max(0, consumed_slice.count(b"<") - consumed_slice.count(b"</"))
    offset = min(consumed, len(payload))
    return offset, depth, consumed


def extract_structured_diagnostic(raw_message: str, payload: bytes = b"") -> StructuredDiagnostic:
    """Extract a rich StructuredDiagnostic from raw callback message and input payload."""
    norm = normalize(raw_message)
    line_m = _RE_LINE.search(raw_message)
    col_m = _RE_COL.search(raw_message)

    line = int(line_m.group(1)) if line_m else None
    col = int(col_m.group(2)) if col_m else None

    offset, depth, consumed = _estimate_spatial_metrics(payload, line)
    phase = _determine_phase(raw_message)

    return StructuredDiagnostic(
        raw_message=raw_message,
        normalized_template=norm,
        callback_name="error",
        line=line,
        column=col,
        byte_offset=offset,
        depth_reached=depth,
        bytes_consumed=consumed,
        failure_phase=phase,
    )


@dataclass
class DiagnosticProfile:
    """Rich execution profile of an input for blackbox differential feedback."""
    sha: str
    payload_len: int
    outcome: str
    max_depth_reached: int = 0
    bytes_consumed: int = 0
    failure_phase: str = "unknown"
    templates_hit: list[str] = field(default_factory=list)
    structured_diagnostics: list[StructuredDiagnostic] = field(default_factory=list)

    @property
    def consumption_ratio(self) -> float:
        if self.payload_len == 0:
            return 1.0
        return min(1.0, self.bytes_consumed / self.payload_len)

    def to_json(self) -> dict[str, Any]:
        return {
            "sha": self.sha[:16],
            "len": self.payload_len,
            "outcome": self.outcome,
            "depth": self.max_depth_reached,
            "consumed": self.bytes_consumed,
            "ratio": round(self.consumption_ratio, 3),
            "phase": self.failure_phase,
            "templates": self.templates_hit,
            "diagnostics": [d.to_json() for d in self.structured_diagnostics],
        }


def build_profile(sha: str, payload: bytes, outcome: str, diagnostics: list[str]) -> DiagnosticProfile:
    """Construct a DiagnosticProfile from payload run results."""
    structured = [extract_structured_diagnostic(d, payload) for d in diagnostics]
    if structured:
        max_depth = max(d.depth_reached for d in structured)
        max_consumed = max(d.bytes_consumed for d in structured)
        # Deepest failure phase
        phase = max(structured, key=lambda d: PHASE_DEPTH_WEIGHT.get(d.failure_phase, 0)).failure_phase
    else:
        # For clean parses, entire document is consumed
        max_depth = max(0, payload.count(b"<") - payload.count(b"</"))
        max_consumed = len(payload)
        phase = "body" if outcome == "parsed_clean" else "unknown"

    return DiagnosticProfile(
        sha=sha,
        payload_len=len(payload),
        outcome=outcome,
        max_depth_reached=max_depth,
        bytes_consumed=max_consumed,
        failure_phase=phase,
        templates_hit=[d.normalized_template for d in structured],
        structured_diagnostics=structured,
    )


def compare_profiles(a: DiagnosticProfile, b: DiagnosticProfile) -> int:
    """Compare two profiles for differential feedback.

    Returns:
       1 if profile 'a' reached a deeper / more advanced parser state than 'b'
      -1 if profile 'b' reached a deeper state than 'a'
       0 if profiles are equivalent in depth
    """
    # 1. Depth comparison
    if a.max_depth_reached != b.max_depth_reached:
        return 1 if a.max_depth_reached > b.max_depth_reached else -1

    # 2. Consumption ratio (fraction of document parsed before rejection)
    if abs(a.consumption_ratio - b.consumption_ratio) > 0.05:
        return 1 if a.consumption_ratio > b.consumption_ratio else -1

    # 3. Phase hierarchy weight
    w_a = PHASE_DEPTH_WEIGHT.get(a.failure_phase, 0)
    w_b = PHASE_DEPTH_WEIGHT.get(b.failure_phase, 0)
    if w_a != w_b:
        return 1 if w_a > w_b else -1

    # 4. Raw bytes consumed
    if a.bytes_consumed != b.bytes_consumed:
        return 1 if a.bytes_consumed > b.bytes_consumed else -1

    return 0


class NoveltyTracker:
    """Tracks per-strategy and per-input novelty scores as a blackbox proxy for coverage."""

    def __init__(self):
        self.seen_templates: set[str] = set()
        self.max_depth_seen: int = 0
        self.max_bytes_consumed_seen: int = 0
        self.seen_phases: set[str] = set()
        self.strategy_scores: dict[str, float] = {}

    def score_input(self, profile: DiagnosticProfile) -> float:
        """Calculate novelty score for an individual input profile."""
        score = 0.0

        # Template novelty (+10.0 per unseen template)
        new_temps = [t for t in profile.templates_hit if t not in self.seen_templates]
        if new_temps:
            score += 10.0 * len(new_temps)
            self.seen_templates.update(new_temps)

        # Depth novelty (+5.0 per unit deeper than previous peak)
        if profile.max_depth_reached > self.max_depth_seen:
            gain = profile.max_depth_reached - self.max_depth_seen
            score += 5.0 * gain
            self.max_depth_seen = profile.max_depth_reached

        # Consumed prefix novelty (+3.0 if significantly exceeds previous prefix)
        if profile.bytes_consumed > self.max_bytes_consumed_seen + 64:
            score += 3.0
            self.max_bytes_consumed_seen = profile.bytes_consumed

        # Phase novelty (+4.0 for reaching a new failure phase)
        if profile.failure_phase not in self.seen_phases and profile.failure_phase != "unknown":
            score += 4.0
            self.seen_phases.add(profile.failure_phase)

        return score

    def evaluate_batch(self, strategy_name: str, profiles: list[DiagnosticProfile]) -> dict[str, Any]:
        """Evaluate a batch of profiles from a strategy and report aggregate novelty metrics."""
        total_novelty = sum(self.score_input(p) for p in profiles)
        self.strategy_scores[strategy_name] = total_novelty

        depths = [p.max_depth_reached for p in profiles]
        consumed = [p.bytes_consumed for p in profiles]

        return {
            "strategy": strategy_name,
            "novelty_score": round(total_novelty, 2),
            "inputs_evaluated": len(profiles),
            "max_depth": max(depths) if depths else 0,
            "avg_depth": round(sum(depths) / max(1, len(depths)), 2),
            "max_consumed": max(consumed) if consumed else 0,
            "avg_consumed": round(sum(consumed) / max(1, len(consumed)), 2),
            "cumulative_templates": len(self.seen_templates),
            "cumulative_phases": sorted(self.seen_phases),
        }
