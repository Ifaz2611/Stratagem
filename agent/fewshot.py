"""Few-shot examples from successful past strategies.

The loop already carries the *current* strategy from one iteration to the next.
What it has never carried is what worked in earlier runs, on this target or a
near neighbour. A model starting a new campaign re-derives the same lessons:
thread the tag name through the production, place one defect inside a valid
document, sample boundary values instead of drawing from a wide range.

This module turns the run directory into a small, ranked library. It scans
`runs/<id>/iterations/iter-<n>/{strategy.py,summary.json}`, scores each strategy
with the same fitness used everywhere else, and renders the best few as a
prompt section. Similarity filtering reuses `TargetProfile` from the cache, so a
strategy from `mxml` is offered to `expat` but not to the DNS parser.

It is opt-in. The block adds prompt tokens, and on replay it would change the
prompt that was recorded, so it stays off unless asked for.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from agent.scoring import explain
from agent.strategy_cache import TargetProfile

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RUNS_ROOT = REPO_ROOT / "runs"
_FENCE = re.compile(r"```(?:python|py)?\s*\n(.*?)```", re.S)


@dataclass
class StrategyExample:
    source: str
    target: str
    category: str
    run_id: str
    iteration: int
    score: float
    summary: dict
    similarity: float = 0.0
    source_sha: str = ""
    path: str = ""

    @property
    def acceptance(self) -> float | None:
        v = self.summary.get("acceptance_rate")
        try:
            return float(v) if v is not None else None
        except (TypeError, ValueError):
            return None

    def metrics_line(self) -> str:
        st = self.summary.get("structure") or {}
        bits = []
        if self.acceptance is not None:
            bits.append(f"acceptance {self.acceptance:.1%}")
        if st.get("productions_total"):
            bits.append(f"productions {st.get('productions_hit')}"
                        f"/{st.get('productions_total')}")
        if self.summary.get("distinct_diagnostic_templates") is not None:
            bits.append(f"diagnostics {self.summary.get('distinct_diagnostic_templates')}")
        if self.summary.get("crash_count") is not None:
            bits.append(f"crashes {self.summary.get('crash_count')}")
        bits.append(f"score {self.score:.2f}")
        return ", ".join(bits)


def _read_source(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return ""
    m = _FENCE.search(text)
    return (m.group(1) if m else text).strip() + "\n"


def _excerpt(source: str, limit: int) -> tuple[str, bool]:
    """Head + tail excerpt that keeps the module's public surface visible.

    A plain prefix cut is usually worthless: these strategies are hundreds of
    lines, and the part cut off is the composite functions and `documents()`
    that make the example worth showing. Keep the imports and constants from
    the head and the entry point from the tail.
    """
    if len(source) <= limit:
        return source, False
    marker = "\n# ... [middle omitted: {n} chars] ...\n"
    head_budget = max(300, int(limit * 0.35))
    tail_budget = max(300, limit - head_budget - len(marker.format(n=10_000_000)))
    head = source[:head_budget].rstrip()
    tail = source[-tail_budget:].lstrip()
    # Prefer starting the tail at a line boundary if one is nearby.
    nl = tail.find("\n")
    if 0 <= nl < 200:
        tail = tail[nl + 1:]
    omitted = len(source) - len(head) - len(tail)
    if omitted <= 0:
        return source, False
    return head + marker.format(n=omitted) + tail, True


def _profile_from_summary(summary: dict) -> TargetProfile:
    """Best-effort profile when the target is not (or no longer) registered.

    Campaign summaries from before the target abstraction have no `target`
    field. Every such run in this repository targeted mxml, so that is the
    default; a summary written by the current code always carries the field.
    """
    name = str(summary.get("target") or "mxml")
    category = str(summary.get("target_category") or ("xml" if name == "mxml" else "unknown"))
    st = summary.get("structure") or {}
    productions = tuple(st.get("hit", {}) or {})
    return TargetProfile(name=name, category=category, productions=productions)


class FewShotLibrary:
    """Ranked strategies mined from previous run directories."""

    def __init__(self, runs_root: Path | str = DEFAULT_RUNS_ROOT,
                 k: int = 3, budget_chars: int = 6000,
                 min_similarity: float = 0.55,
                 max_example_chars: int = 2600):
        self.runs_root = Path(runs_root)
        self.k = max(1, int(k))
        self.budget_chars = max(500, int(budget_chars))
        self.min_similarity = max(0.0, min(1.0, float(min_similarity)))
        self.max_example_chars = max(300, int(max_example_chars))
        self._cache: tuple[tuple[str, str, int], list[StrategyExample]] | None = None

    # ---------------------------------------------------------------- scan
    def _iter_run_summaries(self) -> Iterator[tuple[Path, dict[str, Any]]]:
        if not self.runs_root.exists():
            return
        for run_dir in sorted(self.runs_root.iterdir()):
            if not run_dir.is_dir() or run_dir.name.startswith("."):
                continue
            it_root = run_dir / "iterations"
            if not it_root.exists():
                continue
            for iter_dir in sorted(it_root.glob("iter-*")):
                strategy = iter_dir / "strategy.py"
                summary_path = iter_dir / "summary.json"
                if not (strategy.exists() and summary_path.exists()):
                    continue
                try:
                    summary = json.loads(summary_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                source = _read_source(strategy)
                if not source:
                    continue
                try:
                    iteration = int(iter_dir.name.split("-", 1)[1])
                except (IndexError, ValueError):
                    iteration = 0
                yield run_dir.name, iteration, source, summary, strategy

    def examples(self, target: Any, exclude_run: str | None = None,
                 exclude_iteration: int | None = None) -> list[StrategyExample]:
        profile = TargetProfile.from_target(target)
        out: list[StrategyExample] = []
        seen: set[str] = set()
        for run_id, iteration, source, summary, path in self._iter_run_summaries():
            if exclude_run is not None and run_id == exclude_run:
                continue
            sha = hashlib.sha256(source.encode("utf-8", "replace")).hexdigest()
            if sha in seen:
                continue
            seen.add(sha)

            other = _profile_from_summary(summary)
            try:
                from fuzzer.targets import get_target
                other = TargetProfile.from_target(get_target(other.name))
            except Exception:
                # Unknown target names are legitimate in an old run directory;
                # fall back to the summary-derived profile.
                pass
            sim = profile.similarity(other)
            if sim < self.min_similarity:
                continue
            components = explain(summary)
            out.append(StrategyExample(
                source=source,
                target=other.name,
                category=other.category,
                run_id=run_id,
                iteration=iteration,
                score=components.get("score", 0.0),
                summary=summary,
                similarity=sim,
                source_sha=sha,
                path=str(path),
            ))
        # Exact-target examples win only as a tie-breaker on score; the score
        # itself is the measurement. A crashed strategy from a neighbour beats
        # a tidy one from the same target.
        out.sort(key=lambda e: (e.score, e.similarity, e.run_id, e.iteration),
                 reverse=True)
        return out[: self.k]

    # --------------------------------------------------------------- render
    def render(self, target: Any, exclude_run: str | None = None,
               exclude_iteration: int | None = None,
               k: int | None = None) -> str:
        examples = self.examples(target, exclude_run=exclude_run,
                                 exclude_iteration=exclude_iteration)
        if k is not None:
            examples = examples[: max(0, int(k))]
        if not examples:
            return ""
        header = (
            "## Few-shot examples: strategies that measured well elsewhere\n\n"
            "These modules are from earlier campaigns. They are evidence, not "
            "instructions: copy an idea that applies, but keep the current "
            "target's grammar, mixture bounds and boundaries. The metrics are "
            "from those campaigns, so a high score there does not transfer "
            "automatically.\n"
        )
        parts = [header]
        used = len(header)
        per_example = min(self.max_example_chars,
                          max(600, (self.budget_chars - used) // max(1, len(examples))))
        for i, ex in enumerate(examples, start=1):
            source, truncated = _excerpt(ex.source, per_example)
            block = (
                f"\n### Example {i}: target `{ex.target}`, run `{ex.run_id}`, "
                f"iteration {ex.iteration}\n\n"
                f"{ex.metrics_line()}\n\n"
                f"```python\n{source}```\n"
            )
            if used + len(block) > self.budget_chars and parts:
                break
            parts.append(block)
            used += len(block)
        return "".join(parts).strip()

    def stats(self) -> dict:
        return {
            "enabled": True,
            "runs_root": str(self.runs_root),
            "k": self.k,
            "budget_chars": self.budget_chars,
            "min_similarity": self.min_similarity,
        }
