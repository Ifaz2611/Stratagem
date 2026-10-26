"""Persistent strategy cache, keyed by how similar two targets are.

Refinement is expensive and target families share a great deal. An XML parser
that accepts the same grammar, with the same tracked productions and the same
input-class bounds, is a close neighbour of every other XML parser in this
project even when the C library underneath is different. Re-deriving a good
generator from scratch for `expat` when a `mxml` campaign already produced one
wastes a seed call and the smoke budget that goes with it.

Two safeguards keep reuse honest:

  * Similarity is explicit and auditable. It is a weighted combination of name,
    category, grammar hash and production overlap, not a hunch. `TargetProfile`
    records every input to the calculation.
  * A cached strategy is re-validated against the *current* target before it is
    used. Similarity is a retrieval heuristic; the validation gates are the
    authority. A strategy that fails syntax, interface, smoke or mixture checks
    is skipped and the run falls back to the model.

The cache is opt-in (``--use-strategy-cache``). It defaults off because reusing
a strategy changes which LLM calls a run makes, and the replay guarantee depends
on a run making exactly the calls its transcript records.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent.scoring import score_summary

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CACHE_DIR = REPO_ROOT / "runs" / ".strategy_cache"
CACHE_VERSION = 1


def _sha_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _jaccard(a: tuple[str, ...] | set[str], b: tuple[str, ...] | set[str]) -> float:
    sa, sb = set(a), set(b)
    if not sa and not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


@dataclass(frozen=True)
class TargetProfile:
    """The stable identity of a target for reuse purposes."""

    name: str
    category: str
    description: str = ""
    grammar_hash: str = ""
    productions: tuple[str, ...] = ()
    class_bounds: tuple[tuple[str, float, float], ...] = ()

    @classmethod
    def from_target(cls, target: Any) -> "TargetProfile":
        grammar = getattr(target, "grammar_file", None)
        grammar_hash = ""
        if grammar:
            try:
                p = Path(grammar)
                if p.exists():
                    grammar_hash = _sha_text(p.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                grammar_hash = ""
        bounds = getattr(target, "class_bounds", {}) or {}
        return cls(
            name=str(getattr(target, "name", "unknown")),
            category=str(getattr(target, "category", "unknown")),
            description=str(getattr(target, "description", "")),
            grammar_hash=grammar_hash,
            productions=tuple(getattr(target, "productions", ()) or ()),
            class_bounds=tuple((k, float(v[0]), float(v[1]))
                               for k, v in sorted(bounds.items())),
        )

    def similarity(self, other: "TargetProfile") -> float:
        """A number in [0, 1] that says whether reuse is plausible.

        Weights favour the things that actually shape a generated document:
        the production vocabulary and the grammar. Category is next; the target
        name is a small bonus for an exact repeat. Two XML parsers score 0.80
        even with different names, which is above the default threshold; XML
        and JSON score 0.0.
        """
        name = 1.0 if self.name.lower() == other.name.lower() else 0.0
        category = 1.0 if self.category.lower() == other.category.lower() else 0.0
        grammar = 1.0 if (self.grammar_hash and
                          self.grammar_hash == other.grammar_hash) else 0.0
        productions = _jaccard(self.productions, other.productions)
        bounds = 1.0 if self.class_bounds and self.class_bounds == other.class_bounds else 0.0
        return round(0.18 * name + 0.24 * category + 0.25 * grammar
                     + 0.28 * productions + 0.05 * bounds, 4)

    def to_json(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "grammar_hash": self.grammar_hash,
            "productions": list(self.productions),
            "class_bounds": [list(b) for b in self.class_bounds],
        }

    @classmethod
    def from_json(cls, d: dict) -> "TargetProfile":
        return cls(
            name=str(d.get("name", "unknown")),
            category=str(d.get("category", "unknown")),
            description=str(d.get("description", "")),
            grammar_hash=str(d.get("grammar_hash", "")),
            productions=tuple(d.get("productions", ()) or ()),
            class_bounds=tuple((str(b[0]), float(b[1]), float(b[2]))
                               for b in d.get("class_bounds", ()) or ()),
        )


@dataclass
class CacheMatch:
    source: str
    similarity: float
    score: float
    entry: "CacheEntry"

    def to_json(self) -> dict:
        return {
            "key": self.entry.key,
            "target": self.entry.target.name,
            "category": self.entry.target.category,
            "similarity": self.similarity,
            "score": self.score,
            "run_id": self.entry.run_id,
            "iteration": self.entry.iteration,
            "created_at": self.entry.created_at,
        }


@dataclass
class CacheEntry:
    key: str
    source: str
    target: TargetProfile
    score: float
    run_id: str
    iteration: int
    created_at: str
    summary: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        return {
            "version": CACHE_VERSION,
            "key": self.key,
            "source": self.source,
            "target": self.target.to_json(),
            "score": self.score,
            "run_id": self.run_id,
            "iteration": self.iteration,
            "created_at": self.created_at,
            "summary": self.summary,
        }

    @classmethod
    def from_json(cls, d: dict) -> "CacheEntry | None":
        try:
            return cls(
                key=str(d["key"]),
                source=str(d["source"]),
                target=TargetProfile.from_json(d.get("target") or {}),
                score=float(d.get("score", 0.0)),
                run_id=str(d.get("run_id", "")),
                iteration=int(d.get("iteration", 0)),
                created_at=str(d.get("created_at", "")),
                summary=d.get("summary") or {},
            )
        except (KeyError, TypeError, ValueError):
            return None


class StrategyCache:
    """A directory of validated strategies with target profiles attached."""

    def __init__(self, directory: Path | str = DEFAULT_CACHE_DIR,
                 min_similarity: float = 0.70, max_entries: int = 200):
        self.dir = Path(directory)
        self.entries_dir = self.dir / "entries"
        self.min_similarity = max(0.0, min(1.0, float(min_similarity)))
        self.max_entries = max(1, int(max_entries))

    # ---------------------------------------------------------------- lookup
    def _entries(self) -> list[CacheEntry]:
        if not self.entries_dir.exists():
            return []
        out = []
        for p in self.entries_dir.glob("*.json"):
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            e = CacheEntry.from_json(d)
            if e is not None:
                out.append(e)
        return out

    def lookup(self, target: Any, limit: int = 5,
               min_similarity: float | None = None) -> list[CacheMatch]:
        """Best matches above the similarity threshold, highest score first.

        Returns several so the caller can try the next one when re-validation
        rejects the first. The caller is responsible for validation; this
        function only retrieves.
        """
        profile = TargetProfile.from_target(target)
        threshold = self.min_similarity if min_similarity is None else float(min_similarity)
        matches = []
        for e in self._entries():
            sim = profile.similarity(e.target)
            if sim >= threshold:
                matches.append(CacheMatch(source=e.source, similarity=sim,
                                          score=e.score, entry=e))
        matches.sort(key=lambda m: (m.similarity, m.score), reverse=True)
        return matches[:max(1, int(limit))]

    def best(self, target: Any,
             min_similarity: float | None = None) -> CacheMatch | None:
        found = self.lookup(target, limit=1, min_similarity=min_similarity)
        return found[0] if found else None

    # ----------------------------------------------------------------- store
    def _key(self, source: str, profile: TargetProfile) -> str:
        return _sha_text(source + "\x00" + profile.name + "\x00" + profile.grammar_hash)[:32]

    def store(self, source: str, target: Any, summary: dict,
              run_id: str, iteration: int,
              min_score: float | None = None) -> CacheEntry | None:
        """Persist a validated strategy. Returns None when it was not stored.

        The source is deduplicated per target by a key over source + target
        identity, so re-storing the same strategy after a resume overwrites one
        entry rather than inflating the cache. A minimum score is optional; the
        default keeps even a poor-but-valid strategy, because the few-shot
        library ranks by score and an old strategy is still a useful negative
        example.
        """
        if not source or not source.strip():
            return None
        profile = TargetProfile.from_target(target)
        score = score_summary(summary)
        if min_score is not None and score < min_score:
            return None
        entry = CacheEntry(
            key=self._key(source, profile),
            source=source,
            target=profile,
            score=round(score, 4),
            run_id=run_id,
            iteration=int(iteration),
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            summary=_compact_summary(summary),
        )
        self.entries_dir.mkdir(parents=True, exist_ok=True)
        dest = self.entries_dir / f"{entry.key}.json"
        tmp = dest.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(entry.to_json(), indent=2), encoding="utf-8")
        os.replace(tmp, dest)
        self.prune()
        return entry

    def prune(self) -> int:
        """Keep the highest-scoring `max_entries`. Returns how many were removed."""
        entries = self._entries()
        if len(entries) <= self.max_entries:
            return 0
        entries.sort(key=lambda e: e.score, reverse=True)
        removed = 0
        for e in entries[self.max_entries:]:
            try:
                (self.entries_dir / f"{e.key}.json").unlink()
                removed += 1
            except OSError:
                pass
        return removed

    def stats(self) -> dict:
        entries = self._entries()
        by_target: dict[str, int] = {}
        for e in entries:
            by_target[e.target.name] = by_target.get(e.target.name, 0) + 1
        return {
            "enabled": True,
            "directory": str(self.dir),
            "entries": len(entries),
            "by_target": by_target,
            "min_similarity": self.min_similarity,
            "max_entries": self.max_entries,
            "best_score": round(max((e.score for e in entries), default=0.0), 4),
        }


def _compact_summary(summary: dict) -> dict:
    """Keep enough of a summary to rank an entry without storing every input."""
    st = summary.get("structure") or {}
    return {
        "target": summary.get("target"),
        "examples": summary.get("examples"),
        "acceptance_rate": summary.get("acceptance_rate"),
        "productions_hit": st.get("productions_hit"),
        "productions_total": st.get("productions_total"),
        "max_depth_seen": st.get("max_depth_seen"),
        "distinct_diagnostic_templates": summary.get("distinct_diagnostic_templates"),
        "crash_count": summary.get("crash_count"),
        "crash_groups": list((summary.get("crash_groups") or {}).keys()),
        "wall_clock_s": summary.get("wall_clock_s"),
    }
