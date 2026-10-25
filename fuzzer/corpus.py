"""Record, replay, and intelligently manage campaign inputs.

Recording the corpus means a run can be replayed without regenerating anything,
so replay does not depend on Hypothesis producing an identical draw sequence
across versions or environments.

Intelligent Corpus Management provides:
  * Exact deduplication (SHA-256 hash based)
  * Semantic deduplication (behavioral signature based)
  * Coverage-guided corpus selection / distillation (Greedy Set Cover with
    tie-breaking prioritizing shorter length and faster execution)
  * Corpus prioritization / energy scoring (rarity of productions and diagnostics)
  * Corpus merging across campaigns
  * Checkpoint-friendly incremental serialization
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CORPUS_NAME = "corpus.jsonl.gz"
DISTILLED_CORPUS_NAME = "corpus_distilled.jsonl.gz"


@dataclass
class CorpusEntry:
    """A single input with its execution metadata and coverage characteristics."""
    payload: bytes
    sha256: str = ""
    outcome: str = "parsed_clean"
    diagnostics: list[str] = field(default_factory=list)
    productions: list[str] = field(default_factory=list)
    features: dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0
    length: int = 0
    tag: str = ""
    score: float = 0.0

    def __post_init__(self) -> None:
        if not self.sha256 and self.payload is not None:
            self.sha256 = hashlib.sha256(self.payload).hexdigest()
        if not self.length and self.payload is not None:
            self.length = len(self.payload)
        if hasattr(self.outcome, "value"):
            self.outcome = self.outcome.value

    @property
    def behavioral_signature(self) -> tuple:
        """A signature of execution behavior for semantic deduplication."""
        return (self.outcome, tuple(sorted(self.diagnostics)), tuple(sorted(self.productions)))

    def to_dict(self) -> dict:
        return {
            "sha": self.sha256,
            "outcome": self.outcome,
            "len": self.length,
            "dur_ms": round(self.duration_ms, 2),
            "ndiag": len(self.diagnostics),
            "diagnostics": self.diagnostics,
            "productions": sorted(self.productions),
            "score": round(self.score, 4),
            "tag": self.tag,
            "b64": base64.b64encode(self.payload).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, data: dict) -> CorpusEntry:
        payload = base64.b64decode(data["b64"])
        return cls(
            payload=payload,
            sha256=data.get("sha") or hashlib.sha256(payload).hexdigest(),
            outcome=data.get("outcome", "parsed_clean"),
            diagnostics=data.get("diagnostics", []),
            productions=data.get("productions", []),
            features=data.get("features", {}),
            duration_ms=data.get("dur_ms", 0.0),
            length=data.get("len", len(payload)),
            tag=data.get("tag", ""),
            score=data.get("score", 0.0),
        )


class CorpusManager:
    """Manages a collection of inputs with deduplication, distillation, and prioritization."""

    def __init__(self, entries: list[CorpusEntry] | None = None) -> None:
        self.entries: list[CorpusEntry] = []
        self._sha_set: set[str] = set()
        self._sig_set: set[tuple] = set()
        self.duplicates_rejected: int = 0

        if entries:
            for e in entries:
                self.add_entry(e)

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self):
        return iter(self.entries)

    def add(
        self,
        payload: bytes,
        outcome: str = "parsed_clean",
        diagnostics: list[str] | None = None,
        productions: list[str] | None = None,
        features: dict[str, Any] | None = None,
        duration_ms: float = 0.0,
        tag: str = "",
        deduplicate_exact: bool = True,
        deduplicate_semantic: bool = False,
    ) -> bool:
        """Add an input to the corpus. Returns True if added, False if rejected as duplicate."""
        entry = CorpusEntry(
            payload=payload,
            outcome=outcome,
            diagnostics=diagnostics or [],
            productions=productions or [],
            features=features or {},
            duration_ms=duration_ms,
            tag=tag,
        )
        return self.add_entry(
            entry,
            deduplicate_exact=deduplicate_exact,
            deduplicate_semantic=deduplicate_semantic,
        )

    def add_entry(
        self,
        entry: CorpusEntry,
        deduplicate_exact: bool = True,
        deduplicate_semantic: bool = False,
    ) -> bool:
        """Add a CorpusEntry object. Returns True if added, False if rejected as duplicate."""
        if deduplicate_exact and entry.sha256 in self._sha_set:
            self.duplicates_rejected += 1
            return False

        sig = entry.behavioral_signature
        if deduplicate_semantic and sig in self._sig_set:
            self.duplicates_rejected += 1
            return False

        self.entries.append(entry)
        self._sha_set.add(entry.sha256)
        self._sig_set.add(sig)
        return True

    def deduplicate_exact(self) -> int:
        """Prune exact duplicates in-place. Returns count of duplicates removed."""
        seen: set[str] = set()
        unique: list[CorpusEntry] = []
        removed = 0
        for e in self.entries:
            if e.sha256 in seen:
                removed += 1
            else:
                seen.add(e.sha256)
                unique.append(e)
        self.entries = unique
        self._sha_set = seen
        self.duplicates_rejected += removed
        return removed

    def deduplicate_semantic(self) -> int:
        """Prune semantic duplicates in-place, keeping shortest & fastest entry per signature.

        Returns count of duplicates removed.
        """
        best_by_sig: dict[tuple, CorpusEntry] = {}
        for e in self.entries:
            sig = e.behavioral_signature
            if sig not in best_by_sig:
                best_by_sig[sig] = e
            else:
                current = best_by_sig[sig]
                # Prefer shorter length, then lower execution time
                if (e.length, e.duration_ms) < (current.length, current.duration_ms):
                    best_by_sig[sig] = e

        removed = len(self.entries) - len(best_by_sig)
        self.entries = list(best_by_sig.values())
        self._sha_set = {e.sha256 for e in self.entries}
        self._sig_set = set(best_by_sig.keys())
        self.duplicates_rejected += removed
        return removed

    def select_coverage_guided(
        self,
        features_to_cover: tuple[str, ...] = ("productions", "diagnostics"),
        max_count: int | None = None,
    ) -> list[CorpusEntry]:
        """Coverage-guided corpus distillation via greedy set cover.

        Iteratively selects the entry that covers the maximum number of
        uncovered features (productions, diagnostic templates, outcome).
        Ties are broken by shortest input length and lowest execution duration.
        Unique crashes are always preserved.
        """
        if not self.entries:
            return []

        # Map each entry to its set of feature tokens
        entry_features: list[tuple[CorpusEntry, set[str]]] = []
        universe: set[str] = set()

        for e in self.entries:
            feats: set[str] = set()
            if "productions" in features_to_cover:
                feats.update(f"p:{p}" for p in e.productions)
            if "diagnostics" in features_to_cover:
                feats.update(f"d:{d}" for d in e.diagnostics)
            if "outcomes" in features_to_cover:
                feats.add(f"o:{e.outcome}")
            # Unique crash preservation: ensure distinct crashes aren't discarded
            if e.outcome in ("crash", "timeout"):
                feats.add(f"crash:{e.sha256[:16]}")

            entry_features.append((e, feats))
            universe.update(feats)

        selected: list[CorpusEntry] = []
        covered: set[str] = set()
        remaining = list(entry_features)

        while remaining and (universe - covered):
            if max_count is not None and len(selected) >= max_count:
                break

            # Find entry that adds the most new features
            # Tie-breakers: shortest length, lowest duration
            def score_candidate(item: tuple[CorpusEntry, set[str]]) -> tuple[int, int, float]:
                entry, fset = item
                new_covered = len(fset - covered)
                # Negative length and negative duration for max() sort
                return (new_covered, -entry.length, -entry.duration_ms)

            best_item = max(remaining, key=score_candidate)
            best_entry, best_fset = best_item
            new_covered = len(best_fset - covered)

            if new_covered == 0:
                # No remaining entry can cover any new features
                break

            selected.append(best_entry)
            covered.update(best_fset)
            remaining.remove(best_item)

        # If max_count requested and we still have slots, fill with prioritized entries
        if max_count is not None and len(selected) < max_count:
            selected_shas = {e.sha256 for e in selected}
            for e, _ in remaining:
                if e.sha256 not in selected_shas:
                    selected.append(e)
                    selected_shas.add(e.sha256)
                    if len(selected) >= max_count:
                        break

        return selected

    def distill(
        self,
        features_to_cover: tuple[str, ...] = ("productions", "diagnostics"),
        max_count: int | None = None,
    ) -> CorpusManager:
        """Return a new CorpusManager containing only the distilled subset."""
        distilled_entries = self.select_coverage_guided(
            features_to_cover=features_to_cover, max_count=max_count
        )
        return CorpusManager(distilled_entries)

    def prioritize(self, criterion: str = "balanced") -> list[CorpusEntry]:
        """Assign priority/energy scores to entries and return them sorted descending.

        Scores incorporate:
          * Feature rarity (entries covering rarely-seen productions/diagnostics)
          * Crash bonuses
          * Compactness (favoring shorter inputs)
          * Execution efficiency (favoring faster inputs)
        """
        if not self.entries:
            return []

        # Count feature frequencies
        prod_freq: dict[str, int] = {}
        diag_freq: dict[str, int] = {}
        total = len(self.entries)

        for e in self.entries:
            for p in e.productions:
                prod_freq[p] = prod_freq.get(p, 0) + 1
            for d in e.diagnostics:
                diag_freq[d] = diag_freq.get(d, 0) + 1

        for e in self.entries:
            # Rarity score: rare features contribute more
            rarity = 1.0
            for p in e.productions:
                rarity += 1.0 / math.sqrt(max(1, prod_freq.get(p, 1)))
            for d in e.diagnostics:
                rarity += 1.5 / math.sqrt(max(1, diag_freq.get(d, 1)))

            # Crash bonus
            crash_factor = 3.0 if e.outcome in ("crash", "timeout") else 1.0

            # Compactness bonus (shorter inputs preferred for fast mutation & reproduction)
            compactness = 1.0 / (1.0 + math.log1p(e.length / 50.0))

            # Latency bonus (faster inputs preferred)
            latency = 1.0 / (1.0 + (e.duration_ms / 100.0))

            e.score = round(rarity * crash_factor * compactness * latency, 4)

        self.entries.sort(key=lambda e: e.score, reverse=True)
        return list(self.entries)

    def merge(self, other: CorpusManager) -> int:
        """Merge entries from another corpus manager. Returns count of new entries added."""
        added = 0
        for e in other.entries:
            if self.add_entry(e, deduplicate_exact=True):
                added += 1
        return added

    def export_corpus(
        self,
        path: Path,
        compressed: bool = True,
        include_metadata: bool = True,
    ) -> dict:
        """Write the corpus to disk. Compatible with read_corpus."""
        path.parent.mkdir(parents=True, exist_ok=True)
        total = 0
        open_fn = gzip.open if (compressed or path.suffix == ".gz") else open

        with open_fn(path, "wt", encoding="utf-8") as fh:
            for i, e in enumerate(self.entries):
                total += e.length
                record = {
                    "i": i,
                    "sha": e.sha256[:16],
                    "b64": base64.b64encode(e.payload).decode("ascii"),
                }
                if include_metadata:
                    record.update({
                        "outcome": e.outcome,
                        "dur_ms": round(e.duration_ms, 2),
                        "len": e.length,
                        "ndiag": len(e.diagnostics),
                        "diagnostics": e.diagnostics,
                        "productions": sorted(e.productions),
                        "score": round(e.score, 4),
                    })
                fh.write(json.dumps(record) + "\n")

        digest = hashlib.sha256()
        for e in self.entries:
            digest.update(hashlib.sha256(e.payload).digest())

        return {
            "file": path.name,
            "count": len(self.entries),
            "raw_bytes": total,
            "stored_bytes": path.stat().st_size,
            "corpus_digest": digest.hexdigest()[:16],
        }

    def import_corpus(self, path: Path) -> int:
        """Read entries from a corpus file (.jsonl or .jsonl.gz). Returns count added."""
        if not path.exists():
            return 0
        open_fn = gzip.open if path.suffix == ".gz" else open
        added = 0
        with open_fn(path, "rt", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                entry = CorpusEntry.from_dict(data)
                if self.add_entry(entry):
                    added += 1
        return added

    def payloads(self) -> list[bytes]:
        """Return all payloads in current corpus."""
        return [e.payload for e in self.entries]

    def stats(self) -> dict:
        """Return aggregate corpus metrics."""
        all_prods: set[str] = set()
        all_diags: set[str] = set()
        crashes = 0
        for e in self.entries:
            all_prods.update(e.productions)
            all_diags.update(e.diagnostics)
            if e.outcome in ("crash", "timeout"):
                crashes += 1

        return {
            "count": len(self.entries),
            "unique_shas": len(self._sha_set),
            "duplicates_rejected": self.duplicates_rejected,
            "raw_bytes": sum(e.length for e in self.entries),
            "productions_covered": len(all_prods),
            "diagnostics_covered": len(all_diags),
            "crashes": crashes,
        }


# ---------------------------------------------------------------- Backward-compatible API
def write_corpus(path: Path, payloads: list[bytes]) -> dict:
    """Write the campaign's inputs. Returns a manifest for the summary."""
    path.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        for i, p in enumerate(payloads):
            total += len(p)
            fh.write(json.dumps({
                "i": i,
                "sha": hashlib.sha256(p).hexdigest()[:16],
                "b64": base64.b64encode(p).decode("ascii"),
            }) + "\n")
    digest = hashlib.sha256()
    for p in payloads:
        digest.update(hashlib.sha256(p).digest())
    return {
        "file": path.name,
        "count": len(payloads),
        "raw_bytes": total,
        "stored_bytes": path.stat().st_size,
        "corpus_digest": digest.hexdigest()[:16],
    }


def read_corpus(path: Path) -> list[bytes]:
    out: list[bytes] = []
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(base64.b64decode(json.loads(line)["b64"]))
    return out


def corpus_digest(payloads: list[bytes]) -> str:
    d = hashlib.sha256()
    for p in payloads:
        d.update(hashlib.sha256(p).digest())
    return d.hexdigest()[:16]


@dataclass
class ReplayReport:
    inputs: int = 0
    outcome_matches: int = 0
    outcome_mismatches: list[dict] = field(default_factory=list)
    recorded_digest: str = ""
    replayed_digest: str = ""

    @property
    def ok(self) -> bool:
        return (self.inputs > 0
                and self.outcome_matches == self.inputs
                and self.recorded_digest == self.replayed_digest)


def replay_and_verify(
    iteration_dir: Path,
    harness: Path | None = None,
    extra_args: tuple[str, ...] = (),
) -> ReplayReport:
    """Feed the recorded corpus back through the harness and compare outcomes."""
    from fuzzer.runner import DEFAULT_HARNESS, run_one

    harness = harness or DEFAULT_HARNESS
    payloads = read_corpus(iteration_dir / CORPUS_NAME)
    recorded = [
        json.loads(l)
        for l in (iteration_dir / "results.jsonl").read_text(encoding="utf-8").splitlines()
        if l.strip()
    ]

    rep = ReplayReport(inputs=len(payloads), outcome_mismatches=[])
    rep.recorded_digest = (
        json.loads((iteration_dir / "summary.json").read_text(encoding="utf-8"))
        .get("corpus", {})
        .get("corpus_digest", "")
    )
    rep.replayed_digest = corpus_digest(payloads)

    for i, payload in enumerate(payloads):
        r = run_one(payload, harness=harness, extra_args=extra_args)
        want = recorded[i]["outcome"] if i < len(recorded) else None
        if r.outcome.value == want:
            rep.outcome_matches += 1
        else:
            rep.outcome_mismatches.append(
                {"i": i, "recorded": want, "replayed": r.outcome.value,
                 "sha": r.input_sha256[:16]}
            )
    return rep
