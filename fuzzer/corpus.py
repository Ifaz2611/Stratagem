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
import types
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

CORPUS_NAME = "corpus.jsonl.gz"
DISTILLED_CORPUS_NAME = "corpus_distilled.jsonl.gz"


@dataclass(slots=True)
class CorpusEntry:
    """A single input with its execution metadata and coverage characteristics.

    ``slots`` matters at corpus scale: a million entries would otherwise carry
    a million per-instance ``__dict__`` objects, which can dwarf the payloads
    themselves. Every field is declared, so nothing relies on dynamic
    attributes.
    """
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
    """Manages a collection of inputs with deduplication, distillation, and prioritization.

    ``max_entries`` is an optional memory ceiling. When it is set, the manager
    evicts in batches using the same coverage-guided selection as
    :meth:`distill`, so a long-running campaign or a million-line imported
    corpus cannot grow without bound. The default is ``None``: behaviour for
    existing callers is unchanged.
    """

    def __init__(self, entries: list[CorpusEntry] | None = None,
                 max_entries: int | None = None,
                 evict_batch: int | None = None) -> None:
        if max_entries is not None and max_entries < 1:
            raise ValueError(f"max_entries must be >= 1, got {max_entries}")
        self.entries: list[CorpusEntry] = []
        self._sha_set: set[str] = set()
        # Signature tracking is only paid for when semantic deduplication is
        # actually used. The default survey path adds every input and never
        # needs a tuple of all diagnostics/productions per entry.
        self._sig_set: set[tuple] | None = None
        self.duplicates_rejected: int = 0
        self.max_entries = max_entries
        self.evict_batch = max(
            1, int(evict_batch) if evict_batch is not None
            else max(1, (max_entries or 0) // 10))
        self.evicted: int = 0

        if entries:
            for e in entries:
                self.add_entry(e)

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> Iterator[CorpusEntry]:
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

    def _ensure_signatures(self) -> set[tuple]:
        if self._sig_set is None:
            self._sig_set = {e.behavioral_signature for e in self.entries}
        return self._sig_set

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
        if deduplicate_semantic and sig in self._ensure_signatures():
            self.duplicates_rejected += 1
            return False

        self.entries.append(entry)
        self._sha_set.add(entry.sha256)
        if self._sig_set is not None:
            self._sig_set.add(sig)
        self._maybe_evict()
        return True

    def _maybe_evict(self) -> None:
        """Trim in batches once the corpus is meaningfully over its ceiling."""
        if self.max_entries is None:
            return
        if len(self.entries) > self.max_entries + self.evict_batch:
            self.trim(self.max_entries)

    def trim(self, max_entries: int | None = None) -> int:
        """Reduce the corpus to ``max_entries``, preserving coverage and crashes.

        Returns the number of entries dropped. Crashes are selected first so a
        memory ceiling cannot turn a known bug into a silent omission.
        """
        limit = self.max_entries if max_entries is None else max_entries
        if limit is None or len(self.entries) <= limit:
            return 0
        if limit < 1:
            raise ValueError(f"max_entries must be >= 1, got {limit}")

        crashes = [e for e in self.entries if e.outcome in ("crash", "timeout")]
        selected_crash = crashes[:limit]
        slot_count = max(0, limit - len(selected_crash))
        selected = list(selected_crash)
        if slot_count:
            chosen = self.select_coverage_guided(max_count=slot_count)
            chosen_shas = {e.sha256 for e in selected}
            for e in chosen:
                if e.sha256 in chosen_shas:
                    continue
                selected.append(e)
                chosen_shas.add(e.sha256)
                if len(selected) >= limit:
                    break

        before = len(self.entries)
        if len(selected) < limit:
            chosen_shas = {e.sha256 for e in selected}
            for e in self.entries:
                if e.sha256 in chosen_shas:
                    continue
                selected.append(e)
                chosen_shas.add(e.sha256)
                if len(selected) >= limit:
                    break

        self.entries = selected
        self._sha_set = {e.sha256 for e in selected}
        if self._sig_set is not None:
            self._sig_set = {e.behavioral_signature for e in selected}
        dropped = before - len(selected)
        self.evicted += dropped
        return dropped

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
        if self._sig_set is not None:
            self._sig_set = {e.behavioral_signature for e in unique}
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

    def iter_payloads(self) -> Iterator[bytes]:
        """Iterate payloads without materializing a second list."""
        for e in self.entries:
            yield e.payload

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
            "evicted": self.evicted,
            "max_entries": self.max_entries,
            "signatures_tracked": self._sig_set is not None,
        }

    def memory_stats(self) -> dict:
        """A compact view of the manager's retained state."""
        return {
            "entries": len(self.entries),
            "payload_bytes": sum(e.length for e in self.entries),
            "diagnostics": sum(len(e.diagnostics) for e in self.entries),
            "productions": sum(len(e.productions) for e in self.entries),
            "sha_set": len(self._sha_set),
            "signatures_tracked": (
                None if self._sig_set is None else len(self._sig_set)),
            "max_entries": self.max_entries,
            "evicted": self.evicted,
        }


# ------------------------------------------------------------ streaming writer
class CorpusWriter:
    """Write corpus records as inputs are produced.

    The campaign used to retain every payload until the end and then serialize
    the whole list in one call. That is a second full copy of the corpus at
    peak, and it cannot be checkpointed incrementally. This writer appends one
    gzip member per run, so a resume continues the same file instead of
    rewriting it, while the digest and manifest stay identical to
    :func:`write_corpus`.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        append: bool = False,
        start_count: int = 0,
        initial_raw_bytes: int = 0,
        initial_digest: Any = None,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.count = int(start_count)
        self.raw_bytes = int(initial_raw_bytes)
        self._digest = initial_digest.copy() if initial_digest is not None \
            else hashlib.sha256()
        self._fh = gzip.open(self.path, "at" if append else "wt",
                             encoding="utf-8")
        self._closed = False

    def add(self, payload: bytes) -> None:
        if self._closed:
            raise ValueError("corpus writer is closed")
        sha = hashlib.sha256(payload)
        self._fh.write(json.dumps({
            "i": self.count,
            "sha": sha.hexdigest()[:16],
            "b64": base64.b64encode(payload).decode("ascii"),
        }) + "\n")
        self.count += 1
        self.raw_bytes += len(payload)
        self._digest.update(sha.digest())

    def manifest(self) -> dict:
        """Current manifest. Flushes but leaves the writer open."""
        if not self._closed:
            self._fh.flush()
        return {
            "file": self.path.name,
            "count": self.count,
            "raw_bytes": self.raw_bytes,
            "stored_bytes": self.path.stat().st_size,
            "corpus_digest": self._digest.hexdigest()[:16],
        }

    def close(self) -> dict:
        if not self._closed:
            self._fh.close()
            self._closed = True
        return self.manifest()

    def __enter__(self) -> "CorpusWriter":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: types.TracebackType | None,
    ) -> None:
        self.close()


# ---------------------------------------------------------------- Backward-compatible API
def write_corpus(path: Path, payloads: Iterable[bytes]) -> dict:
    """Write a campaign's inputs from any iterable. Returns a manifest.

    Accepting an iterable means callers can pass ``CorpusManager.iter_payloads``
    or a generator over a large file without first materializing a list.
    """
    writer = CorpusWriter(path)
    try:
        for p in payloads:
            writer.add(p)
    finally:
        manifest = writer.close()
    return manifest


def iter_corpus(path: Path) -> Iterator[bytes]:
    """Yield corpus payloads one record at a time."""
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield base64.b64decode(json.loads(line)["b64"])


def read_corpus(path: Path) -> list[bytes]:
    return list(iter_corpus(path))


def corpus_digest(payloads: Iterable[bytes]) -> str:
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
        json.loads(line)
        for line in (iteration_dir / "results.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
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
