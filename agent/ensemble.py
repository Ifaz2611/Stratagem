"""Multi-model ensembles that vote on the best strategy.

An ensemble in Stratagem is not a majority vote over prose. Each member model
writes a complete candidate strategy, the candidate is screened against the
real target, and a panel of independent objectives ranks the measured results:

  * crashes found (the objective)
  * grammar-production coverage
  * distinct parser diagnostics reached
  * acceptance-rate fit to the band the loop steers toward
  * nesting depth reached
  * throughput (documents per second)

Each objective casts a Borda vote: the best candidate on that dimension gets
`n` points, the next `n-1`, and so on. Summing the points is the ensemble vote.
A candidate that wins on one dimension but is terrible on another does not win
outright, and a candidate cannot win by being lucky on a single metric.

Why Borda rather than an LLM judge: the measured results are already available,
free, and reproducible. Asking a model to rank anonymised summaries would add
an unpredictable call, could be swayed by prose style rather than measurements,
and would not be replayable. The models still contribute through their
candidates; the vote is over evidence.

The module is deliberately independent of the loop. `vote_candidates` takes
plain dataclasses, which makes the vote testable without an LLM or a harness.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from agent.scoring import explain, score_summary


@dataclass
class Candidate:
    """One model's strategy, plus whatever screening measured for it."""

    name: str
    model: str
    source: str = ""
    summary: dict | None = None
    error: str = ""
    components: dict[str, float] = field(default_factory=dict)
    votes: float = 0.0
    rank: int = 0
    score: float = 0.0

    @property
    def eligible(self) -> bool:
        return self.summary is not None and not self.error

    def to_json(self) -> dict:
        return {
            "name": self.name,
            "model": self.model,
            "eligible": self.eligible,
            "error": self.error,
            "score": round(self.score, 4),
            "votes": round(self.votes, 4),
            "rank": self.rank,
            "components": self.components,
            "source_sha256": _sha(self.source) if self.source else None,
        }


def _sha(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# name -> (value function, human label, weight). The crash weight is high
# enough that a candidate which found a bug beats one that merely covered more
# grammar; the other dimensions then break ties among non-crashing candidates.
_CRITERIA: tuple[tuple[str, Callable[[dict], float], str, float], ...] = (
    ("crashes", lambda c: c["crash_groups"] * 1000.0 + c["crash_count"],
     "unique crash groups", 10.0),
    ("coverage", lambda c: c["production_rate"], "grammar production coverage", 1.0),
    ("diagnostics", lambda c: c["diagnostics"], "distinct diagnostics", 1.0),
    ("acceptance", lambda c: c["acceptance_fit"], "acceptance-band fit", 1.0),
    ("depth", lambda c: c["max_depth"], "nesting depth", 1.0),
    ("efficiency", lambda c: c["throughput"], "documents per second", 1.0),
)


@dataclass
class EnsembleResult:
    winner: Candidate | None
    ranked: list[Candidate]
    criteria: dict[str, str]
    votes: dict[str, float]

    def to_json(self) -> dict:
        return {
            "winner": self.winner.to_json() if self.winner else None,
            "criteria": self.criteria,
            "votes": self.votes,
            "candidates": [c.to_json() for c in self.ranked],
        }


def vote_candidates(candidates: list[Candidate]) -> EnsembleResult:
    """Rank screened candidates with a weighted Borda count.

    Ineligible candidates (validation failed, screening crashed) are kept in the
    report but excluded from the vote. If no candidate is eligible the winner is
    None; the loop treats that as "this iteration produced nothing", which is
    the same outcome as a failed single-model attempt.
    """
    eligible = [c for c in candidates if c.eligible]
    for c in candidates:
        c.votes = 0.0
        c.rank = 0
        if c.summary is not None:
            c.components = explain(c.summary)
            c.score = c.components.get("score", score_summary(c.summary))

    criteria: dict[str, str] = {}
    votes: dict[str, float] = {}
    if eligible:
        n = len(eligible)
        for criterion, value_fn, label, weight in _CRITERIA:
            criteria[criterion] = label
            ordered = sorted(eligible, key=lambda c: value_fn(c.components), reverse=True)
            # Dense Borda points: best gets n, next n-1, ... Ties share the
            # higher position, so two equal best candidates are not separated
            # by an accident of list order.
            last_value: float | None = None
            last_points = float(n)
            for i, cand in enumerate(ordered):
                value = value_fn(cand.components)
                if last_value is not None and value == last_value:
                    points = last_points
                else:
                    points = float(n - i)
                    last_value, last_points = value, points
                points *= weight
                cand.votes += points
                votes.setdefault(cand.name, 0.0)
                votes[cand.name] += points

    ranked = sorted(
        candidates,
        key=lambda c: (c.eligible, c.votes, c.score),
        reverse=True,
    )
    for i, cand in enumerate(ranked, start=1):
        cand.rank = i

    winner = ranked[0] if ranked and ranked[0].eligible else None
    return EnsembleResult(winner=winner, ranked=ranked, criteria=criteria, votes=votes)
