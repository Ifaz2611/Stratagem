"""Automatic hyperparameter tuning for the agentic loop.

The loop has four parameters that were previously constants, chosen once:

  * how many documents an iteration runs
  * how many validation repairs an iteration may spend
  * which refinement directive is injected
  * (when ensembles are enabled) how many candidates to screen

A fixed choice cannot be right for both a run where the seed strategy is
already productive and a run where every refinement is stuck. This module
adapts them from the loop's own measurements.

The method is deliberately simple enough to audit with five iterations:

  * ``examples`` uses hill climbing on *yield per document*. Yield is new
    productions + weighted new diagnostics + a large crash bonus, divided by
    the examples spent. When yield rises, spend more next time; when it falls,
    spend less. The band is bounded by the run's configured cap, so tuning can
    never exceed the user's budget.
  * ``repairs`` rises after a gate failure or a campaign failure and falls only
    after a clean streak. Repair budget is insurance; buying it after a loss is
    cheaper than discovering it is missing mid-iteration.
  * ``directive`` uses UCB1 over the rotating directives. The directive with
    the best measured marginal yield is exploited, but an untried directive is
    explored first, and the confidence term keeps a lucky early directive from
    monopolising all remaining iterations.
  * a short history is written to ``tuning.json`` so a resumed run continues
    from the same state instead of restarting the search.

The state is plain JSON and the controller has no I/O beyond that file, which
keeps it testable and replayable.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path

MIN_EXAMPLES = 64


@dataclass
class TuningDecision:
    examples: int
    repairs: int
    directive: str | None
    reason: str = ""

    def to_json(self) -> dict:
        return {
            "examples": self.examples,
            "repairs": self.repairs,
            "directive": self.directive,
            "reason": self.reason,
        }


@dataclass
class DirectiveStats:
    pulls: int = 0
    total_reward: float = 0.0

    @property
    def mean_reward(self) -> float:
        return self.total_reward / self.pulls if self.pulls else 0.0

    def to_json(self) -> dict:
        return {"pulls": self.pulls,
                "total_reward": round(self.total_reward, 4),
                "mean_reward": round(self.mean_reward, 4)}


@dataclass
class Observation:
    iteration: int
    examples: int
    new_productions: int
    new_diagnostics: int
    crash_groups: int
    gate_failures: int = 0
    campaign_failed: bool = False
    cost_usd: float = 0.0
    reward: float = 0.0

    def to_json(self) -> dict:
        return {
            "iteration": self.iteration,
            "examples": self.examples,
            "new_productions": self.new_productions,
            "new_diagnostics": self.new_diagnostics,
            "crash_groups": self.crash_groups,
            "gate_failures": self.gate_failures,
            "campaign_failed": self.campaign_failed,
            "cost_usd": round(self.cost_usd, 4),
            "reward": round(self.reward, 4),
        }


class HyperparameterTuner:
    """A small UCB1 + hill-climbing controller for loop parameters."""

    def __init__(self, max_examples: int = 500, directives: list[str] | None = None,
                 repairs: int = 2, examples: int | None = None,
                 min_examples: int = MIN_EXAMPLES,
                 state_path: Path | str | None = None):
        self.max_examples = max(1, int(max_examples))
        self.min_examples = max(1, min(int(min_examples), self.max_examples))
        self.directives = list(directives or [])
        self.examples = self._clamp(examples if examples is not None else self.max_examples)
        self.repairs = max(1, int(repairs))
        self.max_repairs = 4
        self.yield_ema = 0.0
        self.clean_streak = 0
        self.history: list[Observation] = []
        self.directive_stats: dict[str, DirectiveStats] = {
            d: DirectiveStats() for d in self.directives
        }
        self.state_path = Path(state_path) if state_path else None
        self._pending_directive: str | None = None

    # ---------------------------------------------------------------- state
    def _clamp(self, n: int) -> int:
        return max(self.min_examples, min(self.max_examples, int(n)))

    def decide(self, iteration: int) -> TuningDecision:
        """Return the parameters for this iteration and remember the choice."""
        directive = None
        reason = []
        if iteration > 0 and self.directives:
            directive = self._choose_directive()
            reason.append(f"directive={directive}")
        reason.append(f"examples={self.examples}")
        reason.append(f"repairs={self.repairs}")
        self._pending_directive = directive
        return TuningDecision(examples=self.examples, repairs=self.repairs,
                              directive=directive, reason=", ".join(reason))

    def _choose_directive(self) -> str:
        total = sum(s.pulls for s in self.directive_stats.values())
        untried = [d for d in self.directives if self.directive_stats[d].pulls == 0]
        if untried:
            return untried[0]
        best, best_score = self.directives[0], float("-inf")
        for d in self.directives:
            s = self.directive_stats[d]
            bonus = math.sqrt(2.0 * math.log(max(1, total)) / max(1, s.pulls))
            score = s.mean_reward + bonus
            if score > best_score:
                best, best_score = d, score
        return best

    def observe(self, iteration: int, examples: int,
                new_productions: int, new_diagnostics: int,
                crash_groups: int, gate_failures: int = 0,
                campaign_failed: bool = False,
                cost_usd: float = 0.0) -> Observation:
        """Update the controller from one completed iteration."""
        marginal = (max(0, new_productions)
                    + 1.5 * max(0, new_diagnostics)
                    + 10.0 * max(0, crash_groups))
        reward = 100.0 * marginal / max(1, examples)
        previous_ema = self.yield_ema
        if self.yield_ema == 0.0:
            self.yield_ema = reward
        else:
            self.yield_ema = 0.5 * reward + 0.5 * self.yield_ema

        if previous_ema > 0:
            ratio = reward / previous_ema
            if ratio >= 1.20:
                self.examples = self._clamp(int(round(self.examples * 1.5)))
            elif ratio <= 0.80:
                self.examples = self._clamp(int(round(self.examples * 0.67)))

        if gate_failures > 0 or campaign_failed:
            self.repairs = min(self.max_repairs, self.repairs + 1)
            self.clean_streak = 0
        else:
            self.clean_streak += 1
            if self.clean_streak >= 2 and self.repairs > 1:
                self.repairs -= 1
                self.clean_streak = 0

        directive = self._pending_directive
        if directive and directive in self.directive_stats:
            s = self.directive_stats[directive]
            s.pulls += 1
            s.total_reward += reward

        obs = Observation(
            iteration=iteration,
            examples=examples,
            new_productions=new_productions,
            new_diagnostics=new_diagnostics,
            crash_groups=crash_groups,
            gate_failures=gate_failures,
            campaign_failed=campaign_failed,
            cost_usd=cost_usd,
            reward=reward,
        )
        self.history.append(obs)
        self.save()
        return obs

    # --------------------------------------------------------------- persist
    def to_json(self) -> dict:
        return {
            "enabled": True,
            "max_examples": self.max_examples,
            "min_examples": self.min_examples,
            "current": {
                "examples": self.examples,
                "repairs": self.repairs,
                "yield_ema": round(self.yield_ema, 4),
            },
            "directives": {d: s.to_json() for d, s in self.directive_stats.items()},
            "history": [o.to_json() for o in self.history],
        }

    def save(self) -> None:
        if not self.state_path:
            return
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
            tmp.write_text(json.dumps(self.to_json(), indent=2), encoding="utf-8")
            tmp.replace(self.state_path)
        except OSError:
            # Tuning state is an optimisation. A read-only run directory must
            # not stop a campaign that is otherwise healthy.
            pass

    @classmethod
    def load(cls, state_path: Path | str, max_examples: int = 500,
             directives: list[str] | None = None) -> "HyperparameterTuner":
        p = Path(state_path)
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls(max_examples=max_examples, directives=directives,
                       state_path=p)
        tuner = cls(
            max_examples=max_examples,
            directives=directives or list((d.get("directives") or {}).keys()),
            state_path=p,
        )
        current = d.get("current") or {}
        tuner.examples = tuner._clamp(int(current.get("examples", tuner.examples)))
        tuner.repairs = max(1, min(tuner.max_repairs, int(current.get("repairs", 2))))
        tuner.yield_ema = float(current.get("yield_ema", 0.0))
        for name, sd in (d.get("directives") or {}).items():
            if name in tuner.directive_stats:
                tuner.directive_stats[name].pulls = int(sd.get("pulls", 0))
                tuner.directive_stats[name].total_reward = float(sd.get("total_reward", 0.0))
        for h in d.get("history") or []:
            try:
                tuner.history.append(Observation(
                    iteration=int(h["iteration"]), examples=int(h["examples"]),
                    new_productions=int(h.get("new_productions", 0)),
                    new_diagnostics=int(h.get("new_diagnostics", 0)),
                    crash_groups=int(h.get("crash_groups", 0)),
                    gate_failures=int(h.get("gate_failures", 0)),
                    campaign_failed=bool(h.get("campaign_failed", False)),
                    cost_usd=float(h.get("cost_usd", 0.0)),
                    reward=float(h.get("reward", 0.0)),
                ))
            except (KeyError, TypeError, ValueError):
                continue
        return tuner
