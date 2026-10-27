"""The agentic loop: grammar -> generator -> measure -> refine.

One iteration is:

  1. ask the model for a strategy (seed on iteration 0, refine after that)
  2. validate it (agent/validate.py) and repair if it fails
  3. run it for max_examples through the sanitizer harness
  4. summarise the measured results
  5. feed that summary back

Everything the model sees and says is written to runs/<id>/transcript/, which is
what lets the run be replayed without credentials (docs/design-decisions.md D9).

Budget is enforced on two axes: an iteration cap and a spend cap. Repair calls
count against the spend, so a generator the model cannot get right first time is
charged to the iteration that needed it.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from agent import env as envmod
from agent import llm, validate
from agent.ensemble import Candidate, vote_candidates
from agent.errors import (DebugLog, explain_exception, format_exception,
                          validation_hint)
from agent.fewshot import FewShotLibrary
from agent.progress import RunStatus, normalize_mode
from agent.strategy_cache import StrategyCache
from agent.tuning import HyperparameterTuner, TuningDecision
from fuzzer.campaign import Campaign, MAX_EXAMPLES_PER_ITERATION
from fuzzer.features import PRODUCTIONS

REPO_ROOT = Path(__file__).resolve().parent.parent
PROMPTS_ROOT = REPO_ROOT / "agent" / "prompts"
STRATEGY_DIR = REPO_ROOT / "fuzzer" / "strategies"

GRAMMAR_COMMIT = "e756f2a2ee5565a9300666f100ba6acd874664f7"
MAX_REPAIRS = 2
MAX_ITERATIONS = 5
# Resends for a response whose head was lost in transport. Capped so a
# persistently truncating backend cannot spend the whole budget.
MAX_RESENDS = 2


_LICENSE_BLOCK = re.compile(r"/\*.*?\*/\s*", re.S)
_FORMAT_PRAGMA = re.compile(r"^//\s*\$antlr-format.*$\n?", re.M)
# Refine prompts render "## Current strategy (iteration N)". Older transcripts
# did not record the iteration on each call, so this is the fallback that
# recovers it from the prompt that was actually sent.
_RE_ITERATION = re.compile(r"Current strategy \(iteration (\d+)\)")


def _grammar_body(filename: str) -> str:
    """The grammar text without its BSD licence header or formatter pragmas.

    Both are noise in a prompt: the licence says nothing about the language and
    the pragmas configure a code formatter. Strip them by removing the leading
    comment block, not by splitting on the grammar declaration, which would
    remove the declaration itself.
    """
    raw = (REPO_ROOT / "grammar" / filename).read_text(encoding="utf-8")
    raw = _LICENSE_BLOCK.sub("", raw, count=1)
    raw = _FORMAT_PRAGMA.sub("", raw)
    return raw.strip()

BASELINE = {"acceptance": "0.2%", "productions": "5.3/27", "depth": 0.3, "templates": 3.3}


@dataclass
class Budget:
    max_iterations: int = 5
    max_usd: float = 5.00
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    billable_input: int = 0
    cost_usd: float = 0.0
    # Tokens of authored prompt, excluding the fixed overhead the Claude Code
    # CLI adds. Reported separately so the cost is comparable with what a plain
    # API implementation would show.
    authored_chars: int = 0

    def add(self, r: llm.LLMResponse, prompt_chars: int) -> None:
        self.calls += 1
        self.input_tokens += r.input_tokens
        self.output_tokens += r.output_tokens
        self.billable_input += r.billable_input
        self.cost_usd += r.cost_usd or 0.0
        self.authored_chars += prompt_chars

    @property
    def exhausted(self) -> bool:
        return self.cost_usd >= self.max_usd

    @property
    def mean_call_cost(self) -> float:
        return self.cost_usd / self.calls if self.calls else 0.0

    def would_overrun(self) -> bool:
        """True when the next call is likely to cross the cap.

        A call's cost is known only once it has been billed, so checking the cap
        afterwards lets the last call overshoot: run G finished at $5.45 against
        a $5.00 cap because an iteration needed two extra calls. Refusing a call
        the running average cannot pay for keeps the overshoot to noise. With no
        history the first call is always allowed.
        """
        if self.exhausted:
            return True
        return bool(self.calls) and (self.max_usd - self.cost_usd) < self.mean_call_cost

    def to_json(self) -> dict:
        return {
            "llm_calls": self.calls,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "billable_input_tokens": self.billable_input,
            "authored_prompt_chars": self.authored_chars,
            "authored_prompt_tokens_est": round(self.authored_chars / 4),
            "cost_usd": round(self.cost_usd, 4),
            "max_usd": self.max_usd,
        }


@dataclass
class Loop:
    backend_kind: str = "cli"
    run_id: str = "run"
    max_examples: int = 500
    max_iterations: int = 5
    max_usd: float = 5.00
    model: str | None = None
    base_url: str | None = None
    # Resume at this iteration, reusing the artifacts and transcript already on
    # disk, so a backend failure part-way through a run does not force paying
    # again for the iterations that already succeeded.
    resume_from: int = 0
    # "v1" is the original prompt set; "v2" adds the input-class mixture,
    # marginal scoring and rotating directives. Both are kept so runs using
    # different prompt sets stay comparable.
    prompt_set: str = "v2"
    # The seed and refinement steps can use different models. Coverage gains
    # concentrate almost entirely in the seed, so a more capable model there and
    # a cheaper one for refinement is a reasonable split of a fixed budget.
    seed_model: str | None = None
    refine_model: str | None = None
    target: str = "mxml"

    # ---- agent enhancements (all opt-in; defaults preserve replay behavior)
    # Reuse a validated strategy from a similar target instead of paying for a
    # seed call. Disabled by default because it changes the call sequence.
    use_strategy_cache: bool = False
    cache_dir: str | None = None
    cache_similarity: float = 0.70
    # Append ranked examples from earlier runs to the seed/refine prompt.
    few_shot: bool = False
    few_shot_k: int = 3
    few_shot_budget: int = 6000
    # Adapt examples/repairs/directive after each iteration.
    autotune: bool = False
    tune_state: str | None = None
    # Comma-separated model list, one candidate each. One candidate = off.
    ensemble_models: str | None = None
    ensemble_candidates: int = 1
    screening_examples: int = 50
    # Use a harness produced by `python -m agent.harness_gen`.
    use_generated_harness: bool = False

    # ---- llm backend enhancements
    stream: bool = False
    prompt_ab: str | None = None
    fallbacks: str | None = None
    circuit_breaker: bool = False

    # ---- developer experience
    # auto renders only on a TTY; on also emits plain milestone lines in CI;
    # off is silent. Status lines are separate so they can be kept while the
    # bar is suppressed.
    progress_mode: str = "auto"
    status_mode: str = "auto"
    # Write structured JSONL events to runs/<id>/debug.jsonl. Off by default to
    # keep the recorded artifact set unchanged, on when diagnosing.
    debug: bool = False

    # ---- performance enhancements
    use_result_cache: bool = False
    result_cache_dir: str | Path | None = None
    max_corpus_entries: int | None = None

    budget: Budget = field(init=False)
    out: Path = field(init=False)

    def __post_init__(self) -> None:
        if not 1 <= self.max_examples <= MAX_EXAMPLES_PER_ITERATION:
            raise ValueError(
                f"max_examples must be 1..{MAX_EXAMPLES_PER_ITERATION}, "
                f"got {self.max_examples}")
        if not 1 <= self.max_iterations <= MAX_ITERATIONS:
            raise ValueError(
                f"max_iterations must be 1..{MAX_ITERATIONS}, "
                f"got {self.max_iterations}")
        if not 0 <= self.resume_from < self.max_iterations:
            raise ValueError(
                "resume_from must name an iteration inside this run, got "
                f"{self.resume_from}")
        if self.max_usd <= 0:
            raise ValueError("max_usd must be positive")
        if not 1 <= self.ensemble_candidates <= 8:
            raise ValueError("ensemble_candidates must be 1..8")
        if not 1 <= self.screening_examples <= MAX_EXAMPLES_PER_ITERATION:
            raise ValueError(
                f"screening_examples must be 1..{MAX_EXAMPLES_PER_ITERATION}")
        if not 0.0 <= self.cache_similarity <= 1.0:
            raise ValueError("cache_similarity must be 0..1")
        if self.max_corpus_entries is not None and self.max_corpus_entries < 1:
            raise ValueError(
                f"max_corpus_entries must be >= 1, got {self.max_corpus_entries}")
        self.progress_mode = normalize_mode(self.progress_mode)
        self.status_mode = normalize_mode(self.status_mode)
        self.budget = Budget(self.max_iterations, self.max_usd)
        self.out = REPO_ROOT / "runs" / self.run_id
        self.transcript = self.out / "transcript"
        self.transcript.mkdir(parents=True, exist_ok=True)
        # Created before any fallible setup so a resume/configuration failure
        # also leaves a debug trail.
        self.debug_log: DebugLog | None = (
            DebugLog(self.out / "debug.jsonl") if self.debug else None)
        self._status = RunStatus(self.run_id, self.max_iterations,
                                 mode=self.progress_mode,
                                 status_mode=self.status_mode)
        from agent.prompt_manager import PromptManager, PromptABTester, PromptVersion
        self.prompt_manager = PromptManager(PROMPTS_ROOT)
        try:
            self.prompt_version = self.prompt_manager.get_version(self.prompt_set)
            self.prompts = self.prompt_version.path or (PROMPTS_ROOT / self.prompt_set if self.prompt_set != "v1" else PROMPTS_ROOT)
        except KeyError:
            self.prompts = PROMPTS_ROOT / self.prompt_set if self.prompt_set != "v1" else PROMPTS_ROOT
            if not (self.prompts / "seed.md").exists():
                raise llm.LLMError(f"prompt set not found: {self.prompts}")
            self.prompt_version = PromptVersion.from_dir(self.prompts, name=self.prompt_set)

        self.ab_tester = None
        if self.prompt_ab:
            variants = [v.strip() for v in re.split(r"[,;\s]+", self.prompt_ab) if v.strip()]
            if len(variants) >= 2:
                self.ab_tester = PromptABTester(variants=variants, manager=self.prompt_manager)

        self.directives = self._load_directives()
        self.union_diagnostics: set[str] = set()
        self.union_productions: set[str] = set()
        from fuzzer.targets import get_target
        self.target_obj = get_target(self.target)
        self.system = (self.prompts / "system.md").read_text(encoding="utf-8")

        # A generated harness is an alternative measurement instrument for the
        # target. Resolve it before any campaign can run; if only the source
        # exists attempts a compile, and if that fails the target's reference
        # runner remains in place rather than the run dying at the first input.
        if self.use_generated_harness:
            from agent.harness_gen import (build_generated_harness,
                                           find_generated_harness)
            generated = find_generated_harness(self.target_obj)
            if generated is None:
                generated = build_generated_harness(self.target_obj)
            if generated is not None:
                self.target_obj.harness_binary = generated
                print(f"    [harness] using generated binary {generated}")
            else:
                print("    [harness] no generated harness found for "
                      f"'{self.target}'; falling back to the reference runner")

        self._last_gate_failures = 0
        self._last_source_kind = "llm"
        self._last_ensemble: dict | None = None

        self.cache = None
        if self.use_strategy_cache:
            from agent.strategy_cache import DEFAULT_CACHE_DIR
            self.cache = StrategyCache(
                Path(self.cache_dir) if self.cache_dir else DEFAULT_CACHE_DIR,
                min_similarity=self.cache_similarity)
        self.fewshot = None
        if self.few_shot:
            self.fewshot = FewShotLibrary(k=self.few_shot_k,
                                          budget_chars=self.few_shot_budget)
        self.tuner = None
        if self.autotune:
            state = Path(self.tune_state) if self.tune_state else self.out / "tuning.json"
            if self.resume_from and state.exists():
                self.tuner = HyperparameterTuner.load(
                    state, max_examples=self.max_examples,
                    directives=self.directives)
                print(f"    [tune] restored state from {state}")
            else:
                self.tuner = HyperparameterTuner(
                    max_examples=self.max_examples,
                    directives=self.directives,
                    state_path=state)

        # Restore before building the backends: a resumed replay must start at
        # the first call the resumed iteration actually owns, not at call-1.
        if self.resume_from:
            self._require_resume_artifacts()
            self._restore_budget()
            self._restore_feedback_unions()

        # Call directories are numbered independently of budget.calls, which
        # counts successful calls only. A failed call leaves a directory with
        # no response.json, and numbering from budget.calls alone would reuse
        # that number and overwrite the record of the failure.
        self._call_seq = (max(self.budget.calls, self._last_call_number())
                          if self.resume_from else 0)

        def mk(model):
            kw = {}
            if model:
                kw["model"] = model
            if self.base_url and self.backend_kind in ("openai", "api"):
                kw["base_url"] = self.base_url
            if self.backend_kind == "replay":
                # Resume at the first recorded call of the resumed iteration,
                # not at the end of the transcript: the loop will ask for that
                # iteration's calls again. New calls are written after the
                # existing directories, so nothing is overwritten.
                kw["start"] = (sum(self._calls_per_iteration().get(i, 0)
                                   for i in range(self.resume_from))
                               if self.resume_from else 0)
            fallback_list = [f.strip() for f in re.split(r"[,;\s]+", self.fallbacks) if f.strip()] if self.fallbacks else None
            return llm.make_backend(self.backend_kind,
                                    transcript_dir=self.transcript,
                                    fallbacks=fallback_list,
                                    circuit_breaker=self.circuit_breaker,
                                    **kw)

        if self.backend_kind == "replay":
            # One shared instance: replay consumes recorded calls in order, so
            # two instances would each start from call-1 and desynchronise.
            self.backend = mk(None)
            self.backend_seed = self.backend_refine = self.backend
        else:
            self.backend_seed = mk(self.seed_model or self.model)
            self.backend_refine = mk(self.refine_model or self.model)
            self.backend = self.backend_refine

        # Build one backend per ensemble member. A model list is the normal
        # case; ensemble_candidates > 1 with no list samples the same model
        # several times, which is still useful for variance reduction but is
        # not a multi-model ensemble.
        models = [m.strip() for m in re.split(r"[,;\s]+", self.ensemble_models or "")
                  if m.strip()]
        self.ensemble_models_list = models
        self.ensemble_backends = []
        count = max(self.ensemble_candidates, len(models))
        if count > 1:
            if self.backend_kind == "replay":
                print("    [ensemble] disabled: replay reproduces a recorded "
                      "call sequence and cannot add candidates")
            else:
                for i in range(count):
                    chosen = models[i % len(models)] if models else (
                        self.seed_model or self.model)
                    self.ensemble_backends.append(mk(chosen))
                print(f"    [ensemble] {count} candidate(s), models="
                      f"{', '.join(models) if models else '(backend default)'}")

    # ----------------------------------------------------------------- resume
    @property
    def cost_cap_enforced(self) -> bool:
        """False when the backend reports no per-call price.

        `replay` and `cli` carry a recorded or reported cost, so the spend cap
        is real. The OpenAI-compatible backend returns token counts but no
        price, and guessing one would make the report state a cost that was
        never observed, so max_usd is advisory there and the summary says so
        rather than silently pretending the cap held.
        """
        return self.backend_kind not in ("openai", "api")

    def _require_resume_artifacts(self) -> None:
        """Fail before spending anything if the run cannot actually resume.

        Refinement reads the previous iteration's strategy, summary and results.
        Discovering a missing file halfway through costs an LLM call; checking
        first costs nothing and names the directory that is incomplete.
        """
        prev = self.out / "iterations" / f"iter-{self.resume_from - 1}"
        missing = [n for n in ("strategy.py", "summary.json", "results.jsonl")
                   if not (prev / n).exists()]
        if missing:
            raise ValueError(
                f"--resume-from {self.resume_from} needs iteration "
                f"{self.resume_from - 1} under {prev}; missing "
                f"{', '.join(missing)}")

    def _restore_budget(self) -> None:
        """Rebuild spend from the recorded transcript.

        Without restoring the spend, a resumed run can exceed the budget. The
        call-number sequence is restored separately, from the directories on
        disk, so a resumed run appends rather than overwriting earlier calls.

        A replay resume re-reads the calls at and after the resume point and
        charges their recorded cost again as it goes, so those calls are
        counted for numbering but not for spend: charging them here as well
        would report the same money twice. A live backend is not re-reading
        anything, so every recorded call there is spend that already happened.
        """
        calls = self._recorded_calls()
        replay_start = (sum(self._calls_per_iteration().get(i, 0)
                            for i in range(self.resume_from))
                        if self.backend_kind == "replay" else len(calls))
        for i, (f, d) in enumerate(calls):
            self.budget.calls += 1
            if i >= replay_start:
                continue
            self.budget.input_tokens += d.get("input_tokens", 0)
            self.budget.output_tokens += d.get("output_tokens", 0)
            self.budget.billable_input += d.get("billable_input", 0)
            self.budget.cost_usd += d.get("cost_usd") or 0.0
            # The authored prompt is recoverable from the transcript, and
            # without this a resumed run reports zero authored tokens, which
            # breaks the backend-overhead comparison.
            u = f.parent / "user.md"
            sysf = f.parent / "system.md"
            if u.exists():
                self.budget.authored_chars += len(u.read_text(encoding="utf-8"))
            if sysf.exists():
                self.budget.authored_chars += len(sysf.read_text(encoding="utf-8"))
        print(f"    [resume] restored {self.budget.calls} recorded calls, "
              f"${self.budget.cost_usd:.2f} charged so far")

    def _restore_feedback_unions(self) -> None:
        """Restore all feedback observed before a resumed iteration.

        Without this, the first prompt after resume calls every diagnostic and
        production from only the immediately preceding iteration "new", even
        when earlier iterations already reached it.
        """
        for i in range(self.resume_from):
            f = self.out / "iterations" / f"iter-{i}" / "summary.json"
            if not f.exists():
                continue
            s = json.loads(f.read_text(encoding="utf-8"))
            self.union_diagnostics.update(s.get("diagnostic_templates", {}))
            self.union_productions.update(s.get("structure", {}).get("hit", {}))
        print(f"    [resume] restored feedback union: "
              f"{len(self.union_diagnostics)} diagnostics, "
              f"{len(self.union_productions)} productions")

    def _load_prev(self, it: int) -> tuple[str, dict, list[dict]]:
        """Load iteration it-1's artifacts so refinement has something to refine."""
        d = self.out / "iterations" / f"iter-{it - 1}"
        source = (d / "strategy.py").read_text(encoding="utf-8")
        summary = json.loads((d / "summary.json").read_text(encoding="utf-8"))
        results = [json.loads(l) for l in (d / "results.jsonl").read_text(encoding="utf-8").splitlines()]
        return source, summary, results

    def _last_call_number(self) -> int:
        """Highest call directory on disk, including failed (meta-only) calls."""
        nums = [int(p.name.split("-")[1]) for p in self.transcript.glob("call-*")
                if p.is_dir() and p.name.split("-")[1].isdigit()]
        return max(nums, default=0)

    def _recorded_calls(self) -> list[tuple[Path, dict]]:
        """Recorded calls in transcript order, with the file each came from."""
        return [(f, json.loads(f.read_text(encoding="utf-8")))
                for f in sorted(self.transcript.glob("call-*/response.json"),
                                key=lambda p: int(p.parent.name.split("-")[1]))]

    @staticmethod
    def _call_iteration(f: Path, d: dict) -> int | None:
        """Which iteration paid for a recorded call.

        Newer transcripts store `iteration` on the call itself. For older ones,
        a seed call is iteration 0 and a refine call names its iteration in the
        prompt that was sent. The tag alone is not enough: a truncated response
        is resent with the same tag, so a resend would otherwise look like the
        next iteration.
        """
        it = d.get("iteration")
        if isinstance(it, int):
            return it
        tag = d.get("tag", "")
        if tag.startswith("seed"):
            return 0
        user = f.parent / "user.md"
        if user.exists():
            m = _RE_ITERATION.search(user.read_text(encoding="utf-8"))
            if m:
                return int(m.group(1))
        return None

    def _grouped_calls(self) -> list[list[dict]]:
        """Transcript calls grouped into the iteration that paid for them.

        Calls do not map one-to-one onto iterations: validation repairs,
        campaign repairs and transport resends all belong to the iteration that
        triggered them, and a replay run records a call per reproduced response.
        The result is indexed by iteration, with an empty list for any gap, so
        callers can treat the index as the iteration number.
        """
        groups: dict[int, list[dict]] = {}
        fallback = 0
        for f, d in self._recorded_calls():
            it = self._call_iteration(f, d)
            if it is None:
                # Last resort for a transcript that carries neither field: the
                # old rule was that a non-repair tag opens a new iteration.
                tag = d.get("tag", "")
                if groups and "repair" not in tag and "replay" not in tag:
                    fallback = max(groups) + 1
                it = fallback
            groups.setdefault(it, []).append(d)
        if not groups:
            return []
        return [groups.get(i, []) for i in range(max(groups) + 1)]

    def _iteration_costs(self) -> dict[int, float]:
        """Map iteration index -> cumulative spend, from the recorded transcript."""
        out: dict[int, float] = {}
        cum = 0.0
        for i, group in enumerate(self._grouped_calls()):
            cum += sum(d.get("cost_usd") or 0.0 for d in group)
            out[i] = round(cum, 4)
        return out

    def _calls_per_iteration(self) -> dict[int, int]:
        """Iteration index -> number of recorded calls, from the transcript.

        Read once and cached, because replay writes its own records into the
        same directory and must not count them.
        """
        if getattr(self, "_calls_cache", None) is None:
            self._calls_cache = {i: len(group)
                                 for i, group in enumerate(self._grouped_calls())}
        return self._calls_cache

    def _prior_iterations(self) -> list[dict]:
        """Reconstruct the iteration table for iterations completed before resume."""
        costs = self._iteration_costs()
        rows = []
        for i in range(self.resume_from):
            f = self.out / "iterations" / f"iter-{i}" / "summary.json"
            if not f.exists():
                continue
            s = json.loads(f.read_text(encoding="utf-8")); st = s["structure"]
            rows.append({
                "iteration": i, "strategy": f"gen_iter{i}",
                "acceptance_rate": s["acceptance_rate"],
                "productions_hit": st["productions_hit"],
                "productions_total": st["productions_total"],
                "productions_missing": st["missing"],
                "max_depth": st["max_depth_seen"],
                "distinct_diagnostic_templates": s["distinct_diagnostic_templates"],
                "crash_count": s["crash_count"],
                "crash_groups": list(s["crash_groups"].keys()),
                "cost_usd_cumulative": costs.get(i),
            })
        return rows

    # ------------------------------------------------------------------ calls
    def _load_directives(self) -> list[str]:
        f = self.prompts / "directives.md"
        if not f.exists():
            return []
        import re as _re
        return _re.findall(r"^## \d+\. (.+)$", f.read_text(encoding="utf-8"), _re.M)

    def _debug(self, event: str, **fields) -> None:
        """Record a structured event when --debug is enabled."""
        if self.debug_log is not None:
            self.debug_log.event(event, run_id=self.run_id, **fields)

    def _call(self, user: str, tag: str, backend=None,
              iteration: int | None = None) -> llm.LLMResponse:
        self._call_seq += 1
        n = self._call_seq
        d = self.transcript / f"call-{n}"
        d.mkdir(parents=True, exist_ok=True)
        (d / "system.md").write_text(self.system, encoding="utf-8")
        (d / "user.md").write_text(user, encoding="utf-8")
        meta = {"tag": tag, "call": n}
        if iteration is not None:
            meta["iteration"] = iteration
        (d / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

        t0 = time.monotonic()
        be = backend or self.backend
        self._status.phase(f"llm:{tag}")
        try:
            if getattr(self, "stream", False) and hasattr(be, "complete_stream"):
                r = be.complete_stream(self.system, user)
            else:
                r = be.complete(self.system, user)
        except BaseException as exc:
            self._debug("llm_call_failed", call=n, tag=tag, iteration=iteration,
                        error=f"{type(exc).__name__}: {exc}",
                        prompt_chars=len(user))
            self._status.note(f"LLM call {n} failed: {type(exc).__name__}")
            raise
        elapsed = time.monotonic() - t0
        if getattr(r, "fallback_used", False):
            print(f"    [llm:fallback] failover used: from {r.fallback_from} to {r.backend} ({r.model})")

        rec = r.to_json()
        rec["tag"] = tag
        if iteration is not None:
            rec["iteration"] = iteration
        rec["elapsed_s"] = round(elapsed, 2)
        (d / "response.json").write_text(json.dumps(rec, indent=2), encoding="utf-8")
        self.budget.add(r, len(self.system) + len(user))
        cost = f"${r.cost_usd:.4f}" if r.cost_usd is not None else "n/a"
        print(f"    [llm] call {n} ({tag}) {elapsed:.1f}s  "
              f"in={r.billable_input} out={r.output_tokens} cost={cost}")
        self._status.llm_call(n, tag, elapsed, r.cost_usd)
        self._debug("llm_call", call=n, tag=tag, iteration=iteration,
                    elapsed_s=round(elapsed, 2), input_tokens=r.billable_input,
                    output_tokens=r.output_tokens, cost_usd=r.cost_usd,
                    model=r.model, backend=r.backend)
        return r

    # ---------------------------------------------------------------- prompts
    def _seed_prompt(self) -> str:
        tpl = (self.prompts / "seed.md").read_text(encoding="utf-8")
        return (tpl
                .replace("{grammar_commit}", GRAMMAR_COMMIT)
                .replace("{parser_g4}", _grammar_body("XMLParser.g4"))
                .replace("{lexer_g4}", _grammar_body("XMLLexer.g4"))
                .replace("{productions}", "\n   ".join(
                    "  ".join(PRODUCTIONS[i:i + 4]) for i in range(0, len(PRODUCTIONS), 4))))

    def _refine_prompt(self, it: int, source: str, summary: dict, results: list[dict],
                       directive_override: str | None = None) -> str:
        tpl = (self.prompts / "refine.md").read_text(encoding="utf-8")
        st = summary["structure"]
        slowest = sorted(results, key=lambda r: -r["dur_ms"])[:3]
        slow_txt = "\n".join(
            f"{r['dur_ms']:8.1f} ms  len={r['len']:<6} depth={r['structure']['max_depth']:<3} {r['outcome']}"
            for r in slowest) or "(none)"

        if summary["crash_groups"]:
            crash_txt = "### Crashes found\n\n```\n" + "\n".join(
                f"{sig}  x{b['count']}  {b['label']}"
                for sig, b in summary["crash_groups"].items()) + "\n```\n\n" + (
                "Keep whatever produced these and push harder on the same area.")
        else:
            crash_txt = ("### Crashes found\n\nNone yet. Sanitizers are active and a "
                         "known real bug is detected by this pipeline, so the "
                         "absence is real, not a detection failure.")

        diag = "\n".join(f"{c:5d}  {t}" for t, c in
                         list(summary["diagnostic_templates"].items())[:20]) or "(none)"

        # Marginal contribution: what this iteration found that no earlier one
        # did. Scoring absolute per-iteration counts rewards re-covering old
        # ground; FunFuzz uses marginal coverage as fitness for this reason.
        this_diags = set(summary["diagnostic_templates"])
        this_prods = set(st["hit"])
        new_diags = sorted(this_diags - self.union_diagnostics)
        new_prods = sorted(this_prods - self.union_productions)
        self.union_diagnostics |= this_diags
        self.union_productions |= this_prods
        never_produced = [p for p in PRODUCTIONS if p not in self.union_productions]

        bd = st.get("boundaries", {})
        bound_txt = "\n".join(
            f"{k:20} max={v.get('max', 0):<8} p90={v.get('p90', 0):<8} "
            f"p50={v.get('p50', 0):<8} distinct values={v.get('distinct', 0)}"
            for k, v in bd.items()) or "(not measured)"

        bk = summary.get("buckets", {})
        bucket_txt = "\n".join(
            f"{b:14} share={e['share']:6.1%}  acceptance={e['acceptance_rate']:6.1%}  n={e['n']}"
            for b, e in sorted(bk.items())) or "(not measured)"

        directive = (directive_override
                     or (self.directives[(it - 1) % len(self.directives)]
                         if self.directives else "improve the strategy"))

        return (tpl
                .replace("{directive}", directive)
                .replace("{boundaries}", bound_txt)
                .replace("{buckets}", bucket_txt)
                .replace("{new_diagnostics}",
                         f"{len(new_diags)}\n" + "\n".join(f"  + {d}" for d in new_diags)
                         if new_diags else "0  (nothing new -- this is the problem to fix)")
                .replace("{new_productions}",
                         f"{len(new_prods)}: " + ", ".join(new_prods) if new_prods else "0")
                .replace("{union_diagnostics}", str(len(self.union_diagnostics)))
                .replace("{union_diagnostic_list}",
                         "\n".join(sorted(self.union_diagnostics)) or "(none)")
                .replace("{iteration}", str(it))
                .replace("{strategy_source}", source)
                .replace("{examples}", str(summary["examples"]))
                .replace("{outcomes}", json.dumps(summary["outcomes"], indent=2))
                .replace("{acceptance_rate}", f"{summary['acceptance_rate']:.1%}")
                .replace("{crash_count}", str(summary["crash_count"]))
                .replace("{xml_shaped_rate}", f"{summary['xml_shaped_rate']:.1%}")
                .replace("{productions_hit}", str(st["productions_hit"]))
                .replace("{productions_total}", str(st["productions_total"]))
                .replace("{productions_hit_detail}", "\n".join(
                    f"{v:5d}  {k}" for k, v in sorted(st["hit"].items(), key=lambda kv: -kv[1])) or "(none)")
                .replace("{productions_missing}", "\n".join(never_produced)
                         or "(none -- full coverage across all iterations)")
                .replace("{depth_histogram}", json.dumps(st["depth_histogram"], indent=2))
                .replace("{max_depth}", str(st["max_depth_seen"]))
                .replace("{distinct_templates}", str(summary["distinct_diagnostic_templates"]))
                .replace("{diagnostic_templates}", diag)
                .replace("{input_len}", json.dumps(summary["input_len"], indent=2))
                .replace("{slowest}", slow_txt)
                .replace("{crash_section}", crash_txt))

    # ------------------------------------------------------------------- main
    def _obtain_strategy(self, it: int, prompt: str, tag: str,
                         max_repairs: int | None = None
                         ) -> tuple[str, str] | None:
        """Call, validate, repair. Returns (module_name, source) or None."""
        repairs = MAX_REPAIRS if max_repairs is None else max(0, int(max_repairs))
        self._last_gate_failures = 0
        self._last_source_kind = "llm"
        name = f"gen_iter{it}"
        dest = STRATEGY_DIR / f"{name}.py"
        if self.backend_seed.name == "replay":
            return self._replay_strategy(it, prompt, tag, name, dest)
        if self.ensemble_backends:
            return self._ensemble_strategy(it, prompt, tag, repairs)
        backend = self.backend_seed if tag == "seed" else self.backend_refine
        return self._obtain_single(it, prompt, tag, name, dest, backend, repairs)

    def _obtain_single(self, it: int, prompt: str, tag: str, name: str,
                       dest: Path, backend, max_repairs: int
                       ) -> tuple[str, str] | None:
        """One model's candidate: call, validate, repair up to `max_repairs`."""
        user = prompt
        attempt = 0
        resends = 0
        failures = 0
        while attempt <= max_repairs:
            if self.budget.would_overrun():
                print(f"    [budget] ${self.budget.cost_usd:.2f} spent, mean call "
                      f"${self.budget.mean_call_cost:.2f}; not enough left under "
                      f"${self.budget.max_usd:.2f} for another call")
                print("      hint: raise --max-usd, or resume the completed "
                      "iterations with --resume-from N")
                self._status.note("budget stopped a strategy call")
                self._debug("budget_stop", iteration=it, tag=tag,
                            phase="obtain", spent=self.budget.cost_usd,
                            max_usd=self.budget.max_usd,
                            mean_call_cost=self.budget.mean_call_cost)
                self._last_gate_failures += failures
                return None
            call_tag = tag if attempt == 0 else f"{tag}-repair{attempt}"
            r = self._call(user, call_tag, backend, iteration=it)
            v = validate.validate(r.text, dest, target=self.target)
            if v.ok:
                acc = f"{v.acceptance:.1%}" if v.acceptance is not None else "?"
                print(f"    [gate] {name} passed (smoke acceptance {acc})")
                self._debug("gate_passed", iteration=it, tag=call_tag,
                            stage=v.stage, acceptance=v.acceptance,
                            repairs=failures, call_n=self._call_seq)
                self._last_gate_failures += failures
                return name, v.code
            # A truncated block is a transport failure, not a modelling error:
            # the response arrived without its head. Resend the same prompt
            # rather than spending a repair asking for a fix to correct code.
            if v.stage == "truncated" and resends < MAX_RESENDS:
                resends += 1
                print(f"    [gate] response truncated in transport "
                      f"-> resend {resends}/{MAX_RESENDS}")
                self._debug("gate_truncated", iteration=it, tag=call_tag,
                            resend=resends, max_resends=MAX_RESENDS,
                            call_n=self._call_seq)
                if self.budget.would_overrun():
                    print(f"    [budget] no room under ${self.budget.max_usd:.2f} "
                          f"for another resend")
                    self._debug("budget_stop", iteration=it, tag=call_tag,
                                phase="resend", spent=self.budget.cost_usd,
                                max_usd=self.budget.max_usd)
                    self._last_gate_failures += failures
                    return None
                continue
            failures += 1
            print(f"    [gate] {name} FAILED at '{v.stage}' -> repair "
                  f"{attempt + 1}/{max_repairs}")
            print(f"      {validation_hint(v.stage, run_id=self.run_id)}")
            self._debug("gate_failed", iteration=it, tag=call_tag,
                        stage=v.stage, attempt=attempt + 1,
                        max_repairs=max_repairs, error=v.error,
                        call_n=self._call_seq)
            if attempt == max_repairs or self.budget.would_overrun():
                self._debug("gate_exhausted", iteration=it, tag=call_tag,
                            stage=v.stage, failures=failures)
                self._last_gate_failures += failures
                return None
            user = (prompt + "\n\n---\n\n# Your previous attempt was rejected\n\n"
                    + v.feedback())
            attempt += 1
        self._last_gate_failures += failures
        return None

    def _ensemble_strategy(self, it: int, prompt: str, tag: str,
                           max_repairs: int) -> tuple[str, str] | None:
        """Generate one candidate per model, screen them, and hold a vote.

        The screening campaign is much smaller than the real iteration: it is
        there to rank candidates, not to produce the run's artifact. The winner
        is then run again at full size by the caller, exactly like a
        single-model strategy, so the feedback the next prompt sees is measured
        on the same budget as every other iteration.
        """
        candidates: list[Candidate] = []
        screen_examples = min(self.screening_examples, self.max_examples)
        for idx, backend in enumerate(self.ensemble_backends):
            if self.budget.would_overrun():
                print(f"    [ensemble] budget stops after {idx} candidate(s)")
                break
            name = f"gen_iter{it}_c{idx}"
            dest = STRATEGY_DIR / f"{name}.py"
            model = getattr(backend, "model", "") or self.model or "(default)"
            print(f"    [ensemble] candidate {idx + 1}/{len(self.ensemble_backends)} "
                  f"model={model}")
            got = self._obtain_single(it, prompt, f"{tag}-ens{idx}", name, dest,
                                      backend, max_repairs)
            if got is None:
                candidates.append(Candidate(name=name, model=str(model),
                                            error="validation failed"))
                continue
            _, source = got
            screen_dir = (self.out / "iterations" / f"iter-{it}" /
                          "screening" / f"candidate-{idx}")
            try:
                summary = Campaign(
                    name, screen_examples, screen_dir,
                    mode="survey", target=self.target,
                    random_seed=1000 + it,
                    progress=self.progress_mode,
                    use_result_cache=self.use_result_cache,
                    result_cache_dir=self.result_cache_dir,
                    max_corpus_entries=self.max_corpus_entries,
                ).run()
            except Exception as exc:
                err = f"{type(exc).__name__}: {exc}"
                print(f"    [ensemble] candidate {idx} screening failed: {err[:160]}")
                print(f"      hint: {explain_exception(exc)}")
                self._debug("ensemble_screen_failed", iteration=it,
                            candidate=idx, error=err)
                candidates.append(Candidate(name=name, model=str(model),
                                            source=source, error=err))
                continue
            candidates.append(Candidate(name=name, model=str(model),
                                        source=source, summary=summary))
            print(f"    [ensemble] candidate {idx} screened: "
                  f"accept={summary['acceptance_rate']:.1%} "
                  f"prod={summary['structure']['productions_hit']} "
                  f"diag={summary['distinct_diagnostic_templates']} "
                  f"crashes={summary['crash_count']}")
            self._debug("ensemble_screened", iteration=it, candidate=idx,
                        acceptance=summary["acceptance_rate"],
                        productions=summary["structure"]["productions_hit"],
                        crashes=summary["crash_count"])

        result = vote_candidates(candidates)
        report = result.to_json()
        report["iteration"] = it
        report["screening_examples"] = screen_examples
        self._last_ensemble = report
        report_dir = self.out / "iterations" / f"iter-{it}"
        report_dir.mkdir(parents=True, exist_ok=True)
        (report_dir / "ensemble.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8")

        if result.winner is None:
            print("    [ensemble] no candidate passed the vote")
            return None
        winner = result.winner
        print(f"    [ensemble] winner {winner.name} ({winner.model}) "
              f"votes={winner.votes:.1f} score={winner.score:.2f}")
        dest = STRATEGY_DIR / f"gen_iter{it}.py"
        dest.write_text(winner.source, encoding="utf-8")
        self._last_source_kind = "ensemble"
        return f"gen_iter{it}", winner.source

    def _try_strategy_cache(self, it: int) -> tuple[str, str] | None:
        """Reuse a cached strategy for a similar target, after re-validation.

        Similarity is only a retrieval heuristic. The strategy still has to
        pass the same gates as a freshly generated one, against the current
        target. The first few matches are tried because the closest target may
        have a generator that fails this target's mixture bounds.
        """
        if self.cache is None:
            return None
        matches = self.cache.lookup(self.target_obj, limit=3)
        if not matches:
            return None
        name = f"gen_iter{it}"
        dest = STRATEGY_DIR / f"{name}.py"
        for match in matches:
            response = "```python\n" + match.source + "\n```"
            v = validate.validate(response, dest, target=self.target)
            if not v.ok:
                print(f"    [cache] match from {match.entry.target.name} "
                      f"(sim={match.similarity:.2f}) rejected at '{v.stage}'")
                print(f"      {validation_hint(v.stage, run_id=self.run_id)}")
                self._debug("cache_rejected", iteration=it,
                            source_run=match.entry.run_id,
                            similarity=match.similarity, stage=v.stage)
                continue
            acc = f"{v.acceptance:.1%}" if v.acceptance is not None else "?"
            print(f"    [cache] reusing strategy from {match.entry.target.name} "
                  f"(sim={match.similarity:.2f}, score={match.score:.2f}, "
                  f"smoke acceptance {acc})")
            self._debug("cache_reused", iteration=it,
                        source_run=match.entry.run_id,
                        target=match.entry.target.name,
                        similarity=match.similarity,
                        acceptance=v.acceptance)
            meta = match.to_json()
            meta["smoke_acceptance"] = v.acceptance
            idir = self.out / "iterations" / f"iter-{it}"
            idir.mkdir(parents=True, exist_ok=True)
            (idir / "cache_hit.json").write_text(
                json.dumps(meta, indent=2), encoding="utf-8")
            self._last_source_kind = "cache"
            return name, v.code
        return None

    def _replay_strategy(self, it: int, prompt: str, tag: str, name: str,
                         dest: Path) -> tuple[str, str] | None:
        """Reproduce one iteration's strategy from the recorded transcript.

        Replay reproduces what a run did; it does not re-judge it. The
        validation gates decide how many calls an iteration costs, so running
        today's gates against an old transcript would consume a different number
        of calls and diverge from the recorded sequence. Which calls belong to
        this iteration is already recorded, in each call's `tag`, so replay
        follows that instead: consume the iteration's calls in order and keep
        the last, which is the one the run accepted.
        """
        n = self._calls_per_iteration().get(it, 0)
        if not n:
            print(f"    [replay] no recorded calls for iteration {it}")
            return None
        code = None
        for k in range(n):
            r = self._call(prompt, tag if k == 0 else f"{tag}-replay{k}",
                           self.backend_seed, iteration=it)
            code = validate.extract_code(r.text)
        if code is None:
            print("    [replay] recorded response contained no python block")
            return None
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(code, encoding="utf-8")
        print(f"    [replay] reproduced from {n} recorded call(s)")
        return name, code

    def _repair_campaign(self, it: int, prompt: str, tag: str, name: str,
                         exc: Exception, max_repairs: int | None = None,
                         examples: int | None = None
                         ) -> tuple[str, str, dict] | None:
        """Repair a strategy that passed the gate then died during the campaign.

        Returns (module name, source, summary) once the campaign completes, or
        None when the budget or the repair allowance runs out.
        """
        repairs = MAX_REPAIRS if max_repairs is None else max(0, int(max_repairs))
        run_examples = self.max_examples if examples is None else max(
            1, min(self.max_examples, int(examples)))
        dest = STRATEGY_DIR / f"{name}.py"
        idir = self.out / "iterations" / f"iter-{it}"
        err = f"{type(exc).__name__}: {exc}"
        for attempt in range(1, repairs + 1):
            if self.budget.would_overrun():
                print(f"    [budget] ${self.budget.cost_usd:.2f} spent, mean call "
                      f"${self.budget.mean_call_cost:.2f}; not enough left under "
                      f"${self.budget.max_usd:.2f} for a campaign repair")
                print("      hint: raise --max-usd, then resume with "
                      "--resume-from N to keep completed iterations")
                self._debug("budget_stop", iteration=it, tag=tag,
                            phase="campaign_repair",
                            spent=self.budget.cost_usd,
                            max_usd=self.budget.max_usd)
                return None
            user = (prompt + "\n\n---\n\n# Your previous attempt was rejected\n\n"
                    "The module passed validation but failed part-way through the "
                    f"{run_examples}-document run:\n\n{err[:1200]}\n\n"
                    "The failing path was not taken by the smaller validation "
                    "sample, so check every branch, not only the common one. "
                    "Hypothesis rejects some sizes outright, so keep collection "
                    "sizes well inside its limits and cap them explicitly. "
                    "Fix and resend.")
            backend = self.backend_seed if tag == "seed" else self.backend_refine
            r = self._call(user, f"{tag}-campaign-repair{attempt}", backend,
                           iteration=it)
            v = validate.validate(r.text, dest, target=self.target)
            if not v.ok:
                print(f"    [gate] FAILED at '{v.stage}' -> campaign repair "
                      f"{attempt}/{repairs}")
                print(f"      {validation_hint(v.stage, run_id=self.run_id)}")
                self._debug("campaign_repair_gate_failed", iteration=it,
                            attempt=attempt, stage=v.stage, error=v.error)
                err = v.error or v.stage
                continue
            try:
                summary = Campaign(
                    name, run_examples, idir, mode="survey",
                    target=self.target,
                    progress=self.progress_mode,
                    use_result_cache=self.use_result_cache,
                    result_cache_dir=self.result_cache_dir,
                    max_corpus_entries=self.max_corpus_entries,
                ).run()
            except Exception as again:
                err = f"{type(again).__name__}: {again}"
                print(f"    [run] campaign failed again: {err[:120]}")
                print(f"      hint: {explain_exception(again)}")
                self._debug("campaign_repair_failed", iteration=it,
                            attempt=attempt, error=err)
                continue
            print(f"    [run] campaign repaired on attempt {attempt}")
            self._debug("campaign_repaired", iteration=it, attempt=attempt,
                        acceptance=summary["acceptance_rate"])
            return name, v.code, summary
        return None

    def run(self) -> dict:
        """Run the loop, closing progress and debug resources on every path."""
        try:
            return self._run()
        except BaseException as exc:
            self._debug("run_failed", error=f"{type(exc).__name__}: {exc}")
            raise
        finally:
            self._status.finish()
            if self.debug_log is not None:
                self.debug_log.close()

    def _run(self) -> dict:
        self._status.start()
        self._debug("run_started", backend=self.backend_kind,
                    target=self.target, max_iterations=self.max_iterations,
                    max_examples=self.max_examples, max_usd=self.max_usd,
                    prompt_set=self.prompt_set,
                    resume_from=self.resume_from)
        stopped_early: str | None = None
        iterations: list[dict] = self._prior_iterations()
        prev_source = ""
        prev_summary: dict | None = None
        prev_results: list[dict] = []
        if self.resume_from:
            prev_source, prev_summary, prev_results = self._load_prev(self.resume_from)

        for it in range(self.resume_from, self.max_iterations):
            print(f"\n=== iteration {it} ===")
            if self.budget.exhausted:
                print(f"    budget exhausted (${self.budget.cost_usd:.2f}); stopping")
                print("      hint: resume the completed iterations later with "
                      f"--resume-from {it}")
                self._debug("budget_exhausted", iteration=it,
                            spent=self.budget.cost_usd,
                            max_usd=self.budget.max_usd)
                stopped_early = "budget exhausted"
                break
            self._status.iteration_started(it)
            self._debug("iteration_started", iteration=it,
                        resume=bool(self.resume_from))

            # Per-iteration provenance. These are read when the iteration row
            # is written, so a cache hit or ensemble must not bleed into the
            # next iteration's row.
            self._last_gate_failures = 0
            self._last_source_kind = "llm"
            self._last_ensemble = None

            if self.tuner is not None:
                decision = self.tuner.decide(it)
            else:
                decision = TuningDecision(examples=self.max_examples,
                                          repairs=MAX_REPAIRS,
                                          directive=None, reason="fixed")
            examples = max(1, min(self.max_examples, decision.examples))

            if it == 0:
                prompt, tag = self._seed_prompt(), "seed"
            else:
                prompt = self._refine_prompt(
                    it, prev_source, prev_summary, prev_results,
                    directive_override=decision.directive)
                tag = "refine"

            idir = self.out / "iterations" / f"iter-{it}"
            idir.mkdir(parents=True, exist_ok=True)

            # Few-shot examples are appended after the template is rendered so
            # both prompt sets (which do not contain a placeholder) get them.
            if self.fewshot is not None:
                block = self.fewshot.render(
                    self.target_obj, exclude_run=self.run_id,
                    exclude_iteration=it)
                if block:
                    prompt = prompt + "\n\n---\n\n" + block
                    (idir / "few_shot.md").write_text(block, encoding="utf-8")
                    print(f"    [few-shot] appended {len(block)} chars "
                          f"from earlier runs")

            got = None
            if it == 0 and self.cache is not None:
                got = self._try_strategy_cache(it)
            if got is None:
                try:
                    got = self._obtain_strategy(it, prompt, tag,
                                                max_repairs=decision.repairs)
                except llm.LLMError as exc:
                    # A backend failure must not discard the iterations that
                    # already succeeded. Stop the loop, but fall through to
                    # writing the summary and iteration log for the work
                    # completed so far.
                    print(f"    [llm] FAILED: {exc}")
                    print(f"      hint: {explain_exception(exc)}")
                    self._debug("llm_failed", iteration=it,
                                error=f"{type(exc).__name__}: {exc}",
                                spent=self.budget.cost_usd)
                    if getattr(exc, "usage_limit", False):
                        print(f"    the backend refused on an account limit, not "
                              f"a budget one: ${self.budget.cost_usd:.2f} of "
                              f"${self.max_usd:.2f} is spent. Resume with "
                              f"--resume-from {it} once the limit window has "
                              f"reset.")
                    print("    stopping early; completed iterations are preserved")
                    stopped_early = f"{type(exc).__name__}: {exc}"
                    break
            if got is None:
                print("    [gate] could not obtain a usable strategy; stopping")
                print("      hint: inspect the gate failures with "
                      f"`python -m agent.debug --run-id {self.run_id} "
                      "--transcript`")
                self._debug("no_strategy", iteration=it,
                            gate_failures=self._last_gate_failures)
                stopped_early = "validation gate could not produce a usable strategy"
                break
            name, source = got
            source_kind = self._last_source_kind

            (idir / "strategy.py").write_text(source, encoding="utf-8")

            print(f"    [run] {examples} examples ...")
            self._status.phase("campaign")
            self._debug("campaign_started", iteration=it, strategy=name,
                        examples=examples, target=self.target)
            campaign_failed = False
            try:
                summary = Campaign(
                    name, examples, idir, mode="survey",
                    target=self.target,
                    progress=self.progress_mode,
                    use_result_cache=self.use_result_cache,
                    result_cache_dir=self.result_cache_dir,
                    max_corpus_entries=self.max_corpus_entries,
                ).run()
            except Exception as exc:
                # The validation gate draws a few dozen documents, so a branch
                # it never took can still fail at 500. A strategy that dies
                # here has already been paid for, so spend a repair on the
                # traceback rather than losing the iteration.
                campaign_failed = True
                print(f"    [run] campaign failed: {type(exc).__name__}: {exc}")
                print(f"      hint: {explain_exception(exc)}")
                self._debug("campaign_failed", iteration=it, strategy=name,
                            error=f"{type(exc).__name__}: {exc}")
                repaired = self._repair_campaign(
                    it, prompt, tag, name, exc, max_repairs=decision.repairs,
                    examples=examples)
                if repaired is None:
                    stopped_early = f"campaign failed: {type(exc).__name__}: {exc}"
                    break
                name, source, summary = repaired
                (idir / "strategy.py").write_text(source, encoding="utf-8")
            st = summary["structure"]
            print(f"    accept={summary['acceptance_rate']:.1%} "
                  f"prod={st['productions_hit']}/{st['productions_total']} "
                  f"depth<={st['max_depth_seen']} "
                  f"diag={summary['distinct_diagnostic_templates']} "
                  f"crashes={summary['crash_count']}")
            self._status.iteration_finished(
                it,
                acceptance=summary["acceptance_rate"],
                productions=f"{st['productions_hit']}/{st['productions_total']}",
                crashes=summary["crash_count"],
                cost_usd=self.budget.cost_usd,
            )
            self._debug("iteration_finished", iteration=it, strategy=name,
                        examples=examples, acceptance=summary["acceptance_rate"],
                        productions=st["productions_hit"],
                        productions_total=st["productions_total"],
                        max_depth=st["max_depth_seen"],
                        crashes=summary["crash_count"],
                        cost_usd=round(self.budget.cost_usd, 4),
                        source=source_kind)

            # Persist this iteration's strategy for reuse by later runs. It is
            # only cached after it ran, so a cached entry always has measured
            # results attached and a score to rank it by.
            if self.cache is not None:
                self.cache.store(source, self.target_obj, summary,
                                 self.run_id, it)

            results = [json.loads(l) for l in (idir / "results.jsonl").read_text(encoding="utf-8").splitlines()]
            new_diags = set(summary.get("diagnostic_templates", {})) - self.union_diagnostics
            new_prods = set(st.get("hit", {})) - self.union_productions
            iterations.append({
                "iteration": it, "strategy": name,
                "examples": examples,
                "source": source_kind,
                "acceptance_rate": summary["acceptance_rate"],
                "productions_hit": st["productions_hit"],
                "productions_total": st["productions_total"],
                "productions_missing": st["missing"],
                "max_depth": st["max_depth_seen"],
                "distinct_diagnostic_templates": summary["distinct_diagnostic_templates"],
                "crash_count": summary["crash_count"],
                "crash_groups": list(summary["crash_groups"].keys()),
                "cost_usd_cumulative": round(self.budget.cost_usd, 4),
                "tuning": decision.to_json(),
                "gate_failures": self._last_gate_failures,
                "ensemble": bool(self._last_ensemble),
            })
            if self.tuner is not None:
                self.tuner.observe(
                    it, examples=examples,
                    new_productions=len(new_prods),
                    new_diagnostics=len(new_diags),
                    crash_groups=len(summary["crash_groups"]),
                    gate_failures=self._last_gate_failures,
                    campaign_failed=campaign_failed,
                    cost_usd=self.budget.cost_usd,
                )
            prev_source, prev_summary, prev_results = source, summary, results

        self._debug("run_finished", cost_usd=round(self.budget.cost_usd, 4),
                    llm_calls=self.budget.calls,
                    iterations=len(iterations), stopped_early=stopped_early)
        features = {
            "strategy_cache": self.cache.stats() if self.cache is not None else {"enabled": False},
            "few_shot": self.fewshot.stats() if self.fewshot is not None else {"enabled": False},
            "autotune": self.tuner.to_json() if self.tuner is not None else {"enabled": False},
            "ensemble": {
                "enabled": bool(self.ensemble_backends),
                "models": self.ensemble_models_list,
                "candidates": len(self.ensemble_backends) or 1,
                "screening_examples": self.screening_examples,
                "last_vote": self._last_ensemble,
            },
            "harness": {
                "target": self.target,
                "binary": str(getattr(self.target_obj, "harness_binary", "") or ""),
                "generated": bool(self.use_generated_harness),
            },
        }
        final = {
            "run_id": self.run_id,
            "backend": self.backend_kind,
            "model": self.model or "(backend default)",
            "prompt_set": self.prompt_set,
            "seed_model": self.seed_model,
            "refine_model": self.refine_model,
            "max_examples": self.max_examples,
            "max_iterations": self.max_iterations,
            "target": self.target,
            "iterations": iterations,
            "budget": self.budget.to_json(),
            "cost_cap_enforced": self.cost_cap_enforced,
            "stopped_early": stopped_early,
            "resumed_from": self.resume_from or None,
            "features": features,
        }
        (self.out / "loop_summary.json").write_text(json.dumps(final, indent=2), encoding="utf-8")
        self._write_log(final)
        return final

    def _write_log(self, final: dict) -> None:
        rows = final["iterations"]
        lines = [
            f"# Iteration log: {final['run_id']}", "",
            f"Backend `{final['backend']}`, model `{final['model']}`, "
            f"{final['max_examples']} examples per iteration.", "",
            "| iter | source | examples | accept | productions | max depth | diagnostics | crashes | cum. cost |",
            "|---|---|---|---|---|---|---|---|---|",
            f"| baseline | - | - | {BASELINE['acceptance']} | {BASELINE['productions']} | "
            f"{BASELINE['depth']} | {BASELINE['templates']} | 0 | $0 |",
        ]
        for r in rows:
            cost_str = (f"${r['cost_usd_cumulative']:.2f} |"
                        if r.get("cost_usd_cumulative") is not None else "n/a |")
            lines.append(
                f"| {r['iteration']} | {r.get('source', 'llm')} | "
                f"{r.get('examples', final['max_examples'])} | "
                f"{r['acceptance_rate']:.1%} | "
                f"{r['productions_hit']}/{r['productions_total']} | {r['max_depth']} | "
                f"{r['distinct_diagnostic_templates']} | {r['crash_count']} | {cost_str}")
        b = final["budget"]
        lines += ["", "## Budget", "",
                  f"- LLM calls: **{b['llm_calls']}**",
                  f"- Prompt tokens billed (incl. backend overhead): {b['billable_input_tokens']:,}",
                  f"- Prompt tokens we authored (est.): {b['authored_prompt_tokens_est']:,}",
                  f"- Output tokens: {b['output_tokens']:,}",
                  f"- Cost: **${b['cost_usd']:.2f}** of ${b['max_usd']:.2f} cap"]
        if not final.get("cost_cap_enforced", True):
            lines.append("- Cost cap: **advisory only** — this backend reports no "
                         "per-call price, so the cap cannot be enforced.")
        (self.out / "ITERATION_LOG.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description="Run the Stratagem agentic fuzzing loop.")
    ap.add_argument("--backend", choices=("cli", "openai", "replay"), default=None,
                    help="default comes from LLM_BACKEND in .env, else replay")
    ap.add_argument("--run-id", default="loop")
    ap.add_argument("-n", "--max-examples", type=int, default=500)
    ap.add_argument("-i", "--iterations", type=int, default=5)
    ap.add_argument("--max-usd", type=float, default=5.00)
    ap.add_argument("--model", default=None,
                    help="default comes from LLM_MODEL in .env")
    ap.add_argument("--base-url", default=None,
                    help="OpenAI-compatible endpoint; default OPENAI_BASE_URL in .env")
    ap.add_argument("--resume-from", type=int, default=0,
                    help="resume at this iteration, reusing artifacts on disk")
    ap.add_argument("--prompt-set", default="v2", help="v1 (run A) or v2 (redesigned)")
    ap.add_argument("--seed-model", default=None, help="model for the seed call only")
    ap.add_argument("--refine-model", default=None, help="model for refine calls")
    ap.add_argument("--target", default="mxml",
                    choices=("mxml", "libxml2", "expat", "tinyxml2", "json", "http", "dns", "smtp"),
                    help="fuzzing target parser or protocol (default: mxml)")

    grp = ap.add_argument_group("agent enhancements")
    grp.add_argument("--use-strategy-cache", action="store_true",
                     help="reuse a validated strategy from a similar target")
    grp.add_argument("--cache-dir", default=None,
                     help="cache directory (default: runs/.strategy_cache)")
    grp.add_argument("--cache-similarity", type=float, default=0.70,
                     help="minimum target similarity for reuse (default: 0.70)")
    grp.add_argument("--few-shot", action="store_true",
                     help="append successful strategies from earlier runs to prompts")
    grp.add_argument("--few-shot-k", type=int, default=3,
                     help="maximum few-shot examples (default: 3)")
    grp.add_argument("--few-shot-budget", type=int, default=6000,
                     help="character budget for the few-shot block (default: 6000)")
    grp.add_argument("--autotune", action="store_true",
                     help="adapt examples, repairs and directive after each iteration")
    grp.add_argument("--tune-state", default=None,
                     help="tuning state path (default: runs/<run-id>/tuning.json)")
    grp.add_argument("--ensemble-models", default=None,
                     help="comma-separated models; one strategy candidate each")
    grp.add_argument("--ensemble-candidates", type=int, default=1,
                     help="candidate count when --ensemble-models is omitted (default: 1)")
    grp.add_argument("--screening-examples", type=int, default=50,
                     help="examples used to screen ensemble candidates (default: 50)")
    grp.add_argument("--use-generated-harness", action="store_true",
                     help="use harness/generated/<target>/harness if present")

    grp_llm = ap.add_argument_group("llm enhancements")
    grp_llm.add_argument("--stream", action="store_true",
                         help="stream LLM responses for faster feedback")
    grp_llm.add_argument("--prompt-ab", default=None,
                         help="comma-separated prompt sets for A/B testing (e.g. v4,v5)")
    grp_llm.add_argument("--fallbacks", default=None,
                         help="comma-separated fallback backends (e.g. cli,replay)")
    grp_llm.add_argument("--circuit-breaker", action="store_true",
                         help="enable circuit breaker protection on backend calls")

    grp_dx = ap.add_argument_group("developer experience")
    grp_dx.add_argument("--progress", choices=("auto", "on", "off"),
                        default="auto", dest="progress_mode",
                        help="iteration progress bar (default: auto, TTY only)")
    grp_dx.add_argument("--status", choices=("auto", "on", "off"),
                        default="auto", dest="status_mode",
                        help="real-time status lines (default: auto)")
    grp_dx.add_argument("--debug", action="store_true",
                        help="write structured events to runs/<id>/debug.jsonl "
                             "and print tracebacks on failure")

    grp_perf = ap.add_argument_group("performance enhancements")
    grp_perf.add_argument("--cache-results", action="store_true",
                          help="reuse harness results for identical inputs")
    grp_perf.add_argument("--result-cache-dir", default=None,
                          help="directory for harness result cache database")
    grp_perf.add_argument("--max-corpus-entries", type=int, default=None,
                          help="ceiling on in-memory corpus size")
    a = ap.parse_args()

    # .env is read here rather than at import time, so importing the module for
    # analysis has no side effect on the process environment.
    envmod.load_env()

    # Precedence: explicit flag > .env / environment > safe default. `replay`
    # is the default because it needs no credentials, so a reader who clones
    # the repo and runs the loop reproduces our results instead of being asked
    # for an API key they may not have.
    backend = a.backend or os.environ.get("LLM_BACKEND") or "replay"
    model = a.model or os.environ.get("LLM_MODEL") or None

    print(f"[loop] backend={backend}  target={a.target}  {envmod.describe_env()}")
    if backend in ("openai", "api") and a.max_usd > 0:
        print("[loop] note: this backend reports tokens but no per-call price, so "
              f"--max-usd ${a.max_usd:.2f} is advisory; the iteration cap is the "
              "hard limit. Token counts are recorded exactly.")

    context = {"run_id": a.run_id, "backend": backend, "target": a.target,
               "max_iterations": a.iterations}
    try:
        loop = Loop(
            backend_kind=backend,
            run_id=a.run_id,
            max_examples=a.max_examples,
            max_iterations=a.iterations,
            max_usd=a.max_usd,
            model=model,
            base_url=a.base_url,
            resume_from=a.resume_from,
            prompt_set=a.prompt_set,
            seed_model=a.seed_model,
            refine_model=a.refine_model,
            target=a.target,
            use_strategy_cache=a.use_strategy_cache,
            cache_dir=a.cache_dir,
            cache_similarity=a.cache_similarity,
            few_shot=a.few_shot,
            few_shot_k=a.few_shot_k,
            few_shot_budget=a.few_shot_budget,
            autotune=a.autotune,
            tune_state=a.tune_state,
            ensemble_models=a.ensemble_models,
            ensemble_candidates=a.ensemble_candidates,
            screening_examples=a.screening_examples,
            use_generated_harness=a.use_generated_harness,
            stream=a.stream,
            prompt_ab=a.prompt_ab,
            fallbacks=a.fallbacks,
            circuit_breaker=a.circuit_breaker,
            progress_mode=a.progress_mode,
            status_mode=a.status_mode,
            debug=a.debug,
            use_result_cache=a.cache_results,
            result_cache_dir=a.result_cache_dir,
            max_corpus_entries=a.max_corpus_entries,
        )
        final = loop.run()
    except KeyboardInterrupt:
        print("\n[loop] interrupted; completed iterations are preserved. "
              f"Resume with --run-id {a.run_id} --resume-from N.",
              file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        print(file=sys.stderr)
        print(format_exception(exc, context=context, debug=a.debug),
              file=sys.stderr)
        raise SystemExit(1)

    print(f"\nwrote {loop.out}/ITERATION_LOG.md")
    print(json.dumps(final["budget"], indent=2))


if __name__ == "__main__":
    main()
