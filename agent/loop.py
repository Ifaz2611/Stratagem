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
import time
from dataclasses import dataclass, field
from pathlib import Path

from agent import env as envmod
from agent import llm, validate
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
        self.budget = Budget(self.max_iterations, self.max_usd)
        self.out = REPO_ROOT / "runs" / self.run_id
        self.transcript = self.out / "transcript"
        self.transcript.mkdir(parents=True, exist_ok=True)
        self.prompts = PROMPTS_ROOT / self.prompt_set if self.prompt_set != "v1" else PROMPTS_ROOT
        if not (self.prompts / "seed.md").exists():
            raise llm.LLMError(f"prompt set not found: {self.prompts}")

        self.directives = self._load_directives()
        self.union_diagnostics: set[str] = set()
        self.union_productions: set[str] = set()
        from fuzzer.targets import get_target
        self.target_obj = get_target(self.target)
        self.system = (self.prompts / "system.md").read_text(encoding="utf-8")

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
            return llm.make_backend(self.backend_kind,
                                    transcript_dir=self.transcript, **kw)

        if self.backend_kind == "replay":
            # One shared instance: replay consumes recorded calls in order, so
            # two instances would each start from call-1 and desynchronise.
            self.backend = mk(None)
            self.backend_seed = self.backend_refine = self.backend
        else:
            self.backend_seed = mk(self.seed_model or self.model)
            self.backend_refine = mk(self.refine_model or self.model)
            self.backend = self.backend_refine

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
        r = (backend or self.backend).complete(self.system, user)
        elapsed = time.monotonic() - t0

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

    def _refine_prompt(self, it: int, source: str, summary: dict, results: list[dict]) -> str:
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

        directive = (self.directives[(it - 1) % len(self.directives)]
                     if self.directives else "improve the strategy")

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
    def _obtain_strategy(self, it: int, prompt: str, tag: str) -> tuple[str, str] | None:
        """Call, validate, repair. Returns (module_name, source) or None."""
        name = f"gen_iter{it}"
        dest = STRATEGY_DIR / f"{name}.py"
        if self.backend_seed.name == "replay":
            return self._replay_strategy(it, prompt, tag, name, dest)
        user = prompt
        attempt = 0
        resends = 0
        while attempt <= MAX_REPAIRS:
            if self.budget.would_overrun():
                print(f"    [budget] ${self.budget.cost_usd:.2f} spent, mean call "
                      f"${self.budget.mean_call_cost:.2f}; not enough left under "
                      f"${self.budget.max_usd:.2f} for another call")
                return None
            backend = self.backend_seed if tag == "seed" else self.backend_refine
            r = self._call(user, tag if attempt == 0 else f"{tag}-repair{attempt}",
                           backend, iteration=it)
            v = validate.validate(r.text, dest, target=self.target)
            if v.ok:
                acc = f"{v.acceptance:.1%}" if v.acceptance is not None else "?"
                print(f"    [gate] passed (smoke acceptance {acc})")
                return name, v.code
            # A truncated block is a transport failure, not a modelling error:
            # the response arrived without its head. Resend the same prompt
            # rather than spending a repair asking for a fix to correct code.
            if v.stage == "truncated" and resends < MAX_RESENDS:
                resends += 1
                print(f"    [gate] response truncated in transport "
                      f"-> resend {resends}/{MAX_RESENDS}")
                if self.budget.would_overrun():
                    print(f"    [budget] no room under ${self.budget.max_usd:.2f} "
                          f"for another resend")
                    return None
                continue
            print(f"    [gate] FAILED at '{v.stage}' -> repair {attempt + 1}/{MAX_REPAIRS}")
            if attempt == MAX_REPAIRS or self.budget.would_overrun():
                return None
            user = (prompt + "\n\n---\n\n# Your previous attempt was rejected\n\n"
                    + v.feedback())
            attempt += 1
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
                         exc: Exception) -> tuple[str, str, dict] | None:
        """Repair a strategy that passed the gate then died during the campaign.

        Returns (module name, source, summary) once the campaign completes, or
        None when the budget or the repair allowance runs out.
        """
        dest = STRATEGY_DIR / f"{name}.py"
        idir = self.out / "iterations" / f"iter-{it}"
        err = f"{type(exc).__name__}: {exc}"
        for attempt in range(1, MAX_REPAIRS + 1):
            if self.budget.would_overrun():
                print(f"    [budget] ${self.budget.cost_usd:.2f} spent, mean call "
                      f"${self.budget.mean_call_cost:.2f}; not enough left under "
                      f"${self.budget.max_usd:.2f} for a campaign repair")
                return None
            user = (prompt + "\n\n---\n\n# Your previous attempt was rejected\n\n"
                    "The module passed validation but failed part-way through the "
                    f"{self.max_examples}-document run:\n\n{err[:1200]}\n\n"
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
                      f"{attempt}/{MAX_REPAIRS}")
                err = v.error or v.stage
                continue
            try:
                summary = Campaign(name, self.max_examples, idir, mode="survey", target=self.target).run()
            except Exception as again:
                err = f"{type(again).__name__}: {again}"
                print(f"    [run] campaign failed again: {err[:120]}")
                continue
            print(f"    [run] campaign repaired on attempt {attempt}")
            return name, v.code, summary
        return None

    def run(self) -> dict:
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
                break

            if it == 0:
                prompt, tag = self._seed_prompt(), "seed"
            else:
                prompt = self._refine_prompt(it, prev_source, prev_summary, prev_results)
                tag = "refine"

            try:
                got = self._obtain_strategy(it, prompt, tag)
            except llm.LLMError as exc:
                # A backend failure must not discard the iterations that already
                # succeeded. Stop the loop, but fall through to writing the
                # summary and iteration log for the work completed so far.
                print(f"    [llm] FAILED: {exc}")
                if getattr(exc, "usage_limit", False):
                    print(f"    the backend refused on an account limit, not a "
                          f"budget one: ${self.budget.cost_usd:.2f} of "
                          f"${self.max_usd:.2f} is spent. Resume with "
                          f"--resume-from {it} once the limit window has reset.")
                print("    stopping early; completed iterations are preserved")
                stopped_early = f"{type(exc).__name__}: {exc}"
                break
            if got is None:
                print("    [gate] could not obtain a usable strategy; stopping")
                stopped_early = "validation gate could not produce a usable strategy"
                break
            name, source = got

            idir = self.out / "iterations" / f"iter-{it}"
            idir.mkdir(parents=True, exist_ok=True)
            (idir / "strategy.py").write_text(source, encoding="utf-8")

            print(f"    [run] {self.max_examples} examples ...")
            try:
                summary = Campaign(name, self.max_examples, idir, mode="survey", target=self.target).run()
            except Exception as exc:
                # The validation gate draws a few dozen documents, so a branch
                # it never took can still fail at 500. A strategy that dies
                # here has already been paid for, so spend one repair on the
                # traceback rather than losing the iteration.
                print(f"    [run] campaign failed: {type(exc).__name__}: {exc}")
                repaired = self._repair_campaign(it, prompt, tag, name, exc)
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

            results = [json.loads(l) for l in (idir / "results.jsonl").read_text(encoding="utf-8").splitlines()]
            iterations.append({
                "iteration": it, "strategy": name,
                "acceptance_rate": summary["acceptance_rate"],
                "productions_hit": st["productions_hit"],
                "productions_total": st["productions_total"],
                "productions_missing": st["missing"],
                "max_depth": st["max_depth_seen"],
                "distinct_diagnostic_templates": summary["distinct_diagnostic_templates"],
                "crash_count": summary["crash_count"],
                "crash_groups": list(summary["crash_groups"].keys()),
                "cost_usd_cumulative": round(self.budget.cost_usd, 4),
            })
            prev_source, prev_summary, prev_results = source, summary, results

        final = {
            "run_id": self.run_id,
            "backend": self.backend_kind,
            "model": self.model or "(backend default)",
            "prompt_set": self.prompt_set,
            "seed_model": self.seed_model,
            "refine_model": self.refine_model,
            "max_examples": self.max_examples,
            "iterations": iterations,
            "budget": self.budget.to_json(),
            "cost_cap_enforced": self.cost_cap_enforced,
            "stopped_early": stopped_early,
            "resumed_from": self.resume_from or None,
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
            "| iter | accept | productions | max depth | diagnostics | crashes | cum. cost |",
            "|---|---|---|---|---|---|---|",
            f"| baseline | {BASELINE['acceptance']} | {BASELINE['productions']} | "
            f"{BASELINE['depth']} | {BASELINE['templates']} | 0 | $0 |",
        ]
        for r in rows:
            cost_str = (f"${r['cost_usd_cumulative']:.2f} |"
                        if r.get("cost_usd_cumulative") is not None else "n/a |")
            lines.append(
                f"| {r['iteration']} | {r['acceptance_rate']:.1%} | "
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

    loop = Loop(backend, a.run_id, a.max_examples, a.iterations,
                a.max_usd, model, a.base_url, a.resume_from,
                a.prompt_set, a.seed_model, a.refine_model, a.target)
    final = loop.run()
    print(f"\nwrote {loop.out}/ITERATION_LOG.md")
    print(json.dumps(final["budget"], indent=2))


if __name__ == "__main__":
    main()
