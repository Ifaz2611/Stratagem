"""Actionable errors, structured debug logs, and run diagnosis.

A fuzzing run fails in ways that are hard to read from a traceback alone: the
LLM returned prose instead of code, the transcript ran out, the harness was
never built, a campaign died on the last branch. Each of those has a different
fix, and the raw exception rarely names it.

This module turns failures into three things:

  * :class:`AgentError` -- an exception carrying a ``hint`` and a ``context``
    mapping, rendered by :func:`format_exception`.
  * :class:`DebugLog` -- append-only JSONL events under the run directory, so a
    failure can be reconstructed after the terminal output is gone.
  * :class:`RunDiagnostics` -- a read-only scan of a run's artifacts that names
    what is missing, what failed, and the command most likely to help.

Nothing here needs an LLM, a harness or a network connection.
"""
from __future__ import annotations

import json
import os
import re
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNS_ROOT = REPO_ROOT / "runs"

VALIDATION_STAGES = ("extract", "truncated", "syntax", "interface", "smoke",
                     "mixture", "ok")
_RE_ITERATION = re.compile(r"Current strategy \(iteration (\d+)\)")


def infer_iteration(meta: dict | None, response: dict | None,
                    call_dir: Path) -> int | None:
    """Which iteration paid for a call, tolerating older transcripts.

    Newer recordings store `iteration` on the call. Older ones carry it only
    in the prompt, and a seed call is iteration 0 by definition. Keeping this
    inference here (rather than importing agent.loop) lets the debugger inspect
    transcripts without constructing a Loop or spending budget.
    """
    iteration = (meta or {}).get("iteration")
    if isinstance(iteration, int):
        return iteration
    iteration = (response or {}).get("iteration")
    if isinstance(iteration, int):
        return iteration
    tag = str((meta or {}).get("tag", ""))
    if tag.startswith("seed"):
        return 0
    user = call_dir / "user.md"
    if user.exists():
        match = _RE_ITERATION.search(user.read_text(encoding="utf-8",
                                                     errors="replace"))
        if match:
            return int(match.group(1))
    return None


class AgentError(RuntimeError):
    """Base error with an actionable hint and structured context."""

    def __init__(
        self,
        message: str,
        *,
        hint: str = "",
        context: dict[str, Any] | None = None,
        cause: BaseException | None = None,
    ):
        super().__init__(message)
        self.message = message
        self.hint = hint
        self.context = dict(context or {})
        self.cause = cause

    def __str__(self) -> str:
        return self.message

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": type(self).__name__,
            "message": self.message,
            "hint": self.hint,
            "context": self.context,
        }


class ConfigurationError(AgentError):
    """A flag or environment value is invalid before the run starts."""


class TranscriptError(AgentError):
    """The recorded LLM transcript cannot satisfy the loop's calls."""


class BudgetExhausted(AgentError):
    """The spend or iteration budget cannot pay for the next step."""


class ArtifactError(AgentError):
    """A run artifact is missing, unreadable or inconsistent."""


def _scrub(text: str) -> str:
    """Remove credential values from text before writing it to disk."""
    for var in ("OPENAI_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"):
        value = os.environ.get(var)
        if value and len(value) > 8:
            text = text.replace(value, f"<{var}>")
    return text


def _format_context(context: dict[str, Any]) -> str:
    if not context:
        return ""
    lines = []
    for key, value in context.items():
        if value is None or value == "":
            continue
        lines.append(f"    {key}: {value}")
    return "\n".join(lines)


def format_exception(
    exc: BaseException,
    *,
    context: dict[str, Any] | None = None,
    debug: bool = False,
) -> str:
    """Render an exception as a readable, actionable block.

    The hint comes from the exception itself when it is an :class:`AgentError`,
    otherwise from :func:`explain_exception`. Context supplied by the caller is
    merged with the exception's own context, with the caller winning because it
    knows where in the loop the failure happened.
    """
    if isinstance(exc, AgentError):
        hint = exc.hint or explain_exception(exc)
        merged = {**exc.context, **(context or {})}
        head = f"{type(exc).__name__}: {exc.message}"
    else:
        hint = explain_exception(exc)
        merged = dict(context or {})
        head = f"{type(exc).__name__}: {exc}"

    parts = [head]
    hint_lines = hint.strip().splitlines() if hint else []
    for index, line in enumerate(hint_lines):
        parts.append(f"  hint: {line}" if index == 0 else f"        {line}")
    ctx = _format_context(merged)
    if ctx:
        parts.append("  context:")
        parts.append(ctx)
    if debug:
        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        parts.append("  traceback:")
        parts.extend("    " + ln for ln in tb.rstrip().splitlines())
    else:
        parts.append("  debug: re-run with --debug (or use "
                     "`python -m agent.debug --run-id <id>`) for details")
    return "\n".join(parts)


def validation_hint(stage: str, *, run_id: str = "<run-id>") -> str:
    """A concrete next step for each strategy-validation gate."""
    stage = (stage or "").lower()
    if stage == "extract":
        return ("The response had no fenced python block. Inspect it with "
                f"`python -m agent.debug --run-id {run_id} --call N`; if this "
                "recurs, the prompt or backend is returning prose.")
    if stage == "truncated":
        return ("The response lost the start of the module in transport. The "
                "loop resends twice automatically; if it keeps happening, "
                "inspect the raw call with "
                f"`python -m agent.debug --run-id {run_id} --call N --full`, "
                "or try --stream / a different backend.")
    if stage == "syntax":
        return ("The module does not compile. Read the response with "
                f"`python -m agent.debug --run-id {run_id} --call N --full` and "
                "fix the reported line; a repair call should normally handle "
                "this.")
    if stage == "interface":
        return ("The module imports but does not expose NAME, DESCRIPTION and "
                "documents() -> SearchStrategy[str]. Reproduce the probe with "
                f"`python -m agent.debug --run-id {run_id} --iteration N`.")
    if stage == "smoke":
        return ("The parser rejected too much of the smoke batch. Run the "
                "strategy by hand with `python -m fuzzer.campaign gen_iterN "
                "-n 50` to see the inputs that bounce.")
    if stage == "mixture":
        return ("The input-class mixture is outside bounds. The repair prompt "
                "names the short class; fix that generator rather than only "
                "changing the weights. Inspect the measured buckets with "
                f"`python -m agent.debug --run-id {run_id} --iteration N`.")
    return ("Inspect the failing response with "
            f"`python -m agent.debug --run-id {run_id} --transcript`.")


def explain_exception(exc: BaseException) -> str:
    """Best-effort actionable advice for an exception.

    Hints are matched on type and message because the useful distinction is
    often carried in the text (for example, two different transcript failures
    are both ``LLMError``).
    """
    if isinstance(exc, AgentError):
        return exc.hint
    if isinstance(exc, KeyboardInterrupt):
        return ("Interrupted. Completed iterations are preserved; resume with "
                "`python -m agent.loop --run-id <id> --resume-from N`.")
    if isinstance(exc, MemoryError):
        return ("Out of memory. Lower --max-examples and resume the run; the "
                "completed iterations stay on disk.")
    if isinstance(exc, PermissionError):
        return ("Permission denied. Check ownership of the run directory and "
                "whether another process has the harness binary open.")
    if isinstance(exc, TimeoutError) or type(exc).__name__ in (
            "TimeoutExpired", "CampaignWallClockExceeded"):
        return ("A step exceeded its time limit. Raise --timeout for slow "
                "targets or lower --max-examples; a wall-clock cap of 10 "
                "minutes per campaign is the hard maximum.")

    text = str(exc)
    lower = text.lower()
    typename = type(exc).__name__

    if typename == "LLMError":
        if "transcript exhausted" in lower:
            return ("The loop asked for more calls than the transcript holds, "
                    "which means the code changed since it was recorded. "
                    "Re-record with --backend cli/openai, or replay an older "
                    "commit.")
        if "no recorded calls" in lower:
            return ("Replay needs runs/<id>/transcript. Copy a transcript in, "
                    "or use --backend cli/openai for a live run.")
        if "usage limit" in lower or "quota" in lower or "rate limit" in lower:
            return ("The backend refused on an account limit. Wait for the "
                    "window to reset, then --resume-from the failed iteration.")
        return ("The LLM backend failed. Check credentials and endpoint with "
                "`python -m agent.debug --run-id <id> --events`, then resume.")
    if isinstance(exc, json.JSONDecodeError):
        return ("An artifact is corrupt or truncated JSON. Run "
                "`python -m agent.debug --run-id <id> --diagnose` to locate it; "
                "resume from the last complete iteration.")
    if isinstance(exc, FileNotFoundError):
        if "harness" in lower or "build" in lower or "third_party" in lower:
            return ("The harness binary is missing. Build it with "
                    "`cd harness && ./build.sh asan`, or run inside Docker.")
        if "transcript" in lower:
            return ("The run has no LLM transcript. Start a live run or point "
                    "--run-id at an existing recording.")
        return ("A required file is missing. The path is in the message above; "
                "`python -m agent.debug --run-id <id> --diagnose` lists every "
                "artifact a complete run needs.")
    if isinstance(exc, UnicodeDecodeError):
        return ("An artifact is not valid UTF-8. Read it with --full to see "
                "the raw bytes; regenerate the iteration if it is corrupt.")
    if isinstance(exc, ValueError):
        return ("A value is outside its allowed range. The message names the "
                "flag; see `python -m agent.loop --help` for valid values.")
    if isinstance(exc, OSError):
        return ("An operating-system operation failed. Check free disk space, "
                "path length and whether the file is locked by another run.")
    return ("Run `python -m agent.debug --run-id <id> --diagnose` for an "
            "artifact-level report, or re-run with --debug for a traceback.")


class DebugLog:
    """Append-only JSONL event log for one run.

    A line is one event, so the file stays parseable even when a process is
    killed mid-run. Writes are flushed immediately for the same reason.
    """

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def event(self, event: str, **fields: Any) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "event": event,
        }
        for key, value in fields.items():
            if isinstance(value, Path):
                value = str(value)
            try:
                json.dumps(value)
            except (TypeError, ValueError):
                value = repr(value)
            record[key] = _scrub(value) if isinstance(value, str) else value
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            # Debug logging must never take down the run it is describing.
            pass

    def read(self, limit: int | None = None) -> list[dict]:
        if not self.path.exists():
            return []
        events = []
        for line in self.path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                events.append({"event": "unparseable", "raw": line})
        return events[-limit:] if limit else events

    def close(self) -> None:
        """No-op: writes are already flushed. Kept for a symmetric API."""
        return None


@dataclass
class Finding:
    """One diagnosis result."""

    level: str          # error | warning | info
    code: str
    message: str
    hint: str = ""

    def to_json(self) -> dict[str, Any]:
        return {"level": self.level, "code": self.code,
                "message": self.message, "hint": self.hint}


@dataclass
class RunDiagnostics:
    """Read-only scan of a run directory.

    The scan answers four questions without loading an LLM or harness:

      1. Did the run finish, and if not, where did it stop?
      2. Which iterations are complete, and which artifacts are missing?
      3. How many transcript calls succeeded, failed or were repairs?
      4. Is the environment (harness, budget) healthy enough to resume?
    """

    root: Path | str = RUNS_ROOT
    run_id: str = "loop"

    @property
    def run_dir(self) -> Path:
        return Path(self.root) / self.run_id

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _read_json(path: Path) -> tuple[dict | None, str | None]:
        if not path.exists():
            return None, "missing"
        try:
            return json.loads(path.read_text(encoding="utf-8")), None
        except (OSError, json.JSONDecodeError) as exc:
            return None, f"{type(exc).__name__}: {exc}"

    def _iterations(self) -> tuple[list[dict], list[Finding]]:
        rows: list[dict] = []
        findings: list[Finding] = []
        it_root = self.run_dir / "iterations"
        if not it_root.exists():
            return rows, findings
        for d in sorted(it_root.glob("iter-*"),
                        key=lambda p: int(p.name.split("-")[1])
                        if p.name.split("-")[1].isdigit() else 0):
            suffix = d.name.split("-", 1)[1] if "-" in d.name else ""
            if not suffix.isdigit():
                continue
            idx = int(suffix)
            strategy = d / "strategy.py"
            results = d / "results.jsonl"
            summary, err = self._read_json(d / "summary.json")
            row: dict[str, Any] = {
                "iteration": idx,
                "path": str(d),
                "has_strategy": strategy.exists(),
                "has_summary": summary is not None,
                "has_results": results.exists(),
                "results": 0,
                "acceptance_rate": None,
                "crash_count": None,
            }
            if results.exists():
                row["results"] = sum(
                    1 for line in results.read_text(
                        encoding="utf-8", errors="replace").splitlines()
                    if line.strip())
            if summary:
                row["acceptance_rate"] = summary.get("acceptance_rate")
                row["crash_count"] = summary.get("crash_count")
                row["strategy_name"] = summary.get("strategy")
                row["target"] = summary.get("target")
            if err and err != "missing":
                findings.append(Finding(
                    "error", "corrupt_summary",
                    f"iter-{idx}/summary.json cannot be read: {err}",
                    "Regenerate this iteration or resume before it."))
            if not strategy.exists():
                findings.append(Finding(
                    "warning", "missing_strategy",
                    f"iter-{idx}/strategy.py is missing",
                    "The iteration did not finish writing its generator. "
                    "Resume from the last complete iteration."))
            if summary is None:
                findings.append(Finding(
                    "warning", "missing_summary",
                    f"iter-{idx}/summary.json is missing",
                    "The iteration was interrupted before measurement "
                    "finished; it cannot be used as refinement input."))
            if not results.exists():
                findings.append(Finding(
                    "warning", "missing_results",
                    f"iter-{idx}/results.jsonl is missing",
                    "Per-input results are needed for the refine prompt. "
                    "Re-run the campaign for this iteration."))
            elif row["results"] == 0:
                findings.append(Finding(
                    "warning", "empty_results",
                    f"iter-{idx}/results.jsonl is empty",
                    "The campaign produced no measurements; inspect the "
                    "iteration's crashes/ directory and debug events."))
            rows.append(row)
        return rows, findings

    def _transcript(self) -> tuple[dict, list[Finding]]:
        findings: list[Finding] = []
        calls: list[dict] = []
        tdir = self.run_dir / "transcript"
        info: dict[str, Any] = {
            "calls": 0, "failed": 0, "repairs": 0, "iterations": [],
            "cost_usd": 0.0, "output_tokens": 0, "elapsed_s": 0.0,
        }
        if not tdir.exists():
            findings.append(Finding(
                "warning", "missing_transcript",
                "transcript/ is missing",
                "Replay cannot run, and call-level debugging is unavailable."))
            return info, findings

        dirs = [p for p in tdir.glob("call-*")
                if p.is_dir() and p.name.split("-")[1].isdigit()]
        dirs.sort(key=lambda p: int(p.name.split("-")[1]))
        for d in dirs:
            n = int(d.name.split("-")[1])
            meta, _ = self._read_json(d / "meta.json")
            response, err = self._read_json(d / "response.json")
            tag = (meta or {}).get("tag", "")
            row = {
                "call": n, "tag": tag,
                "iteration": infer_iteration(meta, response, d),
                "ok": response is not None,
                "elapsed_s": None, "cost_usd": None, "backend": None,
                "error": err if response is None else None,
            }
            if response:
                row["elapsed_s"] = response.get("elapsed_s")
                row["cost_usd"] = response.get("cost_usd")
                row["backend"] = response.get("backend")
                row["fallback_used"] = response.get("fallback_used", False)
                info["cost_usd"] += response.get("cost_usd") or 0.0
                info["output_tokens"] += response.get("output_tokens", 0) or 0
                info["elapsed_s"] += response.get("elapsed_s", 0) or 0.0
                if "repair" in str(tag):
                    info["repairs"] += 1
                if row["iteration"] is not None:
                    info["iterations"].append(row["iteration"])
            else:
                info["failed"] += 1
                findings.append(Finding(
                    "error", "failed_call",
                    f"{d.name} has no response.json (tag={tag!r})",
                    f"Inspect the prompt with `python -m agent.debug --run-id "
                    f"{self.run_id} --call {n}`; the backend failed or the "
                    "process stopped during this call."))
            calls.append(row)
        info["calls"] = len(calls)
        info["iterations"] = sorted(set(info["iterations"]))
        info["cost_usd"] = round(info["cost_usd"], 4)
        info["elapsed_s"] = round(info["elapsed_s"], 2)
        info["call_rows"] = calls
        return info, findings

    def _environment(self, summary: dict | None,
                     iterations: list[dict] | None = None
                     ) -> tuple[dict, list[Finding]]:
        findings: list[Finding] = []
        env: dict[str, Any] = {"target": None, "harness": None,
                               "harness_exists": None}
        target = (summary or {}).get("target")
        if not target:
            for row in (iterations or []):
                target = row.get("target") or target
        if not target:
            return env, findings
        env["target"] = target
        try:
            from fuzzer.targets import get_target
            obj = get_target(target)
            harness = getattr(obj, "harness_binary", None)
            env["harness"] = str(harness) if harness else None
            if harness:
                env["harness_exists"] = Path(harness).exists()
                if not Path(harness).exists():
                    findings.append(Finding(
                        "error", "missing_harness",
                        f"harness binary for {target!r} is missing: {harness}",
                        "Build it with `cd harness && ./build.sh asan`, or run "
                        "inside the Docker image where it is prebuilt."))
        except Exception as exc:  # target registry is optional for diagnosis
            findings.append(Finding(
                "warning", "target_lookup_failed",
                f"could not resolve target {target!r}: {type(exc).__name__}: {exc}",
                "Check that the target name is registered in fuzzer/targets."))
        return env, findings

    # ------------------------------------------------------------------ scan
    def scan(self) -> dict[str, Any]:
        findings: list[Finding] = []
        run_dir = self.run_dir
        result: dict[str, Any] = {
            "run_id": self.run_id,
            "run_dir": str(run_dir),
            "exists": run_dir.exists(),
            "summary": None,
            "iterations": [],
            "transcript": {},
            "environment": {},
            "findings": [],
            "suggestions": [],
        }
        if not run_dir.exists():
            findings.append(Finding(
                "error", "run_missing",
                f"no run directory at {run_dir}",
                "List existing runs with `python -m agent.debug --list`."))
            result["findings"] = [f.to_json() for f in findings]
            result["suggestions"] = ["python -m agent.debug --list"]
            return result

        summary, err = self._read_json(run_dir / "loop_summary.json")
        if err and err != "missing":
            findings.append(Finding(
                "error", "corrupt_summary",
                f"loop_summary.json cannot be read: {err}",
                "The run may have been killed mid-write; inspect the "
                "iterations directly."))
        result["summary"] = summary

        iterations, iter_findings = self._iterations()
        findings.extend(iter_findings)
        result["iterations"] = iterations

        transcript, tx_findings = self._transcript()
        findings.extend(tx_findings)
        result["transcript"] = transcript

        environment, env_findings = self._environment(summary, iterations)
        findings.extend(env_findings)
        result["environment"] = environment

        if summary:
            if summary.get("stopped_early"):
                findings.append(Finding(
                    "error", "stopped_early",
                    f"the run stopped early: {summary['stopped_early']}",
                    "Fix the named failure, then resume from the first "
                    "incomplete iteration."))
            budget = summary.get("budget") or {}
            spent = budget.get("cost_usd")
            cap = budget.get("max_usd")
            if spent is not None and cap and spent >= cap:
                findings.append(Finding(
                    "warning", "budget_exhausted",
                    f"spend ${spent:.4f} reached the ${cap:.2f} cap",
                    "Raise --max-usd before resuming if more work is wanted."))
            if summary.get("cost_cap_enforced") is False:
                findings.append(Finding(
                    "info", "cost_cap_advisory",
                    "this backend reports no per-call price; --max-usd is "
                    "advisory and cannot be enforced",
                    "The iteration cap is the hard limit. Token counts are "
                    "still recorded exactly."))
            if not summary.get("iterations"):
                findings.append(Finding(
                    "warning", "no_iterations",
                    "loop_summary.json contains no completed iteration",
                    "Inspect transcript call-1 and the validation gate; a "
                    "seed strategy may never have passed."))
        elif (run_dir / "iterations").exists():
            findings.append(Finding(
                "info", "summary_pending",
                "loop_summary.json is absent but iterations exist",
                "The run is still in progress or was killed before writing "
                "its final summary."))

        # Debug events are optional, but the last failure is often the clearest
        # explanation available.
        events = DebugLog(run_dir / "debug.jsonl").read(limit=200)
        if events:
            result["events"] = events[-20:]
            failures = [e for e in events if "fail" in e.get("event", "")
                        or "error" in e.get("event", "")]
            if failures:
                last = failures[-1]
                findings.append(Finding(
                    "info", "last_debug_failure",
                    f"last debug failure: {last.get('event')} "
                    f"({last.get('error', last.get('stage', ''))})",
                    "See `python -m agent.debug --run-id "
                    f"{self.run_id} --events`."))

        result["findings"] = [f.to_json() for f in findings]
        result["suggestions"] = self._suggestions(result)
        return result

    def _suggestions(self, result: dict[str, Any]) -> list[str]:
        suggestions: list[str] = []
        run_id = self.run_id
        iterations = result.get("iterations") or []
        summary = result.get("summary") or {}
        max_iterations = summary.get("max_iterations")
        complete = {r["iteration"] for r in iterations
                    if r.get("has_summary") and r.get("has_strategy")}
        incomplete = any(not (r.get("has_summary") and r.get("has_strategy"))
                         for r in iterations)
        if complete:
            nxt = max(complete) + 1
            # Do not suggest a resume point the loop would reject. Older
            # summaries have no max_iterations; there, only an interrupted or
            # incomplete run justifies a resume hint.
            room = (nxt < max_iterations) if isinstance(max_iterations, int) else (
                incomplete or bool(summary.get("stopped_early")))
            if room:
                suggestions.append(
                    f"python -m agent.loop --run-id {run_id} --resume-from {nxt}")
        if result.get("transcript", {}).get("failed"):
            first_failed = next((c["call"] for c in
                                 result["transcript"].get("call_rows", [])
                                 if not c.get("ok")), None)
            if first_failed:
                suggestions.append(
                    f"python -m agent.debug --run-id {run_id} "
                    f"--call {first_failed}")
        if not result.get("summary"):
            suggestions.append(
                f"python -m agent.debug --run-id {run_id} --transcript")
        if not suggestions:
            suggestions.append(
                f"python -m agent.debug --run-id {run_id} --transcript")
        return suggestions

    # ----------------------------------------------------------------- render
    def render(self, result: dict[str, Any] | None = None) -> str:
        data = result or self.scan()
        lines = [f"Run diagnosis: {data['run_id']}",
                 f"  directory : {data['run_dir']}"]

        summary = data.get("summary") or {}
        if summary:
            lines.append(f"  backend   : {summary.get('backend', '?')} "
                         f"({summary.get('model', '?')})")
            budget = summary.get("budget") or {}
            lines.append(
                f"  budget    : ${budget.get('cost_usd', 0):.4f} of "
                f"${budget.get('max_usd', 0):.2f} "
                f"({budget.get('llm_calls', 0)} calls)")
            if summary.get("stopped_early"):
                lines.append(f"  stopped   : {summary['stopped_early']}")

        rows = data.get("iterations") or []
        lines.append(f"  iterations: {len(rows)}")
        for row in rows:
            accept = row.get("acceptance_rate")
            accept_txt = f"{accept:.1%}" if isinstance(accept, (int, float)) else "?"
            marks = "".join("s" if row.get("has_strategy") else "-")
            marks += "m" if row.get("has_summary") else "-"
            marks += "r" if row.get("has_results") else "-"
            lines.append(
                f"    iter-{row['iteration']:<2} [{marks}] "
                f"results={row.get('results', 0):<4} accept={accept_txt:<6} "
                f"crashes={row.get('crash_count') if row.get('crash_count') is not None else '?'}")

        tx = data.get("transcript") or {}
        if tx:
            lines.append(
                f"  transcript: {tx.get('calls', 0)} calls, "
                f"{tx.get('failed', 0)} failed, {tx.get('repairs', 0)} repairs, "
                f"${tx.get('cost_usd', 0):.4f}")

        findings = data.get("findings") or []
        errors = [f for f in findings if f["level"] == "error"]
        warnings = [f for f in findings if f["level"] == "warning"]
        infos = [f for f in findings if f["level"] == "info"]
        if not findings:
            lines += ["", "No problems found."]
        else:
            lines += ["", "Findings:"]
            for f in errors + warnings + infos:
                lines.append(f"  [{f['level'].upper():7}] {f['message']}")
                if f.get("hint"):
                    lines.append(f"            -> {f['hint']}")
        suggestions = data.get("suggestions") or []
        if suggestions:
            lines += ["", "Try:"]
            lines.extend(f"  {s}" for s in suggestions)
        return "\n".join(lines)

    def to_json(self, result: dict[str, Any] | None = None) -> dict[str, Any]:
        data = dict(result or self.scan())
        data.pop("events", None)
        return data


def list_runs(root: Path | str = RUNS_ROOT) -> list[dict[str, Any]]:
    """Summarise every run directory, newest first."""
    root = Path(root)
    if not root.exists():
        return []
    rows = []
    for d in root.iterdir():
        if not d.is_dir() or d.name.startswith("."):
            continue
        it_root = d / "iterations"
        iterations = sorted(it_root.glob("iter-*")) if it_root.exists() else []
        rows.append({
            "run_id": d.name,
            "iterations": len(iterations),
            "complete_iterations": sum(
                1 for it in iterations if (it / "summary.json").exists()),
            "has_summary": (d / "loop_summary.json").exists(),
            "mtime": d.stat().st_mtime if d.exists() else 0,
        })
    rows.sort(key=lambda r: r["mtime"], reverse=True)
    return rows


def iter_diagnostics(run_ids: Iterable[str], root: Path | str = RUNS_ROOT
                     ) -> list[dict[str, Any]]:
    return [RunDiagnostics(root, run_id).scan() for run_id in run_ids]
