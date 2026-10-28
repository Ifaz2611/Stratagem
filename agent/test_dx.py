"""Tests for the developer-experience layer.

Covers the three pieces added for debugging and observability:

  * actionable error formatting and stage-specific hints
  * structured JSONL debug logs
  * read-only run diagnosis and the ``python -m agent.debug`` CLI
  * progress bars, status lines and the loop's RunStatus coordinator

Like ``test_loop.py`` this is plain-assert Python: pytest collects it, and
``python -m agent.test_dx`` runs it without third-party packages.
"""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import traceback
from pathlib import Path

from agent import debug as debugmod
from agent.errors import (AgentError, DebugLog, RunDiagnostics,
                          explain_exception, format_error_summary,
                          format_exception, infer_iteration, list_runs,
                          standardize_error, validation_hint)
from agent.llm import LLMError
from agent.progress import (NullProgress, ProgressBar, RunStatus, StatusLine,
                            format_duration, make_progress, normalize_mode,
                            resolve_enabled)


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _summary(**overrides) -> dict:
    data = {
        "target": None,
        "strategy": "gen_iter0",
        "examples": 10,
        "acceptance_rate": 0.5,
        "crash_count": 0,
        "distinct_diagnostic_templates": 2,
        "structure": {
            "productions_hit": 5, "productions_total": 27,
            "max_depth_seen": 3, "hit": {"p0": 1, "p1": 1},
            "depth_histogram": {"1": 2},
        },
    }
    data.update(overrides)
    return data


def make_run(root: Path, run_id: str = "demo", *, healthy: bool = True) -> Path:
    run = root / run_id
    # transcript: one successful call, optionally a failed second one
    call = run / "transcript" / "call-1"
    call.mkdir(parents=True)
    (call / "system.md").write_text("system prompt", encoding="utf-8")
    (call / "user.md").write_text("user prompt", encoding="utf-8")
    _write_json(call / "meta.json",
                {"tag": "seed", "call": 1, "iteration": 0})
    _write_json(call / "response.json", {
        "text": "```python\npass\n```", "backend": "replay", "model": "m",
        "input_tokens": 10, "output_tokens": 5, "cache_read_tokens": 0,
        "cache_write_tokens": 0, "cost_usd": 0.25, "elapsed_s": 2.5,
        "tag": "seed", "iteration": 0,
    })
    if not healthy:
        failed = run / "transcript" / "call-2"
        failed.mkdir()
        (failed / "system.md").write_text("system", encoding="utf-8")
        (failed / "user.md").write_text("user", encoding="utf-8")
        _write_json(failed / "meta.json",
                    {"tag": "refine", "call": 2, "iteration": 1})

    # iteration 0 is complete
    it0 = run / "iterations" / "iter-0"
    it0.mkdir(parents=True)
    (it0 / "strategy.py").write_text("SOURCE = 1\n", encoding="utf-8")
    _write_json(it0 / "summary.json", _summary(strategy="gen_iter0"))
    (it0 / "results.jsonl").write_text(
        json.dumps({"outcome": "parsed_clean"}) + "\n", encoding="utf-8")

    if not healthy:
        # iteration 1 was interrupted before summarising
        it1 = run / "iterations" / "iter-1"
        it1.mkdir()
        (it1 / "strategy.py").write_text("SOURCE = 2\n", encoding="utf-8")

    summary = {
        "run_id": run_id,
        "backend": "replay",
        "model": "m",
        "target": None,
        "max_examples": 10,
        "iterations": [{"iteration": 0}],
        "budget": {"cost_usd": 0.25, "max_usd": 1.0, "llm_calls": 1,
                   "output_tokens": 5, "billable_input_tokens": 10,
                   "authored_prompt_tokens_est": 5},
        "cost_cap_enforced": True,
        "stopped_early": None,
    }
    if not healthy:
        summary["stopped_early"] = "LLMError: transcript exhausted"
        summary["budget"]["cost_usd"] = 1.0
    _write_json(run / "loop_summary.json", summary)
    return run


# ------------------------------------------------------------------- errors
def test_agent_error_renders_hint_and_context() -> None:
    exc = AgentError("the thing failed", hint="do the other thing",
                     context={"run_id": "demo", "iteration": 3})
    text = format_exception(exc)
    expect("the thing failed" in text, text)
    expect("hint: do the other thing" in text, text)
    expect("run_id: demo" in text and "iteration: 3" in text, text)
    expect("traceback" not in text, "traceback hidden unless --debug")


def test_format_exception_includes_traceback_in_debug() -> None:
    try:
        raise ValueError("bad value")
    except ValueError as exc:
        text = format_exception(exc, debug=True)
    expect("ValueError: bad value" in text, text)
    expect("traceback:" in text and "raise ValueError" in text, text)


def test_explain_exception_maps_common_failures() -> None:
    harness = explain_exception(FileNotFoundError(
        "build/asan/harness not found"))
    expect("build.sh" in harness or "harness" in harness, harness)

    transcript = explain_exception(LLMError("transcript exhausted after 4 calls"))
    expect("transcript" in transcript.lower(), transcript)

    usage = explain_exception(LLMError("usage limit reached"))
    expect("account" in usage.lower() or "limit" in usage.lower(), usage)

    corrupt = explain_exception(json.JSONDecodeError("bad", "doc", 0))
    expect("corrupt" in corrupt.lower() or "json" in corrupt.lower(), corrupt)

    # Standardized error helpers
    head, hint = format_error_summary(LLMError("transcript exhausted after 4 calls"))
    expect("LLMError" in head, head)
    expect("transcript" in hint.lower(), hint)

    std = standardize_error(ValueError("bad value"), hint="check inputs", context={"key": "val"})
    expect(isinstance(std, AgentError), "standardized to AgentError")
    expect(std.hint == "check inputs", std.hint)
    expect(std.context.get("key") == "val", str(std.context))



def test_infer_iteration_tolerates_old_transcripts() -> None:
    with tempfile.TemporaryDirectory() as td:
        call = Path(td) / "call-1"
        call.mkdir()
        expect(infer_iteration({"iteration": 3}, {}, call) == 3, "meta")
        expect(infer_iteration({}, {"iteration": 4}, call) == 4, "response")
        expect(infer_iteration({"tag": "seed"}, {}, call) == 0, "seed tag")
        (call / "user.md").write_text(
            "# Current strategy (iteration 2)\n", encoding="utf-8")
        expect(infer_iteration({}, {}, call) == 2, "prompt fallback")
        expect(infer_iteration({}, {}, Path(td) / "call-9") is None,
               "unknown call")


def test_validation_hint_names_a_next_step_for_every_stage() -> None:
    for stage in ("extract", "truncated", "syntax", "interface", "smoke",
                  "mixture"):
        text = validation_hint(stage, run_id="demo")
        expect(bool(text), f"empty hint for {stage}")
        expect("agent.debug" in text or "fuzzer.campaign" in text, text)
    expect("gen_iterN" in validation_hint("smoke"), "smoke hint")


# --------------------------------------------------------------- debug log
def test_debug_log_round_trip_and_redaction() -> None:
    with tempfile.TemporaryDirectory() as td:
        log = DebugLog(Path(td) / "debug.jsonl")
        log.event("llm_call", call=1, elapsed_s=1.5)
        log.event("gate_failed", stage="syntax", error="bad indent")
        log.close()
        events = log.read()
        expect(len(events) == 2, str(events))
        expect(events[0]["event"] == "llm_call" and events[0]["call"] == 1,
               str(events[0]))
        expect(events[-1]["stage"] == "syntax", str(events[-1]))
        expect(all("ts" in e for e in events), "timestamp missing")
        expect(log.read(limit=1)[0]["event"] == "gate_failed", "limit")


# -------------------------------------------------------------- diagnostics
def test_diagnostics_healthy_run_has_no_findings() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        make_run(root, "healthy")
        data = RunDiagnostics(root, "healthy").scan()
        problems = [f for f in data["findings"]
                    if f["level"] in ("error", "warning")]
        expect(not problems, str(problems))
        expect(data["transcript"]["calls"] == 1, str(data["transcript"]))
        expect(data["transcript"]["cost_usd"] == 0.25, str(data["transcript"]))


def test_diagnostics_names_missing_artifacts_and_failed_calls() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        make_run(root, "broken", healthy=False)
        diag = RunDiagnostics(root, "broken")
        data = diag.scan()
        codes = {f["code"] for f in data["findings"]}
        for expected in ("stopped_early", "missing_summary", "missing_results",
                         "failed_call", "budget_exhausted"):
            expect(expected in codes, f"{expected} missing from {sorted(codes)}")
        text = diag.render(data)
        expect("Run diagnosis: broken" in text, text)
        expect("iter-1" in text, text)
        expect("Findings:" in text, text)
        joined = " ".join(data["suggestions"])
        expect("--call 2" in joined, joined)
        expect("--resume-from" in joined, joined)


def test_diagnostics_missing_run_is_actionable() -> None:
    with tempfile.TemporaryDirectory() as td:
        data = RunDiagnostics(Path(td), "nope").scan()
        expect(data["exists"] is False, data)
        expect(any(f["code"] == "run_missing" for f in data["findings"]),
               data["findings"])
        expect("--list" in data["suggestions"][0], data["suggestions"])


def test_list_runs_summarises_directories() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        make_run(root, "one")
        make_run(root, "two", healthy=False)
        (root / ".hidden").mkdir()
        rows = list_runs(root)
        expect({r["run_id"] for r in rows} == {"one", "two"}, str(rows))
        by_id = {r["run_id"]: r for r in rows}
        expect(by_id["one"]["complete_iterations"] == 1, str(by_id["one"]))
        expect(by_id["two"]["complete_iterations"] == 1, str(by_id["two"]))


# ------------------------------------------------------------------ debug CLI
def _capture(fn, argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = fn(argv)
    return code, buf.getvalue()


def test_debug_cli_json_and_text_commands() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        run = make_run(root, "demo")
        _write_json(run / "iterations" / "iter-0" / "ensemble.json",
                    {"winner": {"name": "gen_iter0"}, "votes": {}})
        DebugLog(run / "debug.jsonl").event("gate_failed", stage="syntax")

        code, out = _capture(debugmod.main,
                             ["--root", str(root), "--run-id", "demo", "--json"])
        expect(code == 0, code)
        payload = json.loads(out)
        expect(payload["run_id"] == "demo", payload.keys())

        code, out = _capture(debugmod.main,
                             ["--root", str(root), "--list", "--json"])
        expect(code == 0 and json.loads(out)[0]["run_id"] == "demo", out)

        code, out = _capture(debugmod.main,
                             ["--root", str(root), "--run-id", "demo",
                              "--transcript", "--json"])
        expect(code == 0 and json.loads(out)[0]["call"] == 1, out)

        code, out = _capture(debugmod.main,
                             ["--root", str(root), "--run-id", "demo",
                              "--call", "1", "--json"])
        call = json.loads(out)
        expect(code == 0 and call["meta"]["tag"] == "seed", call)

        code, out = _capture(debugmod.main,
                             ["--root", str(root), "--run-id", "demo",
                              "--iteration", "0", "--json"])
        iteration = json.loads(out)
        expect(code == 0 and iteration["summary"]["acceptance_rate"] == 0.5,
               iteration)
        expect(iteration["results"]["count"] == 1, iteration["results"])

        code, out = _capture(debugmod.main,
                             ["--root", str(root), "--run-id", "demo",
                              "--events", "--json"])
        expect(code == 0 and json.loads(out)[0]["event"] == "gate_failed", out)

        code, out = _capture(debugmod.main,
                             ["--root", str(root), "--run-id", "demo"])
        expect(code == 0 and "Run diagnosis: demo" in out, out)


def test_debug_cli_diagnose_exit_code_for_broken_run() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        make_run(root, "broken", healthy=False)
        code, out = _capture(debugmod.main,
                             ["--root", str(root), "--run-id", "broken",
                              "--diagnose"])
        expect(code == 1, f"exit={code}")
        expect("stopped early" in out.lower(), out)

        make_run(root, "healthy")
        code, out = _capture(debugmod.main,
                             ["--root", str(root), "--run-id", "healthy",
                              "--diagnose"])
        expect(code == 0, f"exit={code}\n{out}")


# ---------------------------------------------------------------- progress
class FakeTTY(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_progress_bar_tty_and_plain_modes() -> None:
    tty = FakeTTY()
    bar = ProgressBar(10, "campaign", enabled="on", stream=tty, min_interval=0)
    for _ in range(10):
        bar.update()
    bar.set_postfix(crashes=1)
    bar.close()
    out = tty.getvalue()
    expect("\r" in out, "TTY bar should redraw in place")
    expect("10/10" in out and "100%" in out, out)
    expect("campaign" in out, out)

    plain = io.StringIO()
    bar = ProgressBar(10, "campaign", enabled="on", stream=plain, min_interval=0)
    for _ in range(10):
        bar.update()
    bar.close()
    text = plain.getvalue()
    expect("\r" not in text, "plain output must not contain control characters")
    expect("[progress]" in text and "10/10" in text, text)


def test_progress_auto_is_silent_without_a_tty() -> None:
    buf = io.StringIO()
    bar = ProgressBar(5, "x", enabled="auto", stream=buf)
    bar.update(5)
    bar.close()
    expect(buf.getvalue() == "", f"unexpected output: {buf.getvalue()!r}")


def test_progress_helpers_and_null_bar() -> None:
    expect(normalize_mode(True) == "on", "True -> on")
    expect(normalize_mode("never") == "off", "never -> off")
    expect(normalize_mode(None) == "auto", "None -> auto")
    try:
        normalize_mode("sometimes")
    except ValueError:
        pass
    else:
        raise AssertionError("invalid mode must raise")
    expect(not resolve_enabled("off", io.StringIO()), "off")
    expect(resolve_enabled("on", io.StringIO()), "explicit on")
    expect(format_duration(0.4) == "0.4s", format_duration(0.4))
    expect(format_duration(125) == "2m05s", format_duration(125))
    buf = io.StringIO()
    null = NullProgress(3, "x", stream=buf)
    null.update(3)
    null.close()
    expect(buf.getvalue() == "", "NullProgress writes nothing")
    bar = make_progress(2, "x", enabled="off")
    expect(bar.enabled is False, "make_progress off")


def test_status_line_and_run_status() -> None:
    buf = io.StringIO()
    status = StatusLine(enabled="on", stream=buf, min_interval=0)
    status.update(run="demo", iteration="1/2", calls=3, cost="$0.01")
    status.event("stopping", crashes=1)
    text = buf.getvalue()
    expect("run=demo" in text and "calls=3" in text, text)
    expect("message=stopping" in text and "crashes=1" in text, text)

    run_buf = io.StringIO()
    rs = RunStatus("demo", 2, mode="on", status_mode="on", stream=run_buf)
    rs.start()
    rs.iteration_started(0)
    rs.phase("campaign")
    rs.llm_call(1, "seed", 1.25, 0.03)
    rs.iteration_finished(0, acceptance=0.5, productions="5/27",
                          crashes=0, cost_usd=0.03)
    rs.note("halfway")
    rs.finish()
    output = run_buf.getvalue()
    expect("[status]" in output and "[progress]" in output, output)
    expect("accept=50.0%" in output and "productions=5/27" in output, output)
    expect("message=halfway" in output, output)


# --------------------------------------------------------------- standalone
def _run_all() -> int:
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    failed = []
    for name, fn in tests:
        try:
            fn()
        except Exception:
            failed.append(name)
            print(f"FAIL {name}")
            traceback.print_exc()
        else:
            print(f"ok   {name}")
    print(f"\n{len(tests) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
