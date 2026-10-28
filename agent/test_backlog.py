"""Regression tests for the backlog bug-fix items.

These cover the five entries under ``todo.md`` -> *Bug Fixes*:

  * byte-serialisation edge cases (surrogate pairs, bytes-like inputs);
  * bounded memory in long-running campaigns, tuners and fallback backends;
  * diagnostic-normalisation edge cases (NUL, CRLF, uppercase hex, truncation);
  * UTC timestamps that always spell their offset as ``Z``;
  * Windows portability (native binary names, atomic replace, ``cmd`` reproducer).

Like the other agent suites this is plain-assert Python: pytest collects it and
``python -m agent.test_backlog`` runs it without third-party packages.
"""
from __future__ import annotations

import hashlib
import json
import re
import tempfile
import traceback
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from agent.llm import MAX_FALLBACK_EVENTS, FallbackBackend
from agent.prompt_manager import MAX_TRIALS_PER_VARIANT, PromptABTester
from agent.tuning import MAX_OBSERVATIONS, HyperparameterTuner
from fuzzer import campaign as campaign_mod
from fuzzer import diagnostics, triage
from fuzzer.campaign import MAX_REPRODUCER_INPUTS, Campaign
from fuzzer.platform_compat import (IS_WINDOWS, atomic_write_text,
                                   native_binary, replace_file)
from fuzzer.reproducer import (MinimalReproducerBundle,
                               generate_batch_reproducer)
from fuzzer.runner import Outcome, RunResult, _killed_returncode
from fuzzer.timeutil import parse_utc, utc_iso, utc_now


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


# --------------------------------------------------------------- serialisation
def test_encode_handles_bytes_and_surrogate_pairs() -> None:
    # Raw bytes pass through unchanged, including non-UTF-8 values.
    expect(campaign_mod._encode(b"\x80\xff") == b"\x80\xff",
           "bytes payload was altered")
    expect(campaign_mod._encode(bytearray(b"ab")) == b"ab",
           "bytearray payload was altered")
    expect(campaign_mod._encode(memoryview(b"ab")) == b"ab",
           "memoryview payload was altered")

    # A valid UTF-16 surrogate pair is one scalar, not CESU-8.
    emoji = "\U0001F600"
    expect(campaign_mod._encode("\ud83d\ude00") == emoji.encode("utf-8"),
           "surrogate pair was not combined into one scalar")
    expect(campaign_mod._encode(emoji) == emoji.encode("utf-8"),
           "astral character encoded differently from its surrogate pair")

    # A lone surrogate still takes the documented surrogatepass path.
    expect(campaign_mod._encode("\ud800") == b"\xed\xa0\x80",
           "lone high surrogate did not use surrogatepass")

    # The surrogateescape sentinels stand for raw bytes 0x80..0xFF.
    expect(campaign_mod._encode("\udc80") == b"\x80",
           "raw-byte sentinel was not preserved")
    expect(campaign_mod._encode("A\udcffB") == b"A\xffB",
           "mixed raw-byte sentinels were not preserved")
    expect(campaign_mod._encode("\udc80\ud83d\ude00")
           == b"\x80" + emoji.encode("utf-8"),
           "raw sentinel and surrogate pair did not compose")

    try:
        campaign_mod._encode(42)  # type: ignore[arg-type]
    except TypeError:
        pass
    else:
        raise AssertionError("non-text document did not raise TypeError")


# ----------------------------------------------------------------- diagnostics
def test_diagnostic_normalization_edge_cases() -> None:
    # Both spellings of a hex literal must collapse to the same template.
    upper = diagnostics.normalize(
        "Bad control character 0X1F in element root on line 3.")
    expect("0x%x" in upper, f"uppercase hex not normalised: {upper!r}")
    expect("0X" not in upper, f"uppercase prefix survived: {upper!r}")

    # A raw NUL ends the C string; trailing bytes are not part of the template.
    tail = "Missing close tag </unclosed> under parent <root> on line 7"
    expect(diagnostics.normalize(tail + "\x00junk <x> 99")
           == diagnostics.normalize(tail),
           "bytes after a NUL changed the template")

    # CRLF from a stored stderr blob is normalised to LF.
    crlf = diagnostics.normalize(
        "first line\r\nBad control character 0x01 in element root on line 3.")
    expect("\r" not in crlf, f"CR survived normalisation: {crlf!r}")
    expect(crlf.startswith("first line\n"), f"CRLF not normalised: {crlf!r}")

    # The 1023-byte buffer test runs before whitespace stripping, so a message
    # that only looks short after strip() is still reported as truncated.
    padded = "A" * (diagnostics._MXML_MSG_BYTES - 2) + "  "
    expect(len(padded) == diagnostics._MXML_MSG_BYTES,
           "test message is not buffer-sized")
    expect(len(padded.strip()) < diagnostics._MXML_MSG_BYTES,
           "test message does not shrink when stripped")
    expect(diagnostics.normalize(padded) == diagnostics._TRUNCATED,
           "truncation was hidden by whitespace stripping")


# --------------------------------------------------------------------- triage
def test_triage_parses_windows_paths_and_deadlysignal() -> None:
    stderr = (
        "==42==ERROR:AddressSanitizer:DEADLYSIGNAL\n"
        "    #0 0x00007ff6 in mxml_parse_file C:\\src\\mxml-file.c:1234\n"
        "    #1 0x00007ff7 in ?? ()\n"
        "    #2 0x00007ff8 in mxml_load_file C:/build/src/mxml-file.c:99\n"
        "    #3 0x00007ff9 in main C:\\src\\harness.c:42\n"
    )
    rep = triage.parse_report(stderr)
    expect(rep is not None, "sanitizer report was not parsed")
    assert rep is not None  # narrow the type for readers and type checkers
    expect(rep.tool == "AddressSanitizer", f"wrong tool: {rep.tool!r}")
    expect(rep.bug_type == "DEADLYSIGNAL", f"wrong bug type: {rep.bug_type!r}")
    expect([f.func for f in rep.frames] == ["mxml_parse_file", "mxml_load_file"],
           f"unexpected frames: {[f.func for f in rep.frames]}")
    expect(rep.frames[0].file == "mxml-file.c",
           f"Windows path not reduced to a basename: {rep.frames[0].file!r}")
    expect(rep.frames[1].file == "mxml-file.c",
           f"forward-slash path not reduced to a basename: {rep.frames[1].file!r}")


# ----------------------------------------------------------------------- time
def test_utc_timestamp_helpers() -> None:
    expect(utc_iso(0) == "1970-01-01T00:00:00Z",
           f"epoch did not format as UTC Z: {utc_iso(0)!r}")
    expect(utc_iso(0, timespec="milliseconds") == "1970-01-01T00:00:00.000Z",
           "millisecond formatting was not UTC Z")
    expect(utc_now().utcoffset() == timedelta(0),
           "utc_now() is not timezone-aware UTC")

    parsed = parse_utc("2024-01-02T03:04:05Z")
    expect(parsed.utcoffset() == timedelta(0),
           "parsed timestamp is not UTC")
    expect(parse_utc("2024-01-02T03:04:05")
           == parsed, "naive timestamp was not assumed UTC")
    expect(parse_utc("2024-01-02T05:04:05+02:00")
           == parsed, "explicit offset was not converted to UTC")


# ------------------------------------------------------------------- memory
def test_agent_histories_are_bounded() -> None:
    expect(MAX_REPRODUCER_INPUTS >= 1,
           "campaign reproducer bound must be positive")
    tuner = HyperparameterTuner(max_examples=100, min_examples=10)
    for i in range(MAX_OBSERVATIONS + 5):
        tuner.observe(i, 10, 0, 0, 0)
    expect(len(tuner.history) == MAX_OBSERVATIONS,
           f"tuner kept {len(tuner.history)} observations")
    expect(tuner.history[0].iteration == 5,
           "tuner did not keep the newest observation window")

    backend = FallbackBackend(primary=object(), fallbacks=[])
    expect(backend.fallback_history.maxlen == MAX_FALLBACK_EVENTS,
           "fallback history is not a bounded deque")
    for i in range(MAX_FALLBACK_EVENTS + 5):
        backend.fallback_history.append({"i": i})
    expect(len(backend.fallback_history) == MAX_FALLBACK_EVENTS,
           f"fallback kept {len(backend.fallback_history)} events")
    expect(backend.fallback_history[0]["i"] == 5,
           "fallback did not keep the newest event window")

    tester = PromptABTester(["v2"])
    for i in range(MAX_TRIALS_PER_VARIANT + 5):
        tester.record_trial("v2", i, {"productions_hit": i})
    trials = tester.get_trials("v2")
    expect(len(trials) == MAX_TRIALS_PER_VARIANT,
           f"A/B tester kept {len(trials)} trials")
    expect(trials[0]["trial_id"] == 5,
           "A/B tester did not keep the newest trial window")


# -------------------------------------------------------- campaign accounting
def _fake_result(payload: bytes, outcome: Outcome, *,
                 stderr: str = "", signal_name: str | None = None,
                 duration_s: float = 0.0, is_slow: bool = False) -> RunResult:
    return RunResult(
        outcome=outcome,
        returncode=0 if outcome.is_accepted else -9,
        signal_name=signal_name,
        stderr=stderr,
        duration_s=duration_s,
        input_sha256=hashlib.sha256(payload).hexdigest(),
        input_len=len(payload),
        is_slow=is_slow,
    )


def test_campaign_uses_counters_and_utc_checkpoints() -> None:
    calls: list[bytes] = []

    def fake_run(_self, payload, _target, _cache, _context):
        calls.append(payload)
        # The first two inputs time out; the rest are merely slow.
        if len(calls) <= 2:
            return _fake_result(payload, Outcome.TIMEOUT, signal_name="TIMEOUT",
                                duration_s=5.0, is_slow=True)
        return _fake_result(payload, Outcome.PARSED_CLEAN,
                            duration_s=0.01, is_slow=True)

    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "counters"
        campaign = Campaign(
            strategy_name="baseline",
            max_examples=4,
            out_dir=out,
            slow_threshold_s=0.0,
            max_timeout_streak=10,
            checkpoint_interval=2,
            progress=False,
        )
        with patch.object(Campaign, "_run_payload", fake_run):
            summary = campaign.run()

        expect(len(calls) == 4, f"expected 4 examples, ran {len(calls)}")
        expect(summary["timeout_count"] == 2,
               f"timeout count was {summary['timeout_count']}")
        expect(summary["slow_input_count"] == 2,
               f"slow-input count was {summary['slow_input_count']}")
        expect(len(list((out / "timeouts").glob("*.bin"))) == 2,
               "timeout inputs were not persisted")
        expect(len(list((out / "slow_inputs").glob("*.bin"))) == 2,
               "slow inputs were not persisted")

        checkpoint = json.loads(
            (out / "checkpoint.json").read_text(encoding="utf-8"))
        expect(checkpoint["timeouts"] == 2,
               "checkpoint timeout count is wrong")
        expect(checkpoint["slow_inputs"] == 2,
               "checkpoint slow-input count is wrong")
        expect("timestamp_utc" in checkpoint,
               "checkpoint has no UTC timestamp")
        expect(parse_utc(checkpoint["timestamp_utc"]).utcoffset()
               == timedelta(0), "checkpoint timestamp is not UTC")
        expect("generated_at_utc" in summary,
               "summary has no UTC generation timestamp")
        expect(parse_utc(summary["generated_at_utc"]).utcoffset()
               == timedelta(0), "summary timestamp is not UTC")


def test_campaign_reproducer_retention_is_bounded() -> None:
    captured: list[str] = []

    class FakeBundle:
        def __init__(self, signature: str) -> None:
            self.signature = signature

        def to_json(self) -> dict:
            return {"signature": self.signature}

    def fake_bundle(*, payload, target, out_dir, minimize_first, signature):
        captured.append(signature)
        return FakeBundle(signature)

    count = {"n": 0}

    def fake_run(_self, payload, _target, _cache, _context):
        count["n"] += 1
        n = count["n"]
        stderr = (
            "==1==ERROR: AddressSanitizer: SEGV on unknown address\n"
            f"    #0 0x1000 in crash_site_{n} C:\\src\\file_{n}.c:{n}\n"
        )
        return _fake_result(payload, Outcome.CRASH, stderr=stderr,
                            signal_name="SEGV")

    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "crashes"
        campaign = Campaign(
            strategy_name="baseline",
            max_examples=5,
            out_dir=out,
            max_timeout_streak=10,
            progress=False,
        )
        with patch.object(campaign_mod, "MAX_REPRODUCER_INPUTS", 2), \
                patch.object(Campaign, "_run_payload", fake_run), \
                patch("fuzzer.reproducer.create_reproducer_bundle",
                      side_effect=fake_bundle):
            summary = campaign.run()

        expect(summary["crash_count"] == 5,
               f"expected 5 crashes, got {summary['crash_count']}")
        expect(len(captured) == 2,
               f"reproducer inputs were not capped: {len(captured)}")
        expect(len(set(captured)) == 2,
               "bounded reproducer inputs were not distinct signatures")


# ----------------------------------------------------------------- portability
def test_native_binary_and_atomic_writes() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        plain = root / "harness"
        resolved = native_binary(plain)
        expected = plain.with_name("harness.exe") if IS_WINDOWS else plain
        expect(resolved == expected,
               f"native_binary returned {resolved} instead of {expected}")
        already = root / "harness.exe"
        expect(native_binary(already) == already,
               "an .exe path was given a second suffix")

        source = root / "source.tmp"
        dest = root / "dest.txt"
        source.write_text("new", encoding="utf-8")
        dest.write_text("old", encoding="utf-8")
        replace_file(source, dest)
        expect(dest.read_text(encoding="utf-8") == "new",
               "replace_file did not replace the destination")
        expect(not source.exists(), "replace_file left the temporary file")

        nested = root / "nested" / "state.json"
        atomic_write_text(nested, '{"ok": true}')
        expect(json.loads(nested.read_text(encoding="utf-8")) == {"ok": True},
               "atomic_write_text wrote the wrong content")
        leftovers = [p for p in nested.parent.iterdir() if p.suffix == ".tmp"]
        expect(not leftovers, f"atomic write left temporary files: {leftovers}")


def test_runner_uses_portable_killed_returncode() -> None:
    expect(_killed_returncode() == -9,
           f"killed returncode was {_killed_returncode()}")


# ------------------------------------------------------------------ reproducer
def test_reproducer_bundle_includes_windows_script() -> None:
    bundle = MinimalReproducerBundle(
        minimized_document=b"<a/>",
        original_len=4,
        minimized_len=4,
        reduction_pct=0.0,
        signature="sig",
        label="label",
        tool="AddressSanitizer",
        bug_type="SEGV",
        severity="HIGH",
        target="mxml",
        verified_runs=3,
        verified_ok=3,
        deterministic=True,
        python_script="print('python')",
        c_test_case="int main(void) { return 0; }",
        shell_script="#!/bin/sh\n",
        raw_stderr="==1==ERROR: AddressSanitizer: SEGV\n",
    )
    with tempfile.TemporaryDirectory() as td:
        files = bundle.write_bundle(Path(td) / "bundle")
        expect(files["batch"].exists(), "reproduce.cmd was not written")
        text = files["batch"].read_text(encoding="utf-8")
        expect(text.startswith("@echo off"), "cmd script has no @echo off")
        expect("harness.exe" in text, "cmd script does not try harness.exe")
        expect("reproducer.bin" in text, "cmd script does not use the payload")
        expect(files["shell"].exists(), "reproduce.sh was not written")

    standalone = generate_batch_reproducer("custom.bin")
    expect("custom.bin" in standalone,
           "generate_batch_reproducer ignored its payload name")


def test_html_report_stamps_utc_generation_time() -> None:
    from fuzzer.visual_report import generate_html_dashboard

    with tempfile.TemporaryDirectory() as td:
        out = generate_html_dashboard({}, Path(td) / "report.html")
        html = out.read_text(encoding="utf-8")
    stamp = re.search(r"Generated \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", html)
    expect(stamp is not None,
           "dashboard has no UTC 'Generated ...Z' stamp")


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
