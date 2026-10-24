"""Execute the harness against one generated input and classify what happened.

This module owns the crash/no-crash decision. Everything downstream depends on
it: the acceptance-rate signal, crash triage and the reported results.

Classification rules:

  * Killed by a signal  -> crash. SIGSEGV, SIGABRT, SIGFPE, SIGBUS all mean the
    process died rather than returning an answer.

  * Sanitizer text in stderr -> crash, even if the exit status looks benign.
    Belt and braces: the build sets -fno-sanitize-recover=all so UBSan aborts,
    but if that flag were ever lost, UBSan would print "runtime error:" and exit
    0, and a status-only check would silently record every UB finding as clean.

  * Timeout -> crash. A parser that hangs instead of terminating is a real bug,
    not a slow success. Recorded as its own outcome so hangs stay distinguishable
    from memory bugs in triage.

  * Exit 1 -> a well-formed rejection, NOT a crash. A parser refusing malformed
    input is the parser working correctly.

  * Exit 3 -> parsed, but the parser emitted diagnostics. mxml complains and
    still returns a tree for some inputs (see grammar/ADAPTATIONS.md), so this
    is a genuine fourth state, not a variant of rejection.
"""
from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# Cap each harness invocation so a hang is recorded as a crash instead of
# stalling the rest of the campaign.
PER_RUN_TIMEOUT_S = 5.0

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_HARNESS = REPO_ROOT / "build" / "asan" / "harness"

# Sanitizer environment. Set here rather than inherited from the shell so a
# forgotten export cannot silently change what counts as a crash.
#
#   halt_on_error / abort_on_error : make UBSan fatal. Without this it prints and
#     continues, exiting 0.
#   detect_leaks=0 : mxml abandons partial node trees on rejection, so leaks
#     would fire on most inputs and bury real crashes. See design-decisions D4.
SANITIZER_ENV = {
    "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:symbolize=1:print_stacktrace=1",
    "UBSAN_OPTIONS": "halt_on_error=1:abort_on_error=1:print_stacktrace=1",
}

SANITIZER_MARKERS = (
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "LeakSanitizer",
    "runtime error:",
)


class Outcome(str, Enum):
    PARSED_CLEAN = "parsed_clean"    # exit 0
    PARSED_DIAG = "parsed_diag"      # exit 3: parsed, but complained
    REJECTED = "rejected"            # exit 1: well-formed rejection
    HARNESS_ERROR = "harness_error"  # exit 2: our bug, not the library's
    CRASH = "crash"                  # signal or sanitizer report
    TIMEOUT = "timeout"              # hang; counts as a crash

    @property
    def is_crash(self) -> bool:
        return self in (Outcome.CRASH, Outcome.TIMEOUT)

    @property
    def is_accepted(self) -> bool:
        """Did the parser accept the document? Used for the acceptance-rate band.

        Deliberately counts PARSED_DIAG as accepted: mxml returned a tree, so
        the input got through the front door, which is what the signal measures.
        """
        return self in (Outcome.PARSED_CLEAN, Outcome.PARSED_DIAG)


@dataclass
class RunResult:
    outcome: Outcome
    returncode: int
    signal_name: str | None = None
    diagnostics: list[str] = field(default_factory=list)
    stderr: str = ""
    duration_s: float = 0.0
    input_sha256: str = ""
    input_len: int = 0

    def to_json(self) -> dict:
        """Compact form for the JSONL log. stderr only kept when it matters."""
        d = {
            "outcome": self.outcome.value,
            "rc": self.returncode,
            "dur_ms": round(self.duration_s * 1000, 2),
            "sha": self.input_sha256[:16],
            "len": self.input_len,
            "ndiag": len(self.diagnostics),
            "diagnostics": self.diagnostics,
        }
        if self.signal_name:
            d["signal"] = self.signal_name
        if self.outcome.is_crash:
            d["stderr"] = self.stderr
        return d


def _signal_name(rc: int) -> str | None:
    """subprocess reports a negative returncode when the child died on a signal."""
    if rc >= 0:
        return None
    try:
        return signal.Signals(-rc).name
    except ValueError:
        return f"SIG{-rc}"


def run_one(
    document: bytes,
    harness: Path | str = DEFAULT_HARNESS,
    timeout_s: float = PER_RUN_TIMEOUT_S,
    extra_args: tuple[str, ...] = (),
) -> RunResult:
    """Run the harness on one document, fed via stdin.

    stdin rather than a temp file: at 500 examples per iteration, creating and
    unlinking a file per input adds avoidable syscall churn and a cleanup
    failure mode. Crashing inputs get written to disk separately by the caller,
    which is the only time the bytes need to persist.
    """
    env = {**os.environ, **SANITIZER_ENV}
    sha = hashlib.sha256(document).hexdigest()
    started = time.monotonic()

    try:
        proc = subprocess.run(
            [str(harness), *extra_args],
            input=document,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_s,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        return RunResult(
            outcome=Outcome.TIMEOUT,
            returncode=-signal.SIGKILL,
            signal_name="TIMEOUT",
            stderr=(exc.stderr or b"").decode("utf-8", "replace"),
            duration_s=time.monotonic() - started,
            input_sha256=sha,
            input_len=len(document),
        )

    duration = time.monotonic() - started
    stdout = proc.stdout.decode("utf-8", "replace")
    stderr = proc.stderr.decode("utf-8", "replace")
    rc = proc.returncode

    diagnostics = [
        line.split("\t", 1)[1]
        for line in stdout.splitlines()
        if line.startswith("DIAG\t")
    ]

    saw_sanitizer = any(m in stderr for m in SANITIZER_MARKERS)

    if rc < 0 or saw_sanitizer:
        outcome = Outcome.CRASH
    elif rc == 0:
        outcome = Outcome.PARSED_CLEAN
    elif rc == 3:
        outcome = Outcome.PARSED_DIAG
    elif rc == 1:
        outcome = Outcome.REJECTED
    elif rc == 2:
        outcome = Outcome.HARNESS_ERROR
    else:
        # An exit code the harness never emits. Treat as a crash rather than
        # silently dropping it: an unexplained status is exactly the kind of
        # thing that should be looked at, not swallowed.
        outcome = Outcome.CRASH

    return RunResult(
        outcome=outcome,
        returncode=rc,
        signal_name=_signal_name(rc),
        diagnostics=diagnostics,
        stderr=stderr,
        duration_s=duration,
        input_sha256=sha,
        input_len=len(document),
    )
