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
from typing import Any

from fuzzer.platform_compat import native_binary

# Cap each harness invocation so a hang is recorded as a crash instead of
# stalling the rest of the campaign.
PER_RUN_TIMEOUT_S = 5.0
DEFAULT_SLOW_THRESHOLD_S = 1.0

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_HARNESS = native_binary(REPO_ROOT / "build" / "asan" / "harness")


def _killed_returncode() -> int:
    """Return code a killed child would report, portably.

    ``signal.SIGKILL`` does not exist on Windows, where ``subprocess`` kills
    with TerminateProcess instead.
    """
    return -int(getattr(signal, "SIGKILL", 9))


class SanitizerType(str, Enum):
    ASAN = "asan"
    UBSAN = "ubsan"
    TSAN = "tsan"
    MSAN = "msan"
    LSAN = "lsan"


# Sanitizer environment. Set here rather than inherited from the shell so a
# forgotten export cannot silently change what counts as a crash.
#
#   halt_on_error / abort_on_error : make UBSan/ASan/TSan/MSan fatal.
#   detect_leaks=0 : mxml abandons partial node trees on rejection, so leaks
#     would fire on most inputs and bury real crashes. See design-decisions D4.
SANITIZER_ENV = {
    "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:symbolize=1:print_stacktrace=1",
    "UBSAN_OPTIONS": "halt_on_error=1:abort_on_error=1:print_stacktrace=1",
    "TSAN_OPTIONS": "abort_on_error=1:symbolize=1:report_bugs=1:exitcode=66",
    "MSAN_OPTIONS": "abort_on_error=1:symbolize=1:exitcode=66",
}

SANITIZER_MARKERS = (
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "LeakSanitizer",
    "ThreadSanitizer",
    "MemorySanitizer",
    "runtime error:",
    "data race",
    "use-of-uninitialized-value",
    "lock-order-inversion",
    "destroy-locked-mutex",
)


def detect_sanitizer(stderr: str) -> str | None:
    """Detect which sanitizer reported an error in stderr, if any."""
    if not stderr:
        return None
    if "ThreadSanitizer" in stderr or "data race" in stderr or "lock-order-inversion" in stderr:
        return "ThreadSanitizer"
    if "MemorySanitizer" in stderr or "use-of-uninitialized-value" in stderr:
        return "MemorySanitizer"
    if "AddressSanitizer" in stderr:
        return "AddressSanitizer"
    if "LeakSanitizer" in stderr:
        return "LeakSanitizer"
    if "UndefinedBehaviorSanitizer" in stderr or "runtime error:" in stderr:
        return "UndefinedBehaviorSanitizer"
    return None


def get_sanitizer_env(
    sanitizers: tuple[str, ...] | None = None,
    extra_options: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build environment variables dictionary for specified sanitizers."""
    env = dict(SANITIZER_ENV)
    if sanitizers:
        allowed_keys = {f"{s.upper()}_OPTIONS" for s in sanitizers}
        env = {k: v for k, v in env.items() if k in allowed_keys}
    if extra_options:
        env.update(extra_options)
    return env


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
    is_slow: bool = False
    slow_threshold_s: float | None = None
    sanitizer: str | None = None
    # True when the result came from the deterministic result cache rather
    # than a fresh harness invocation. It is only recorded in the JSONL log
    # when set, so existing artifacts are byte-identical with caching off.
    cached: bool = False

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
        if self.is_slow:
            d["is_slow"] = True
        if self.outcome == Outcome.TIMEOUT:
            d["timeout"] = True
        if self.signal_name:
            d["signal"] = self.signal_name
        if self.sanitizer:
            d["sanitizer"] = self.sanitizer
        if self.outcome.is_crash:
            d["stderr"] = self.stderr
        if self.cached:
            d["cached"] = True
        return d

    @classmethod
    def from_json(cls, data: dict) -> "RunResult":
        """Rebuild a result serialized by :meth:`to_json`.

        Used by the deterministic result cache. ``to_json`` truncates the SHA
        to 16 characters for the JSONL log; the cache adds the full digest so
        a cached result still names the input it came from.
        """
        outcome = data.get("outcome", Outcome.HARNESS_ERROR.value)
        try:
            outcome = Outcome(outcome)
        except ValueError:
            outcome = Outcome.HARNESS_ERROR
        sha = data.get("input_sha256") or data.get("sha") or ""
        return cls(
            outcome=outcome,
            returncode=int(data.get("rc", 0)),
            signal_name=data.get("signal"),
            diagnostics=list(data.get("diagnostics") or []),
            stderr=data.get("stderr", ""),
            duration_s=float(data.get("dur_ms", 0.0)) / 1000.0,
            input_sha256=sha,
            input_len=int(data.get("len", 0)),
            is_slow=bool(data.get("is_slow")),
            slow_threshold_s=data.get("slow_threshold_s"),
            sanitizer=data.get("sanitizer"),
            cached=bool(data.get("cached")),
        )


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
    target: Any = None,
    slow_threshold_s: float | None = None,
    sanitizers: tuple[str, ...] | None = None,
    sanitizer_env: dict[str, str] | None = None,
) -> RunResult:
    """Run the harness on one document, fed via stdin.

    stdin rather than a temp file: at 500 examples per iteration, creating and
    unlinking a file per input adds avoidable syscall churn and a cleanup
    failure mode. Crashing inputs get written to disk separately by the caller,
    which is the only time the bytes need to persist.
    """
    if target is not None:
        from fuzzer.targets import get_target
        t = get_target(target)
        try:
            return t.run(
                document,
                timeout_s=timeout_s,
                extra_args=extra_args,
                slow_threshold_s=slow_threshold_s,
                sanitizers=sanitizers,
                sanitizer_env=sanitizer_env,
            )
        except TypeError:
            return t.run(
                document,
                timeout_s=timeout_s,
                extra_args=extra_args,
                slow_threshold_s=slow_threshold_s,
            )

    harness_path = Path(harness)
    if not (harness_path.exists() and os.access(str(harness_path), os.X_OK)):
        from fuzzer.targets import get_target
        try:
            return get_target("mxml").run(
                document,
                timeout_s=timeout_s,
                extra_args=extra_args,
                slow_threshold_s=slow_threshold_s,
                sanitizers=sanitizers,
                sanitizer_env=sanitizer_env,
            )
        except TypeError:
            return get_target("mxml").run(
                document,
                timeout_s=timeout_s,
                extra_args=extra_args,
                slow_threshold_s=slow_threshold_s,
            )

    env_vars = get_sanitizer_env(sanitizers, sanitizer_env)
    env = {**os.environ, **env_vars}
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
        dur = time.monotonic() - started
        return RunResult(
            outcome=Outcome.TIMEOUT,
            returncode=_killed_returncode(),
            signal_name="TIMEOUT",
            stderr=(exc.stderr or b"").decode("utf-8", "replace"),
            duration_s=dur,
            input_sha256=sha,
            input_len=len(document),
            is_slow=True,
            slow_threshold_s=slow_threshold_s,
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

    detected_san = detect_sanitizer(stderr)
    saw_sanitizer = bool(detected_san) or any(m in stderr for m in SANITIZER_MARKERS)

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

    is_slow = slow_threshold_s is not None and duration >= slow_threshold_s
    return RunResult(
        outcome=outcome,
        returncode=rc,
        signal_name=_signal_name(rc),
        diagnostics=diagnostics,
        stderr=stderr,
        duration_s=duration,
        input_sha256=sha,
        input_len=len(document),
        is_slow=is_slow,
        slow_threshold_s=slow_threshold_s,
        sanitizer=detected_san,
    )
