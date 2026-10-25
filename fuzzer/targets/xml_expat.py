"""Expat XML parser target implementation."""
from __future__ import annotations

import hashlib
import re
import time
import xml.parsers.expat as expat
from pathlib import Path

from fuzzer.runner import (
    PER_RUN_TIMEOUT_S,
    Outcome,
    RunResult,
)
from fuzzer.targets.xml_base import XMLTarget, REPO_ROOT

_EXPAT_SUBS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"line \d+"), "line %d"),
    (re.compile(r"column \d+"), "column %d"),
    (re.compile(r"'[^']*'"), "'%s'"),
    (re.compile(r"\b\d+\b"), "%d"),
]


def normalize_expat(message: str) -> str:
    """Normalize Expat diagnostic string to a canonical template."""
    out = message.strip()
    for pattern, repl in _EXPAT_SUBS:
        out = pattern.sub(repl, out)
    return out


class ExpatTarget(XMLTarget):
    """Expat XML parser target."""

    name: str = "expat"
    description: str = "Expat stream-oriented XML parser"
    harness_binary: Path = REPO_ROOT / "build" / "expat" / "harness"

    def normalize_diagnostic(self, message: str) -> str:
        return normalize_expat(message)

    def run_reference(
        self,
        payload: bytes,
        timeout_s: float = PER_RUN_TIMEOUT_S,
        extra_args: tuple[str, ...] = (),
    ) -> RunResult:
        """Run Expat using Python's standard library C-binding or subprocess."""
        started = time.monotonic()
        sha = hashlib.sha256(payload).hexdigest()

        if not payload.strip():
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic("no element found on line 1")],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )

        parser = expat.ParserCreate()
        # Track if any callbacks were hit
        seen_elements: list[str] = []
        parser.StartElementHandler = lambda name, attrs: seen_elements.append(name)

        try:
            parser.Parse(payload, True)
            return RunResult(
                outcome=Outcome.PARSED_CLEAN,
                returncode=0,
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )
        except expat.ExpatError as exc:
            err_str = expat.ErrorString(exc.code)
            diag = f"{err_str} on line {exc.lineno}, column {exc.offset}"
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic(diag)],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )
        except Exception as exc:
            return RunResult(
                outcome=Outcome.HARNESS_ERROR,
                returncode=2,
                stderr=str(exc),
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )
