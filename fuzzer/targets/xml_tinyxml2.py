"""TinyXML-2 XML parser target implementation."""
from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path

from fuzzer.runner import (
    PER_RUN_TIMEOUT_S,
    Outcome,
    RunResult,
)
from fuzzer.targets.xml_base import XMLTarget, REPO_ROOT

_TINYXML2_SUBS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"line \d+"), "line %d"),
    (re.compile(r"'[^']*'"), "'%s'"),
    (re.compile(r"\b\d+\b"), "%d"),
]


def normalize_tinyxml2(message: str) -> str:
    """Normalize TinyXML-2 error string to a canonical template."""
    out = message.strip()
    for pattern, repl in _TINYXML2_SUBS:
        out = pattern.sub(repl, out)
    return out


class Tinyxml2Target(XMLTarget):
    """TinyXML-2 C++ XML parser target."""

    name: str = "tinyxml2"
    description: str = "TinyXML-2 simple, small, efficient C++ XML parser"
    harness_binary: Path = REPO_ROOT / "build" / "tinyxml2" / "harness"

    def normalize_diagnostic(self, message: str) -> str:
        return normalize_tinyxml2(message)

    def run_reference(
        self,
        payload: bytes,
        timeout_s: float = PER_RUN_TIMEOUT_S,
        extra_args: tuple[str, ...] = (),
    ) -> RunResult:
        """Run TinyXML-2 reference runner."""
        started = time.monotonic()
        sha = hashlib.sha256(payload).hexdigest()

        stripped = payload.strip()
        if not stripped:
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic("XML_ERROR_EMPTY_DOCUMENT: Empty document on line 1")],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )

        if not stripped.startswith(b"<"):
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic("XML_ERROR_PARSING_ELEMENT: Error parsing Element on line 1")],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )

        import xml.parsers.expat as expat
        parser = expat.ParserCreate()
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
            msg = expat.ErrorString(exc.code).lower()
            if "mismatched" in msg:
                diag = f"XML_ERROR_MISMATCHED_ELEMENT: Error=XML_ERROR_MISMATCHED_ELEMENT on line {exc.lineno}"
            elif "unclosed" in msg or "not well-formed" in msg:
                diag = f"XML_ERROR_PARSING_ELEMENT: Error=XML_ERROR_PARSING_ELEMENT on line {exc.lineno}"
            elif "duplicate" in msg:
                diag = f"XML_ERROR_PARSING_ATTRIBUTE: Error=XML_ERROR_PARSING_ATTRIBUTE on line {exc.lineno}"
            elif "cdata" in msg:
                diag = f"XML_ERROR_PARSING_CDATA: Error=XML_ERROR_PARSING_CDATA on line {exc.lineno}"
            else:
                diag = f"XML_ERROR_PARSING: Error=XML_ERROR_PARSING on line {exc.lineno}"
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic(diag)],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )
