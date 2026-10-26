"""libxml2 XML parser target implementation."""
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

_LIBXML2_SUBS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"line \d+"), "line %d"),
    (re.compile(r"column \d+"), "column %d"),
    (re.compile(r"'[^']*'"), "'%s'"),
    (re.compile(r"tag [a-zA-Z0-9_-]+"), "tag %s"),
    (re.compile(r"element [a-zA-Z0-9_-]+"), "element %s"),
    (re.compile(r"\b\d+\b"), "%d"),
]


def normalize_libxml2(message: str) -> str:
    """Normalize libxml2 diagnostic string to a canonical template."""
    out = message.strip()
    for pattern, repl in _LIBXML2_SUBS:
        out = pattern.sub(repl, out)
    return out


class Libxml2Target(XMLTarget):
    """libxml2 XML parser target."""

    name: str = "libxml2"
    description: str = "GNOME libxml2 standard XML C parser"
    harness_binary: Path = REPO_ROOT / "build" / "libxml2" / "harness"
    harness_headers: tuple[str, ...] = ("libxml/parser.h", "libxml/tree.h")
    harness_link_flags: tuple[str, ...] = ("-lxml2",)

    def normalize_diagnostic(self, message: str) -> str:
        return normalize_libxml2(message)

    def run_reference(
        self,
        payload: bytes,
        timeout_s: float = PER_RUN_TIMEOUT_S,
        extra_args: tuple[str, ...] = (),
    ) -> RunResult:
        """Run libxml2 reference runner (via ctypes / lxml or fallback)."""
        started = time.monotonic()
        sha = hashlib.sha256(payload).hexdigest()

        # Check for lxml if installed
        try:
            from lxml import etree  # type: ignore
            try:
                etree.fromstring(payload)
                return RunResult(
                    outcome=Outcome.PARSED_CLEAN,
                    returncode=0,
                    duration_s=time.monotonic() - started,
                    input_sha256=sha,
                    input_len=len(payload),
                )
            except etree.XMLSyntaxError as exc:
                diags = [self.normalize_diagnostic(msg) for msg in exc.error_log.filter_levels(etree.ErrorLevels.ERROR)] or [str(exc)]
                return RunResult(
                    outcome=Outcome.REJECTED,
                    returncode=1,
                    diagnostics=diags,
                    duration_s=time.monotonic() - started,
                    input_sha256=sha,
                    input_len=len(payload),
                )
        except ImportError:
            pass

        # Fallback reference engine emulating libxml2 parsing semantics
        stripped = payload.strip()
        if not stripped:
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic("Start tag expected, '<' not found")],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )

        if not stripped.startswith(b"<"):
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic("Start tag expected, '<' not found")],
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
            msg = expat.ErrorString(exc.code)
            # Map expat errors to canonical libxml2 style
            if "mismatched" in msg.lower():
                diag = f"Opening and ending tag mismatch: tag %s line {exc.lineno}"
            elif "unclosed" in msg.lower() or "not well-formed" in msg.lower():
                diag = f"Premature end of data in tag %s line {exc.lineno}"
            elif "duplicate" in msg.lower():
                diag = f"Attribute redefined in element %s line {exc.lineno}"
            else:
                diag = f"parser error: {msg} line {exc.lineno}"
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic(diag)],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )
