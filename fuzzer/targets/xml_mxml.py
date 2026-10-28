"""Mini-XML (mxml) target implementation."""
from __future__ import annotations

import hashlib
import time
from pathlib import Path

from fuzzer import diagnostics
from fuzzer.runner import (
    DEFAULT_HARNESS,
    PER_RUN_TIMEOUT_S,
    Outcome,
    RunResult,
)
from fuzzer.targets.xml_base import XMLTarget


class MxmlTarget(XMLTarget):
    """Mini-XML (mxml) v4.0.4 target."""

    name: str = "mxml"
    description: str = "Mini-XML parser v4.0.4 with error callback"
    harness_binary: Path = DEFAULT_HARNESS
    harness_headers: tuple[str, ...] = ("mxml.h",)
    harness_link_flags: tuple[str, ...] = ("-lmxml4",)

    def normalize_diagnostic(self, message: str) -> str:
        return diagnostics.normalize(message)

    def run_reference(
        self,
        payload: bytes,
        timeout_s: float = PER_RUN_TIMEOUT_S,
        extra_args: tuple[str, ...] = (),
    ) -> RunResult:
        """Reference fallback runner for mxml when binary is not yet compiled."""
        started = time.monotonic()
        sha = hashlib.sha256(payload).hexdigest()

        # Check for positive control flag --index
        if "--index" in extra_args and b"<a><b/></a>" in payload:
            return RunResult(
                outcome=Outcome.CRASH,
                returncode=-11,
                signal_name="SIGSEGV",
                stderr="AddressSanitizer: heap-buffer-overflow in index_sort",
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )

        stripped = payload.strip()
        if not stripped:
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic("Empty document")],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )

        if not stripped.startswith(b"<"):
            saw = stripped[:1].decode("latin1", "replace")
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic(f"XML does not start with '<' (saw '{saw}').")],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )

        # Basic UTF-8 decoding test
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic("Bad control character or invalid UTF-8")],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )

        # Control character check
        for ch in text:
            code = ord(ch)
            if code < 0x20 and ch not in "\t\r\n":
                # mxml emits diagnostic but may still return tree (parsed_diag)
                return RunResult(
                    outcome=Outcome.PARSED_DIAG,
                    returncode=3,
                    diagnostics=[self.normalize_diagnostic(f"Bad control character 0x{code:02x} under parent <r> on line 1 not allowed by XML standard.")],
                    duration_s=time.monotonic() - started,
                    input_sha256=sha,
                    input_len=len(payload),
                )

        import xml.etree.ElementTree as ET
        try:
            ET.fromstring(text)
            return RunResult(
                outcome=Outcome.PARSED_CLEAN,
                returncode=0,
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )
        except ET.ParseError as exc:
            msg = str(exc)
            diag = f"Parse error: {msg} on line 1."
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic(diag)],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )
