"""SMTP protocol command parser target implementation."""
from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path
from typing import Any

from fuzzer.runner import (
    PER_RUN_TIMEOUT_S,
    Outcome,
    RunResult,
)
from fuzzer.targets.base import BaseTarget, REPO_ROOT
from fuzzer.targets.protocol_features import (
    SMTP_PRODUCTIONS,
    analyze_smtp,
    coverage_smtp,
)

_SMTP_SUBS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"line \d+"), "line %d"),
    (re.compile(r"'[^']*'"), "'%s'"),
    (re.compile(r"\b\d+\b"), "%d"),
]


def normalize_smtp(message: str) -> str:
    out = message.strip()
    for pattern, repl in _SMTP_SUBS:
        out = pattern.sub(repl, out)
    return out


class SMTPTarget(BaseTarget):
    """SMTP command line and state protocol parser target (RFC 5321)."""

    name: str = "smtp"
    category: str = "protocol"
    description: str = "SMTP text command parser and state engine"
    harness_binary: Path = REPO_ROOT / "build" / "protocols" / "smtp_harness"
    grammar_file: Path = REPO_ROOT / "grammar" / "SMTP.g4"
    productions: tuple[str, ...] = SMTP_PRODUCTIONS

    def is_valid_shape(self, payload: bytes) -> bool:
        """SMTP sessions begin with standard commands."""
        stripped = payload.lstrip().upper()
        verbs = (b"HELO", b"EHLO", b"MAIL", b"RCPT", b"DATA", b"RSET", b"NOOP", b"QUIT", b"VRFY", b"EXPN", b"HELP")
        return stripped.startswith(verbs)

    def normalize_diagnostic(self, message: str) -> str:
        return normalize_smtp(message)

    def analyze_features(self, text: str, payload: bytes = b"") -> Any:
        return analyze_smtp(text, payload)

    def summarize_structure(self, feature_list: list) -> dict:
        return coverage_smtp(feature_list)

    def run_reference(
        self,
        payload: bytes,
        timeout_s: float = PER_RUN_TIMEOUT_S,
        extra_args: tuple[str, ...] = (),
    ) -> RunResult:
        """Reference SMTP session parser validating RFC 5321 commands."""
        started = time.monotonic()
        sha = hashlib.sha256(payload).hexdigest()

        if not payload.strip():
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic("Empty SMTP stream")],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )

        try:
            text = payload.decode("latin1")
        except Exception as exc:
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic(f"Decode error: {exc}")],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )

        lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
        in_data = False

        for idx, line in enumerate(lines, start=1):
            if not line and idx == len(lines):
                break
            if len(line) > 1000:
                return RunResult(
                    outcome=Outcome.REJECTED,
                    returncode=1,
                    diagnostics=[self.normalize_diagnostic(f"500 Line too long ({len(line)} > 1000) on line {idx}")],
                    duration_s=time.monotonic() - started,
                    input_sha256=sha,
                    input_len=len(payload),
                )
            if in_data:
                if line == ".":
                    in_data = False
                continue

            parts = line.split(None, 1)
            if not parts:
                continue
            verb = parts[0].upper()

            if verb == "DATA":
                in_data = True
            elif verb in ("HELO", "EHLO"):
                if len(parts) < 2 or not parts[1].strip():
                    return RunResult(
                        outcome=Outcome.REJECTED,
                        returncode=1,
                        diagnostics=[self.normalize_diagnostic(f"501 Syntax error in {verb} parameters on line {idx}")],
                        duration_s=time.monotonic() - started,
                        input_sha256=sha,
                        input_len=len(payload),
                    )
            elif verb == "MAIL":
                if len(parts) < 2 or not parts[1].upper().startswith("FROM:"):
                    return RunResult(
                        outcome=Outcome.REJECTED,
                        returncode=1,
                        diagnostics=[self.normalize_diagnostic(f"501 Syntax error in MAIL command on line {idx}")],
                        duration_s=time.monotonic() - started,
                        input_sha256=sha,
                        input_len=len(payload),
                    )
            elif verb == "RCPT":
                if len(parts) < 2 or not parts[1].upper().startswith("TO:"):
                    return RunResult(
                        outcome=Outcome.REJECTED,
                        returncode=1,
                        diagnostics=[self.normalize_diagnostic(f"501 Syntax error in RCPT command on line {idx}")],
                        duration_s=time.monotonic() - started,
                        input_sha256=sha,
                        input_len=len(payload),
                    )
            elif verb in ("QUIT", "RSET", "NOOP"):
                pass
            else:
                return RunResult(
                    outcome=Outcome.REJECTED,
                    returncode=1,
                    diagnostics=[self.normalize_diagnostic(f"500 Command unrecognized: '{verb}' on line {idx}")],
                    duration_s=time.monotonic() - started,
                    input_sha256=sha,
                    input_len=len(payload),
                )

        return RunResult(
            outcome=Outcome.PARSED_CLEAN,
            returncode=0,
            duration_s=time.monotonic() - started,
            input_sha256=sha,
            input_len=len(payload),
        )
