"""JSON parser target implementation for Stratagem."""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path

from fuzzer.runner import (
    PER_RUN_TIMEOUT_S,
    Outcome,
    RunResult,
)
from fuzzer.targets.base import BaseTarget, REPO_ROOT
from fuzzer.targets.json_features import JSON_PRODUCTIONS, analyze, coverage

_JSON_SUBS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"line \d+"), "line %d"),
    (re.compile(r"column \d+"), "column %d"),
    (re.compile(r"char \d+"), "char %d"),
    (re.compile(r"'[^']*'"), "'%s'"),
    (re.compile(r'"[^"]*"'), '"%s"'),
    (re.compile(r"\b\d+\b"), "%d"),
]


def normalize_json(message: str) -> str:
    """Normalize JSON parser diagnostic string to a canonical template."""
    out = message.strip()
    for pattern, repl in _JSON_SUBS:
        out = pattern.sub(repl, out)
    return out


class JSONTarget(BaseTarget):
    """JSON parser target (proof-of-concept for non-XML grammars)."""

    name: str = "json"
    category: str = "json"
    description: str = "JSON parser target proof-of-concept for non-XML grammars"
    harness_binary: Path = REPO_ROOT / "build" / "json" / "harness"
    grammar_file: Path = REPO_ROOT / "grammar" / "JSON.g4"
    productions: tuple[str, ...] = JSON_PRODUCTIONS
    harness_headers: tuple[str, ...] = ("cJSON.h",)
    harness_link_flags: tuple[str, ...] = ("-lcjson",)

    def is_valid_shape(self, payload: bytes) -> bool:
        """JSON inputs typically begin with '{', '[', '\"', digits, or literals."""
        stripped = payload.lstrip()
        if not stripped:
            return False
        first = stripped[:1]
        return first in b"{[\"-0123456789tfn"

    def normalize_diagnostic(self, message: str) -> str:
        return normalize_json(message)

    def analyze_features(self, text: str, payload: bytes = b""):
        return analyze(text, payload)

    def summarize_structure(self, feature_list: list) -> dict:
        return coverage(feature_list)

    def run_reference(
        self,
        payload: bytes,
        timeout_s: float = PER_RUN_TIMEOUT_S,
        extra_args: tuple[str, ...] = (),
    ) -> RunResult:
        """Execute JSON parser using Python's high-speed C-accelerated json module."""
        started = time.monotonic()
        sha = hashlib.sha256(payload).hexdigest()

        if not payload.strip():
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic("Expecting value: line 1 column 1 (char 0)")],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )

        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            diag = f"Invalid UTF-8 byte at position {exc.start}"
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic(diag)],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )

        try:
            json.loads(text)
            return RunResult(
                outcome=Outcome.PARSED_CLEAN,
                returncode=0,
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )
        except json.decoder.JSONDecodeError as exc:
            diag = f"{exc.msg}: line {exc.lineno} column {exc.colno} (char {exc.pos})"
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
