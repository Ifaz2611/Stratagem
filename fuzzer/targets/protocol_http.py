"""HTTP protocol parser target implementation."""
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
from fuzzer.targets.base import BaseTarget, REPO_ROOT
from fuzzer.targets.protocol_features import (
    HTTP_PRODUCTIONS,
    analyze_http,
    coverage_http,
)

_HTTP_SUBS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"line \d+"), "line %d"),
    (re.compile(r"'[^']*'"), "'%s'"),
    (re.compile(r"\b\d+\b"), "%d"),
]


def normalize_http(message: str) -> str:
    out = message.strip()
    for pattern, repl in _HTTP_SUBS:
        out = pattern.sub(repl, out)
    return out


class HTTPTarget(BaseTarget):
    """HTTP/1.1 message and request parser target."""

    name: str = "http"
    category: str = "protocol"
    description: str = "HTTP protocol request and header parser"
    harness_binary: Path = REPO_ROOT / "build" / "protocols" / "http_harness"
    grammar_file: Path = REPO_ROOT / "grammar" / "HTTP.g4"
    productions: tuple[str, ...] = HTTP_PRODUCTIONS

    def is_valid_shape(self, payload: bytes) -> bool:
        """HTTP requests begin with standard methods or HTTP/."""
        stripped = payload.lstrip()
        methods = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE", b"HTTP/")
        return stripped.startswith(methods)

    def normalize_diagnostic(self, message: str) -> str:
        return normalize_http(message)

    def analyze_features(self, text: str, payload: bytes = b""):
        return analyze_http(text, payload)

    def summarize_structure(self, feature_list: list) -> dict:
        return coverage_http(feature_list)

    def run_reference(
        self,
        payload: bytes,
        timeout_s: float = PER_RUN_TIMEOUT_S,
        extra_args: tuple[str, ...] = (),
    ) -> RunResult:
        """Reference HTTP parser validating RFC 7230 request line and headers."""
        started = time.monotonic()
        sha = hashlib.sha256(payload).hexdigest()

        if not payload.strip():
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic("Empty HTTP request")],
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

        # Parse request line
        lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
        req_line = lines[0].strip()
        parts = req_line.split(" ")
        if len(parts) != 3:
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic("Malformed HTTP request line on line 1")],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )

        method, uri, version = parts
        if not re.match(r"^[A-Za-z0-9!#$%&'*+-.^_`|~]+$", method):
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic(f"Invalid method token '{method}' on line 1")],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )

        if not version.startswith("HTTP/"):
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic(f"Invalid HTTP version '{version}' on line 1")],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )

        # Parse headers
        headers: dict[str, str] = {}
        for idx, line in enumerate(lines[1:], start=2):
            if not line:
                break
            if ":" not in line:
                return RunResult(
                    outcome=Outcome.REJECTED,
                    returncode=1,
                    diagnostics=[self.normalize_diagnostic(f"Missing ':' in header on line {idx}")],
                    duration_s=time.monotonic() - started,
                    input_sha256=sha,
                    input_len=len(payload),
                )
            name, val = line.split(":", 1)
            if " " in name or "\t" in name or not name.strip():
                return RunResult(
                    outcome=Outcome.REJECTED,
                    returncode=1,
                    diagnostics=[self.normalize_diagnostic(f"Invalid header name '{name}' on line {idx}")],
                    duration_s=time.monotonic() - started,
                    input_sha256=sha,
                    input_len=len(payload),
                )
            headers[name.strip().lower()] = val.strip()

        # Check for request smuggling indicators
        if "content-length" in headers and "transfer-encoding" in headers:
            return RunResult(
                outcome=Outcome.PARSED_DIAG,
                returncode=3,
                diagnostics=[self.normalize_diagnostic("Ambiguous framing: both Content-Length and Transfer-Encoding on line 2")],
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
