"""DNS binary wire protocol parser target implementation."""
from __future__ import annotations

import hashlib
import re
import struct
import time
from pathlib import Path

from fuzzer.runner import (
    PER_RUN_TIMEOUT_S,
    Outcome,
    RunResult,
)
from fuzzer.targets.base import BaseTarget, REPO_ROOT
from fuzzer.targets.protocol_features import (
    DNS_PRODUCTIONS,
    analyze_dns,
    coverage_dns,
)

_DNS_SUBS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"offset \d+"), "offset %d"),
    (re.compile(r"type \d+"), "type %d"),
    (re.compile(r"\b\d+\b"), "%d"),
]


def normalize_dns(message: str) -> str:
    out = message.strip()
    for pattern, repl in _DNS_SUBS:
        out = pattern.sub(repl, out)
    return out


class DNSTarget(BaseTarget):
    """DNS wire-format parser target (RFC 1035)."""

    name: str = "dns"
    category: str = "protocol"
    description: str = "DNS binary wire-format packet parser"
    harness_binary: Path = REPO_ROOT / "build" / "protocols" / "dns_harness"
    grammar_file: Path = REPO_ROOT / "grammar" / "DNS.txt"
    productions: tuple[str, ...] = DNS_PRODUCTIONS

    def is_valid_shape(self, payload: bytes) -> bool:
        """DNS messages must have at least the 12-byte header."""
        return len(payload) >= 12

    def normalize_diagnostic(self, message: str) -> str:
        return normalize_dns(message)

    def analyze_features(self, text: str, payload: bytes = b""):
        return analyze_dns(text, payload)

    def summarize_structure(self, feature_list: list) -> dict:
        return coverage_dns(feature_list)

    def run_reference(
        self,
        payload: bytes,
        timeout_s: float = PER_RUN_TIMEOUT_S,
        extra_args: tuple[str, ...] = (),
    ) -> RunResult:
        """Reference DNS packet decoder checking header, questions, and RRs."""
        started = time.monotonic()
        sha = hashlib.sha256(payload).hexdigest()

        if len(payload) < 12:
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic(f"Truncated DNS header: length {len(payload)} < 12")],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )

        tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", payload[:12])

        offset = 12
        seen_ptrs = set()

        # Parse question section
        for q_idx in range(qdcount):
            # Parse QNAME
            name_len = 0
            while True:
                if offset >= len(payload):
                    return RunResult(
                        outcome=Outcome.REJECTED,
                        returncode=1,
                        diagnostics=[self.normalize_diagnostic(f"Buffer underflow parsing QNAME at offset {offset}")],
                        duration_s=time.monotonic() - started,
                        input_sha256=sha,
                        input_len=len(payload),
                    )
                b = payload[offset]
                if b == 0:
                    offset += 1
                    break
                elif (b & 0xC0) == 0xC0:
                    if offset + 1 >= len(payload):
                        return RunResult(
                            outcome=Outcome.REJECTED,
                            returncode=1,
                            diagnostics=[self.normalize_diagnostic(f"Incomplete pointer at offset {offset}")],
                            duration_s=time.monotonic() - started,
                            input_sha256=sha,
                            input_len=len(payload),
                        )
                    ptr_offset = ((b & 0x3F) << 8) | payload[offset + 1]
                    if ptr_offset >= len(payload):
                        return RunResult(
                            outcome=Outcome.REJECTED,
                            returncode=1,
                            diagnostics=[self.normalize_diagnostic(f"Pointer out of bounds: {ptr_offset} >= {len(payload)} at offset {offset}")],
                            duration_s=time.monotonic() - started,
                            input_sha256=sha,
                            input_len=len(payload),
                        )
                    if ptr_offset in seen_ptrs or ptr_offset == offset:
                        # Compression loop!
                        return RunResult(
                            outcome=Outcome.CRASH,
                            returncode=-1,
                            signal_name="SIGABRT",
                            stderr="DNS pointer compression loop detected",
                            diagnostics=[self.normalize_diagnostic(f"Compression loop at offset {offset}")],
                            duration_s=time.monotonic() - started,
                            input_sha256=sha,
                            input_len=len(payload),
                        )
                    seen_ptrs.add(ptr_offset)
                    offset += 2
                    break
                elif b > 63:
                    return RunResult(
                        outcome=Outcome.REJECTED,
                        returncode=1,
                        diagnostics=[self.normalize_diagnostic(f"Label length too large: {b} > 63 at offset {offset}")],
                        duration_s=time.monotonic() - started,
                        input_sha256=sha,
                        input_len=len(payload),
                    )
                else:
                    offset += 1
                    name_len += b
                    if name_len > 255:
                        return RunResult(
                            outcome=Outcome.REJECTED,
                            returncode=1,
                            diagnostics=[self.normalize_diagnostic(f"Domain name exceeds 255 bytes at offset {offset}")],
                            duration_s=time.monotonic() - started,
                            input_sha256=sha,
                            input_len=len(payload),
                        )
                    if offset + b > len(payload):
                        return RunResult(
                            outcome=Outcome.REJECTED,
                            returncode=1,
                            diagnostics=[self.normalize_diagnostic(f"Truncated label data at offset {offset}")],
                            duration_s=time.monotonic() - started,
                            input_sha256=sha,
                            input_len=len(payload),
                        )
                    offset += b

            # QTYPE and QCLASS
            if offset + 4 > len(payload):
                return RunResult(
                    outcome=Outcome.REJECTED,
                    returncode=1,
                    diagnostics=[self.normalize_diagnostic(f"Truncated QTYPE/QCLASS at offset {offset}")],
                    duration_s=time.monotonic() - started,
                    input_sha256=sha,
                    input_len=len(payload),
                )
            offset += 4

        return RunResult(
            outcome=Outcome.PARSED_CLEAN,
            returncode=0,
            duration_s=time.monotonic() - started,
            input_sha256=sha,
            input_len=len(payload),
        )
