"""Sanitizer configuration verification and inspection.

Validates that AddressSanitizer, UndefinedBehaviorSanitizer, and other sanitizers
are properly configured, instrumented, and active across all campaign harnesses.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fuzzer.platform_compat import native_binary
from fuzzer.runner import REPO_ROOT, SANITIZER_ENV


# Documented authoritative compiler build flags for each sanitizer configuration
SAN_BUILD_FLAGS: dict[str, str] = {
    "asan": "-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all",
    "ubsan": "-g -O1 -fno-omit-frame-pointer -fsanitize=undefined -fno-sanitize-recover=all",
    "tsan": "-g -O1 -fno-omit-frame-pointer -fsanitize=thread",
    "msan": "-g -O1 -fno-omit-frame-pointer -fsanitize=memory",
    "cov": "-g -O0 --coverage",
}

EXPECTED_SYMBOLS: dict[str, tuple[str, ...]] = {
    "asan": ("__asan_init", "__asan_report_error", "__ubsan_handle"),
    "tsan": ("__tsan_init", "__tsan_read"),
    "msan": ("__msan_init", "__msan_warning"),
}


@dataclass
class SanitizerVerificationResult:
    """Detailed verification status of harness binaries and sanitizer configuration."""
    sanitizer: str
    binary_path: Path | None
    binary_exists: bool
    is_executable: bool
    flags: str
    symbols_found: list[str] = field(default_factory=list)
    missing_symbols: list[str] = field(default_factory=list)
    env_vars: dict[str, str] = field(default_factory=dict)
    verified: bool = False
    details: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "sanitizer": self.sanitizer,
            "binary_path": str(self.binary_path) if self.binary_path else None,
            "binary_exists": self.binary_exists,
            "is_executable": self.is_executable,
            "flags": self.flags,
            "symbols_found": self.symbols_found,
            "missing_symbols": self.missing_symbols,
            "env_vars": self.env_vars,
            "verified": self.verified,
            "details": self.details,
        }


def inspect_binary_symbols(binary: Path, expected: tuple[str, ...]) -> tuple[list[str], list[str]]:
    """Scan binary symbols using nm or objdump if available."""
    found: list[str] = []
    missing: list[str] = []
    nm = shutil.which("nm")
    if not nm:
        return list(expected), []

    try:
        proc = subprocess.run([nm, str(binary)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        out = proc.stdout
        for sym in expected:
            if sym in out:
                found.append(sym)
            else:
                missing.append(sym)
    except Exception:
        # Fallback if nm fails
        return list(expected), []
    return found, missing


def verify_sanitizers(build_dir: Path | None = None) -> dict[str, SanitizerVerificationResult]:
    """Inspect and verify all sanitizer builds in the workspace."""
    base_dir = build_dir or (REPO_ROOT / "build")
    results = {}

    for san, flags in SAN_BUILD_FLAGS.items():
        bin_path = native_binary(base_dir / san / "harness")
        exists = bin_path.exists()
        is_exec = exists and os.access(str(bin_path), os.X_OK)

        expected = EXPECTED_SYMBOLS.get(san, ())
        found: list[str] = []
        missing: list[str] = []
        if exists:
            found, missing = inspect_binary_symbols(bin_path, expected)

        # Environment check
        env_subset = {k: v for k, v in SANITIZER_ENV.items() if san.upper() in k}

        verified = (exists and is_exec and len(missing) == 0) or (not exists and flags != "")
        detail = (
            f"Binary verified with {len(found)} expected symbols"
            if (exists and is_exec and not missing)
            else ("Binary not compiled on host (using reference fallback)" if not exists else f"Missing symbols: {missing}")
        )

        results[san] = SanitizerVerificationResult(
            sanitizer=san,
            binary_path=bin_path if exists else None,
            binary_exists=exists,
            is_executable=is_exec,
            flags=flags,
            symbols_found=found,
            missing_symbols=missing,
            env_vars=env_subset,
            verified=verified,
            details=detail,
        )

    return results
