"""Base target abstraction layer for Stratagem.

This module defines the Target interface and registry, allowing Stratagem
to support multiple parser targets across different grammars and protocols:
- XML parsers: mxml, libxml2, expat, tinyxml2
- Non-XML grammars: JSON (cJSON / proof-of-concept)
- Network protocols: HTTP, DNS, SMTP

Each target encapsulates:
  * Harness execution (native sanitizer-instrumented binary or reference runner)
  * Target-specific diagnostic normalization
  * Grammar productions and feature extraction
  * Input shape validation and classification bounds
"""
from __future__ import annotations

import abc
import hashlib
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fuzzer.runner import (
    DEFAULT_HARNESS,
    PER_RUN_TIMEOUT_S,
    SANITIZER_ENV,
    SANITIZER_MARKERS,
    Outcome,
    RunResult,
    _signal_name,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class BaseTarget(abc.ABC):
    """Abstract base class for a fuzzing target."""

    name: str = "base"
    category: str = "xml"  # "xml", "json", "protocol"
    description: str = "Base target"
    harness_binary: Path | None = None
    grammar_file: Path | None = None
    productions: tuple[str, ...] = ()
    class_bounds: dict[str, tuple[float, float]] = {
        "well_formed": (0.35, 1.0),
        "near_miss": (0.15, 1.0),
        "byte_hostile": (0.15, 0.45),
    }

    # Metadata used by agent/harness_gen.py when it writes a target-specific
    # driver. Defaults describe a self-contained C harness with no external
    # library, which is true for the protocol targets. Parser-library targets
    # override the header and link fields.
    harness_language: str = "c"
    harness_headers: tuple[str, ...] = ()
    harness_link_flags: tuple[str, ...] = ()

    @abc.abstractmethod
    def is_valid_shape(self, payload: bytes) -> bool:
        """Check whether input has the target's expected superficial shape."""
        raise NotImplementedError

    @abc.abstractmethod
    def normalize_diagnostic(self, message: str) -> str:
        """Normalize target-specific error message into a canonical template."""
        raise NotImplementedError

    @abc.abstractmethod
    def analyze_features(self, text: str, payload: bytes = b"") -> Any:
        """Analyze structural features of generated input."""
        raise NotImplementedError

    @abc.abstractmethod
    def summarize_structure(self, feature_list: list[Any]) -> dict:
        """Aggregate feature statistics over a batch of inputs."""
        raise NotImplementedError

    def run_native(
        self,
        payload: bytes,
        binary_path: Path,
        timeout_s: float = PER_RUN_TIMEOUT_S,
        extra_args: tuple[str, ...] = (),
        slow_threshold_s: float | None = None,
    ) -> RunResult:
        """Execute a compiled harness binary using the standard line protocol."""
        env = {**os.environ, **SANITIZER_ENV}
        sha = hashlib.sha256(payload).hexdigest()
        started = time.monotonic()

        try:
            proc = subprocess.run(
                [str(binary_path), *extra_args],
                input=payload,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_s,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            dur = time.monotonic() - started
            return RunResult(
                outcome=Outcome.TIMEOUT,
                returncode=-1,
                signal_name="TIMEOUT",
                stderr=(exc.stderr or b"").decode("utf-8", "replace"),
                duration_s=dur,
                input_sha256=sha,
                input_len=len(payload),
                is_slow=True,
                slow_threshold_s=slow_threshold_s,
            )

        duration = time.monotonic() - started
        stdout = proc.stdout.decode("utf-8", "replace")
        stderr = proc.stderr.decode("utf-8", "replace")
        rc = proc.returncode

        raw_diags = [
            line.split("\t", 1)[1]
            for line in stdout.splitlines()
            if line.startswith("DIAG\t")
        ]
        # Normalize through the target's diagnostic normalizer
        diagnostics = [self.normalize_diagnostic(d) for d in raw_diags]

        saw_sanitizer = any(m in stderr for m in SANITIZER_MARKERS)

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
            input_len=len(payload),
            is_slow=is_slow,
            slow_threshold_s=slow_threshold_s,
        )

    def run_reference(
        self,
        payload: bytes,
        timeout_s: float = PER_RUN_TIMEOUT_S,
        extra_args: tuple[str, ...] = (),
    ) -> RunResult:
        """Run reference / in-process / fallback parser implementation.

        Subclasses should implement this to provide portable execution when
        a compiled C/C++ harness binary is not present on the host system.
        """
        raise NotImplementedError(f"Target '{self.name}' has no reference runner")

    def run(
        self,
        payload: bytes,
        timeout_s: float = PER_RUN_TIMEOUT_S,
        extra_args: tuple[str, ...] = (),
        slow_threshold_s: float | None = None,
    ) -> RunResult:
        """Execute input against this target.

        Uses the native binary if available and executable; otherwise falls
        back to the target's reference runner.
        """
        if self.harness_binary and self.harness_binary.exists() and os.access(str(self.harness_binary), os.X_OK):
            res = self.run_native(payload, self.harness_binary, timeout_s, extra_args, slow_threshold_s=slow_threshold_s)
        else:
            try:
                res = self.run_reference(payload, timeout_s, extra_args, slow_threshold_s=slow_threshold_s)
            except TypeError:
                res = self.run_reference(payload, timeout_s, extra_args)

        if slow_threshold_s is not None and res.duration_s >= slow_threshold_s:
            res.is_slow = True
            res.slow_threshold_s = slow_threshold_s
        return res


# Registry of known targets
_REGISTRY: dict[str, BaseTarget] = {}


def register_target(target: BaseTarget) -> None:
    """Register a target instance in the global registry."""
    _REGISTRY[target.name.lower()] = target


def get_target(name_or_target: str | BaseTarget) -> BaseTarget:
    """Retrieve a target by name or return the target instance if already one."""
    if isinstance(name_or_target, BaseTarget):
        return name_or_target
    key = name_or_target.lower().strip()
    if key in _REGISTRY:
        return _REGISTRY[key]
    raise KeyError(f"Unknown target: '{name_or_target}'. Available: {list(_REGISTRY.keys())}")


def list_targets() -> dict[str, BaseTarget]:
    """Return all registered targets."""
    return dict(_REGISTRY)


def get_default_target() -> BaseTarget:
    """Return the default target (mxml for backwards compatibility)."""
    return get_target("mxml")
