"""Minimise a crashing input using Hypothesis's shrinker, then verify it.

Steps 5.4 and 5.5:

  5.4 "use Hypothesis's shrinking (it runs automatically when a @given-wrapped
       test fails) ... If you're driving the harness outside of a @given test
       loop, make sure you're still invoking Hypothesis's shrinker rather than
       just keeping the first crashing example you saw."

  5.5 "Re-run each minimized reproducer once, standalone, against the pinned
       build to confirm it deterministically reproduces the crash."

The shrinker only runs when a @given test *fails*, so minimisation is not a
separate algorithm we implement: it is a consequence of letting the assertion
propagate. That is why `hunt` mode exists in fuzzer/campaign.py and why this
module raises rather than recording.

Verification re-runs the shrunk input N times as a fresh process. A reproducer
that fires only sometimes is worse than useless in a report, and the check is
cheap.
"""
from __future__ import annotations

import importlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from fuzzer import triage
from fuzzer.campaign import _encode
from fuzzer.runner import DEFAULT_HARNESS, Outcome, run_one

VERIFY_RUNS = 5


@dataclass
class Minimized:
    found: bool
    document: bytes = b""
    outcome: str = ""
    signature: str = ""
    label: str = ""
    stderr: str = ""
    examples_before_shrink: int = 0
    verified_runs: int = 0
    verified_ok: int = 0
    report: dict | None = None

    @property
    def deterministic(self) -> bool:
        return self.verified_runs > 0 and self.verified_ok == self.verified_runs

    def to_json(self) -> dict:
        return {
            "found": self.found,
            "document": self.document.decode("utf-8", "replace"),
            "document_len": len(self.document),
            "outcome": self.outcome,
            "signature": self.signature,
            "label": self.label,
            "examples_before_shrink": self.examples_before_shrink,
            "verified_runs": self.verified_runs,
            "verified_ok": self.verified_ok,
            "deterministic": self.deterministic,
            "report": self.report,
        }


def _identity(outcome: Outcome, stderr: str) -> str:
    """Return the root-cause identity used to keep shrinking on one fault."""
    if outcome is Outcome.TIMEOUT:
        return "timeout"
    report = triage.parse_report(stderr)
    return report.signature if report else "unparsed"


def hunt_and_shrink(strategy_name: str, max_examples: int = 500,
                    harness: Path = DEFAULT_HARNESS,
                    extra_args: tuple[str, ...] = (),
                    target_signature: str | None = None) -> Minimized:
    """Run a strategy until it crashes, letting Hypothesis shrink the failure."""
    importlib.invalidate_caches()
    mod = importlib.import_module(f"fuzzer.strategies.{strategy_name}")
    mod = importlib.reload(mod)

    seen: list[str] = []
    crashes: list[tuple[bytes, str, str, str]] = []
    wanted = target_signature

    @settings(max_examples=max_examples, deadline=None, database=None,
              derandomize=True,
              suppress_health_check=[HealthCheck.too_slow,
                                     HealthCheck.data_too_large,
                                     HealthCheck.filter_too_much,
                                     HealthCheck.large_base_example])
    @given(mod.documents())
    def _hunt(doc: str) -> None:
        nonlocal wanted
        seen.append(doc)
        payload = _encode(doc)
        r = run_one(payload, harness=harness, extra_args=extra_args)
        identity = _identity(r.outcome, r.stderr)
        if r.outcome.is_crash and (wanted is None or identity == wanted):
            if wanted is None:
                wanted = identity
            crashes.append((payload, r.outcome.value, r.stderr, identity))
        # Raising here is what hands control to Hypothesis's shrinker. Recording
        # the crash and returning would keep the FIRST crashing example instead
        # of shrinking it to a minimal reproducer.
        assert not (r.outcome.is_crash and identity == wanted), (
            f"{r.outcome.value} rc={r.returncode} sig={identity}")

    n_before = 0
    try:
        _hunt()
        return Minimized(found=False, examples_before_shrink=len(seen))
    except AssertionError:
        n_before = len(seen)

    # After shrinking, the LAST crash recorded is the smallest one Hypothesis
    # reached, because it replays the shrunk candidate before reporting.
    payload, outcome, stderr, identity = crashes[-1]
    rep = triage.parse_report(stderr)
    m = Minimized(
        found=True, document=payload, outcome=outcome,
        signature=identity,
        label=rep.label if rep else outcome,
        stderr=stderr, examples_before_shrink=n_before,
        report=rep.to_json() if rep else None,
    )
    return verify(m, harness, extra_args)


def verify(m: Minimized, harness: Path = DEFAULT_HARNESS,
           extra_args: tuple[str, ...] = (), runs: int = VERIFY_RUNS) -> Minimized:
    """Re-run the minimised input standalone; confirm it reproduces every time."""
    ok = 0
    for _ in range(runs):
        r = run_one(m.document, harness=harness, extra_args=extra_args)
        if r.outcome.is_crash and _identity(r.outcome, r.stderr) == m.signature:
            ok += 1
    m.verified_runs = runs
    m.verified_ok = ok
    return m
