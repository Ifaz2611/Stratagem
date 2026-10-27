"""Local CI runner, mirroring the GitHub Actions workflow.

Two things are worth running before a push:

  * ``--unit``    compile check, the agent test suite, and both self-check
                  suites. Needs no harness, network or LLM credentials.
  * ``--replay``  copies a recorded transcript into a scratch run, replays it
                  through the real harness, and verifies every completed
                  iteration's strategy is byte-identical. Needs the asan
                  harness built (Linux/macOS or WSL/Docker).

Usage::

    python scripts/ci.py                 # same as --unit
    python scripts/ci.py --unit --cov
    python scripts/ci.py --replay --run-id loop --iterations 5 --examples 10
    python scripts/ci.py --full --json

The script exits non-zero on the first failed step group and is safe to run
from any working directory.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Step:
    name: str
    ok: bool
    duration_s: float
    command: str = ""
    detail: str = ""

    def to_json(self) -> dict:
        return asdict(self)


@dataclass
class Report:
    steps: list[Step] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(s.ok for s in self.steps)

    def add(self, step: Step) -> None:
        self.steps.append(step)
        status = "ok" if step.ok else "FAILED"
        print(f"[ci] {status:6} {step.name} ({step.duration_s:.1f}s)")
        if step.detail and not step.ok:
            for line in step.detail.rstrip().splitlines()[-15:]:
                print(f"      {line}")

    def to_json(self) -> dict:
        return {"ok": self.ok,
                "steps": [s.to_json() for s in self.steps]}


def _run(command: list[str], *, capture: bool = False,
         cwd: Path = ROOT, env: dict[str, str] | None = None
         ) -> subprocess.CompletedProcess:
    printable = " ".join(command)
    print(f"[ci] $ {printable}")
    full_env = dict(os.environ)
    full_env.setdefault("PYTHONUNBUFFERED", "1")
    full_env.setdefault("STRATAGEM_NO_PROGRESS", "1")
    if env:
        full_env.update(env)
    return subprocess.run(
        command, cwd=str(cwd), env=full_env,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
        text=True,
    )


def _step(name: str, command: list[str], *, capture: bool = False,
          env: dict[str, str] | None = None) -> Step:
    started = time.monotonic()
    try:
        proc = _run(command, capture=capture, env=env)
    except FileNotFoundError as exc:
        return Step(name, False, time.monotonic() - started,
                    " ".join(command), str(exc))
    elapsed = time.monotonic() - started
    output = (proc.stdout or "") if capture else ""
    ok = proc.returncode == 0
    return Step(name, ok, elapsed, " ".join(command),
                output if not ok else "")


def run_unit(report: Report, *, cov: bool = False) -> None:
    report.add(_step("compile", [sys.executable, "-m", "compileall", "-q",
                                 "agent", "fuzzer", "scripts"]))

    try:
        import pytest  # noqa: F401
    except ImportError:
        report.add(Step(
            "pytest available", False, 0.0,
            detail=("pytest is not installed. Run "
                    "`pip install -r requirements-dev.txt`.")))
        return

    agent_cmd = [sys.executable, "-m", "pytest", "agent", "-q"]
    if cov:
        agent_cmd += ["--cov=agent", "--cov-report=term-missing"]
    report.add(_step("agent tests", agent_cmd, capture=True))

    report.add(_step("agent self-checks",
                     [sys.executable, "-m", "agent.selftest"], capture=True))
    report.add(_step("fuzzer self-checks",
                     [sys.executable, "-m", "fuzzer.selftest"], capture=True))


def _harness_path() -> Path:
    return ROOT / "build" / "asan" / "harness"


def run_replay(report: Report, *, run_id: str = "loop",
               iterations: int = 5, examples: int = 10,
               keep: bool = False) -> None:
    source = ROOT / "runs" / run_id
    transcript = source / "transcript"
    if not transcript.exists():
        report.add(Step("replay prerequisites", False, 0.0,
                        detail=f"no transcript at {transcript}"))
        return
    harness = _harness_path()
    if not harness.exists():
        report.add(Step(
            "replay prerequisites", False, 0.0,
            detail=(f"harness not built at {harness}. Run "
                    "`cd harness && ./build.sh asan` (Linux/macOS/WSL) or "
                    "use the Docker image.")))
        return
    if os.name == "nt":
        report.add(Step(
            "replay prerequisites", False, 0.0,
            detail=("the asan harness is a POSIX binary; run the replay "
                    "check inside WSL2 or Docker on Windows.")))
        return

    replay_id = f"ci-replay-{run_id}"
    dest = ROOT / "runs" / replay_id
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    shutil.copytree(transcript, dest / "transcript")

    command = [
        sys.executable, "-m", "agent.loop",
        "--backend", "replay", "--run-id", replay_id,
        "-n", str(examples), "-i", str(iterations),
        "--progress", "off", "--status", "off",
    ]
    step = _step("replay loop", command, capture=True,
                 env={"LLM_BACKEND": "replay",
                      "STRATAGEM_NO_PROGRESS": "1"})
    report.add(step)

    try:
        completed = [d for d in sorted((source / "iterations").glob("iter-*"))
                     if (d / "summary.json").exists()]
        compared = 0
        mismatches: list[str] = []
        for d in completed:
            a = d / "strategy.py"
            b = dest / "iterations" / d.name / "strategy.py"
            if not b.exists():
                mismatches.append(f"{d.name}: replay produced no strategy")
                continue
            if a.read_bytes() != b.read_bytes():
                mismatches.append(f"{d.name}: strategy differs")
                continue
            compared += 1
        ok = not mismatches and compared > 0
        detail = ("; ".join(mismatches) if mismatches
                  else "" if ok else "no completed iterations to compare")
        report.add(Step("replay strategy identity", ok, 0.0,
                        "byte-compare strategy.py", detail))
        report.add(Step(
            "replay artifact check", (dest / "loop_summary.json").exists()
            and (dest / "ITERATION_LOG.md").exists(), 0.0,
            detail=f"outputs under {dest}"))
    finally:
        if not keep and dest.exists():
            shutil.rmtree(dest, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Run Stratagem's CI checks locally.")
    ap.add_argument("--unit", action="store_true",
                    help="compile, agent tests and self-checks (default)")
    ap.add_argument("--replay", action="store_true",
                    help="replay a recorded run through the harness")
    ap.add_argument("--full", action="store_true",
                    help="unit checks plus the replay smoke test")
    ap.add_argument("--cov", action="store_true",
                    help="collect agent coverage (requires pytest-cov)")
    ap.add_argument("--run-id", default="loop",
                    help="recorded run used by --replay (default: loop)")
    ap.add_argument("--iterations", type=int, default=5,
                    help="iterations to replay (default: 5)")
    ap.add_argument("--examples", type=int, default=10,
                    help="examples per replay iteration (default: 10)")
    ap.add_argument("--keep", action="store_true",
                    help="keep the scratch replay run for inspection")
    ap.add_argument("--json", action="store_true",
                    help="print a machine-readable summary at the end")
    args = ap.parse_args(argv)

    do_unit = args.unit or args.full or not args.replay
    do_replay = args.replay or args.full

    report = Report()
    started = time.monotonic()
    if do_unit:
        run_unit(report, cov=args.cov)
    if do_replay:
        run_replay(report, run_id=args.run_id,
                   iterations=args.iterations, examples=args.examples,
                   keep=args.keep)

    elapsed = time.monotonic() - started
    print(f"\n[ci] {'PASS' if report.ok else 'FAIL'} in {elapsed:.1f}s")
    if args.json:
        payload = report.to_json()
        payload["duration_s"] = round(elapsed, 2)
        print(json.dumps(payload, indent=2))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
