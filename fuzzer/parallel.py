"""Parallel campaign execution framework.

Allows running multiple fuzzing campaigns concurrently across:
  * Multiple parser / protocol targets simultaneously (e.g. mxml, libxml2, expat, tinyxml2, json, http)
  * Multiple strategies simultaneously (e.g. baseline, byte_probe)
  * Multiple random seeds / trials simultaneously for statistical significance
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from fuzzer import triage
from fuzzer.campaign import Campaign, MAX_EXAMPLES_PER_ITERATION, MAX_WALL_CLOCK_S
from fuzzer.runner import DEFAULT_HARNESS

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class CampaignTask:
    """Specification of an individual campaign task to execute in parallel."""
    name: str
    strategy_name: str
    target: str = "mxml"
    max_examples: int = 500
    out_dir: Path | str | None = None
    mode: str = "survey"
    random_seed: int | None = None
    extra_args: tuple[str, ...] = ()
    wall_clock_cap_s: float = MAX_WALL_CLOCK_S
    timeout_s: float = 5.0
    slow_threshold_s: float = 1.0
    checkpoint_interval: int = 50
    adaptive_batch: bool = False
    resume: bool = False

    def to_campaign(self, base_out_dir: Path | None = None) -> Campaign:
        """Instantiate a Campaign object from this task specification."""
        if self.out_dir is not None:
            resolved_dir = Path(self.out_dir)
        elif base_out_dir is not None:
            resolved_dir = base_out_dir / self.name
        else:
            resolved_dir = REPO_ROOT / "runs" / self.name

        return Campaign(
            strategy_name=self.strategy_name,
            max_examples=self.max_examples,
            out_dir=resolved_dir,
            mode=self.mode,
            extra_args=self.extra_args,
            random_seed=self.random_seed,
            wall_clock_cap_s=self.wall_clock_cap_s,
            target=self.target,
            timeout_s=self.timeout_s,
            slow_threshold_s=self.slow_threshold_s,
            checkpoint_interval=self.checkpoint_interval,
            adaptive_batch=self.adaptive_batch,
            resume=self.resume,
        )


@dataclass
class ParallelRunSummary:
    """Aggregated results across all concurrently executed campaigns."""
    total_campaigns: int = 0
    completed_campaigns: int = 0
    failed_campaigns: int = 0
    total_examples: int = 0
    total_crashes: int = 0
    unique_crashes: int = 0
    total_wall_clock_s: float = 0.0
    throughput_eps: float = 0.0
    campaigns: dict[str, dict] = field(default_factory=dict)
    failures: dict[str, str] = field(default_factory=dict)
    cross_campaign_crashes: list[str] = field(default_factory=list)
    crash_groups: dict[str, Any] = field(default_factory=dict)
    start_time: float = 0.0
    end_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "total_campaigns": self.total_campaigns,
            "completed_campaigns": self.completed_campaigns,
            "failed_campaigns": self.failed_campaigns,
            "total_examples": self.total_examples,
            "total_crashes": self.total_crashes,
            "unique_crashes": self.unique_crashes,
            "total_wall_clock_s": round(self.total_wall_clock_s, 2),
            "throughput_eps": round(self.throughput_eps, 2),
            "campaigns": self.campaigns,
            "failures": self.failures,
            "cross_campaign_crashes": self.cross_campaign_crashes,
            "crash_groups": self.crash_groups,
        }


def _run_single_campaign(task_or_campaign: CampaignTask | Campaign, base_out_dir: Path | None) -> tuple[str, dict]:
    """Worker function executed inside thread or process pool."""
    if isinstance(task_or_campaign, CampaignTask):
        name = task_or_campaign.name
        campaign = task_or_campaign.to_campaign(base_out_dir=base_out_dir)
    else:
        name = task_or_campaign.strategy_name
        campaign = task_or_campaign

    summary = campaign.run()
    return name, summary


class ParallelCampaignRunner:
    """Orchestrates concurrent execution of multiple campaigns."""

    def __init__(
        self,
        tasks: list[CampaignTask | Campaign],
        max_workers: int | None = None,
        base_out_dir: Path | str | None = None,
        worker_mode: str = "threads",
        on_complete: Callable[[str, dict], None] | None = None,
    ) -> None:
        if not tasks:
            raise ValueError("ParallelCampaignRunner requires at least one task")
        self.tasks = tasks
        self.max_workers = max_workers or min(os.cpu_count() or 4, len(tasks))
        self.base_out_dir = Path(base_out_dir) if base_out_dir else None
        self.worker_mode = worker_mode
        self.on_complete = on_complete

    def run(self) -> ParallelRunSummary:
        """Run all tasks in parallel, aggregate metrics, and return ParallelRunSummary."""
        started = time.monotonic()
        total = len(self.tasks)
        completed = 0
        failed = 0
        total_examples = 0
        total_crashes = 0
        all_crash_records: list[dict] = []
        all_crash_shas: set[str] = set()
        campaign_summaries: dict[str, dict] = {}
        failure_records: dict[str, str] = {}

        executor_cls = (
            concurrent.futures.ProcessPoolExecutor
            if self.worker_mode == "processes"
            else concurrent.futures.ThreadPoolExecutor
        )

        with executor_cls(max_workers=self.max_workers) as executor:
            future_to_task = {
                executor.submit(_run_single_campaign, task, self.base_out_dir): (
                    task.name if isinstance(task, CampaignTask) else task.strategy_name
                )
                for task in self.tasks
            }

            for future in concurrent.futures.as_completed(future_to_task):
                task_name = future_to_task[future]
                try:
                    name, summary = future.result()
                    campaign_summaries[name] = summary
                    completed += 1
                    total_examples += summary.get("examples", 0)
                    total_crashes += summary.get("crash_count", 0)

                    # Collect crash data for cross-campaign triage
                    crash_groups = summary.get("crash_groups", {})
                    for sig, grp in crash_groups.items():
                        for sample in grp.get("samples", []):
                            all_crash_records.append({
                                "sha": sample.get("sha", ""),
                                "stderr": sample.get("stderr", ""),
                                "outcome": "crash",
                                "rc": sample.get("rc", -11),
                                "signal": sample.get("signal", ""),
                                "productions": [],
                            })
                            all_crash_shas.add(sample.get("sha", ""))

                    if self.on_complete:
                        self.on_complete(name, summary)

                except Exception as exc:
                    failed += 1
                    err_msg = f"{type(exc).__name__}: {exc}"
                    failure_records[task_name] = err_msg

        elapsed = time.monotonic() - started
        cross_groups = triage.group(all_crash_records) if all_crash_records else {}
        throughput = (total_examples / elapsed) if elapsed > 0 else 0.0

        summary = ParallelRunSummary(
            total_campaigns=total,
            completed_campaigns=completed,
            failed_campaigns=failed,
            total_examples=total_examples,
            total_crashes=total_crashes,
            unique_crashes=len(all_crash_shas),
            total_wall_clock_s=elapsed,
            throughput_eps=throughput,
            campaigns=campaign_summaries,
            failures=failure_records,
            cross_campaign_crashes=sorted(all_crash_shas),
            crash_groups=cross_groups,
            start_time=started,
            end_time=time.monotonic(),
        )

        if self.base_out_dir:
            self.base_out_dir.mkdir(parents=True, exist_ok=True)
            out_file = self.base_out_dir / "parallel_summary.json"
            out_file.write_text(json.dumps(summary.to_dict(), indent=2), encoding="utf-8")

        return summary


def run_parallel_targets(
    strategy: str,
    targets: list[str],
    max_examples: int = 500,
    base_out_dir: Path | str | None = None,
    max_workers: int | None = None,
    mode: str = "survey",
    adaptive_batch: bool = False,
) -> ParallelRunSummary:
    """Helper to run one strategy across multiple targets concurrently."""
    tasks = [
        CampaignTask(
            name=f"{strategy}-{tgt}-{mode}",
            strategy_name=strategy,
            target=tgt,
            max_examples=max_examples,
            mode=mode,
            adaptive_batch=adaptive_batch,
        )
        for tgt in targets
    ]
    runner = ParallelCampaignRunner(
        tasks, max_workers=max_workers, base_out_dir=base_out_dir
    )
    return runner.run()


def run_parallel_strategies(
    strategies: list[str],
    target: str = "mxml",
    max_examples: int = 500,
    base_out_dir: Path | str | None = None,
    max_workers: int | None = None,
    mode: str = "survey",
    adaptive_batch: bool = False,
) -> ParallelRunSummary:
    """Helper to run multiple strategies against a single target concurrently."""
    tasks = [
        CampaignTask(
            name=f"{strat}-{target}-{mode}",
            strategy_name=strat,
            target=target,
            max_examples=max_examples,
            mode=mode,
            adaptive_batch=adaptive_batch,
        )
        for strat in strategies
    ]
    runner = ParallelCampaignRunner(
        tasks, max_workers=max_workers, base_out_dir=base_out_dir
    )
    return runner.run()


def run_parallel_seeds(
    strategy: str,
    target: str = "mxml",
    seeds: list[int] = (1, 2, 3),
    max_examples: int = 500,
    base_out_dir: Path | str | None = None,
    max_workers: int | None = None,
    mode: str = "survey",
) -> ParallelRunSummary:
    """Helper to run independent reproducible trials of the same campaign across seeds."""
    tasks = [
        CampaignTask(
            name=f"{strategy}-{target}-seed{s}",
            strategy_name=strategy,
            target=target,
            max_examples=max_examples,
            mode=mode,
            random_seed=s,
        )
        for s in seeds
    ]
    runner = ParallelCampaignRunner(
        tasks, max_workers=max_workers, base_out_dir=base_out_dir
    )
    return runner.run()


def main() -> None:
    ap = argparse.ArgumentParser(description="Run multiple fuzzing campaigns concurrently.")
    ap.add_argument("--strategy", default="baseline", help="Strategy module name")
    ap.add_argument("--strategies", nargs="+", default=None, help="List of strategies to run in parallel")
    ap.add_argument("--target", default="mxml", help="Target parser or protocol")
    ap.add_argument("--targets", nargs="+", default=None, help="List of targets to run in parallel")
    ap.add_argument("--seeds", nargs="+", type=int, default=None, help="List of random seeds to run in parallel")
    ap.add_argument("-n", "--max-examples", type=int, default=500, help="Max examples per campaign")
    ap.add_argument("-w", "--workers", type=int, default=None, help="Max parallel worker threads")
    ap.add_argument("-o", "--out", default=None, help="Base output directory")
    ap.add_argument("--mode", choices=("survey", "hunt"), default="survey")
    ap.add_argument("--adaptive-batch", action="store_true", help="Enable adaptive batch sizes")
    args = ap.parse_args()

    base_out = Path(args.out) if args.out else REPO_ROOT / "runs" / f"parallel-{int(time.time())}"

    if args.targets:
        print(f"Running parallel targets: {args.targets} with strategy '{args.strategy}'...")
        summary = run_parallel_targets(
            strategy=args.strategy,
            targets=args.targets,
            max_examples=args.max_examples,
            base_out_dir=base_out,
            max_workers=args.workers,
            mode=args.mode,
            adaptive_batch=args.adaptive_batch,
        )
    elif args.strategies:
        print(f"Running parallel strategies: {args.strategies} on target '{args.target}'...")
        summary = run_parallel_strategies(
            strategies=args.strategies,
            target=args.target,
            max_examples=args.max_examples,
            base_out_dir=base_out,
            max_workers=args.workers,
            mode=args.mode,
            adaptive_batch=args.adaptive_batch,
        )
    elif args.seeds:
        print(f"Running parallel trials with seeds: {args.seeds} on '{args.strategy}/{args.target}'...")
        summary = run_parallel_seeds(
            strategy=args.strategy,
            target=args.target,
            seeds=args.seeds,
            max_examples=args.max_examples,
            base_out_dir=base_out,
            max_workers=args.workers,
            mode=args.mode,
        )
    else:
        # Default parallel demo: run mxml, json, http concurrently
        demo_targets = ["mxml", "json", "http"]
        print(f"Running default parallel target suite: {demo_targets}...")
        summary = run_parallel_targets(
            strategy=args.strategy,
            targets=demo_targets,
            max_examples=args.max_examples,
            base_out_dir=base_out,
            max_workers=args.workers,
            mode=args.mode,
            adaptive_batch=args.adaptive_batch,
        )

    print("\n=== Parallel Execution Summary ===")
    print(f"Campaigns  : {summary.completed_campaigns}/{summary.total_campaigns} completed ({summary.failed_campaigns} failed)")
    print(f"Total time : {summary.total_wall_clock_s:.2f}s")
    print(f"Examples   : {summary.total_examples} ({summary.throughput_eps:.1f} ex/s)")
    print(f"Crashes    : {summary.total_crashes} ({summary.unique_crashes} unique across all campaigns)")
    print("\nCampaign Breakdown:")
    for name, s in summary.campaigns.items():
        print(f"  {name:<30} accept={s.get('acceptance_rate', 0):.1%} crashes={s.get('crash_count', 0)} in {s.get('wall_clock_s', 0):.2f}s")
    if summary.failures:
        print("\nFailures:")
        for name, err in summary.failures.items():
            print(f"  {name}: {err}")
    print(f"\nArtifacts saved to: {base_out}")


if __name__ == "__main__":
    main()
