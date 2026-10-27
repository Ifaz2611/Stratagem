"""Filesystem-coordinated distributed fuzzing.

Local parallelism (``fuzzer.parallel``) shares one machine's CPU. This module
shards a campaign across processes or machines that share a directory, using
only stdlib primitives:

  * the planner writes one deterministic task per shard under ``tasks/``;
  * a worker claims a task by creating ``claims/<id>.json`` with ``O_EXCL``.
    That is atomic on local filesystems and on NFS/SMB mounts that honour
    exclusive create, so two workers cannot run the same shard;
  * a completed shard atomically publishes ``done/<id>.json`` containing the
    campaign summary; failures publish ``failed/<id>.json``;
  * ``merge`` aggregates shard summaries and corpora into one result;
  * a claim older than its lease is reclaimed, so a crashed worker does not
    strand a shard forever.

Sharding is deterministic. Each shard gets ``base_seed + shard_index``, so a
plan can be reproduced exactly and shards do not duplicate Hypothesis draws.
The work directory can be an NFS mount, a Docker volume, or a synchronized
folder; there is no server to run and no new dependency to install.

Example::

    python -m fuzzer.distributed plan --workdir runs/dist \\
        --strategy baseline --target mxml --examples 2000 --shards 4

    # on four machines, all pointed at the same workdir:
    python -m fuzzer.distributed work --workdir runs/dist --worker-id box-1

    python -m fuzzer.distributed merge --workdir runs/dist
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import socket
import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from fuzzer import triage
from fuzzer.campaign import (
    MAX_EXAMPLES_PER_ITERATION,
    MAX_WALL_CLOCK_S,
    Campaign,
)
from fuzzer.corpus import CORPUS_NAME, CorpusManager
from fuzzer.runner import DEFAULT_HARNESS, DEFAULT_SLOW_THRESHOLD_S, PER_RUN_TIMEOUT_S

PLAN_NAME = "plan.json"
SUMMARY_NAME = "distributed_summary.json"
MERGED_CORPUS_NAME = "merged_corpus.jsonl.gz"
PLAN_VERSION = 1
TASKS_DIR = "tasks"
CLAIMS_DIR = "claims"
DONE_DIR = "done"
FAILED_DIR = "failed"


def _atomic_write(path: Path, text: str) -> None:
    """Write a file without exposing a partially written JSON document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(
        f".{path.name}.{os.getpid()}.{time.monotonic_ns()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-._")
    return cleaned or "task"


def _split(total: int, parts: int) -> list[int]:
    if parts < 1:
        raise ValueError("shards must be >= 1")
    if total < 1:
        raise ValueError("examples must be >= 1")
    base, remainder = divmod(total, parts)
    return [base + (1 if i < remainder else 0) for i in range(parts)]


@dataclass
class ShardTask:
    """One reproducible slice of one strategy/target campaign."""

    task_id: str
    strategy: str
    target: str = "mxml"
    examples: int = 500
    seed: int | None = 0
    mode: str = "survey"
    out_dir: str = ""
    timeout_s: float = PER_RUN_TIMEOUT_S
    slow_threshold_s: float = DEFAULT_SLOW_THRESHOLD_S
    extra_args: tuple[str, ...] = ()
    checkpoint_interval: int = 50
    adaptive_batch: bool = False
    use_result_cache: bool = False
    max_corpus_entries: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "strategy": self.strategy,
            "target": self.target,
            "examples": self.examples,
            "seed": self.seed,
            "mode": self.mode,
            "out_dir": self.out_dir,
            "timeout_s": self.timeout_s,
            "slow_threshold_s": self.slow_threshold_s,
            "extra_args": list(self.extra_args),
            "checkpoint_interval": self.checkpoint_interval,
            "adaptive_batch": self.adaptive_batch,
            "use_result_cache": self.use_result_cache,
            "max_corpus_entries": self.max_corpus_entries,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ShardTask":
        values = dict(data)
        values["extra_args"] = tuple(values.get("extra_args") or ())
        return cls(**values)

    def to_campaign(self, work_dir: Path | str) -> Campaign:
        """Build the campaign this shard describes."""
        work_path = Path(work_dir)
        out = Path(self.out_dir)
        if not out.is_absolute():
            out = work_path / out
        return Campaign(
            strategy_name=self.strategy,
            max_examples=self.examples,
            out_dir=out,
            harness=DEFAULT_HARNESS,
            mode=self.mode,
            extra_args=self.extra_args,
            random_seed=self.seed,
            wall_clock_cap_s=MAX_WALL_CLOCK_S,
            target=self.target,
            timeout_s=self.timeout_s,
            slow_threshold_s=self.slow_threshold_s,
            checkpoint_interval=self.checkpoint_interval,
            adaptive_batch=self.adaptive_batch,
            use_result_cache=self.use_result_cache,
            result_cache_dir=(work_path / ".result_cache"
                              if self.use_result_cache else None),
            max_corpus_entries=self.max_corpus_entries,
        )


@dataclass
class DistributedPlan:
    """The persisted list of shards for one distributed run."""

    work_dir: Path
    tasks: list[ShardTask] = field(default_factory=list)
    created: float = field(default_factory=time.time)
    version: int = PLAN_VERSION
    config: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "created": self.created,
            "config": self.config,
            "tasks": [t.to_dict() for t in self.tasks],
        }

    def save(self) -> Path:
        path = self.work_dir / PLAN_NAME
        _atomic_write(path, json.dumps(self.to_dict(), indent=2))
        for task in self.tasks:
            _atomic_write(
                self.task_path(task),
                json.dumps(task.to_dict(), indent=2),
            )
        return path

    @classmethod
    def load(cls, work_dir: Path | str) -> "DistributedPlan":
        root = Path(work_dir)
        path = root / PLAN_NAME
        if not path.exists():
            raise FileNotFoundError(f"no distributed plan at {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("version") != PLAN_VERSION:
            raise ValueError(
                f"unsupported plan version {data.get('version')!r}; "
                f"expected {PLAN_VERSION}")
        return cls(
            work_dir=root,
            tasks=[ShardTask.from_dict(t) for t in data.get("tasks", [])],
            created=float(data.get("created", 0.0)),
            version=PLAN_VERSION,
            config=dict(data.get("config") or {}),
        )

    # ----------------------------------------------------------------- paths
    def task_path(self, task: ShardTask) -> Path:
        return self.work_dir / TASKS_DIR / f"{task.task_id}.json"

    def claim_path(self, task: ShardTask) -> Path:
        return self.work_dir / CLAIMS_DIR / f"{task.task_id}.json"

    def done_path(self, task: ShardTask) -> Path:
        return self.work_dir / DONE_DIR / f"{task.task_id}.json"

    def failed_path(self, task: ShardTask) -> Path:
        return self.work_dir / FAILED_DIR / f"{task.task_id}.json"

    # ----------------------------------------------------------------- status
    def status(self, *, lease_s: float = 6 * 3600.0) -> dict[str, Any]:
        now = time.time()
        done: list[str] = []
        failed: list[str] = []
        pending: list[str] = []
        claimed: list[dict[str, Any]] = []
        for task in self.tasks:
            if self.done_path(task).exists():
                done.append(task.task_id)
            elif self.failed_path(task).exists():
                failed.append(task.task_id)
            else:
                claim = self.claim_path(task)
                if claim.exists():
                    meta = _read_json(claim)
                    if meta and "claimed_at" in meta:
                        try:
                            claimed_at = float(meta["claimed_at"])
                        except (ValueError, TypeError):
                            claimed_at = 0.0
                    else:
                        try:
                            claimed_at = claim.stat().st_mtime
                        except OSError:
                            claimed_at = now
                    stale = (lease_s is not None
                             and claimed_at > 0.0
                             and now - claimed_at > float(lease_s))
                    claimed.append({
                        "task_id": task.task_id,
                        "worker_id": meta.get("worker_id") if meta else None,
                        "pid": meta.get("pid") if meta else None,
                        "claimed_at": claimed_at,
                        "stale": stale,
                    })
                else:
                    pending.append(task.task_id)
        complete = len(done) + len(failed) == len(self.tasks)
        return {
            "work_dir": str(self.work_dir),
            "total": len(self.tasks),
            "done": len(done),
            "failed": len(failed),
            "claimed": len(claimed),
            "pending": len(pending),
            "complete": complete,
            "done_tasks": done,
            "failed_tasks": failed,
            "pending_tasks": pending,
            "claims": claimed,
        }


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError, UnicodeDecodeError):
        return None


def plan_shards(
    work_dir: Path | str,
    *,
    strategies: Iterable[str],
    targets: Iterable[str],
    examples: int = 500,
    shards: int = 4,
    seed: int | None = 0,
    mode: str = "survey",
    timeout_s: float = PER_RUN_TIMEOUT_S,
    slow_threshold_s: float = DEFAULT_SLOW_THRESHOLD_S,
    extra_args: Iterable[str] = (),
    adaptive_batch: bool = False,
    use_result_cache: bool = False,
    max_corpus_entries: int | None = None,
    force: bool = False,
) -> DistributedPlan:
    """Create a deterministic shard plan for every strategy/target pair."""
    root = Path(work_dir)
    plan_path = root / PLAN_NAME
    if plan_path.exists() and not force:
        raise FileExistsError(
            f"{plan_path} already exists; use force=True to replace it")
    strategy_list = list(dict.fromkeys(strategies))
    target_list = list(dict.fromkeys(targets))
    if not strategy_list or not target_list:
        raise ValueError("at least one strategy and one target are required")

    sizes = _split(examples, shards)
    if max(sizes) > MAX_EXAMPLES_PER_ITERATION:
        raise ValueError(
            f"each shard must be <= {MAX_EXAMPLES_PER_ITERATION} examples; "
            f"{examples} examples over {shards} shards gives {max(sizes)}")
    base_seed = 0 if seed is None else int(seed)
    tasks: list[ShardTask] = []
    for strategy in strategy_list:
        for target in target_list:
            for index, size in enumerate(sizes):
                if size <= 0:
                    continue
                task_id = _slug(f"{strategy}-{target}-{mode}") + f"-s{index:03d}"
                tasks.append(ShardTask(
                    task_id=task_id,
                    strategy=strategy,
                    target=target,
                    examples=size,
                    seed=base_seed + index,
                    mode=mode,
                    out_dir=f"shards/{task_id}",
                    timeout_s=timeout_s,
                    slow_threshold_s=slow_threshold_s,
                    extra_args=tuple(str(a) for a in extra_args),
                    adaptive_batch=adaptive_batch,
                    use_result_cache=use_result_cache,
                    max_corpus_entries=max_corpus_entries,
                ))
    plan = DistributedPlan(
        work_dir=root,
        tasks=tasks,
        config={
            "strategies": strategy_list,
            "targets": target_list,
            "examples_per_pair": examples,
            "shards": shards,
            "seed": base_seed,
            "mode": mode,
            "adaptive_batch": adaptive_batch,
            "use_result_cache": use_result_cache,
            "max_corpus_entries": max_corpus_entries,
        },
    )
    plan.save()
    return plan


def _claim_next(
    plan: DistributedPlan,
    worker_id: str,
    *,
    lease_s: float = 6 * 3600.0,
) -> ShardTask | None:
    """Atomically claim the first unfinished shard, reclaiming stale leases."""
    now = time.time()
    for task in sorted(plan.tasks, key=lambda t: t.task_id):
        if plan.done_path(task).exists() or plan.failed_path(task).exists():
            continue
        claim = plan.claim_path(task)
        if claim.exists():
            meta = _read_json(claim)
            if meta and "claimed_at" in meta:
                try:
                    claimed_at = float(meta["claimed_at"])
                except (ValueError, TypeError):
                    claimed_at = 0.0
            else:
                # If the file exists but JSON is not readable yet, it was
                # likely created milliseconds ago by a concurrent worker.
                # Fall back to file modification time.
                try:
                    claimed_at = claim.stat().st_mtime
                except OSError:
                    continue
            if claimed_at <= 0.0 or lease_s is None or now - claimed_at <= float(lease_s):
                continue
            try:
                claim.unlink()
            except OSError:
                continue
        claim.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(str(claim), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except (FileExistsError, OSError):
            continue
        payload = json.dumps({
            "worker_id": worker_id,
            "pid": os.getpid(),
            "claimed_at": now,
        }).encode("utf-8")
        try:
            os.write(fd, payload)
        except OSError:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                claim.unlink()
            except OSError:
                pass
            continue
        else:
            try:
                os.close(fd)
            except OSError:
                pass
        # The shard may have completed between the existence checks and the
        # claim. Do not run it twice.
        if plan.done_path(task).exists() or plan.failed_path(task).exists():
            try:
                claim.unlink()
            except OSError:
                pass
            continue
        return task
    return None


def _release_claim(plan: DistributedPlan, task: ShardTask) -> None:
    try:
        plan.claim_path(task).unlink()
    except OSError:
        pass


def run_worker(
    work_dir: Path | str,
    worker_id: str | None = None,
    *,
    once: bool = False,
    poll_s: float = 2.0,
    lease_s: float = 6 * 3600.0,
    idle_timeout_s: float | None = 300.0,
    max_tasks: int | None = None,
    campaign_factory: Callable[[ShardTask, Path], Any] | None = None,
    on_task: Callable[[ShardTask, dict | None, BaseException | None], None] | None = None,
) -> dict[str, Any]:
    """Claim and run shards until the plan is complete or the worker idles out.

    ``campaign_factory`` exists so tests (and embedders) can run a shard
    without constructing a harness-backed Campaign. It receives the task and
    the shared work directory.
    """
    root = Path(work_dir)
    plan = DistributedPlan.load(root)
    worker = worker_id or f"{socket.gethostname()}-{os.getpid()}"
    stats: dict[str, Any] = {
        "worker_id": worker,
        "completed": 0,
        "failed": 0,
        "idle_polls": 0,
        "tasks": [],
        "started": time.time(),
        "finished": None,
    }
    idle_since = time.monotonic()
    while True:
        task = _claim_next(plan, worker, lease_s=lease_s)
        if task is None:
            if once:
                break
            current = plan.status(lease_s=lease_s)
            if current["complete"]:
                break
            stats["idle_polls"] += 1
            if (idle_timeout_s is not None
                    and time.monotonic() - idle_since >= idle_timeout_s):
                break
            time.sleep(max(0.01, poll_s))
            continue

        idle_since = time.monotonic()
        started = time.monotonic()
        summary: dict | None = None
        error: BaseException | None = None
        try:
            campaign = (campaign_factory(task, root) if campaign_factory
                        else task.to_campaign(root))
            summary = campaign.run()
            _atomic_write(
                plan.done_path(task),
                json.dumps({
                    "task": task.to_dict(),
                    "worker_id": worker,
                    "pid": os.getpid(),
                    "finished_at": time.time(),
                    "wall_clock_s": round(time.monotonic() - started, 3),
                    "summary": summary,
                }, indent=2),
            )
            stats["completed"] += 1
            stats["tasks"].append({"task_id": task.task_id, "status": "done"})
        except Exception as exc:  # keep the worker alive after one bad shard
            error = exc
            _atomic_write(
                plan.failed_path(task),
                json.dumps({
                    "task": task.to_dict(),
                    "worker_id": worker,
                    "pid": os.getpid(),
                    "finished_at": time.time(),
                    "error": f"{type(exc).__name__}: {exc}",
                    "traceback": traceback.format_exc(),
                }, indent=2),
            )
            stats["failed"] += 1
            stats["tasks"].append({
                "task_id": task.task_id,
                "status": "failed",
                "error": f"{type(exc).__name__}: {exc}",
            })
        finally:
            _release_claim(plan, task)

        if on_task is not None:
            on_task(task, summary, error)
        if once:
            break
        if max_tasks is not None and stats["completed"] + stats["failed"] >= max_tasks:
            break

    stats["finished"] = time.time()
    stats["status"] = plan.status(lease_s=lease_s)
    return stats


def run_local(
    work_dir: Path | str,
    *,
    workers: int = 2,
    poll_s: float = 0.05,
    lease_s: float = 6 * 3600.0,
    idle_timeout_s: float = 30.0,
    campaign_factory: Callable[[ShardTask, Path], Any] | None = None,
) -> dict[str, Any]:
    """Run several workers in one process, useful as a single-machine demo."""
    if workers < 1:
        raise ValueError("workers must be >= 1")
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(
                run_worker,
                work_dir,
                f"local-{i}",
                once=False,
                poll_s=poll_s,
                lease_s=lease_s,
                idle_timeout_s=idle_timeout_s,
                campaign_factory=campaign_factory,
            )
            for i in range(workers)
        ]
        results = [f.result() for f in futures]
    return {
        "workers": results,
        "completed": sum(r["completed"] for r in results),
        "failed": sum(r["failed"] for r in results),
        "wall_clock_s": round(time.monotonic() - started, 3),
    }


def _collect_crash_records(summaries: Iterable[dict[str, Any]]) -> list[dict]:
    records: list[dict] = []
    for summary in summaries:
        for group in (summary.get("crash_groups") or {}).values():
            for sample in group.get("samples", []):
                records.append({
                    "sha": sample.get("sha", ""),
                    "stderr": sample.get("stderr", ""),
                    "outcome": "crash",
                    "rc": sample.get("rc", -11),
                    "signal": sample.get("signal", ""),
                    "productions": sample.get("productions", []),
                })
    return records


def merge_results(
    work_dir: Path | str,
    *,
    lease_s: float = 6 * 3600.0,
    write: bool = True,
    include_campaigns: bool = True,
    max_corpus_entries: int | None = None,
    merge_corpus: bool = True,
) -> dict[str, Any]:
    """Aggregate completed shard summaries and corpora into one result."""
    root = Path(work_dir)
    plan = DistributedPlan.load(root)
    summaries: dict[str, dict] = {}
    failures: dict[str, str] = {}
    for task in plan.tasks:
        done = plan.done_path(task)
        if done.exists():
            data = _read_json(done)
            if data and isinstance(data.get("summary"), dict):
                summaries[task.task_id] = data["summary"]
        elif plan.failed_path(task).exists():
            data = _read_json(plan.failed_path(task)) or {}
            failures[task.task_id] = str(data.get("error", "unknown failure"))

    outcomes: dict[str, int] = {}
    total_examples = 0
    crash_count = 0
    wall_clock = 0.0
    for summary in summaries.values():
        examples = int(summary.get("examples", 0) or 0)
        total_examples += examples
        crash_count += int(summary.get("crash_count", 0) or 0)
        wall_clock = max(wall_clock, float(summary.get("wall_clock_s", 0.0) or 0.0))
        for outcome, count in (summary.get("outcomes") or {}).items():
            outcomes[outcome] = outcomes.get(outcome, 0) + int(count)
    accepted = outcomes.get("parsed_clean", 0) + outcomes.get("parsed_diag", 0)

    crash_records = _collect_crash_records(summaries.values())
    unique_crash_shas = sorted({
        sample.get("sha", "")
        for summary in summaries.values()
        for group in (summary.get("crash_groups") or {}).values()
        for sample in group.get("samples", [])
        if sample.get("sha")
    })

    merged_corpus: dict[str, Any] | None = None
    if merge_corpus:
        manager = CorpusManager(max_entries=max_corpus_entries)
        imported = 0
        for task in plan.tasks:
            if task.task_id not in summaries:
                continue
            corpus_path = root / task.out_dir / CORPUS_NAME
            if corpus_path.exists():
                imported += manager.import_corpus(corpus_path)
        if imported:
            merged_corpus = manager.export_corpus(root / MERGED_CORPUS_NAME)

    status = plan.status(lease_s=lease_s)
    result: dict[str, Any] = {
        "work_dir": str(root),
        "complete": status["complete"],
        "total_tasks": status["total"],
        "completed_tasks": len(summaries),
        "failed_tasks": len(failures),
        "pending_tasks": status["pending"] + status["claimed"],
        "examples": total_examples,
        "outcomes": outcomes,
        "acceptance_rate": (round(accepted / total_examples, 4)
                            if total_examples else 0.0),
        "crash_count": crash_count,
        "unique_crash_inputs": len(unique_crash_shas),
        "unique_crashes": unique_crash_shas,
        "crash_groups": triage.group(crash_records) if crash_records else {},
        "clusters": [c.to_json() for c in triage.cluster_crashes(crash_records)],
        "triage_summary": triage.triage_summary(crash_records),
        "wall_clock_s": round(wall_clock, 3),
        "throughput_eps": (round(total_examples / wall_clock, 2)
                           if wall_clock > 0 else 0.0),
        "failures": failures,
        "merged_corpus": merged_corpus,
    }
    if include_campaigns:
        result["campaigns"] = summaries
    if write:
        _atomic_write(
            root / SUMMARY_NAME,
            json.dumps(result, indent=2),
        )
    return result


def status(work_dir: Path | str, *, lease_s: float = 6 * 3600.0) -> dict[str, Any]:
    """Report shard counts without loading any campaign summaries."""
    return DistributedPlan.load(work_dir).status(lease_s=lease_s)


# ----------------------------------------------------------------------- CLI
def _add_plan_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--workdir", required=True, help="Shared work directory")
    ap.add_argument("--strategy", default="baseline")
    ap.add_argument("--strategies", nargs="+", default=None,
                    help="Multiple strategies (overrides --strategy)")
    ap.add_argument("--target", default="mxml")
    ap.add_argument("--targets", nargs="+", default=None,
                    help="Multiple targets (overrides --target)")
    ap.add_argument("--examples", type=int, default=500,
                    help="Examples per strategy/target pair")
    ap.add_argument("--shards", type=int, default=4)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--mode", choices=("survey", "hunt"), default="survey")
    ap.add_argument("--adaptive-batch", action="store_true")
    ap.add_argument("--cache-results", action="store_true")
    ap.add_argument("--max-corpus-entries", type=int, default=None)
    ap.add_argument("--timeout", type=float, default=PER_RUN_TIMEOUT_S)
    ap.add_argument("--slow-threshold", type=float,
                    default=DEFAULT_SLOW_THRESHOLD_S)
    ap.add_argument("--force", action="store_true",
                    help="Replace an existing plan")


def _cmd_plan(args: argparse.Namespace) -> int:
    plan = plan_shards(
        args.workdir,
        strategies=args.strategies or [args.strategy],
        targets=args.targets or [args.target],
        examples=args.examples,
        shards=args.shards,
        seed=args.seed,
        mode=args.mode,
        timeout_s=args.timeout,
        slow_threshold_s=args.slow_threshold,
        adaptive_batch=args.adaptive_batch,
        use_result_cache=args.cache_results,
        max_corpus_entries=args.max_corpus_entries,
        force=args.force,
    )
    print(json.dumps({
        "work_dir": str(plan.work_dir),
        "tasks": len(plan.tasks),
        "examples": sum(t.examples for t in plan.tasks),
        "shards": args.shards,
        "seeds": [t.seed for t in plan.tasks],
    }, indent=2))
    return 0


def _cmd_work(args: argparse.Namespace) -> int:
    stats = run_worker(
        args.workdir,
        args.worker_id,
        once=args.once,
        poll_s=args.poll,
        lease_s=args.lease,
        idle_timeout_s=args.idle_timeout,
        max_tasks=args.max_tasks,
    )
    print(json.dumps(stats, indent=2))
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    stats = run_local(
        args.workdir,
        workers=args.workers,
        poll_s=getattr(args, "poll", 0.05),
        lease_s=args.lease,
        idle_timeout_s=args.idle_timeout,
    )
    merged = merge_results(args.workdir, lease_s=args.lease)
    print(json.dumps({"local_run": stats, "merged": merged}, indent=2))
    return 0


def _cmd_merge(args: argparse.Namespace) -> int:
    result = merge_results(
        args.workdir,
        lease_s=args.lease,
        include_campaigns=not args.no_campaigns,
        max_corpus_entries=args.max_corpus_entries,
        merge_corpus=not args.no_corpus,
    )
    print(json.dumps(result, indent=2))
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    print(json.dumps(status(args.workdir, lease_s=args.lease), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m fuzzer.distributed",
        description="Shard campaigns across machines sharing a directory.")
    sub = ap.add_subparsers(dest="command", required=True)

    p_plan = sub.add_parser("plan", help="Create a deterministic shard plan")
    _add_plan_args(p_plan)
    p_plan.set_defaults(func=_cmd_plan)

    p_work = sub.add_parser("work", help="Claim and run shards")
    p_work.add_argument("--workdir", required=True)
    p_work.add_argument("--worker-id", default=None)
    p_work.add_argument("--once", action="store_true",
                        help="Run at most one shard and exit")
    p_work.add_argument("--poll", type=float, default=2.0)
    p_work.add_argument("--lease", type=float, default=6 * 3600.0)
    p_work.add_argument("--idle-timeout", type=float, default=300.0)
    p_work.add_argument("--max-tasks", type=int, default=None)
    p_work.set_defaults(func=_cmd_work)

    p_run = sub.add_parser("run", help="Run local workers until the plan is done")
    p_run.add_argument("--workdir", required=True)
    p_run.add_argument("--workers", type=int, default=2)
    p_run.add_argument("--poll", type=float, default=0.05)
    p_run.add_argument("--lease", type=float, default=6 * 3600.0)
    p_run.add_argument("--idle-timeout", type=float, default=30.0)
    p_run.set_defaults(func=_cmd_run)

    p_merge = sub.add_parser("merge", help="Aggregate completed shards")
    p_merge.add_argument("--workdir", required=True)
    p_merge.add_argument("--lease", type=float, default=6 * 3600.0)
    p_merge.add_argument("--no-campaigns", action="store_true")
    p_merge.add_argument("--no-corpus", action="store_true")
    p_merge.add_argument("--max-corpus-entries", type=int, default=None)
    p_merge.set_defaults(func=_cmd_merge)

    p_status = sub.add_parser("status", help="Show shard progress")
    p_status.add_argument("--workdir", required=True)
    p_status.add_argument("--lease", type=float, default=6 * 3600.0)
    p_status.set_defaults(func=_cmd_status)

    args = ap.parse_args(argv)
    try:
        return int(args.func(args))
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
