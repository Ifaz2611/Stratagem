"""Command-line debugging tools for Stratagem runs.

Every run already records enough to reconstruct a failure: the prompt, the
response, the validation verdict, the campaign summary and the measurement.
This command surfaces those artifacts without asking a reader to remember the
directory layout.

Usage::

    python -m agent.debug --list
    python -m agent.debug --run-id loop
    python -m agent.debug --run-id loop --diagnose
    python -m agent.debug --run-id loop --transcript
    python -m agent.debug --run-id loop --call 3 --full
    python -m agent.debug --run-id loop --iteration 2
    python -m agent.debug --run-id loop --events
    python -m agent.debug --run-id loop --diagnose --json

All commands are read-only. Add ``--json`` for machine-readable output.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from agent.errors import (REPO_ROOT, RunDiagnostics, format_exception,
                          list_runs)


def _runs_root(value: str | None) -> Path:
    return Path(value).expanduser() if value else REPO_ROOT / "runs"


def _run_dir(root: Path, run_id: str) -> Path:
    return root / run_id


def _file_text(path: Path, *, full: bool, head: int = 120,
               tail: int = 40) -> str:
    text = path.read_text(encoding="utf-8", errors="replace")
    if full:
        return text
    lines = text.splitlines()
    if len(lines) <= head + tail:
        return "\n".join(lines)
    return "\n".join(lines[:head] + [
        f"... ({len(lines) - head - tail} lines omitted; use --full) ..."
    ] + lines[-tail:])


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def _truncate_text(text: str, *, full: bool, head: int = 120,
                   tail: int = 40) -> str:
    if full:
        return text
    lines = text.splitlines()
    if len(lines) <= head + tail:
        return text
    return "\n".join(lines[:head] + [
        f"... ({len(lines) - head - tail} lines omitted; use --full) ..."
    ] + lines[-tail:])


def cmd_list(args: argparse.Namespace) -> int:
    root = _runs_root(args.root)
    rows = list_runs(root)
    if args.json:
        _print_json(rows)
        return 0
    if not rows:
        print(f"no runs under {root}")
        return 0
    print(f"{'run id':32} {'iters':>5} {'done':>5} {'summary':>7}")
    print("-" * 55)
    for row in rows:
        print(f"{row['run_id'][:32]:32} {row['iterations']:>5} "
              f"{row['complete_iterations']:>5} "
              f"{'yes' if row['has_summary'] else 'no':>7}")
    return 0


def cmd_summary(args: argparse.Namespace) -> int:
    diag = RunDiagnostics(_runs_root(args.root), args.run_id)
    data = diag.scan()
    if args.json:
        _print_json(diag.to_json(data))
        return 0
    print(diag.render(data))
    return 0


def cmd_transcript(args: argparse.Namespace) -> int:
    diag = RunDiagnostics(_runs_root(args.root), args.run_id)
    data = diag.scan()
    rows = data.get("transcript", {}).get("call_rows", [])
    if args.json:
        _print_json(rows)
        return 0
    if not rows:
        print(f"no transcript calls under {diag.run_dir / 'transcript'}")
        return 1
    print(f"{'call':>5} {'iter':>4} {'tag':22} {'time':>7} {'cost':>9} {'backend':10} status")
    print("-" * 84)
    for row in rows:
        elapsed = row.get("elapsed_s")
        cost = row.get("cost_usd")
        print(f"{row['call']:>5} {str(row.get('iteration') or '-'):>4} "
              f"{(row.get('tag') or '')[:22]:22} "
              f"{f'{elapsed:.1f}s' if isinstance(elapsed, (int, float)) else '-':>7} "
              f"{f'${cost:.4f}' if isinstance(cost, (int, float)) else '-':>9} "
              f"{str(row.get('backend') or '-'):10} "
              f"{'ok' if row.get('ok') else 'FAILED'}")
    return 0


def cmd_call(args: argparse.Namespace) -> int:
    run_dir = _run_dir(_runs_root(args.root), args.run_id)
    call_dir = run_dir / "transcript" / f"call-{args.call}"
    if not call_dir.exists():
        print(f"no call directory at {call_dir}", file=sys.stderr)
        return 2
    payload: dict[str, Any] = {"call": args.call, "path": str(call_dir)}
    for name in ("meta.json", "response.json"):
        f = call_dir / name
        if f.exists():
            try:
                payload[name[:-5]] = json.loads(f.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                payload[name[:-5]] = {"error": str(exc)}
    for name in ("system.md", "user.md"):
        f = call_dir / name
        if f.exists():
            payload[name[:-3]] = _file_text(f, full=args.full,
                                            head=80, tail=20)
    if args.json:
        _print_json(payload)
        return 0
    meta = payload.get("meta") or {}
    print(f"call {args.call}  tag={meta.get('tag', '?')}  "
          f"iteration={meta.get('iteration', '?')}")
    print(f"directory: {call_dir}")
    if "response" in payload:
        resp = payload["response"]
        print(f"backend={resp.get('backend')} model={resp.get('model')} "
              f"elapsed={resp.get('elapsed_s')}s cost=${resp.get('cost_usd')}")
        print("\n--- response text ---")
        print(_truncate_text(str(resp.get("text", "")), full=args.full,
                             head=100, tail=30))
    else:
        print("\nNo response.json: this call never completed. The prompt is "
              "still recorded below.")
    for name in ("user", "system"):
        if name in payload:
            print(f"\n--- {name} prompt ---")
            print(payload[name])
    return 0


def cmd_iteration(args: argparse.Namespace) -> int:
    diag = RunDiagnostics(_runs_root(args.root), args.run_id)
    it_dir = diag.run_dir / "iterations" / f"iter-{args.iteration}"
    if not it_dir.exists():
        print(f"no iteration directory at {it_dir}", file=sys.stderr)
        return 2
    payload: dict[str, Any] = {"iteration": args.iteration, "path": str(it_dir)}
    summary: dict | None = None
    summary_file = it_dir / "summary.json"
    if summary_file.exists():
        try:
            summary = json.loads(summary_file.read_text(encoding="utf-8"))
            payload["summary"] = summary
        except json.JSONDecodeError as exc:
            payload["summary_error"] = str(exc)
    for name in ("strategy.py", "ensemble.json", "cache_hit.json",
                 "few_shot.md", "checkpoint.json"):
        f = it_dir / name
        if f.exists():
            payload[name] = _file_text(f, full=args.full, head=100, tail=30)
    results = it_dir / "results.jsonl"
    if results.exists():
        rows = []
        for line in results.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        outcomes: dict[str, int] = {}
        for row in rows:
            outcomes[row.get("outcome", "?")] = outcomes.get(
                row.get("outcome", "?"), 0) + 1
        payload["results"] = {"count": len(rows), "outcomes": outcomes}
    if args.json:
        _print_json(payload)
        return 0
    print(f"iter-{args.iteration}: {it_dir}")
    if summary:
        st = summary.get("structure", {})
        print(f"  acceptance  : {summary.get('acceptance_rate', 0):.1%}")
        print(f"  productions : {st.get('productions_hit', '?')}/"
              f"{st.get('productions_total', '?')}")
        print(f"  max depth   : {st.get('max_depth_seen', '?')}")
        print(f"  diagnostics : {summary.get('distinct_diagnostic_templates', '?')}")
        print(f"  crashes     : {summary.get('crash_count', '?')}")
        print(f"  examples    : {summary.get('examples', '?')} in "
              f"{summary.get('wall_clock_s', '?')}s")
    elif "summary_error" in payload:
        print(f"  summary.json is corrupt: {payload['summary_error']}")
    if "results" in payload:
        print(f"  outcomes    : {payload['results']['outcomes']}")
    for name in ("ensemble.json", "cache_hit.json"):
        if name in payload:
            print(f"\n--- {name} ---")
            print(payload[name])
    if "strategy.py" in payload:
        print("\n--- strategy.py ---")
        print(payload["strategy.py"])
    return 0


def cmd_events(args: argparse.Namespace) -> int:
    from agent.errors import DebugLog
    diag = RunDiagnostics(_runs_root(args.root), args.run_id)
    events = DebugLog(diag.run_dir / "debug.jsonl").read(
        limit=args.limit or None)
    if args.json:
        _print_json(events)
        return 0
    if not events:
        print("no debug events recorded (run the loop with --debug)")
        return 0
    for event in events:
        ts = str(event.get("ts", ""))[11:23]
        name = event.get("event", "?")
        rest = " ".join(
            f"{k}={v}" for k, v in event.items() if k not in ("ts", "event")
        )
        print(f"{ts} {name:24} {rest}")
    return 0


def cmd_diagnose(args: argparse.Namespace) -> int:
    root = _runs_root(args.root)
    if args.run_id:
        diag = RunDiagnostics(root, args.run_id)
        data = diag.scan()
        if args.json:
            _print_json(diag.to_json(data))
        else:
            print(diag.render(data))
        errors = [f for f in data.get("findings", []) if f["level"] == "error"]
        return 1 if errors else 0

    rows = list_runs(root)
    broken = 0
    for row in rows:
        diag = RunDiagnostics(root, row["run_id"])
        data = diag.scan()
        errors = [f for f in data.get("findings", []) if f["level"] == "error"]
        if errors:
            broken += 1
            print(f"{row['run_id']}: {len(errors)} error(s)")
            for finding in errors:
                print(f"  - {finding['message']}")
    if not rows:
        print(f"no runs under {root}")
    elif not broken:
        print(f"checked {len(rows)} run(s): no errors")
    return 1 if broken else 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="python -m agent.debug",
        description="Inspect a Stratagem run without re-running it.")
    ap.add_argument("--root", default=None,
                    help="runs directory (default: <repo>/runs)")
    ap.add_argument("--run-id", default="loop",
                    help="run to inspect (default: loop)")
    ap.add_argument("--list", action="store_true",
                    help="list runs and exit")
    ap.add_argument("--diagnose", action="store_true",
                    help="scan artifacts and report problems")
    ap.add_argument("--transcript", action="store_true",
                    help="table of recorded LLM calls")
    ap.add_argument("--call", type=int, default=None, metavar="N",
                    help="show prompt and response for call N")
    ap.add_argument("--iteration", type=int, default=None, metavar="N",
                    help="show artifacts and metrics for iteration N")
    ap.add_argument("--events", action="store_true",
                    help="show the JSONL debug event log")
    ap.add_argument("--limit", type=int, default=50,
                    help="maximum events for --events (default: 50)")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable output")
    ap.add_argument("--full", action="store_true",
                    help="do not truncate long prompts, responses or strategies")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.list:
            return cmd_list(args)
        if args.transcript:
            return cmd_transcript(args)
        if args.call is not None:
            return cmd_call(args)
        if args.iteration is not None:
            return cmd_iteration(args)
        if args.events:
            return cmd_events(args)
        if args.diagnose:
            return cmd_diagnose(args)
        # Default: summary, then a diagnosis if anything is wrong. This is what
        # a reader gets from the command they are most likely to guess.
        diag = RunDiagnostics(_runs_root(args.root), args.run_id)
        data = diag.scan()
        if args.json:
            _print_json(diag.to_json(data))
        else:
            print(diag.render(data))
        return 0
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        print(format_exception(exc, debug=args.full), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
