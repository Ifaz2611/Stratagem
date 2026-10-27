# Developer Experience

This page covers the tooling added to make Stratagem's agent loop easier to
test, observe, debug and integrate. None of it changes a run's LLM call
sequence, so recorded transcripts remain valid.

## Test suite

The agent suite is hermetic. It uses test doubles for the LLM backend and the
campaign runner, and every run artifact is written to a temporary directory.
No harness, credentials or network access is needed.

```bash
pip install -r requirements-dev.txt
python -m pytest agent -q

# Coverage for the agent package
python -m pytest agent -q --cov=agent --cov-report=term-missing
```

`agent/test_loop.py` covers the loop's decisions, not just its happy path:

- budget accounting and the pre-call overrun guard
- flag validation, including resume bounds and progress modes
- seed/refine prompt construction
- transcript recording, iteration attribution and resume restoration
- strategy acquisition: first pass, repair, truncation resend, budget stop
- campaign repair after a gate pass
- end-to-end runs, early stops, ensemble voting, cache reuse and debug events

`agent/test_dx.py` covers error formatting, stage-specific hints, JSONL debug
logs, run diagnosis, the debug CLI, progress bars and status lines.

Both files also run without pytest:

```bash
python -m agent.test_loop
python -m agent.test_dx
```

The existing self-check suites remain useful because they cover the measurement
layer, which the loop consumes:

```bash
python -m agent.selftest
python -m fuzzer.selftest
```

### What is not in the hermetic suite

Campaign tests that execute the sanitizer harness are integration tests. They
need the pinned target and a built binary, so they run in the CI replay job or
under `scripts/ci.py --replay`, not in the unit job.

## Debugging a run

Every LLM call already records `system.md`, `user.md`, `meta.json` and, when it
completes, `response.json` under `runs/<id>/transcript/call-N/`. The debugger
turns that layout into commands:

```bash
# One-line health summary plus artifact findings
python -m agent.debug --run-id loop --diagnose

# Every recorded call, with iteration, time, cost and status
python -m agent.debug --run-id loop --transcript

# One prompt and response (add --full to stop truncating)
python -m agent.debug --run-id loop --call 3 --full

# Metrics and strategy for one iteration
python -m agent.debug --run-id loop --iteration 2

# Structured events written when the loop ran with --debug
python -m agent.debug --run-id loop --events

# Machine-readable output for scripts
python -m agent.debug --run-id loop --diagnose --json
```

`--diagnose` checks for incomplete iterations, missing `summary.json` or
`results.jsonl`, failed transcript calls, a missing harness, an exhausted budget
and an early stop. It exits non-zero when it finds an error, so CI can use it as
a gate.

### Enabling the event log

```bash
python -m agent.loop --backend replay --run-id demo --debug
```

This writes `runs/demo/debug.jsonl`, one JSON object per event: run start,
each LLM call, gate outcomes, budget stops, campaign failures and run finish.
The file is append-only and flushed per event, so it survives a killed process.
Credentials are scrubbed before anything is written.

### Better error output

Loop failures now print a hint and the context needed to act on it:

```
LLMError: transcript exhausted after 5 calls
  hint: The loop asked for more calls than the transcript holds, which means
        the code changed since it was recorded.
  context:
    run_id: demo
    backend: replay
    target: mxml
  debug: re-run with --debug ... for details
```

Validation failures print the stage-specific next step automatically, for
example pointing at `--call N` for syntax errors or at `fuzzer.campaign` for a
smoke-batch rejection.

## Progress and status

Progress goes to **stderr**, so stdout stays parseable. Rendering is automatic
only when stderr is a terminal. In CI it is silent unless forced.

```bash
# Auto: bars on a TTY, silent in logs
python -m agent.loop --backend openai --run-id demo

# Force bars even in a log: milestone lines, no control characters
python -m agent.loop --backend openai --run-id demo --progress on

# Keep status lines but suppress the bar
python -m agent.loop --backend openai --run-id demo --progress off --status on

# Campaigns have the same flag
python -m fuzzer.campaign baseline --target mxml --progress on
```

The loop shows an iteration bar plus `[status]` lines for LLM calls, phase,
cost and the acceptance/production/crash result of each iteration. A campaign
shows an input bar with live crash and timeout counts. Set
`STRATAGEM_NO_PROGRESS=1` to disable automatic output for a whole environment.

## CI/CD

`.github/workflows/ci.yml` runs three jobs:

| Job | What it does |
|---|---|
| `unit` | Python 3.10/3.11/3.12 matrix: compile check, agent tests with coverage, agent and fuzzer self-checks |
| `replay` | Fetches the pinned target, builds the ASan/UBSan harness, replays the recorded `loop` transcript and verifies every completed strategy is byte-identical |
| `docker` | Builds the container on branch pushes and smoke-tests a one-iteration replay plus `agent.debug --diagnose` |

The same checks run locally through one entry point:

```bash
# Unit only (default); safe on any OS
python scripts/ci.py --unit --cov

# Unit plus the harness replay smoke test (Linux/macOS/WSL/Docker)
python scripts/ci.py --full

# Replay a different recording with a smaller example budget
python scripts/ci.py --replay --run-id loop --iterations 5 --examples 10

# Keep the scratch replay run for inspection
python scripts/ci.py --replay --keep
```

`scripts/ci.py` exits non-zero on failure and prints a JSON summary with
`--json`:

```json
{
  "ok": true,
  "steps": [
    {"name": "compile", "ok": true, "duration_s": 0.27},
    {"name": "agent tests", "ok": true, "duration_s": 3.71}
  ],
  "duration_s": 7.91
}
```

On Windows, run the replay job inside WSL2 or Docker; the ASan binary is a
POSIX executable. The unit job works natively.

## Adding a test

Place hermetic tests in `agent/test_*.py` and use plain `assert`/helper style so
they run under pytest and as a module. Patch `agent.loop.Campaign` rather than
executing the harness, and point `agent.loop.REPO_ROOT` at a temporary
directory if the test writes run artifacts. See `agent/test_loop.py` for the
reusable `loop_env()` helper.
