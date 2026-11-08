# Getting Started with Stratagem

This guide explains what Stratagem is, how to install it, how to run fuzzing
campaigns, and how the agent's learning loop works.

## Table of Contents

1. [What Is This Project?](#what-is-this-project)
2. [How It Works](#how-it-works)
3. [System Requirements](#system-requirements)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Building the Harness](#building-the-harness)
7. [Running Your First Campaign](#running-your-first-campaign)
8. [How the Agent "Trains"](#how-the-agent-trains)
9. [Using the Results](#using-the-results)
10. [Advanced Usage](#advanced-usage)
11. [Developer Tools](#developer-tools)
12. [Troubleshooting](#troubleshooting)

---

## What Is This Project?

**Stratagem** is an *agentic grammar fuzzing framework*. Instead of a
traditional fuzzer that blindly mutates bytes, Stratagem uses a
Large Language Model (LLM) as the driving intelligence:

1. The LLM writes a **Python test strategy** (a Hypothesis generator) that
   produces test inputs based on a formal grammar.
2. The strategy is **validated** and run against a real, sanitizer-instrumented
   parser — currently Mini-XML (mxml) v4.0.4, plus libxml2, Expat, TinyXML-2,
   JSON, HTTP, DNS, and SMTP targets.
3. The results (acceptance rate, error diversity, grammar coverage, crashes)
   are fed back to the LLM.
4. The LLM **refines** the strategy, and the cycle repeats.

Over several iterations the agent learns to generate inputs that are more
interesting to the parser: well-formed documents, near-miss documents that
almost parse, and byte-hostile inputs that stress encodings and error paths.

It is **blackbox** by design — the agent never sees code coverage inside the
parser, only the parser's observable behavior (diagnostics, exit codes, crash
signals). This keeps the feedback loop clean and reproducible.

### What it can find

- Memory-safety crashes (ASan/UBSan aborts) in the target parser
- Logic bugs and parser inconsistencies (checked differentially against
  Expat, libxml2, TinyXML-2)
- Coverage gaps in the grammar (which productions the parser never reaches)
- Unique error-message paths worth investigating

Historical campaigns over ~10,000 inputs found a real upstream bug (non-ASCII
error-message corruption, fixed in PR #357) and reproduced a known memory leak
— see `docs/findings.md`.

### Project layout

```
.
├── agent/           # The agentic loop and LLM backends
│   ├── loop.py      # Main generate → validate → run → refine cycle
│   ├── llm.py       # LLM backends: cli, openai, replay
│   ├── validate.py  # 4-gate strategy validation
│   ├── ensemble.py  # Multi-model candidate voting
│   ├── strategy_cache.py  # Reuse strategies across similar targets
│   ├── tuning.py    # Automatic hyperparameter adaptation
│   ├── fewshot.py   # Inject past winning strategies into prompts
│   ├── prompts/     # Prompt templates, versions v1–v5
│   └── ...
├── fuzzer/          # The fuzzing engine
│   ├── campaign.py  # Run a strategy through the harness
│   ├── runner.py    # Execute harness, classify outcomes
│   ├── strategies/  # LLM-generated strategies land here
│   └── targets/     # Target abstraction (mxml, json, http, dns, smtp, ...)
├── grammar/         # ANTLR grammars (XML, JSON, HTTP, SMTP)
├── harness/         # C harness compiled with ASan/UBSan
├── docs/            # Architecture, findings, tutorials
├── scripts/         # fetch_grammar.sh, fetch_target.sh, ci.py, ...
├── runs/            # All campaign outputs
├── run.sh           # Docker entry point
└── getstart.md      # This file
```

---

## How It Works

### The agentic loop

Each iteration of `python -m agent.loop` performs five steps:

```
1. GENERATE   The LLM writes a Hypothesis strategy from the grammar + feedback
2. VALIDATE   4 gates: extract code → syntax → interface → smoke test (50 inputs)
3. RUN        The campaign feeds 500 generated documents to the harness
4. SUMMARIZE  Measure acceptance rate, diagnostic diversity, structure coverage
5. REFINE     Feed the summary back to the LLM with a directive to improve
```

If validation fails, the loop sends the specific failure feedback back to the
LLM and allows up to **2 repair attempts** before abandoning that iteration.

### Input classes

Every generated document falls into one of three buckets:

| Class | Meaning | Enforced bounds |
|---|---|---|
| `well_formed` | Should parse cleanly | ≥ 35% |
| `near_miss` | XML-shaped but structurally wrong (`<a></b>`) | ≥ 15% |
| `byte_hostile` | Encoding issues, control bytes, truncation | 15–45% |

The agent steers the mixture toward these bounds; validation rejects strategies
whose smoke-test mixture falls outside them.

### Crash detection

The C harness (`harness/harness.c`) classifies each input by exit code:

| Code | Meaning |
|---|---|
| 0 | Parsed cleanly |
| 3 | Parsed with diagnostics (mxml's "parsed-but-complained" state) |
| 1 | Rejected at the parser's front door |
| 2 | Harness error |
| signal | Crash (ASan/UBSan abort) |

Sanitizers are configured to **abort** on error so a crash is unmistakable.

### Feedback signals (blackbox purity)

The agent measures, without any coverage instrumentation:

- **Acceptance rate** — fraction of inputs the parser accepted (target 40–70%)
- **Diagnostic templates** — distinct parser error messages reached
- **Productions hit** — which of the 27 tracked grammar productions were used
- **Input class mixture** — well_formed / near_miss / byte_hostile shares
- **Marginal yield** — new diagnostics or coverage gained per extra example
- **Crashes** — grouped by signature for deduplication

---

## System Requirements

### Minimum

- **OS**: Linux, macOS, or Windows (WSL2 or Docker strongly recommended)
- **Python**: 3.10+
- **RAM**: 4 GB minimum, 8 GB recommended
- **Disk**: ~2 GB free
- **C toolchain**: gcc or clang + make (to build the harness)

### For LLM backends

| Backend | Extra requirements |
|---|---|
| `replay` | None — replays recorded transcripts, no network |
| `openai` | API key + OpenAI-compatible endpoint |
| `cli` | Claude Code CLI + subscription token |

### Docker (optional but recommended)

- Docker Engine 20.10+

---

## Installation

### Option 1: Docker (recommended)

```bash
# Clone the repository
git clone <repository-url>
cd Fuzz-agent

# Build the image (replay + openai backends)
./run.sh build

# Or include the Claude Code CLI
./run.sh build --with-cli

# Enter the container
./run.sh shell
```

The image pre-builds Mini-XML with sanitizers and installs all Python
dependencies. `runs/` is bind-mounted, so campaign artifacts persist on your
host.

You can also run one command without entering a shell:

```bash
./run.sh python -m agent.loop --backend replay --run-id demo
```

### Option 2: Local development

#### Step 1 — system dependencies

**Ubuntu/Debian:**

```bash
sudo apt-get update
sudo apt-get install -y build-essential git python3 python3-venv libxml2-dev
```

**macOS:**

```bash
brew install python3 git
```

**Windows:** use WSL2 (recommended) or Docker. Native Windows requires
MinGW-w64 and `make` in your PATH; the project is primarily tested on
Linux/macOS.

#### Step 2 — virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate       # Windows
```

#### Step 3 — Python dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
# For contributors/tests:
pip install -r requirements-dev.txt
```

Key dependencies: `hypothesis` (strategy generation) and `openai`
(OpenAI-compatible backend).

#### Step 4 — fetch grammar and target

```bash
./scripts/fetch_grammar.sh   # ANTLR XML grammar
./scripts/fetch_target.sh    # Mini-XML v4.0.4 (checksum-verified)
```

Both scripts verify checksums so every environment tests the exact same
parser revision.

---

## Configuration

Copy the example config and edit it:

```bash
cp .env.example .env
```

### Backend: replay (default)

No credentials, no network. Replays a recorded transcript from `runs/`.

```bash
LLM_BACKEND=replay
```

### Backend: openai (any OpenAI-compatible endpoint)

```bash
LLM_BACKEND=openai
OPENAI_API_KEY=sk-your-key
OPENAI_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-5
```

Works with OpenAI, Anthropic's OpenAI-compatible layer, Ollama, vLLM, or any
gateway:

```bash
# Anthropic via OpenAI-compatible layer
OPENAI_BASE_URL=https://api.anthropic.com/v1
LLM_MODEL=claude-sonnet-5

# Local Ollama
OPENAI_BASE_URL=http://localhost:11434/v1
LLM_MODEL=llama2
```

### Backend: cli (Claude Code subscription)

```bash
LLM_BACKEND=cli
CLAUDE_CODE_OAUTH_TOKEN=your-token    # generate: claude setup-token
```

Requires building the Docker image with `--with-cli`, or having the Claude
Code CLI installed locally.

### Precedence

Explicit CLI flags > shell environment > `.env` > defaults. So this works
without editing `.env`:

```bash
LLM_BACKEND=replay python -m agent.loop --run-id test
```

---

## Building the Harness

The C harness must be compiled with sanitizers for crash detection.

### Local build

```bash
cd harness
./build.sh          # ASan + UBSan, output: build/asan/harness
cd ..
```

In Docker it is pre-built; verify with `ls build/asan/harness` inside the
container.

### Smoke test

```bash
cd harness
./smoke_test.sh
```

Checks a known crash (issue #350), a similar non-crashing control, and basic
parsing. Expect the crash to be detected and the control to pass.

---

## Running Your First Campaign

### Quick start — replay mode (no credentials)

```bash
python -m agent.loop \
  --backend replay \
  --run-id my-first-run \
  --max-iterations 3 \
  --max-examples 500
```

This replays recorded LLM responses, regenerates the strategies, and runs
each through the harness. Results land in `runs/my-first-run/`.

### With a real LLM

```bash
# OpenAI-compatible
python -m agent.loop \
  --backend openai \
  --model gpt-5 \
  --run-id openai-run \
  --max-iterations 5 \
  --max-examples 500 \
  --max-usd 5.00

# Claude Code CLI
python -m agent.loop \
  --backend cli \
  --model sonnet \
  --run-id claude-run \
  --max-iterations 5 \
  --max-examples 500 \
  --max-usd 5.00
```

### All loop options

```
python -m agent.loop [OPTIONS]

Core:
  --backend {cli,openai,replay}   default: LLM_BACKEND env, else replay
  --run-id TEXT                   run directory name (default: loop)
  -n, --max-examples INT          documents per iteration (default: 500)
  -i, --iterations INT            max iterations (default: 5)
  --max-usd FLOAT                 spend cap in USD (default: 5.00)
  --model TEXT                    model override (default: LLM_MODEL env)
  --base-url TEXT                 OpenAI-compatible endpoint override
  --prompt-set {v1..v5}           prompt version (default: v2)
  --seed-model TEXT               model for the seed call only
  --refine-model TEXT             model for refine calls
  --target {mxml,libxml2,expat,tinyxml2,json,http,dns,smtp}
  --resume-from INT               resume at this iteration (0-based)

Agent enhancements:
  --ensemble-models m1,m2         one strategy candidate per model, voted on
  --ensemble-candidates N         N candidates of the same model
  --screening-examples N          examples per ensemble screen (default: 50)
  --use-strategy-cache            reuse a validated strategy from a similar target
  --cache-similarity FLOAT        similarity threshold (default: 0.70)
  --few-shot                      inject past winning strategies into prompts
  --few-shot-k N                  max few-shot examples (default: 3)
  --autotune                      adapt examples/repairs/directive per iteration
  --tune-state PATH               tuning state file
  --use-generated-harness         use harness/generated/<target>/ if present

LLM enhancements:
  --stream                        stream responses for faster feedback
  --prompt-ab v4,v5               A/B test prompt sets
  --fallbacks cli,replay          fallback backends on failure
  --circuit-breaker               protect against failing backends

Performance:
  --cache-results                 reuse harness results for identical inputs
  --max-corpus-entries N          bound in-memory corpus size

Discovery:
  --coverage-guided               optional coverage feedback (off by default)
  --no-structured-diagnostics     disable structured diagnostic extraction

Developer experience:
  --progress {auto,on,off}        progress bars (default: auto, TTY only)
  --status {auto,on,off}          real-time status lines
  --debug                         write runs/<id>/debug.jsonl event log
```

### Choosing a target

```bash
python -m agent.loop --target expat --backend replay --run-id expat-run
python -m fuzzer.campaign baseline --target json
```

Targets: `mxml` (default), `libxml2`, `expat`, `tinyxml2`, `json`, `http`,
`dns`, `smtp`. See `docs/tutorial-adding-targets.md` to add your own.

### Useful campaign shapes

```bash
# Quick smoke run
python -m agent.loop --backend replay --run-id quick -i 1 -n 100

# Budget-conscious real run
python -m agent.loop --backend openai --model gpt-4o-mini \
  --run-id budget -i 5 -n 500 --max-usd 2.00

# Resume an interrupted run
python -m agent.loop --backend replay --run-id my-run --resume-from 2
```

---

## How the Agent "Trains"

Stratagem does not do gradient training — the LLM weights never change. What
"training" means here is the agent **accumulating and reusing strategy
knowledge** across iterations and across runs. Five mechanisms do this:

### 1. Iterative refinement (the core loop)

Each iteration, the LLM receives the previous strategy plus a structured
feedback summary and must improve it. The loop rotates through refinement
**directives** — focused instructions like "increase near-miss share",
"reach an uncovered production", or "shrink input sizes" — so each iteration
attacks a different weakness.

### 2. Prompt sets (v1–v5)

The prompts live in `agent/prompts/v*/` and evolve:

- **v1**: original acceptance/diagnostics/coverage feedback
- **v2**: added input-class mixture, marginal scoring, rotating directives
- **v3–v5**: further refinements (size boundaries, validation rules)

```bash
python -m agent.loop --prompt-set v5 --run-id v5-run
```

Use `--prompt-ab v4,v5` to A/B two prompt sets statistically.

### 3. Few-shot reuse (`--few-shot`)

The loop scans `runs/*/iterations/` for past successful strategies, ranks them
with the same scoring function used for measurement, and injects the top-k
(only from similar targets) into the seed/refine prompt. Successful strategies
from earlier runs literally become examples for new ones.

```bash
python -m agent.loop --backend openai --few-shot --few-shot-k 3
```

### 4. Strategy cache (`--use-strategy-cache`)

Validated strategies are stored in `runs/.strategy_cache/` keyed by a
`TargetProfile` (target name, category, grammar hash, production vocabulary).
When you fuzz a similar target — e.g., moving from `mxml` to `expat` (both
XML, similarity ~0.8–1.0) — the best matching strategy is retrieved and
**re-validated** against the new target before use, skipping the seed LLM
call. XML and JSON score below 0.10, so cross-format reuse never happens by
accident. Delete the cache directory to reset.

```bash
python -m agent.loop --backend openai --target expat \
  --use-strategy-cache --run-id expat-reuse
```

### 5. Automatic tuning (`--autotune`)

Adapts loop hyperparameters from the measurements already collected:

- **examples**: hill-climbs the per-iteration budget on marginal yield
- **repairs**: rises after validation/campaign failures, falls after clean streaks
- **directive**: UCB1 bandit over the rotating refinement directives

State persists in `runs/<run-id>/tuning.json` and survives `--resume-from`.

```bash
python -m agent.loop --backend openai --autotune -i 5
```

### 6. Ensemble voting (`--ensemble-models`)

Several models each write a candidate strategy. Each is screened on a small
campaign, then ranked by a weighted vote over **measurements** — crashes count
10× more than tidiness. No extra LLM calls beyond the candidates; fully
replayable.

```bash
python -m agent.loop --backend openai \
  --ensemble-models gpt-5,gpt-4o-mini,claude-sonnet-5 \
  --screening-examples 80
```

### Split models

Use a strong model for the one-shot seed and a cheap model for refinements:

```bash
python -m agent.loop --backend openai \
  --seed-model gpt-5 --refine-model gpt-4o-mini
```

### The takeaway

- **First run**: the agent "learns" within a single campaign — each iteration
  sees the previous iteration's failures.
- **Across runs**: `--few-shot`, `--use-strategy-cache`, and `--autotune` carry
  knowledge forward so later campaigns start smarter.
- **Across targets**: the strategy cache transfers validated knowledge between
  similar parsers.

---

## Using the Results

### Directory layout

```
runs/my-run/
├── iterations/
│   ├── iter-0/
│   │   ├── strategy.py        # the generated Hypothesis strategy
│   │   ├── summary.json       # iteration statistics
│   │   ├── results.jsonl      # one record per input
│   │   ├── corpus.jsonl.gz    # generated inputs (base64)
│   │   ├── crashes/           # crash artifacts + sanitizer stderr
│   │   ├── ensemble.json      # vote report (ensembles only)
│   │   ├── cache_hit.json     # reuse provenance (cache only)
│   │   └── few_shot.md        # examples injected (few-shot only)
│   └── iter-1/ ...
├── transcript/                # every LLM call: system.md, user.md,
│   ├── call-1/ ...            #   response.json, meta.json
├── tuning.json                # autotune state (autotune only)
├── debug.jsonl                # structured event log (--debug only)
└── final_summary.json
```

### Key metrics in `summary.json`

- `acceptance_rate` — aim for 40–70%; too low means inputs die at the front door
- `distinct_diagnostic_templates` — unique parser errors reached
- `structure.productions_hit / productions_total` — grammar coverage
- `buckets` — well_formed / near_miss / byte_hostile shares and rates
- `crash_count` — crashes found this iteration

### Real-time output

```
[llm] call 1 (seed) 45.2s  in=15000 out=2000 cost=$0.15
[validate] extracting code... OK
[validate] checking syntax... OK
[validate] checking interface... OK
[validate] smoke test: 50 examples, acceptance=42%... OK
[campaign] running 500 examples...
strategy   : gen_iter0  (survey mode)
examples   : 500  in 45.2s
outcomes   : {'parsed_clean': 150, 'parsed_diag': 80, 'rejected': 270}
accept rate: 46.0%
crashes    : 0
productions: 22/27   missing: x_bom, x_invalid_utf8
diag templates reached: 15
```

### Replay any run

Every run records its full transcript. Reproduce it exactly:

```bash
python -m agent.loop --backend replay --run-id <original-run-id>
```

Note: replay requires the same code version — if strategies or prompts
changed, the recorded call sequence may no longer match.

---

## Advanced Usage

### Run a single strategy without the agent

```bash
# Baseline strategy
python -m fuzzer.campaign baseline --max-examples 500 --out runs/baseline-test

# An LLM-generated strategy from a previous run
python -m fuzzer.campaign gen_iter0 --target expat -n 500
```

### Hunt mode (crash minimization)

```bash
python -m fuzzer.campaign gen_iter0 --mode hunt --max-examples 1000 --out runs/hunt
```

Hypothesis's shrinker minimizes any crashing input.

### Independent trials (measure variance)

```bash
for seed in 11 22 33; do
  python -m fuzzer.campaign gen_iter0 --seed $seed -n 500 --out runs/trial-$seed
done
```

### Multi-target parallel campaigns

```bash
python -m fuzzer.campaign gen_iter0 --parallel \
  --targets mxml json http -w 3
```

### Generated harnesses

Let the agent write a C harness for a new target, gate it structurally, and
compile it:

```bash
python -m agent.harness_gen --target expat --backend openai --compile
python -m agent.loop --backend openai --target expat --use-generated-harness
```

### Differential testing

`fuzzer/differential.py` provides a `DifferentialEngine` that runs the same
inputs through multiple parser targets and reports divergent diagnostics —
useful for catching parser inconsistencies that a single-target campaign
can't see. It is a library used by the test suite; wire it into your own
script or extend a target to expose it.

### Control experiment (vs classic fuzzers)

Compare Stratagem's yield against libFuzzer/AFL++ on the same target:

```bash
python scripts/run_control_experiment.py --target mxml --budget 500
```

### Leak detection (separate pass)

The main runs disable leak detection (`detect_leaks=0`) so leak reports don't
bury real crashes. Leaks are hunted afterward over the recorded corpora:

```bash
python scripts/leak_pass.py            # every run
python scripts/leak_pass.py my-run     # one run
```

The script re-runs corpus inputs with `detect_leaks=1` and writes
`runs/analysis/leak_pass.json`.

---

## Developer Tools

### Tests

```bash
pip install -r requirements-dev.txt

python -m pytest agent -q        # hermetic agent suite (no harness/network)
python -m agent.test_loop        # without pytest
python -m agent.test_dx
python -m agent.selftest
python -m fuzzer.selftest
```

### Debug a run

```bash
python -m agent.debug --run-id loop --diagnose      # artifact-level diagnosis
python -m agent.debug --run-id loop --transcript    # list recorded calls
python -m agent.debug --run-id loop --call 3 --full # inspect one call
python -m agent.debug --run-id loop --iteration 2
python -m agent.debug --run-id loop --diagnose --json
```

Or record events during the run itself:

```bash
python -m agent.loop --backend replay --run-id demo --debug
```

### Progress control

```bash
python -m agent.loop --backend openai --run-id demo            # auto (TTY bars)
python -m agent.loop --backend openai --run-id demo --progress on
python -m agent.loop --backend openai --run-id demo --progress off --status on
```

Progress goes to stderr so stdout stays parseable.
`STRATAGEM_NO_PROGRESS=1` disables it entirely.

### Local CI

```bash
python scripts/ci.py --unit --cov   # unit tests on any OS
python scripts/ci.py --full         # adds harness + replay-identity check
```

---

## Troubleshooting

### "No recorded calls under runs/.../transcript"

Replay mode needs an existing transcript. Run once with a real backend first:

```bash
python -m agent.loop --backend openai --run-id original
python -m agent.loop --backend replay --run-id replay-copy
```

### "OPENAI_API_KEY is not set"

```bash
echo "OPENAI_API_KEY=sk-your-key" >> .env
# or
export OPENAI_API_KEY=sk-your-key
```

### "Harness not found at build/asan/harness"

```bash
cd harness && ./build.sh && cd ..
```

### "Validation failed: smoke test acceptance too low"

Normal in early iterations — the loop will request repairs. If it persists,
inspect `runs/<id>/iterations/iter-*/strategy.py`.

### "Transcript exhausted after N calls"

Code changed since the transcript was recorded. Regenerate with a real
backend, or check out the matching code version.

### Docker issues

| Error | Fix |
|---|---|
| `Permission denied` on `run.sh` | `chmod +x run.sh` |
| ASan "Shadow memory range interleaves" | Ensure `run.sh` keeps `--security-opt seccomp=unconfined` |
| Crash signatures all identical | Ensure `--cap-add SYS_PTRACE` is present (symbolization) |

### Build issues

| Error | Fix |
|---|---|
| `mxml.h: No such file or directory` | `./scripts/fetch_target.sh` |
| Missing grammar | `./scripts/fetch_grammar.sh` |

### LLM backend issues

- **CLI timeouts**: reduce `-n`/`-i`, use a faster model, check connectivity
- **Usage limit reached**: the loop stops immediately on quota errors — wait
  for reset, switch backend, or lower `--max-usd`
- **Very slow campaigns**: lower `-n`; check harness speed with
  `time build/asan/harness < input.xml`

---

## Next Steps

- [README.md](README.md) — feature overview and quick examples
- [docs/architecture.md](docs/architecture.md) — system architecture
- [docs/tutorial-adding-targets.md](docs/tutorial-adding-targets.md) — add a new target
- [docs/design-decisions.md](docs/design-decisions.md) — engineering rationale (D1–D13)
- [docs/findings.md](docs/findings.md) — what past campaigns discovered
- [docs/developer-experience.md](docs/developer-experience.md) — tests, debug, CI
- [agent/README.md](agent/README.md) — agent internals and enhancement details
- [grammar/ADAPTATIONS.md](grammar/ADAPTATIONS.md) — grammar vs parser differences
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute

## Getting Help

- **This framework**: check docs and existing issues
- **Mini-XML**: https://github.com/michaelrsweet/mxml
- **Hypothesis**: https://hypothesis.readthedocs.io/
- **Claude Code**: https://docs.anthropic.com/
- **OpenAI API**: https://platform.openai.com/docs
