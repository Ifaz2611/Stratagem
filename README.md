# Stratagem: Agentic Grammar Fuzzing

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

An innovative blackbox fuzzing framework that leverages Large Language Models (LLMs) to generate and refine test strategies for parsing software. Stratagem demonstrates the power of agentic fuzzing by targeting the Mini-XML (mxml) parser v4.0.4, with support for multiple parsers and protocols.

## Overview

Stratagem explores a novel approach to grammar-based fuzzing by using LLMs as the driving intelligence behind test strategy generation. Unlike traditional mutation-based fuzzing, an agent writes Hypothesis strategies in Python, tests them against real parsers, receives feedback, and iteratively improves the strategy in a closed loop.

### Key Features

- **Agentic Loop**: LLM generates Python strategies → tests them → receives feedback → refines
- **Blackbox Operation**: No code coverage signals; works only with parser results and input properties
- **Multiple LLM Backends**: Claude Code CLI, OpenAI-compatible APIs, and replay mode
- **Multi-Model Ensembles**: Several models propose strategies; measured candidates are ranked by weighted vote
- **Strategy Cache**: Validated strategies are reused across similar targets after re-validation
- **Automatic Tuning**: Example budget, repair allowance, and refinement directive adapt after each iteration
- **Few-Shot Reuse**: Successful strategies from earlier runs are ranked and injected into new prompts
- **Generated Harnesses**: Target-specific C/C++ drivers can be generated, gated, and compiled
- **Grammar-Based**: Uses ANTLR grammars adapted for target parsers
- **Sanitizer Integration**: AddressSanitizer and UndefinedBehaviorSanitizer for crash detection
- **Reproducible**: All LLM interactions are recorded for replay without credentials
- **Developer Tooling**: Hermetic loop tests, actionable errors, a run debugger, progress bars and CI/CD workflows

### Project Structure

```
.
├── agent/           # Agentic loop and LLM backends
│   ├── loop.py      # Main iteration logic
│   ├── llm.py       # LLM backend implementations
│   ├── validate.py  # Strategy validation gates
│   ├── ensemble.py  # Multi-model candidate voting
│   ├── strategy_cache.py  # Cross-target strategy reuse
│   ├── tuning.py    # Automatic loop hyperparameter tuning
│   ├── fewshot.py   # Successful past strategies as prompt examples
│   ├── harness_gen.py     # Target-specific harness generation
│   ├── errors.py    # Actionable errors, debug log, run diagnosis
│   ├── debug.py     # `python -m agent.debug` CLI
│   ├── progress.py  # Progress bars and real-time status lines
│   ├── test_loop.py # Hermetic agent-loop test suite
│   ├── test_dx.py   # Error/debug/progress tests
│   └── prompts/     # Prompt templates (v1-v5)
├── fuzzer/          # Fuzzing engine
│   ├── campaign.py  # Run strategies through harness
│   ├── runner.py    # Execute harness and classify results
│   ├── features.py  # Analyze generated documents
│   ├── strategies/  # Generated strategy modules
│   └── triage.py    # Crash deduplication
├── grammar/         # ANTLR grammars
│   ├── XMLParser.g4
│   ├── XMLLexer.g4
│   ├── JSON.g4
│   ├── HTTP.g4
│   ├── SMTP.g4
│   └── ADAPTATIONS.md
├── harness/         # C harness for mxml
│   ├── harness.c
│   └── build.sh
├── docs/            # Documentation
│   ├── design-decisions.md
│   ├── findings.md
│   └── REPORT.md
├── scripts/         # Utility scripts
│   ├── ci.py        # Local CI runner mirroring GitHub Actions
│   └── ...
├── .github/workflows/ci.yml  # Unit, replay and container CI jobs
├── runs/            # Campaign outputs
└── run.sh           # Docker entry point
```

## Target: Mini-XML v4.0.4

The project primarily fuzzes [Mini-XML](https://github.com/michaelrsweet/mxml), a small C XML library, pinned to commit `0d5afc42` (v4.0.4). mxml was chosen because:

- Small and well-maintained codebase
- Provides detailed error messages through callbacks
- Has recursive XML structure suitable for grammar-based generation
- Parses iteratively (not recursively), avoiding trivial stack overflow

## How It Works

### The Agentic Loop

Each iteration follows these steps:

1. **Generate**: LLM writes a Python Hypothesis strategy based on XML grammar
2. **Validate**: Four-gate validation checks syntax, interface, and smoke testing
3. **Run**: Execute 500 generated documents through the sanitizer-instrumented harness
4. **Summarize**: Measure acceptance rate, diagnostic diversity, structural coverage
5. **Refine**: Feed summary back to LLM with instructions to improve

### Input Classification

Documents are classified into three buckets:

- **well_formed**: Should parse cleanly
- **near_miss**: Structurally wrong but XML-shaped (e.g., `<a></b>`)
- **byte_hostile**: Encoding issues, control bytes, truncation

The loop steers the generator to maintain a healthy mixture across all three.

### Crash Detection

The C harness (`harness/harness.c`) classifies results via exit codes:

- `0`: Parsed without diagnostics
- `3`: Parsed with diagnostics (mxml's "parsed-but-complained" state)
- `1`: Rejected (well-formed rejection, not a crash)
- `2`: Harness error
- Signal/sanitizer abort: Crash

Sanitizers (ASan, UBSan) are configured to abort on error rather than continue.

## Findings

The historical campaigns (10,000 inputs from 19 strategies) found:

- **Fixed upstream**: Non-ASCII character damage in error messages (PR #357)
- **Reproduced**: Known leak on `<a a>` error path (issue #354)
- **Coverage**: Grammar-based strategies achieved 38-45% parser coverage vs 13% random baseline
- **No crashes**: No memory-safety crashes or timeouts found

See `docs/findings.md` for detailed analysis.

## Installation

### Prerequisites

- Docker (for containerized builds, recommended)
- Python 3.10+ with virtual environment
- C compiler (gcc or clang) and make (for harness build)
- For LLM backends: Claude Code CLI or OpenAI API key

**Platform Notes:**
- **Linux/macOS**: Fully supported
- **Windows**: Use WSL2 or Docker for best results. Native Windows requires MinGW-w64 and make.

### Quick Start with Docker

```bash
# Build the container
./run.sh build

# Enter the container
./run.sh shell

# Inside the container, run a campaign
python -m agent.loop --backend replay --run-id demo
```

### Local Development

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Build the harness with sanitizers
cd harness
./build.sh
cd ..

# Run a campaign
python -m agent.loop --backend replay --run-id my-run
```

See [getstart.md](getstart.md) for detailed installation and usage instructions.

## Configuration

Copy `.env.example` to `.env` and configure your LLM backend:

```bash
cp .env.example .env
```

Available backends:

- `replay` (default): No credentials, replays recorded transcripts
- `openai`: Any OpenAI-compatible endpoint (set `OPENAI_API_KEY` and `OPENAI_BASE_URL`)
- `cli`: Claude Code headless (set `CLAUDE_CODE_OAUTH_TOKEN`)

## Running Campaigns

### Basic Campaign

```bash
python -m agent.loop \
  --backend replay \
  --run-id my-campaign \
  --max-iterations 5 \
  --max-examples 500 \
  --max-usd 5.00
```

### With Specific Model

```bash
python -m agent.loop \
  --backend openai \
  --model gpt-5 \
  --run-id gpt5-run
```

### Resume Interrupted Run

```bash
python -m agent.loop \
  --backend replay \
  --run-id my-campaign \
  --resume-from 2
```

### Switching Targets

Stratagem supports multiple targets across document grammars and network protocols via the Target Abstraction Layer:

- **XML Parsers**: `mxml` (default), `libxml2`, `expat`, `tinyxml2`
- **JSON Parsers**: `json` (proof-of-concept for non-XML grammars)
- **Network Protocol Parsers**: `http`, `dns`, `smtp`

To run a campaign against a specific target:

```bash
# Fuzz Expat XML parser
python -m fuzzer.campaign baseline --target expat

# Fuzz JSON parser
python -m fuzzer.campaign json_baseline --target json

# Fuzz HTTP protocol parser
python -m fuzzer.campaign http_baseline --target http

# Fuzz DNS binary wire-format parser
python -m fuzzer.campaign dns_baseline --target dns

# Fuzz SMTP command parser
python -m fuzzer.campaign smtp_baseline --target smtp

# Run agentic loop on a target
python -m agent.loop --target expat --backend replay --run-id expat-campaign
```

### Agent Enhancements

All five enhancements are opt-in. With none of the flags below, a run makes exactly the LLM calls it made before, so replay transcripts stay valid.

```bash
# Ensemble: one candidate per model, screened and ranked by weighted vote
python -m agent.loop --backend openai \
  --ensemble-models gpt-5,claude-sonnet-5 \
  --screening-examples 80 --target expat --run-id ensemble-expat

# Reuse a validated strategy from a similar target (XML -> XML, after re-validation)
python -m agent.loop --backend openai --target expat \
  --use-strategy-cache --run-id expat-reuse

# Adapt examples/repairs/directive from measured marginal yield
python -m agent.loop --backend openai --autotune --iterations 5

# Inject the best strategies from earlier runs as few-shot examples
python -m agent.loop --backend openai --few-shot --few-shot-k 3

# Generate a harness for a target, then run against it
python -m agent.harness_gen --target expat --backend openai --compile
python -m agent.loop --backend openai --target expat --use-generated-harness

# Stream responses for real-time feedback and token telemetry
python -m agent.loop --backend openai --stream --run-id stream-run

# Multi-tier fallback backend with circuit breaker protection
python -m agent.loop --backend openai --fallbacks cli,replay --circuit-breaker

# A/B test prompt sets (v4 vs v5) with statistical significance evaluation
python -m agent.loop --backend openai --prompt-ab v4,v5 --iterations 10
```

See [agent/README.md](agent/README.md#agent-enhancements) for the mechanisms, safeguards, and output artifacts.

## Developer Experience

The loop, campaign runner and debugger share a small set of developer tools. They do not change the LLM call sequence, so replay transcripts stay valid.

### Tests

```bash
pip install -r requirements-dev.txt

# Hermetic agent suite: no harness, network or credentials
python -m pytest agent -q

# Without pytest
python -m agent.test_loop
python -m agent.test_dx

# Measurement-layer self-checks
python -m agent.selftest
python -m fuzzer.selftest
```

### Debug a run

```bash
# Artifact-level diagnosis, with an actionable exit code
python -m agent.debug --run-id loop --diagnose

# List recorded calls and inspect one
python -m agent.debug --run-id loop --transcript
python -m agent.debug --run-id loop --call 3 --full

# Inspect an iteration or machine-readable output
python -m agent.debug --run-id loop --iteration 2
python -m agent.debug --run-id loop --diagnose --json

# Record structured events while the loop runs
python -m agent.loop --backend replay --run-id demo --debug
```

Failures now print a hint, the run context and the command most likely to help. `--debug` also writes `runs/<id>/debug.jsonl`, an append-only event log that survives a killed process.

### Progress

```bash
# Auto (default): bars on a TTY, silent in CI logs
python -m agent.loop --backend openai --run-id demo

# Force milestone lines in a log, or keep status without a bar
python -m agent.loop --backend openai --run-id demo --progress on
python -m agent.loop --backend openai --run-id demo --progress off --status on

# Campaigns accept the same flag
python -m fuzzer.campaign baseline --target mxml --progress on
```

Progress is written to stderr; stdout stays parseable. Set `STRATAGEM_NO_PROGRESS=1` to disable automatic rendering.

### CI

`.github/workflows/ci.yml` runs unit tests on Python 3.10-3.12, builds the harness and verifies replay identity, and builds/smoke-tests the container. Run the same checks locally:

```bash
python scripts/ci.py --unit --cov   # any OS
python scripts/ci.py --full         # adds the harness replay check
```

See [docs/developer-experience.md](docs/developer-experience.md) for the full guide.

## Output

Each campaign creates a directory under `runs/`:

```
runs/my-campaign/
├── iterations/
│   ├── iter-0/
│   │   ├── strategy.py      # Generated strategy
│   │   ├── summary.json     # Iteration summary
│   │   ├── results.jsonl    # Per-input results
│   │   ├── ensemble.json    # Candidate vote report (ensembles only)
│   │   ├── cache_hit.json   # Reused strategy provenance (cache only)
│   │   └── few_shot.md      # Examples injected into this prompt (few-shot only)
│   ├── iter-1/
│   └── ...
├── transcript/              # LLM prompts and responses
│   ├── call-1/
│   │   ├── system.md
│   │   ├── user.md
│   │   └── response.json
│   └── ...
├── tuning.json              # Hyperparameter search state (autotune only)
└── final_summary.json
```

## Design Decisions

Key engineering choices are documented in `docs/design-decisions.md`:

- D1: Target selection (mxml v4.0.4)
- D2: Blackbox boundary (no coverage in loop)
- D3: UBSan stops the process
- D4: Leak detection in separate pass
- D5: Acceptance uses a range (40-70%)
- D6: Gcov for evaluation only
- D9: Reproducibility via recorded bytes
- D13: Raw bytes through surrogateescape

## Grammar Adaptations

The ANTLR grammars are adapted for specific parser behaviors. See `grammar/ADAPTATIONS.md` for:

- Named entities (mxml only supports 4: amp, lt, gt, quot)
- Matching tag names (grammar allows `<a></b>`, mxml rejects)
- Character reference limits
- Unquoted attributes (mxml accepts, grammar rejects)
- Non-ASCII name ranges
- And 6 more adaptations

## Documentation

- [getstart.md](getstart.md) - Installation and usage guide
- [docs/design-decisions.md](docs/design-decisions.md) - Engineering rationale
- [docs/findings.md](docs/findings.md) - Test results and bug reports
- [docs/REPORT.md](docs/REPORT.md) - Project report
- [docs/developer-experience.md](docs/developer-experience.md) - Tests, debugging, progress and CI
- [grammar/ADAPTATIONS.md](grammar/ADAPTATIONS.md) - Grammar vs parser differences
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contributing guidelines
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - Code of conduct

## Research Context

This project investigates:

- Whether LLMs can effectively drive grammar-based fuzzing
- Blackbox feedback signals without code coverage
- Reproducibility in agentic systems
- Cost-effectiveness vs traditional fuzzers (AFL, libFuzzer)

The framework is designed to be extensible to other parsers and grammars.

## License

This project is licensed under the MIT License - see the [license](license) file for details.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md) when participating in this project.

## Acknowledgments

- Mini-XML by Michael R Sweet
- ANTLR grammars-v4 community
- Hypothesis testing library
