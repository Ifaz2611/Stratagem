# Stratagem: Agentic Grammar Fuzzing

A blackbox fuzzing framework that uses Large Language Models (LLMs) to generate and refine test strategies for parsing software. The project demonstrates agentic fuzzing by targeting the Mini-XML (mxml) parser v4.0.4.

## Overview

This project explores using LLMs as the driving intelligence behind a grammar-based fuzzer. Instead of traditional mutation-based fuzzing, an agent writes Hypothesis strategies in Python, tests them against a real C parser, receives feedback, and iteratively improves the strategy.

### Key Features

- **Agentic Loop**: LLM generates Python strategies → tests them → receives feedback → refines
- **Blackbox Operation**: No code coverage signals; works only with parser results and input properties
- **Multiple LLM Backends**: Claude Code CLI, OpenAI-compatible APIs, and replay mode
- **Multi-Model Ensembles**: several models propose strategies; measured candidates are ranked by a weighted vote
- **Strategy Cache**: validated strategies are reused across similar targets after re-validation
- **Automatic Tuning**: example budget, repair allowance, and refinement directive adapt after each iteration
- **Few-Shot Reuse**: successful strategies from earlier runs are ranked and injected into new prompts
- **Generated Harnesses**: a target-specific C/C++ driver can be generated, gated, and compiled
- **Grammar-Based**: Uses ANTLR XML grammar adapted for the target parser
- **Sanitizer Integration**: AddressSanitizer and UndefinedBehaviorSanitizer for crash detection
- **Reproducible**: All LLM interactions are recorded for replay without credentials

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
│   └── prompts/     # Prompt templates (v1-v5)
├── fuzzer/          # Fuzzing engine
│   ├── campaign.py  # Run strategies through harness
│   ├── runner.py    # Execute harness and classify results
│   ├── features.py  # Analyze generated documents
│   ├── strategies/  # Generated strategy modules
│   └── triage.py    # Crash deduplication
├── grammar/         # ANTLR XML grammar
│   ├── XMLParser.g4
│   ├── XMLLexer.g4
│   └── ADAPTATIONS.md
├── harness/         # C harness for mxml
│   ├── harness.c
│   └── build.sh
├── docs/            # Documentation
│   ├── design-decisions.md
│   ├── findings.md
│   └── REPORT.md
├── scripts/         # Utility scripts
├── runs/            # Campaign outputs
└── run.sh           # Docker entry point
```

## Target: Mini-XML v4.0.4

The project fuzzes [Mini-XML](https://github.com/michaelrsweet/mxml), a small C XML library, pinned to commit `0d5afc42` (v4.0.4). mxml was chosen because:

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

All five enhancements are opt-in. With none of the flags below, a run makes
exactly the LLM calls it made before, so replay transcripts stay valid.

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

See [agent/README.md](agent/README.md#agent-enhancements) for the mechanisms,
safeguards, and output artifacts.

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

The ANTLR XML grammar is adapted for mxml's behavior. See `grammar/ADAPTATIONS.md` for:

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
- [grammar/ADAPTATIONS.md](grammar/ADAPTATIONS.md) - Grammar vs parser differences
- [todo.md](todo.md) - Future expansion ideas

## Research Context

This project investigates:

- Whether LLMs can effectively drive grammar-based fuzzing
- Blackbox feedback signals without code coverage
- Reproducibility in agentic systems
- Cost-effectiveness vs traditional fuzzers (AFL, libFuzzer)

The framework is designed to be extensible to other parsers and grammars.

## License

See individual component licenses. The project uses:

- Mini-XML (LGPL with exceptions)
- ANTLR grammars (BSD)
- Hypothesis (MPL 2.0)
- OpenAI Python SDK (Apache 2.0)

## Contributing

This is a research project. For suggestions or questions, please refer to the issues in the target repository (mxml) for any reported bugs.

## Acknowledgments

- Mini-XML by Michael R Sweet
- ANTLR grammars-v4 community
- Hypothesis testing library

