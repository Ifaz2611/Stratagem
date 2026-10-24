# Getting Started with Stratagem

This guide will help you install, configure, and run the agentic grammar fuzzing framework.

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Building the Harness](#building-the-harness)
5. [Running Your First Campaign](#running-your-first-campaign)
6. [Understanding the Output](#understanding-the-output)
7. [Advanced Usage](#advanced-usage)
8. [Troubleshooting](#troubleshooting)

## System Requirements

### Minimum Requirements

- **Operating System**: Linux, macOS, or Windows (with WSL2 recommended)
- **Python**: 3.10 or higher
- **Memory**: 4 GB RAM minimum (8 GB recommended)
- **Disk**: 2 GB free space

### For Docker Setup

- Docker Engine 20.10+
- Docker Compose (optional)

### For LLM Backends

- **Replay mode**: No additional requirements
- **Claude Code CLI**: Install via `npm install -g @anthropic-ai/claude-code`
- **OpenAI-compatible**: API key and endpoint URL

## Installation

### Option 1: Docker (Recommended)

Docker provides a reproducible environment with all dependencies pre-configured.

#### Step 1: Clone the Repository

```bash
git clone <repository-url>
cd Stratagem
```

#### Step 2: Build the Container

```bash
# Basic build (replay and OpenAI backends)
./run.sh build

# Build with Claude Code CLI support
./run.sh build --with-cli
```

The build process:
- Downloads and compiles Mini-XML with sanitizers
- Installs Python dependencies
- Configures the harness
- Sets up the runtime environment

#### Step 3: Verify the Build

```bash
# Enter the container
./run.sh shell

# Inside the container, verify the harness
ls -la build/asan/harness
python -c "import hypothesis; print(hypothesis.__version__)"
```

### Option 2: Local Development

For development or custom configurations, install locally.

#### Step 1: Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    git \
    python3 \
    python3-venv \
    libxml2-dev
```

**macOS:**
```bash
brew install python3 git
```

**Windows (WSL2):**
```bash
sudo apt-get update
sudo apt-get install -y build-essential git python3 python3-venv
```

#### Step 2: Create Python Virtual Environment

```bash
# Create virtual environment
python3 -m venv .venv

# Activate it
# On Linux/macOS:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate
```

#### Step 3: Install Python Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

The main dependencies are:
- `hypothesis==6.140.3` - Property-based testing library
- `openai==2.14.0` - OpenAI API client (for openai backend)

#### Step 4: Fetch Grammar and Target

```bash
# Download ANTLR XML grammar
./scripts/fetch_grammar.sh

# Download and checkout Mini-XML v4.0.4
./scripts/fetch_target.sh
```

These scripts verify checksums to ensure reproducibility.

## Configuration

### Environment Variables

Copy the example configuration:

```bash
cp .env.example .env
```

Edit `.env` to configure your LLM backend:

#### Replay Mode (Default)

No configuration needed. Replays recorded transcripts without network access.

```bash
LLM_BACKEND=replay
```

#### OpenAI-Compatible Backend

For OpenAI, Anthropic, or local models (Ollama, vLLM):

```bash
LLM_BACKEND=openai
OPENAI_API_KEY=sk-your-api-key-here
OPENAI_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-5
```

**Examples:**

```bash
# Anthropic via OpenAI-compatible layer
LLM_BACKEND=openai
OPENAI_API_KEY=sk-ant-your-key
OPENAI_BASE_URL=https://api.anthropic.com/v1
LLM_MODEL=claude-sonnet-5

# Local Ollama
LLM_BACKEND=openai
OPENAI_API_KEY=not-needed
OPENAI_BASE_URL=http://localhost:11434/v1
LLM_MODEL=llama2
```

#### Claude Code CLI Backend

Requires a Claude subscription:

```bash
LLM_BACKEND=cli
CLAUDE_CODE_OAUTH_TOKEN=your-token-here
```

Generate a token with:
```bash
claude setup-token
```

### Environment Variable Precedence

Environment variables set in your shell take precedence over `.env`:

```bash
# This overrides .env
LLM_BACKEND=replay python -m agent.loop --run-id test
```

## Building the Harness

The C harness must be compiled with sanitizers for crash detection.

### Inside Docker

The harness is pre-built in the container. Verify it:

```bash
./run.sh shell
ls -la build/asan/harness
```

### Local Build

```bash
cd harness
./build.sh
cd ..
```

The build script:
- Compiles Mini-XML with AddressSanitizer and UndefinedBehaviorSanitizer
- Links the harness against the instrumented library
- Places the binary at `build/asan/harness`

### Verify the Build

Run the smoke test:

```bash
cd harness
./smoke_test.sh
```

This tests:
- Positive control: Known crash (issue #350)
- Negative control: Similar non-crashing input
- Basic parsing functionality

Expected output should show the crash detected and the control passing.

## Running Your First Campaign

### Quick Start with Replay Mode

Replay mode uses pre-recorded LLM responses, requiring no credentials:

```bash
python -m agent.loop \
  --backend replay \
  --run-id my-first-run \
  --max-iterations 3 \
  --max-examples 500
```

**What happens:**

1. The loop loads a recorded transcript from `runs/loop/transcript/`
2. It replays the LLM responses in order
3. Each iteration generates and tests 500 XML documents
4. Results are saved to `runs/my-first-run/`

### Run with a Real LLM

#### Using OpenAI

```bash
python -m agent.loop \
  --backend openai \
  --model gpt-5 \
  --run-id openai-run \
  --max-iterations 5 \
  --max-examples 500 \
  --max-usd 5.00
```

#### Using Claude Code CLI

```bash
python -m agent.loop \
  --backend cli \
  --model sonnet \
  --run-id claude-run \
  --max-iterations 5 \
  --max-examples 500 \
  --max-usd 5.00
```

### Command-Line Options

```
python -m agent.loop [OPTIONS]

Options:
  --backend {replay,openai,cli}
          LLM backend to use (default: replay)
  --run-id TEXT
          Identifier for this run (default: run)
  --max-iterations INTEGER
          Number of iterations (1-5, default: 5)
  --max-examples INTEGER
          Examples per iteration (1-500, default: 500)
  --max-usd FLOAT
          Cost cap in USD (default: 5.00)
  --model TEXT
          Override default model
  --base-url TEXT
          Override base URL for openai backend
  --seed-model TEXT
          Model for seed generation (if different from refine)
  --refine-model TEXT
          Model for refinement iterations
  --prompt-set {v1,v2,v3,v4,v5}
          Prompt version to use (default: v2)
  --resume-from INTEGER
          Resume from this iteration (0-based)
```

### Example Campaigns

#### Short Test Run

```bash
python -m agent.loop \
  --backend replay \
  --run-id quick-test \
  --max-iterations 1 \
  --max-examples 100
```

#### Budget-Conscious Run

```bash
python -m agent.loop \
  --backend openai \
  --model gpt-4o-mini \
  --run-id budget-run \
  --max-iterations 5 \
  --max-examples 500 \
  --max-usd 2.00
```

#### Resume Interrupted Run

If a run fails midway:

```bash
python -m agent.loop \
  --backend replay \
  --run-id my-run \
  --resume-from 2
```

This resumes from iteration 2, using the already-completed iterations 0 and 1.

## Understanding the Output

### Directory Structure

```
runs/my-run/
├── iterations/
│   ├── iter-0/
│   │   ├── strategy.py          # Generated Hypothesis strategy
│   │   ├── summary.json         # Iteration statistics
│   │   ├── results.jsonl        # Per-input results (one per line)
│   │   ├── corpus.jsonl.gz      # Generated inputs (base64-encoded)
│   │   └── crashes/             # Crash artifacts (if any)
│   │       ├── abc123...xml     # Crashing input
│   │       └── abc123...stderr.txt  # Sanitizer output
│   ├── iter-1/
│   └── ...
├── transcript/
│   ├── call-1/
│   │   ├── system.md            # System prompt
│   │   ├── user.md              # User prompt
│   │   ├── meta.json            # Call metadata
│   │   └── response.json        # LLM response
│   ├── call-2/
│   └── ...
└── final_summary.json
```

### Summary.json Structure

Each iteration's summary includes:

```json
{
  "strategy": "gen_iter0",
  "mode": "survey",
  "examples": 500,
  "wall_clock_s": 45.2,
  "outcomes": {
    "parsed_clean": 150,
    "parsed_diag": 80,
    "rejected": 270
  },
  "acceptance_rate": 0.46,
  "buckets": {
    "well_formed": {"share": 0.35, "acceptance_rate": 0.85},
    "near_miss": {"share": 0.40, "acceptance_rate": 0.15},
    "byte_hostile": {"share": 0.25, "acceptance_rate": 0.02}
  },
  "crash_count": 0,
  "distinct_diagnostic_templates": 15,
  "structure": {
    "productions_hit": 22,
    "productions_total": 27,
    "missing": ["x_bom", "x_invalid_utf8"],
    "max_depth_seen": 12
  },
  "diagnostic_templates": {
    "XML does not start with '<'": 45,
    "mismatched close tag": 30,
    ...
  }
}
```

### Key Metrics

- **acceptance_rate**: Fraction of inputs the parser accepted (aim for 40-70%)
- **distinct_diagnostic_templates**: Number of unique error messages reached
- **productions_hit/productions_total**: Grammar productions covered
- **buckets**: Distribution across well_formed, near_miss, byte_hostile

### Real-Time Output

During a run, you'll see:

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
xml-shaped : 98.0%
crashes    : 0
productions: 22/27   missing: x_bom, x_invalid_utf8
diag templates reached: 15
```

## Advanced Usage

### Running a Single Strategy

Test a specific strategy without the agentic loop:

```bash
python -m fuzzer.campaign baseline \
  --max-examples 500 \
  --out runs/baseline-test
```

### Hunt Mode (Crash Minimization)

Enable Hypothesis's shrinker for crash minimization:

```bash
python -m fuzzer.campaign my-strategy \
  --mode hunt \
  --max-examples 1000 \
  --out runs/hunt
```

### Independent Trials

Run a strategy with different seeds to measure variance:

```bash
python -m fuzzer.campaign gen_iter0 \
  --seed 11 \
  --max-examples 500 \
  --out runs/trial-11

python -m fuzzer.campaign gen_iter0 \
  --seed 22 \
  --max-examples 500 \
  --out runs/trial-22

python -m fuzzer.campaign gen_iter0 \
  --seed 33 \
  --max-examples 500 \
  --out runs/trial-33
```

### Custom Prompt Sets

Use different prompt versions:

```bash
# v1: Original prompts
python -m agent.loop --prompt-set v1 --run-id v1-run

# v2: Added input-class mixture, marginal scoring
python -m agent.loop --prompt-set v2 --run-id v2-run

# v3-v5: Further refinements
python -m agent.loop --prompt-set v5 --run-id v5-run
```

### Split Seed/Refine Models

Use a powerful model for seeding, cheaper for refinement:

```bash
python -m agent.loop \
  --backend openai \
  --seed-model gpt-5 \
  --refine-model gpt-4o-mini \
  --run-id hybrid-run
```

### Leak Detection Pass

Separate pass with LeakSanitizer enabled:

```bash
# Rebuild with leak detection
cd harness
ASAN_OPTIONS=detect_leaks=1 ./build.sh
cd ..

# Run campaign
python -m agent.loop --backend replay --run-id leak-pass
```

## Troubleshooting

### Common Issues

#### "No recorded calls under runs/.../transcript"

**Cause**: Using replay mode without a transcript.

**Solution**:
```bash
# First run with a real backend to create a transcript
python -m agent.loop --backend openai --run-id original

# Then replay it
python -m agent.loop --backend replay --run-id replay-copy
```

#### "OPENAI_API_KEY is not set"

**Cause**: OpenAI backend configured but no key provided.

**Solution**:
```bash
# Set in .env
echo "OPENAI_API_KEY=sk-your-key" >> .env

# Or export in shell
export OPENAI_API_KEY=sk-your-key
```

#### "Harness not found at build/asan/harness"

**Cause**: Harness not built.

**Solution**:
```bash
cd harness
./build.sh
cd ..
```

#### "Validation failed: smoke test acceptance too low"

**Cause**: Generated strategy rejects most inputs at the parser's front door.

**Solution**: This is normal during early iterations. The loop will request repairs. If it persists, check the strategy in `runs/*/iterations/iter-*/strategy.py`.

#### "Transcript exhausted after N calls"

**Cause**: Code changed since transcript was recorded.

**Solution**: Use a transcript that matches your code version, or regenerate with a real backend.

### Docker Issues

#### "Permission denied" when running ./run.sh

**Cause**: Script not executable.

**Solution**:
```bash
chmod +x run.sh
```

#### "seccomp=unconfined not supported"

**Cause**: Docker seccomp not available (some cloud environments).

**Solution**: Edit `run.sh` to remove `--security-opt seccomp=unconfined`, but be aware ASan may fail.

### Build Issues

#### "mxml.h: No such file or directory"

**Cause**: Mini-XML not fetched or not in expected location.

**Solution**:
```bash
./scripts/fetch_target.sh
```

#### "asan: Shadow memory range interleaves with an existing memory mapping"

**Cause**: Docker's default seccomp profile blocks personality() call.

**Solution**: Ensure `run.sh` includes `--security-opt seccomp=unconfined`.

### LLM Backend Issues

#### "claude CLI timed out after 1800s"

**Cause**: Strategy too complex or model slow.

**Solution**:
- Reduce `max-examples` or iteration count
- Use a faster model
- Check network connectivity

#### "usage limit reached"

**Cause**: API quota exceeded.

**Solution**:
- Wait for quota reset
- Use a different backend
- Reduce campaign size

### Performance Issues

#### Campaign running very slowly

**Possible causes**:
- Harness invocations slow (check with `time build/asan/harness < input.xml`)
- Too many examples per iteration
- LLM backend latency

**Solutions**:
- Reduce `max-examples`
- Use faster LLM model
- Check if sanitizers are slowing down (expected but shouldn't be extreme)

#### Out of memory

**Cause**: Large corpus or deep nesting.

**Solution**:
- Reduce `max-examples`
- Check strategy for runaway recursion
- Increase system RAM

## Next Steps

- Read [docs/design-decisions.md](docs/design-decisions.md) to understand engineering choices
- Review [docs/findings.md](docs/findings.md) for what the project discovered
- Examine [grammar/ADAPTATIONS.md](grammar/ADAPTATIONS.md) for grammar details
- Check [todo.md](todo.md) for future expansion ideas

## Getting Help

For issues specific to:
- **This framework**: Check the documentation and existing issues
- **Mini-XML**: See https://github.com/michaelrsweet/mxml
- **Hypothesis**: See https://hypothesis.readthedocs.io/
- **Claude Code**: See https://docs.anthropic.com/
- **OpenAI API**: See https://platform.openai.com/docs
