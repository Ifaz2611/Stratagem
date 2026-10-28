# Fuzzer Directory

This directory contains the fuzzing engine that executes strategies, measures results, and analyzes the generated inputs. It works with the agent (which generates strategies) and the harness (which executes against the target).

## Components

### campaign.py

Runs a strategy through the harness for a bounded number of examples.

**Key responsibilities:**
- Import and execute generated strategies
- Serialize documents to bytes (surrogateescape handling)
- Run harness for each example
- Collect results, features, and crash data
- Summarize statistics (acceptance, diagnostics, coverage)
- Persist artifacts (corpus, crashes, results)

**Main class:**
- `Campaign`: Configurable campaign runner

**Modes:**
- **survey**: Run all examples without asserting (default for agentic loop)
- **hunt**: Assert "no crash" to trigger Hypothesis's shrinker (for minimization)

**Usage:**
```python
from fuzzer.campaign import Campaign

campaign = Campaign(
    strategy_name="my_strategy",
    max_examples=500,
    out_dir="runs/my-campaign",
    mode="survey",
)

summary = campaign.run()
```

**Hypothesis settings:**
- `deadline=None`: No per-example timeout (spawning process is slow)
- `database=None`: No caching across iterations
- `derandomize=True`: Fixed sequence for reproducibility
- `suppress_health_check`: Disable too_slow/data_too_large checks

### runner.py

Executes the harness against one generated input and classifies the result.

**Key responsibilities:**
- Spawn harness process with input
- Parse stdout protocol (DIAG, RESULT lines)
- Check stderr for sanitizer markers
- Classify outcome (parsed, rejected, crash, timeout)
- Extract diagnostics from parser

**Main class:**
- `RunResult`: Classification result with metadata

**Outcome enum:**
- `PARSED_CLEAN`: Exit 0, no diagnostics
- `PARSED_DIAG`: Exit 3, parsed with diagnostics
- `REJECTED`: Exit 1, well-formed rejection
- `HARNESS_ERROR`: Exit 2, our fault
- `CRASH`: Signal or sanitizer report
- `TIMEOUT`: Process hung (5s timeout)

**Usage:**
```python
from fuzzer.runner import run_one

result = run_one(document_bytes, harness="build/asan/harness")
print(result.outcome)  # Outcome enum
print(result.diagnostics)  # List of parser messages
```

**Sanitizer detection:**
- Looks for "AddressSanitizer", "UndefinedBehaviorSanitizer", "LeakSanitizer"
- Any match → classified as crash
- UBSan configured to abort (see design-decisions.md D3)

### features.py

Structural analysis of generated documents.

**Key responsibilities:**
- Detect which grammar productions appear in documents
- Measure nesting depth and structural diversity
- Classify documents into buckets (well_formed, near_miss, byte_hostile)
- Track boundary measures (name lengths, attribute counts, etc.)

**Main classes:**
- `Features`: Feature set for one document
- `PRODUCTIONS`: 27 tracked production names

**Production categories:**
- Grammar productions: `g_prolog`, `g_element_paired`, `g_attribute_dquot`, etc.
- Adaptations (mxml accepts, grammar cannot): `x_attribute_unquoted`, `x_doctype`, etc.
- Near-miss (rejected by mxml): `x_mismatched_tags`, `x_entity_unsupported`, etc.
- Byte-level: `x_bom`, `x_invalid_utf8`, `x_embedded_nul`, etc.

**Buckets:**
- `well_formed`: Should parse cleanly
- `near_miss`: Structurally wrong but XML-shaped
- `byte_hostile`: Encoding issues, control bytes, truncation

**Usage:**
```python
from fuzzer.features import analyze, coverage

# Analyze one document
features = analyze(document_text, payload_bytes)
print(features.productions)  # Set of productions
print(features.bucket)  # Classification
print(features.max_depth)  # Nesting depth

# Aggregate over a campaign
coverage_summary = coverage(feature_list)
print(coverage_summary["productions_hit"])  # Number covered
print(coverage_summary["missing"])  # Productions not seen
```

**Design choice:**
- Post-hoc scanning (not generator-instrumented)
- Keeps strategy contract small: `documents() -> SearchStrategy[str]`
- Same measurement for baseline and all strategies

### diagnostics.py

Normalization and histogram of parser diagnostic messages.

**Key responsibilities:**
- Normalize diagnostic templates (remove variable text)
- Count occurrences of each template
- Provide distinct count as coverage proxy

**Usage:**
```python
from fuzzer import diagnostics

# From a list of diagnostic strings
templates = diagnostics.histogram(diagnostic_list)
# Returns: {"template text": count, ...}

distinct = len(templates)
```

**Normalization rules:**
- Remove numbers, file paths, line numbers
- Standardize whitespace
- Keep error type and location structure

### triage.py

Crash deduplication and grouping.

**Key responsibilities:**
- Normalize stack traces
- Group crashes by signature
- Generate human-readable labels

**Key function:**
- `group(crash_records)`: Groups crashes by normalized signature

**Normalization:**
- Remove repeated recursive frames
- Remove address changes
- Remove line number changes
- Keep function names and structure

**Usage:**
```python
from fuzzer import triage

groups = triage.group(crash_records)
# Returns: {signature: {"count": N, "label": "...", ...}}
```

**Limitations:**
- Stack-based signatures are estimates
- Can merge different bugs or split one bug (Klees et al.)
- Kept as best-effort deduplication

### corpus.py

Corpus persistence and management.

**Key responsibilities:**
- Write generated inputs to disk
- Base64-encode payloads (may contain NULs or invalid bytes)
- Compress with gzip
- Generate manifest with metadata

**Usage:**
```python
from fuzzer import corpus

manifest = corpus.write_corpus(output_path, payload_list)
# Returns manifest with counts and hashes
```

**Format:**
- JSONL with one record per line
- Each record: base64-encoded payload + metadata
- Gzipped for disk efficiency

### minimize.py

Crash minimization using Hypothesis's shrinker.

**Key responsibilities:**
- Re-run crashes in "hunt" mode
- Let Hypothesis shrink to minimal example
- Save shrunk input

**Usage:**
```python
from fuzzer.minimize import minimize_crash

shrunk = minimize_crash(original_payload, strategy_path)
```

### selftest.py

Self-test suite for the fuzzer components.

**Responsibilities:**
- Test feature extraction on known inputs
- Verify runner classification
- Check corpus encoding/decoding

**Usage:**
```python
python -m fuzzer.selftest
```

### strategies/

Directory for generated strategy modules.

**Strategy contract:**
```python
from hypothesis import strategies as st

NAME = "strategy_name"
DESCRIPTION = "Human-readable description"

def documents() -> st.SearchStrategy[str]:
    """Return a Hypothesis strategy for generating XML documents."""
    return st.recursive(...)
```

**Built-in strategies:**
- `baseline.py`: Random text baseline
- `byte_probe.py`: Fixed byte-oriented test cases

**Generated strategies:**
- Named `gen_iter0`, `gen_iter1`, etc.
- Written by the agent during campaigns
- Each iteration produces one strategy

## Data Flow

```
1. Agent generates strategy
   ↓
2. Campaign imports strategy
   ↓
3. Campaign draws examples via Hypothesis
   ↓
4. Runner executes harness for each example
   ↓
5. Features analyzes each document
   ↓
6. Campaign aggregates results
   ↓
7. Summary sent back to agent
```

## Key Design Decisions

### Encoding (D13)

Generated strategies return Python `str`, but mxml receives bytes. The serializer handles this:

- U+DC80..U+DCFF → raw bytes 0x80..0xFF (surrogateescape)
- A valid UTF-16 surrogate pair → one UTF-8 scalar (e.g. U+D83D U+DE00 → 😀)
- Other lone surrogates → invalid UTF-8 (surrogatepass)
- Regular text → UTF-8

Pairs are combined before the raw-byte rule, so `"\ud83d\udc80"` is U+1F080 rather than a high surrogate followed by the sentinel for 0x80. This preserves raw byte-oriented cases (UTF-16 BOMs, malformed UTF-8) through the str-only interface.

### Mode Selection

Two modes because Hypothesis serves different purposes:

- **survey**: Never assert, collect statistics over all examples
  - Used by agentic loop for feedback
  - Measures acceptance, diversity, coverage

- **hunt**: Assert "no crash", trigger shrinker
  - Used for crash minimization
  - Hypothesis automatically shrinks failing example

### Timeout Handling

- Per-run timeout: 5 seconds (prevents hangs)
- Wall-clock cap: 10 minutes per iteration
- Timeout → classified as crash (not slow success)

### Sanitizer Environment

Set in Python, not inherited from shell:

```python
SANITIZER_ENV = {
    "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:...",
    "UBSAN_OPTIONS": "halt_on_error=1:abort_on_error=1:...",
}
```

Ensures consistent configuration regardless of user's shell.

## Output Files

### Per Iteration

```
runs/<run-id>/iterations/iter-N/
├── strategy.py              # Generated strategy
├── summary.json             # Statistics
├── results.jsonl            # Per-input results
├── corpus.jsonl.gz         # Generated inputs
└── crashes/                # Crash artifacts (if any)
    ├── <sha>.xml           # Crashing input
    └── <sha>.stderr.txt    # Sanitizer output
```

### Summary Structure

```json
{
  "strategy": "gen_iter0",
  "examples": 500,
  "acceptance_rate": 0.46,
  "outcomes": {
    "parsed_clean": 150,
    "parsed_diag": 80,
    "rejected": 270
  },
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
  }
}
```

## Running Single Strategies

For testing without the agentic loop:

```bash
python -m fuzzer.campaign baseline \
  --max-examples 500 \
  --out runs/baseline-test
```

With a specific seed:

```bash
python -m fuzzer.campaign my_strategy \
  --seed 11 \
  --max-examples 500 \
  --out runs/trial-11
```

In hunt mode (crash minimization):

```bash
python -m fuzzer.campaign my_strategy \
  --mode hunt \
  --max-examples 1000 \
  --out runs/hunt
```

## Advanced Fuzzing Capabilities

### Parallel Fuzzing (`fuzzer/parallel.py`)

Run multiple campaigns concurrently across targets, strategies, or random seeds.

```bash
# Run multiple targets in parallel
python -m fuzzer.parallel --strategy baseline --targets mxml json http --workers 3

# Run multiple strategies against one target
python -m fuzzer.parallel --strategies baseline byte_probe --target mxml --workers 2

# Run multiple trials across random seeds for statistical evaluation
python -m fuzzer.parallel --strategy baseline --seeds 1 2 3 4 5 --workers 4
```

Python API:
```python
from fuzzer.parallel import ParallelCampaignRunner, CampaignTask, run_parallel_targets

summary = run_parallel_targets(
    strategy="baseline",
    targets=["mxml", "json", "http"],
    max_examples=500,
    max_workers=3,
)
print(f"Completed {summary.completed_campaigns} in {summary.total_wall_clock_s:.2f}s")
```

### Adaptive Batch Sizes (`fuzzer/batching.py`)

Dynamically adjusts batch size based on strategy feedback:
- Scales **up** when new crashes, productions, or diagnostic templates are found
- Scales **up** when within the target acceptance rate window
- Scales **down** when generating malformed / invalid shape inputs
- Scales **down** on timeouts or latency spikes
- Clamped strictly between `min_batch_size` and `max_batch_size`

```bash
python -m fuzzer.campaign baseline --target mxml --adaptive-batch
```

Python API:
```python
from fuzzer.batching import AdaptiveBatchController, AdaptiveBatchConfig

controller = AdaptiveBatchController(
    AdaptiveBatchConfig(initial_batch_size=50, min_batch_size=10, max_batch_size=500)
)
```

### Intelligent Corpus Management (`fuzzer/corpus.py`)

Provides deduplication, feature tracking, energy-based prioritization, and coverage-guided distillation:
- **Exact Deduplication**: SHA-256 hash checking prevents redundant storage
- **Semantic Deduplication**: Filters inputs sharing identical behavior signatures `(outcome, diagnostics, productions)`
- **Coverage-Guided Distillation**: Greedy Set Cover algorithm selects the minimal subset of inputs that preserves 100% feature coverage
- **Energy / Priority Scoring**: Rarity of covered productions and diagnostic templates, compactness, and execution speed determine seed weight

```python
from fuzzer.corpus import CorpusManager

mgr = CorpusManager()
mgr.add(payload, outcome="parsed_clean", productions=["g_element_paired"])

# Distill corpus to minimal set covering all features
distilled = mgr.distill()
distilled.export_corpus(Path("runs/corpus_distilled.jsonl.gz"))
```

### Timeout & Slow Input Handling

Detects and quarantines pathological inputs:
- Per-input timeout cap (`timeout_s`, default 5.0s) catches hangs
- Slow input threshold (`slow_threshold_s`, default 1.0s) tracks high-latency inputs
- Automatic streak detection halts execution if consecutive hangs occur
- Artifact isolation:
  - `timeouts/*.bin` and `timeouts/*.meta.json`
  - `slow_inputs/*.bin` and `slow_inputs/*.meta.json`

```bash
python -m fuzzer.campaign baseline --timeout 2.5 --slow-threshold 0.5
```

### Incremental Campaign Persistence

Safeguards long-running campaigns against interruption:
- Streaming `results.jsonl` with flush
- Immediate write of crashes to `crashes/` as they occur
- Periodic checkpointing (`checkpoint.json`) every `checkpoint_interval` inputs
- Seamless resumption via `--resume` without losing completed progress
- Graceful `SIGINT` (Ctrl+C) handling preserving intermediate summaries

```bash
# Long running test with checkpoints every 25 inputs
python -m fuzzer.campaign baseline -n 500 --checkpoint-interval 25

# Resume an interrupted campaign
python -m fuzzer.campaign baseline -n 500 --resume --out runs/my-run
```

## Performance Considerations

### Process Spawning

Each harness invocation spawns a process. This is slower than in-process but:
- Isolates crashes (doesn't kill the fuzzer)
- Allows sanitizer to detect real failures
- Necessary for blackbox testing

### Corpus Persistence

All payloads are retained for:
- Exact reproducibility
- Replay without regenerating
- Post-run analysis

Compression (gzip) mitigates disk usage.

### Feature Analysis

Post-hoc scanning adds overhead but:
- Keeps strategy contract simple
- Ensures consistent measurement
- Acceptable for 500 examples/iteration

## See Also

- `agent/loop.py` - Agentic loop that uses Campaign
- `agent/validate.py` - Strategy validation before campaign
- `harness/harness.c` - C harness executed by Runner
- `docs/design-decisions.md` - Design decisions D10, D11, D13
