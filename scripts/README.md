# Scripts Directory

This directory contains utility scripts for fetching dependencies, measuring coverage, and analyzing results.

## Dependency Management

### fetch_grammar.sh

Downloads the ANTLR XML grammar from the `antlr/grammars-v4` repository at a pinned commit.

**Usage:**
```bash
./scripts/fetch_grammar.sh [--force]
```

**What it does:**
- Fetches `XMLLexer.g4` and `XMLParser.g4` from GitHub at commit `e756f2a2ee5565a9300666f100ba6acd874664f7`
- Verifies SHA256 checksums for reproducibility
- Creates `grammar/SOURCE.txt` with provenance information
- Skips download if files already match expected checksums (unless `--force` is used)

**Why pinning matters:**
- The grammar is a living repository; unpinned downloads would change over time
- Checksum verification ensures we're fuzzing against the exact grammar described in documentation
- Raw URL fetch is faster than full git clone for two small files

### fetch_target.sh

Clones the Mini-XML library at the exact pinned commit.

**Usage:**
```bash
./scripts/fetch_target.sh
```

**What it does:**
- Clones mxml from GitHub to `third_party/mxml`
- Checks out commit `0d5afc4278d7a336d554602b951c2979c3f8f296` (v4.0.4)
- Verifies the actual commit SHA matches the expected one
- Skips if already at the correct commit

**Why pinning matters:**
- Ensures reproducibility across different machines and time
- Prevents accidental fuzzing of different code versions
- The pinned tag (v4.0.4) is the latest stable release with no functional differences from main

## Coverage Analysis

### coverage_trials.py

Runs a strategy multiple times with different Hypothesis seeds to measure variance in coverage results.

**Usage:**
```bash
python scripts/coverage_trials.py <strategy_name> <output_dir>
```

**What it does:**
- Runs the specified strategy at seeds 11, 22, and 33
- Each trial uses 500 inputs
- Collects gcov line coverage of `mxml-file.c`
- Outputs mean and standard deviation across trials
- Writes results to `runs/analysis/coverage_trials.json`

**Why multiple seeds:**
- Hypothesis strategies produce different samples on each run
- A single sample is too unstable for comparison (observed 2.4 point variance)
- Three trials reduce input-sampling noise to measure true strategy quality

### coverage_study.py

Comprehensive coverage analysis across multiple saved strategies.

**Usage:**
```bash
python scripts/coverage_study.py
```

**What it does:**
- Iterates through saved strategies from historical runs
- Runs each at seeds 11, 22, 33
- Aggregates coverage statistics
- Generates comparison tables for analysis

**Output:**
- Coverage data in `runs/analysis/`
- Comparison tables used in `docs/comparison.md`

### coverage_from_corpus.py

Measures coverage from a saved corpus of inputs.

**Usage:**
```bash
python scripts/coverage_from_corpus.py <corpus_path> <output_dir>
```

**What it does:**
- Reads a saved corpus (JSONL format with base64-encoded inputs)
- Feeds each input through the harness
- Measures what parser code each input reaches
- Useful for understanding which inputs hit which coverage

## Result Analysis

### verify_replay.sh

Verifies that a replay run reproduces the original results exactly.

**Usage:**
```bash
./scripts/verify_replay.sh <run_id>
```

**What it does:**
- Rebuilds each generated strategy from the saved LLM transcript
- Re-runs the strategy through the harness
- Compares classifications and corpus digests with the original run
- Validates that both five-iteration historical runs replay all 2,500 classifications correctly

**Why this matters:**
- Ensures reproducibility of the agentic loop
- Confirms the transcript capture is complete
- Validates that strategy files match byte-for-byte

### make_iteration_log.py

Generates a human-readable iteration log from a run's artifacts.

**Usage:**
```bash
python scripts/make_iteration_log.py <run_id>
```

**What it does:**
- Reads iteration summaries from `runs/<run_id>/iterations/iter-*/summary.json`
- Creates a markdown table showing progression across iterations
- Outputs to `runs/<run_id>/ITERATION_LOG.md`

**Example output:**
```
| iteration | strategy   | acceptance | diagnostics | coverage |
|-----------|------------|------------|-------------|----------|
| 0         | gen_iter0  | 46.0%      | 15          | 41.82%   |
| 1         | gen_iter1  | 48.2%      | 17          | 43.30%   |
```

### recompute_features.py

Recomputes feature analysis for a saved corpus.

**Usage:**
```bash
python scripts/recompute_features.py <corpus_path>
```

**What it does:**
- Re-scans saved documents with the current feature analyzer
- Useful when the feature analysis code has been updated
- Updates feature counts without regenerating inputs

### leak_pass.py

Runs a separate leak detection pass with LeakSanitizer enabled.

**Usage:**
```bash
python scripts/leak_pass.py <run_id>
```

**What it does:**
- Re-runs a campaign with `ASAN_OPTIONS=detect_leaks=1`
- Collects leak signatures across all inputs
- Outputs leak statistics to `runs/analysis/leak_pass.json`

**Why separate pass:**
- Main campaigns run with `detect_leaks=0` to avoid known leak dominating results
- mxml leaks on `<a a>` error path (8.2% of historical corpus)
- Separate pass keeps leak results without mixing with fatal memory errors

## Example Workflow

```bash
# 1. Fetch dependencies
./scripts/fetch_grammar.sh
./scripts/fetch_target.sh

# 2. Run a campaign
python -m agent.loop --backend replay --run-id my-run

# 3. Generate iteration log
python scripts/make_iteration_log.py my-run

# 4. Measure coverage with multiple trials
python scripts/coverage_trials.py gen_iter0 runs/my-run/coverage

# 5. Verify reproducibility
./scripts/verify_replay.sh my-run

# 6. Run leak detection
python scripts/leak_pass.py my-run
```

## Script Requirements

- Bash 4.0+ for shell scripts
- Python 3.10+ for Python scripts
- Git for fetch_target.sh
- curl for fetch_grammar.sh
- gcov/lcov for coverage scripts
- Mini-XML built with --coverage flag for coverage analysis

## Notes

- All scripts are designed to be idempotent (safe to run multiple times)
- Fetch scripts verify checksums to ensure reproducibility
- Coverage scripts require a separate build with `--coverage` enabled
- Analysis scripts assume the standard `runs/` directory structure
