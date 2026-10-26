# Agent Directory

This directory contains the agentic loop implementation and LLM backend integrations. The agent is responsible for generating strategies, validating them, and iteratively refining them based on feedback from the fuzzing campaign.

## Components

### loop.py

The main agentic loop implementation. This is the core of the framework.

**Key responsibilities:**
- Orchestrates the iteration cycle (generate → validate → run → summarize → refine)
- Manages LLM backend instances
- Enforces budget caps (iterations and spend)
- Handles resume functionality for interrupted runs
- Maintains feedback unions across iterations

**Main classes:**
- `Loop`: Main loop controller with configuration
- `Budget`: Tracks LLM API usage and costs

**Usage:**
```python
from agent.loop import Loop

loop = Loop(
    backend_kind="openai",
    run_id="my-campaign",
    max_iterations=5,
    max_examples=500,
    max_usd=5.00,
)

loop.run()
```

### llm.py

Pluggable LLM backend implementations with a unified interface.

**Supported backends:**
- **cli**: Claude Code headless (subscription-backed)
- **openai**: Any OpenAI-compatible endpoint (OpenAI, Anthropic, Ollama, vLLM, gateways)
- **replay**: Replays recorded responses (no network, no credentials)

**Key classes:**
- `ClaudeCLIBackend`: Claude Code CLI integration
- `OpenAICompatBackend`: OpenAI-compatible API client
- `ReplayBackend`: Transcript replay for reproducibility
- `LLMResponse`: Standardized response structure

**Usage:**
```python
from agent.llm import make_backend

backend = make_backend("openai", transcript_dir="runs/my-run/transcript")
response = backend.complete(system_prompt, user_prompt)
```

**Features:**
- Automatic retry for transient failures (CLI backend)
- Usage limit detection to avoid wasted retries
- Credential redaction from error messages
- Cost tracking for budget enforcement

### validate.py

Four-gate validation system for LLM-generated strategies.

**Validation gates (in order):**
1. **Extract**: Pull Python code block from LLM response
2. **Truncated**: Detect if response head was lost in transport
3. **Syntax**: Compile the module with `compile()`
4. **Interface**: Import and test the `documents()` function
5. **Smoke**: Run 50 examples through real harness

**Key classes:**
- `Validation`: Validation result with stage and feedback
- `CLASS_BOUNDS`: Required input-class mixture (well_formed, near_miss, byte_hostile)

**Usage:**
```python
from agent.validate import validate

result = validate(llm_response_text, dest_path="fuzzer/strategies/my_strategy.py")
if not result.ok:
    # Send result.feedback() back to LLM for repair
    pass
```

**Smoke test metrics:**
- Acceptance rate must be 10-95%
- Input-class mixture enforced via CLASS_BOUNDS
- 7-point sampling margin for noise tolerance

### env.py

Environment configuration and helpers.

**Responsibilities:**
- Repository root path resolution
- Environment variable handling
- Configuration validation

### ensemble.py

Multi-model candidate generation and voting. Each model writes a strategy, the
strategy is screened on a small campaign, and a weighted Borda vote ranks the
measured results. The crash criterion has ten times the weight of the others, so
a candidate that found a bug beats a tidier candidate that did not.

**Key API:**
```python
from agent.ensemble import Candidate, vote_candidates

result = vote_candidates([
    Candidate("a", "gpt-5", source=code_a, summary=summary_a),
    Candidate("b", "claude", source=code_b, summary=summary_b),
])
print(result.winner.name, result.votes)
```

The vote is over measurements, not prose, so it adds no LLM calls and is
replayable. `EnsembleResult.to_json()` is written to `iterations/iter-N/ensemble.json`.

### strategy_cache.py

Persistent cache of validated strategies keyed by target similarity.

`TargetProfile` combines target name, category, grammar hash, production
vocabulary and class bounds. The default threshold of 0.70 means two XML
parsers are neighbours (0.80-1.00) while XML and JSON are not (below 0.10).
A cached strategy is always re-validated against the current target; similarity
only decides what to retrieve.

```python
from agent.strategy_cache import StrategyCache
cache = StrategyCache("runs/.strategy_cache", min_similarity=0.70)
cache.store(source, target, summary, run_id, iteration)
matches = cache.lookup(get_target("expat"))
```

### tuning.py

Adapts loop hyperparameters from the measurements the loop already collects:

- `examples`: hill-climbs on marginal yield per document
- `repairs`: rises after a gate/campaign failure, falls after a clean streak
- `directive`: UCB1 over the rotating refinement directives
- state is persisted to `tuning.json`, so `--resume-from` continues the search

### fewshot.py

Scans `runs/*/iterations/iter-*/` and ranks past strategies with the shared
scoring function. Similarity filtering prevents an XML strategy being offered
to a DNS target. Long strategies are excerpted as head + tail so the
`documents()` entry point survives truncation. The rendered block is appended
to the seed/refine prompt and saved as `few_shot.md`.

### harness_gen.py

Generates a target-specific C/C++ harness from the target's metadata and grammar.
Before writing `harness.c`, the structural gate requires: `main`, stdin reading,
`DIAG<TAB>` output, all four exit codes, required headers, balanced delimiters,
and no shell/process/socket calls. `--compile` builds with ASan+UBSan.

```bash
python -m agent.harness_gen --target expat --backend openai --compile
```

### prompts/

Directory containing prompt templates for different versions.

**Prompt versions:**
- **v1**: Original prompts (acceptance, diagnostics, features)
- **v2**: Added marginal feedback, input classes, rotating directives
- **v3-v5**: Further refinements (size boundaries, validation rules)

**Each version contains:**
- `system.md`: System prompt for the LLM
- `seed.md`: Initial strategy generation prompt
- `refine.md`: Refinement prompt with feedback
- `directives.md`: Rotating refinement directives (v2+)

**Key prompt components:**
- Grammar rules (XMLParser.g4, XMLLexer.g4)
- Production list (27 tracked features)
- Feedback summary structure
- Input-class requirements

## The Agentic Loop

### Iteration Flow

```
1. GENERATE
   ├─ Load system prompt
   ├─ Load user prompt (seed or refine)
   ├─ Call LLM backend
   └─ Save response to transcript

2. VALIDATE
   ├─ Extract Python code
   ├─ Check for truncation
   ├─ Compile syntax
   ├─ Test interface
   ├─ Run smoke test (50 examples)
   └─ If failed: request repair (max 2 repairs)

3. RUN
   ├─ Import strategy module
   ├─ Run Campaign with 500 examples
   ├─ Collect results and summaries
   └─ Save artifacts

4. SUMMARIZE
   ├─ Calculate acceptance rate
   ├─ Count distinct diagnostics
   ├─ Measure structural coverage
   ├─ Group crashes by signature
   └─ Build feedback summary

5. REFINE
   ├─ Load previous strategy
   ├─ Load previous summary
   ├─ Construct refine prompt
   ├─ Add rotating directive
   └─ Back to step 1
```

### Budget Enforcement

Two budget axes:
- **Iteration cap**: Maximum number of iterations (default: 5)
- **Spend cap**: Maximum USD cost (default: $5.00)

The budget check refuses a call when the remaining budget cannot cover the running average call cost, preventing overshoot.

### Resume Functionality

Interrupted runs can be resumed:

```bash
python -m agent.loop --backend replay --run-id my-run --resume-from 2
```

Resume:
- Restores budget from transcript
- Restores feedback unions (diagnostics, productions seen)
- Starts at the specified iteration
- Reuses existing artifacts (strategy, summary, results)

## LLM Backend Selection

### Replay Mode (Default)

No credentials needed. Replays recorded transcripts.

**Pros:**
- No cost
- No network dependency
- Fully reproducible
- Fast

**Cons:**
- Requires an existing transcript
- Cannot generate new strategies

**Use for:**
- Reproducing historical runs
- Testing framework changes
- Development and debugging

### Claude Code CLI

Uses Claude subscription (not API credits).

**Pros:**
- Subscription-based billing
- Access to latest models
- No separate API key management

**Cons:**
- Requires Claude Code CLI installation
- Subscription limits apply
- Slower than direct API

**Configuration:**
```bash
LLM_BACKEND=cli
CLAUDE_CODE_OAUTH_TOKEN=<token>
```

### OpenAI-Compatible

Works with OpenAI, Anthropic, local models, gateways.

**Pros:**
- Most flexible
- Can use local models (Ollama, vLLM)
- Can use gateways/proxies
- Per-token pricing

**Cons:**
- Requires API key
- Cost varies by provider
- No cost reporting from some providers

**Configuration:**
```bash
LLM_BACKEND=openai
OPENAI_API_KEY=<key>
OPENAI_BASE_URL=<url>
LLM_MODEL=<model>
```

**Examples:**
```bash
# OpenAI
OPENAI_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-5

# Anthropic (via OpenAI-compatible layer)
OPENAI_BASE_URL=https://api.anthropic.com/v1
LLM_MODEL=claude-sonnet-5

# Local Ollama
OPENAI_BASE_URL=http://localhost:11434/v1
LLM_MODEL=llama2
```

## Transcript Structure

All LLM interactions are recorded for reproducibility:

```
runs/<run-id>/transcript/
├── call-1/
│   ├── system.md          # System prompt
│   ├── user.md            # User prompt
│   ├── meta.json          # Call metadata (tag, call number)
│   └── response.json      # LLM response with usage stats
├── call-2/
└── ...
```

**Response metadata:**
- `backend`: Which backend was used
- `model`: Model name
- `input_tokens`: Prompt token count
- `output_tokens`: Response token count
- `cache_read_tokens`: Cached input tokens
- `cache_write_tokens`: Cache creation tokens
- `cost_usd`: Cost in USD (if reported)
- `tag`: Call type (seed, refine, repair)
- `elapsed_s`: Wall-clock time

## Error Handling

### Transient Failures

The CLI backend automatically retries transient failures:
- Non-zero exit with little/no stderr
- Backoff: 15s, 60s, 180s, 420s, 900s
- Max 5 retries

### Usage Limits

Usage limits are detected and reported immediately:
- No retries on usage limit errors
- Run stops to avoid wasting budget
- Clear error message

### Validation Failures

Failed validation triggers a repair request:
- Max 2 repairs per iteration
- Specific feedback per failure stage
- If repairs exhausted, iteration fails

## Configuration

### Environment Variables

From `.env` or shell:

```bash
LLM_BACKEND=replay|openai|cli
LLM_MODEL=<model>                    # Optional override
OPENAI_API_KEY=<key>                # For openai backend
OPENAI_BASE_URL=<url>               # For openai backend
CLAUDE_CODE_OAUTH_TOKEN=<token>     # For cli backend
```

### Loop Parameters

```python
Loop(
    backend_kind="replay",          # Backend to use
    run_id="run",                   # Run identifier
    max_examples=500,              # Examples per iteration
    max_iterations=5,               # Max iterations
    max_usd=5.00,                  # Cost cap in USD
    model=None,                     # Model override
    base_url=None,                  # Base URL override
    resume_from=0,                  # Resume from iteration
    prompt_set="v2",                # Prompt version
    seed_model=None,                # Model for seed
    refine_model=None,              # Model for refinement
)
```

## Agent Enhancements

All enhancements are opt-in. The defaults leave the call sequence unchanged,
which is what keeps `--backend replay` working against existing transcripts.

| Flag | Effect | Artifacts |
|---|---|---|
| `--ensemble-models m1,m2` | one candidate per model; screen and vote | `iterations/iter-N/ensemble.json` |
| `--ensemble-candidates N` | N samples of the same model when no list | same |
| `--screening-examples N` | examples per ensemble screening campaign | same |
| `--use-strategy-cache` | reuse a validated strategy from a similar target | `iterations/iter-N/cache_hit.json`, `runs/.strategy_cache/` |
| `--cache-similarity F` | retrieval threshold (default 0.70) | same |
| `--few-shot` | append ranked past strategies to prompts | `iterations/iter-N/few_shot.md` |
| `--autotune` | adapt examples, repairs, and directive | `tuning.json` |
| `--use-generated-harness` | run against `harness/generated/<target>/` | harness binary |

### Replay safety

Caching a seed can remove an LLM call, and an ensemble adds calls. Both change
the transcript, so both are off by default. Ensemble is explicitly disabled
under `--backend replay`; cache and few-shot are safe to use with replay only
when the cache is empty or the transcript was recorded with them enabled.

### Cache lifecycle

A strategy enters the cache after its campaign completes, so every entry has
measured results and a score. Entries are deduplicated by source + target, and
the cache keeps the best 200. Delete `runs/.strategy_cache/` to start fresh.

### Tuning state

`tuning.json` records the current examples/repairs values, per-directive UCB
statistics and the full observation history. Delete it (or pass `--tune-state`
elsewhere) to restart the search. On `--resume-from`, the state is restored and
the search continues rather than restarting.

## See Also

- `fuzzer/campaign.py` - Campaign execution and measurement
- `fuzzer/runner.py` - Harness execution and classification
- `docs/design-decisions.md` - Design decisions related to the agent
- `getstart.md` - Usage guide for running campaigns
