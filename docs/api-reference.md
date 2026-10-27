# API Reference

This document provides API documentation for the key modules in Stratagem.

## Table of Contents

- [Agent Loop (`agent.loop`)](#agent-loop-agentloop)
- [LLM Backends (`agent.llm`)](#llm-backends-agentllm)
- [Campaign Execution (`fuzzer.campaign`)](#campaign-execution-fuzzercampaign)
- [Target Abstraction (`fuzzer.targets.base`)](#target-abstraction-fuzzertargetsbase)
- [Validation (`agent.validate`)](#validation-agentvalidate)
- [Strategy Cache (`agent.strategy_cache`)](#strategy-cache-agentstrategy_cache)
- [Ensemble (`agent.ensemble`)](#ensemble-agentensemble)

---

## Agent Loop (`agent.loop`)

The agentic loop is the core of Stratagem, orchestrating strategy generation, validation, execution, and refinement.

### Main Classes

#### `Budget`

Budget tracking for LLM API costs and iteration limits.

```python
@dataclass
class Budget:
    max_iterations: int = 5
    max_usd: float = 5.00
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    billable_input: int = 0
    cost_usd: float = 0.0
    authored_chars: int = 0
```

**Methods:**

- `add(response: LLMResponse, prompt_chars: int) -> None`: Add response metrics to budget
- `exhausted -> bool`: Check if budget limits have been reached

**Example:**

```python
from agent.loop import Budget

budget = Budget(max_iterations=10, max_usd=10.00)
budget.add(llm_response, prompt_chars=1000)

if budget.exhausted:
    print("Budget exhausted")
```

#### `IterationResult`

Result of a single agentic loop iteration.

```python
@dataclass
class IterationResult:
    iteration: int
    strategy_code: str
    validation_passed: bool
    summary: dict
    repair_count: int
    duration_s: float
```

### Main Functions

#### `run_loop(config: LoopConfig) -> FinalSummary`

Run the complete agentic fuzzing loop.

**Parameters:**

- `config`: Configuration object containing:
  - `backend`: LLM backend to use ("replay", "openai", "cli")
  - `target`: Target parser name
  - `run_id`: Unique identifier for this run
  - `max_iterations`: Maximum number of iterations
  - `max_examples`: Examples per iteration
  - `max_usd`: Maximum USD to spend on LLM calls

**Returns:**

- `FinalSummary`: Aggregated results across all iterations

**Example:**

```python
from agent.loop import run_loop
from dataclasses import dataclass

@dataclass
class LoopConfig:
    backend: str = "replay"
    target: str = "mxml"
    run_id: str = "my-campaign"
    max_iterations: int = 5
    max_examples: int = 500
    max_usd: float = 5.00

config = LoopConfig()
summary = run_loop(config)
print(f"Total strategies: {summary.total_strategies}")
print(f"Best coverage: {summary.best_coverage}")
```

---

## LLM Backends (`agent.llm`)

Pluggable LLM backends for the agentic loop.

### Classes

#### `LLMResponse`

Response from an LLM backend.

```python
@dataclass
class LLMResponse:
    text: str
    backend: str
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    cost_usd: float | None = None
    raw: dict = field(default_factory=dict)
    streaming: bool = False
    duration_s: float = 0.0
    time_to_first_token_s: float | None = None
    tokens_per_second: float = 0.0
    fallback_used: bool = False
    fallback_from: str = ""
```

**Properties:**

- `billable_input -> int`: Total billable input tokens including cache traffic

**Methods:**

- `to_json() -> dict`: Convert response to JSON-serializable dict

**Example:**

```python
from agent.llm import LLMResponse

response = LLMResponse(
    text="def strategy(): ...",
    backend="openai",
    model="gpt-5",
    input_tokens=1000,
    output_tokens=500,
    cost_usd=0.01
)

print(f"Cost: ${response.cost_usd}")
print(f"Billable tokens: {response.billable_input}")
```

#### `LLMBackend`

Abstract base class for LLM backends.

**Methods:**

- `call(system: str, user: str, **kwargs) -> LLMResponse`: Make an LLM call
- `stream(system: str, user: str, **kwargs) -> Iterator[LLMResponse]`: Stream LLM response

**Available Backends:**

1. **`ReplayBackend`**: Replays recorded responses from disk (no credentials needed)
2. **`OpenAIBackend`**: Uses OpenAI-compatible API endpoints
3. **`CLIBackend`**: Uses Claude Code headless CLI

**Example:**

```python
from agent.llm import get_backend

# Get backend by name
backend = get_backend("replay", run_id="my-run")

# Make a call
response = backend.call(
    system="You are a fuzzing strategy generator.",
    user="Generate a strategy for XML parsing."
)

print(response.text)
```

### Functions

#### `get_backend(backend_name: str, **kwargs) -> LLMBackend`

Factory function to get an LLM backend instance.

**Parameters:**

- `backend_name`: One of "replay", "openai", "cli"
- `run_id`: For replay backend, the run ID to replay
- `model`: Model name (for openai/cli backends)
- `fallbacks`: List of fallback backend names

**Returns:**

- `LLMBackend`: Configured backend instance

**Example:**

```python
from agent.llm import get_backend

# Replay mode (default, no credentials)
backend = get_backend("replay", run_id="loop")

# OpenAI API
backend = get_backend("openai", model="gpt-5")

# Claude Code CLI
backend = get_backend("cli", model="sonnet")

# With fallbacks
backend = get_backend("openai", fallbacks=["cli", "replay"])
```

---

## Campaign Execution (`fuzzer.campaign`)

Runs fuzzing strategies through the harness and collects results.

### Classes

#### `Campaign`

Main campaign execution class.

```python
@dataclass
class Campaign:
    strategy_name: str
    max_examples: int
    out_dir: Path
    harness: Path = DEFAULT_HARNESS
    mode: str = "survey"
    extra_args: tuple[str, ...] = ()
    random_seed: int | None = None
    wall_clock_cap_s: float = MAX_WALL_CLOCK_S
    target: Any = "mxml"
```

**Parameters:**

- `strategy_name`: Name of the strategy module to load
- `max_examples`: Maximum number of examples to generate
- `out_dir`: Output directory for results
- `harness`: Path to harness binary
- `mode`: Execution mode ("survey", "fast", "deep")
- `extra_args`: Additional arguments to pass to harness
- `random_seed`: Random seed for reproducibility
- `wall_clock_cap_s`: Maximum wall-clock time for campaign
- `target`: Target parser to fuzz

**Methods:**

- `run() -> CampaignResult`: Execute the campaign
- `load_strategy() -> SearchStrategy`: Load the strategy module
- `save_results(results: list) -> None`: Save results to disk

**Example:**

```python
from fuzzer.campaign import Campaign
from pathlib import Path

campaign = Campaign(
    strategy_name="baseline",
    max_examples=500,
    out_dir=Path("runs/my-campaign"),
    target="mxml"
)

result = campaign.run()
print(f"Acceptance rate: {result.acceptance_rate}")
print(f"Coverage: {result.coverage}")
```

#### `CampaignResult`

Results from a campaign execution.

```python
@dataclass
class CampaignResult:
    total_examples: int
    acceptance_rate: float
    coverage: float
    crashes: int
    timeouts: int
    diagnostics: dict
    features: dict
    duration_s: float
```

### Functions

#### `run_one_campaign(args: argparse.Namespace) -> CampaignResult`

Run a single campaign from command-line arguments.

**Parameters:**

- `args`: Parsed command-line arguments

**Returns:**

- `CampaignResult`: Campaign execution results

**Example:**

```python
import argparse
from fuzzer.campaign import run_one_campaign

parser = argparse.ArgumentParser()
parser.add_argument("--target", default="mxml")
parser.add_argument("--max-examples", type=int, default=500)
args = parser.parse_args()

result = run_one_campaign(args)
```

---

## Target Abstraction (`fuzzer.targets.base`)

The target abstraction layer provides a uniform interface for fuzzing different parsers and protocols.

### Classes

#### `BaseTarget`

Abstract base class for fuzzing targets.

```python
class BaseTarget(abc.ABC):
    name: str = "base"
    category: str = "xml"
    description: str = "Base target"
    harness_binary: Path | None = None
    grammar_file: Path | None = None
    productions: tuple[str, ...] = ()
    class_bounds: dict[str, tuple[float, float]] = {
        "well_formed": (0.35, 1.0),
        "near_miss": (0.15, 1.0),
        "byte_hostile": (0.15, 0.45),
    }
    harness_language: str = "c"
    harness_headers: tuple[str, ...] = ()
    harness_link_flags: tuple[str, ...] = ()
```

**Abstract Methods:**

- `is_valid_shape(payload: bytes) -> bool`: Check if input has expected shape
- `normalize_diagnostic(message: str) -> str`: Normalize error message to template
- `analyze_features(text: str, payload: bytes = b"") -> Any`: Analyze input features
- `summarize_structure(feature_list: list[Any]) -> dict`: Aggregate feature statistics
- `run_reference(payload: bytes, ...) -> RunResult`: Run reference parser

**Concrete Methods:**

- `run_native(payload: bytes, binary_path: Path, ...) -> RunResult`: Run native binary
- `run(payload: bytes, ...) -> RunResult`: Execute input (uses native or reference)
- `harness_for_sanitizer(sanitizer: str) -> Path | None`: Get harness for sanitizer

**Example:**

```python
from fuzzer.targets.base import BaseTarget, register_target
from pathlib import Path

class MyTarget(BaseTarget):
    name = "my_parser"
    category = "custom"
    description = "My custom parser"

    def is_valid_shape(self, payload: bytes) -> bool:
        return payload.startswith(b"<")

    def normalize_diagnostic(self, message: str) -> str:
        return message.strip()

    def analyze_features(self, text: str, payload: bytes = b""):
        return {"length": len(text)}

    def summarize_structure(self, feature_list: list) -> dict:
        return {"avg_length": sum(f["length"] for f in feature_list) / len(feature_list)}

    def run_reference(self, payload: bytes, ...):
        # Reference implementation
        pass

# Register the target
register_target(MyTarget())
```

### Functions

#### `get_target(name_or_target: str | BaseTarget) -> BaseTarget`

Retrieve a target by name or return the target instance.

**Parameters:**

- `name_or_target`: Target name string or BaseTarget instance

**Returns:**

- `BaseTarget`: Target instance

**Raises:**

- `KeyError`: If target name is not found

**Example:**

```python
from fuzzer.targets.base import get_target

# Get by name
target = get_target("mxml")

# Pass instance directly
target = get_target(target)

# Run an input
result = target.run(b"<root/>")
print(result.outcome)
```

#### `list_targets() -> dict[str, BaseTarget]`

Return all registered targets.

**Returns:**

- `dict`: Mapping of target names to target instances

**Example:**

```python
from fuzzer.targets.base import list_targets

targets = list_targets()
for name, target in targets.items():
    print(f"{name}: {target.description}")
```

#### `get_default_target() -> BaseTarget`

Return the default target (mxml for backwards compatibility).

**Returns:**

- `BaseTarget`: Default target instance

**Example:**

```python
from fuzzer.targets.base import get_default_target

target = get_default_target()
print(target.name)  # "mxml"
```

---

## Validation (`agent.validate`)

Strategy validation gates to ensure generated strategies are safe and functional.

### Classes

#### `ValidationResult`

Result of strategy validation.

```python
@dataclass
class ValidationResult:
    is_valid: bool
    reason: str = ""
    syntax_errors: list[str] = field(default_factory=list)
    interface_errors: list[str] = field(default_factory=list)
    smoke_test_passed: bool = False
    class_bounds_ok: bool = False
```

### Functions

#### `validate_strategy(strategy_code: str, target: BaseTarget) -> ValidationResult`

Validate a generated strategy through four gates.

**Gates:**

1. **Syntax gate**: Check Python syntax validity
2. **Interface gate**: Verify required functions exist
3. **Smoke test gate**: Run small batch (50 examples) to check basic functionality
4. **Class bounds gate**: Verify input class distribution is within acceptable range

**Parameters:**

- `strategy_code`: Python code for the strategy
- `target`: Target to validate against

**Returns:**

- `ValidationResult`: Validation result with details

**Example:**

```python
from agent.validate import validate_strategy
from fuzzer.targets.base import get_target

target = get_target("mxml")
strategy_code = """
def documents():
    return st.just("<root/>")
"""

result = validate_strategy(strategy_code, target)

if result.is_valid:
    print("Strategy is valid")
else:
    print(f"Validation failed: {result.reason}")
    print(f"Syntax errors: {result.syntax_errors}")
```

#### `validate_syntax(code: str) -> list[str]`

Check Python syntax validity.

**Parameters:**

- `code`: Python code to validate

**Returns:**

- `list[str]`: List of syntax error messages (empty if valid)

**Example:**

```python
from agent.validate import validate_syntax

code = "def test():\n    return 1"
errors = validate_syntax(code)

if errors:
    print(f"Syntax errors: {errors}")
else:
    print("Syntax is valid")
```

#### `validate_interface(code: str) -> list[str]`

Verify strategy has required interface.

**Parameters:**

- `code`: Python code to validate

**Returns:**

- `list[str]`: List of interface error messages (empty if valid)

**Required Interface:**

- Function named `documents()` that returns a Hypothesis strategy

**Example:**

```python
from agent.validate import validate_interface

code = """
def documents():
    return st.text()
"""

errors = validate_interface(code)
if errors:
    print(f"Interface errors: {errors}")
```

---

## Strategy Cache (`agent.strategy_cache`)

Cross-target strategy reuse via similarity-based retrieval.

### Classes

#### `StrategyCache`

Cache for storing and retrieving validated strategies.

```python
class StrategyCache:
    cache_dir: Path
    similarity_threshold: float = 0.7
```

**Methods:**

- `save(strategy_code: str, target: BaseTarget, metrics: dict) -> None`: Save a strategy
- `find_similar(target: BaseTarget) -> list[CacheEntry]`: Find similar strategies
- `load(entry: CacheEntry) -> str`: Load strategy code from cache entry

**Example:**

```python
from agent.strategy_cache import StrategyCache
from fuzzer.targets.base import get_target

cache = StrategyCache(cache_dir=Path("cache"))
target = get_target("mxml")

# Save a strategy
cache.save(
    strategy_code="def documents(): ...",
    target=target,
    metrics={"coverage": 0.5, "acceptance": 0.6}
)

# Find similar strategies
similar = cache.find_similar(target)
for entry in similar:
    print(f"Similarity: {entry.similarity}")
    strategy = cache.load(entry)
```

#### `CacheEntry`

Entry in the strategy cache.

```python
@dataclass
class CacheEntry:
    target_name: str
    category: str
    grammar_hash: str
    strategy_code: str
    metrics: dict
    similarity: float
    timestamp: float
```

#### `TargetProfile`

Profile for similarity computation.

```python
@dataclass
class TargetProfile:
    name: str
    category: str
    grammar_hash: str
    productions: tuple[str, ...]
    class_bounds: dict[str, tuple[float, float]]
```

**Methods:**

- `similarity(other: TargetProfile) -> float`: Compute similarity score (0.0 to 1.0)

**Example:**

```python
from agent.strategy_cache import TargetProfile
from fuzzer.targets.base import get_target

target1 = get_target("mxml")
target2 = get_target("libxml2")

profile1 = TargetProfile.from_target(target1)
profile2 = TargetProfile.from_target(target2)

similarity = profile1.similarity(profile2)
print(f"Similarity: {similarity}")
```

---

## Ensemble (`agent.ensemble`)

Multi-model ensemble for strategy selection via weighted voting.

### Classes

#### `Candidate`

A candidate strategy from an ensemble member.

```python
@dataclass
class Candidate:
    model: str
    strategy_code: str
    metrics: dict
    screening_cost_usd: float
```

### Functions

#### `vote_candidates(candidates: list[Candidate], weights: dict) -> Candidate`

Rank candidates by weighted Borda vote.

**Criteria:**

- Crashes (10x weight)
- Coverage (1x weight)
- Diagnostics (1x weight)
- Acceptance fit (1x weight)
- Depth (1x weight)
- Throughput (1x weight)

**Parameters:**

- `candidates`: List of candidate strategies
- `weights`: Custom weights for each criterion (optional)

**Returns:**

- `Candidate`: Highest-scoring candidate

**Example:**

```python
from agent.ensemble import Candidate, vote_candidates

candidates = [
    Candidate(
        model="gpt-5",
        strategy_code="def documents(): ...",
        metrics={"crashes": 0, "coverage": 0.5, "diagnostics": 10},
        screening_cost_usd=0.01
    ),
    Candidate(
        model="claude-sonnet-5",
        strategy_code="def documents(): ...",
        metrics={"crashes": 1, "coverage": 0.6, "diagnostics": 12},
        screening_cost_usd=0.01
    )
]

winner = vote_candidates(candidates)
print(f"Winner: {winner.model}")
```

#### `screen_candidate(candidate: Candidate, target: BaseTarget, examples: int) -> Candidate`

Run a candidate on a small screening campaign.

**Parameters:**

- `candidate`: Candidate to screen
- `target`: Target to run against
- `examples`: Number of examples for screening

**Returns:**

- `Candidate`: Candidate with updated metrics

**Example:**

```python
from agent.ensemble import screen_candidate
from fuzzer.targets.base import get_target

target = get_target("mxml")
candidate = Candidate(model="gpt-5", strategy_code="...", metrics={}, screening_cost_usd=0)

screened = screen_candidate(candidate, target, examples=80)
print(f"Coverage: {screened.metrics['coverage']}")
```

---

## Common Types

### `RunResult`

Result from running a single input through a target.

```python
@dataclass
class RunResult:
    outcome: Outcome
    returncode: int
    signal_name: str = ""
    diagnostics: list[str] = field(default_factory=list)
    stderr: str = ""
    duration_s: float = 0.0
    input_sha256: str = ""
    input_len: int = 0
    is_slow: bool = False
    slow_threshold_s: float | None = None
    sanitizer: str = ""
```

### `Outcome`

Enumeration of possible execution outcomes.

```python
class Outcome(Enum):
    PARSED_CLEAN = "parsed_clean"
    PARSED_DIAG = "parsed_diag"
    REJECTED = "rejected"
    HARNESS_ERROR = "harness_error"
    CRASH = "crash"
    TIMEOUT = "timeout"
```

---

## Usage Examples

### Complete Campaign Example

```python
from agent.loop import run_loop
from fuzzer.campaign import Campaign
from fuzzer.targets.base import get_target

# Run agentic loop
summary = run_loop(config)

# Or run a specific strategy
target = get_target("mxml")
campaign = Campaign(
    strategy_name="baseline",
    max_examples=500,
    out_dir=Path("runs/my-campaign"),
    target=target
)
result = campaign.run()
```

### Custom Target Example

```python
from fuzzer.targets.base import BaseTarget, register_target
from fuzzer.runner import Outcome, RunResult
import json

class JSONTarget(BaseTarget):
    name = "json"
    category = "json"

    def is_valid_shape(self, payload: bytes) -> bool:
        stripped = payload.lstrip()
        return bool(stripped) and stripped[0] in b"{[\""

    def normalize_diagnostic(self, message: str) -> str:
        return message.strip()

    def analyze_features(self, text: str, payload: bytes = b""):
        try:
            data = json.loads(text)
            return {"keys": len(data) if isinstance(data, dict) else 0}
        except:
            return {"keys": 0}

    def summarize_structure(self, feature_list: list) -> dict:
        return {"avg_keys": sum(f["keys"] for f in feature_list) / len(feature_list)}

    def run_reference(self, payload: bytes, ...):
        try:
            json.loads(payload.decode())
            return RunResult(outcome=Outcome.PARSED_CLEAN, returncode=0, ...)
        except json.JSONDecodeError:
            return RunResult(outcome=Outcome.REJECTED, returncode=1, ...)

register_target(JSONTarget())
```

### Validation Example

```python
from agent.validate import validate_strategy
from fuzzer.targets.base import get_target

target = get_target("mxml")
strategy_code = """
import hypothesis.strategies as st

def documents():
    return st.builds(
        lambda tag, content: f"<{tag}>{content}</{tag}>",
        tag=st.sampled_from(["a", "b", "c"]),
        content=st.text()
    )
"""

result = validate_strategy(strategy_code, target)

if result.is_valid:
    print("Strategy passed all gates")
else:
    print(f"Failed: {result.reason}")
```

---

## Error Handling

### Common Exceptions

- `LLMError`: LLM backend error (network, auth, rate limit)
- `ValidationError`: Strategy validation failed
- `CampaignError`: Campaign execution error
- `TargetError`: Target execution error

### Example

```python
from agent.llm import LLMError
from agent.validate import ValidationError

try:
    result = validate_strategy(code, target)
except ValidationError as e:
    print(f"Validation failed: {e}")
    # Handle repair or fallback
```

---

## See Also

- [Architecture Documentation](architecture.md)
- [Tutorial: Adding New Targets](tutorial-adding-targets.md)
- [Design Decisions](design-decisions.md)
- [Developer Experience](developer-experience.md)
