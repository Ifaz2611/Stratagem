# Tutorial: Adding New Targets to Stratagem

This tutorial walks you through adding a new fuzzing target to Stratagem. A "target" is a parser or protocol that you want to fuzz using the agentic framework.

## Table of Contents

- [Understanding Targets](#understanding-targets)
- [Prerequisites](#prerequisites)
- [Step-by-Step Guide](#step-by-step-guide)
  - [Step 1: Choose Your Target](#step-1-choose-your-target)
  - [Step 2: Find or Create a Grammar](#step-2-find-or-create-a-grammar)
  - [Step 3: Implement the Target Class](#step-3-implement-the-target-class)
  - [Step 4: Register the Target](#step-4-register-the-target)
  - [Step 5: Implement Feature Analysis](#step-5-implement-feature-analysis)
  - [Step 6: Create or Build a Harness](#step-6-create-or-build-a-harness)
  - [Step 7: Test Your Target](#step-7-test-your-target)
  - [Step 8: Run a Campaign](#step-8-run-a-campaign)
- [Complete Example](#complete-example)
- [Advanced Topics](#advanced-topics)

## Understanding Targets

Stratagem's target abstraction layer (defined in `fuzzer/targets/base.py`) allows you to fuzz multiple parsers and protocols through a common interface. Each target encapsulates:

- **Harness execution**: How to run the parser with a test input
- **Diagnostic normalization**: Converting error messages to canonical templates
- **Grammar productions**: The structural elements the grammar can generate
- **Feature extraction**: Analyzing input structure for coverage metrics
- **Input classification**: Categorizing inputs as well-formed, near-miss, or byte-hostile

Existing targets include:
- XML parsers: `mxml`, `libxml2`, `expat`, `tinyxml2`
- JSON parser: `json` (cJSON)
- Network protocols: `http`, `dns`, `smtp`

## Prerequisites

Before adding a new target, ensure you have:

1. **A parser or protocol implementation** that you want to fuzz
2. **A grammar** for the input format (ANTLR .g4 format preferred)
3. **Python 3.10+** and Stratagem's dependencies installed
4. **Understanding of the target's behavior**:
   - What inputs it accepts as valid
   - What error messages it produces
   - Whether it has known issues or crash scenarios

## Step-by-Step Guide

### Step 1: Choose Your Target

Decide what you want to fuzz. Common categories:

- **Parser libraries**: XML, JSON, YAML, TOML, etc.
- **Network protocols**: HTTP, DNS, SMTP, FTP, etc.
- **File formats**: PDF, PNG, WAV, etc.
- **Configuration languages**: INI, properties, etc.

For this tutorial, we'll add a YAML parser target as an example.

### Step 2: Find or Create a Grammar

Stratagem uses ANTLR grammars to generate test inputs. You have two options:

**Option A: Use an existing grammar**
Search [ANTLR4 grammars repository](https://github.com/antlr/grammars-v4) for your format.

**Option B: Create a new grammar**
If no suitable grammar exists, create one following ANTLR4 syntax.

For YAML, we'd use an existing grammar like `YAML.g4` and place it in the `grammar/` directory.

```bash
# Example: Copy grammar to grammar directory
cp /path/to/YAML.g4 grammar/
```

### Step 3: Implement the Target Class

Create a new file in `fuzzer/targets/` for your target. Let's create `yaml_target.py`:

```python
"""YAML parser target implementation for Stratagem."""
from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path

from fuzzer.runner import (
    PER_RUN_TIMEOUT_S,
    Outcome,
    RunResult,
)
from fuzzer.targets.base import BaseTarget, REPO_ROOT

# Import your feature analysis module (we'll create this in Step 5)
# from fuzzer.targets.yaml_features import YAML_PRODUCTIONS, analyze_yaml, coverage_yaml

# Diagnostic normalization patterns
_YAML_SUBS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"line \d+"), "line %d"),
    (re.compile(r"column \d+"), "column %d"),
    (re.compile(r"'[^']*'"), "'%s'"),
    (re.compile(r"\b\d+\b"), "%d"),
]


def normalize_yaml(message: str) -> str:
    """Normalize YAML parser diagnostic string to a canonical template."""
    out = message.strip()
    for pattern, repl in _YAML_SUBS:
        out = pattern.sub(repl, out)
    return out


class YAMLTarget(BaseTarget):
    """YAML parser target implementation."""

    name: str = "yaml"
    category: str = "yaml"  # Custom category for your format
    description: str = "YAML parser target (e.g., PyYAML, libyaml)"
    harness_binary: Path = REPO_ROOT / "build" / "yaml" / "harness"
    grammar_file: Path = REPO_ROOT / "grammar" / "YAML.g4"
    productions: tuple[str, ...] = ()  # Will be populated from yaml_features

    # If using a C library, specify headers and link flags
    harness_headers: tuple[str, ...] = ("yaml.h",)
    harness_link_flags: tuple[str, ...] = ("-lyaml",)

    def is_valid_shape(self, payload: bytes) -> bool:
        """Check whether input has the target's expected superficial shape."""
        stripped = payload.lstrip()
        if not stripped:
            return False
        # YAML documents often start with key-value pairs, comments, or document markers
        return (
            stripped.startswith(b"#") or  # Comment
            stripped.startswith(b"---") or  # Document start
            bool(re.match(rb"[a-zA-Z_][a-zA-Z0-9_]*\s*:", stripped))  # Key-value
        )

    def normalize_diagnostic(self, message: str) -> str:
        """Normalize target-specific error message into a canonical template."""
        return normalize_yaml(message)

    def analyze_features(self, text: str, payload: bytes = b""):
        """Analyze structural features of generated input."""
        # TODO: Implement in yaml_features.py
        # return analyze_yaml(text, payload)
        return {}

    def summarize_structure(self, feature_list: list) -> dict:
        """Aggregate feature statistics over a batch of inputs."""
        # TODO: Implement in yaml_features.py
        # return coverage_yaml(feature_list)
        return {}

    def run_reference(
        self,
        payload: bytes,
        timeout_s: float = PER_RUN_TIMEOUT_S,
        extra_args: tuple[str, ...] = (),
    ) -> RunResult:
        """Reference YAML parser using Python's yaml module (PyYAML)."""
        try:
            import yaml
        except ImportError:
            raise ImportError(
                "PyYAML not installed. Install with: pip install pyyaml"
            )

        started = time.monotonic()
        sha = hashlib.sha256(payload).hexdigest()

        if not payload.strip():
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic("Empty YAML document")],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )

        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            diag = f"Invalid UTF-8 byte at position {exc.start}"
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic(diag)],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )

        try:
            yaml.safe_load(text)
            return RunResult(
                outcome=Outcome.PARSED_CLEAN,
                returncode=0,
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )
        except yaml.YAMLError as exc:
            # Extract error context from PyYAML exception
            if hasattr(exc, 'problem_mark'):
                line = exc.problem_mark.line + 1 if exc.problem_mark else 1
                column = exc.problem_mark.column + 1 if exc.problem_mark else 1
                diag = f"{exc.problem}: line {line} column {column}"
            else:
                diag = str(exc)
            return RunResult(
                outcome=Outcome.REJECTED,
                returncode=1,
                diagnostics=[self.normalize_diagnostic(diag)],
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )
        except Exception as exc:
            return RunResult(
                outcome=Outcome.HARNESS_ERROR,
                returncode=2,
                stderr=str(exc),
                duration_s=time.monotonic() - started,
                input_sha256=sha,
                input_len=len(payload),
            )
```

### Step 4: Register the Target

Add your target to the registry in `fuzzer/targets/__init__.py`:

```python
from fuzzer.targets.yaml_target import YAMLTarget

# Register the target
from fuzzer.targets.base import register_target
register_target(YAMLTarget())
```

Now your target is available via `get_target("yaml")`.

### Step 5: Implement Feature Analysis

Create `fuzzer/targets/yaml_features.py` to analyze YAML structure:

```python
"""YAML feature extraction and coverage analysis."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# Define grammar productions from YAML.g4
YAML_PRODUCTIONS = (
    "document",
    "mapping",
    "sequence",
    "scalar",
    "key",
    "value",
    "comment",
    "anchor",
    "alias",
    "tag",
    # Add more productions based on your grammar
)


@dataclass
class YAMLFeatures:
    """Structural features of a YAML document."""

    has_document_start: bool = False
    has_document_end: bool = False
    mapping_count: int = 0
    sequence_count: int = 0
    scalar_count: int = 0
    nesting_depth: int = 0
    has_anchors: bool = False
    has_aliases: bool = False
    has_tags: bool = False
    has_comments: bool = False
    key_count: int = 0
    empty_lines: int = 0


def analyze_yaml(text: str, payload: bytes = b"") -> YAMLFeatures:
    """Analyze structural features of a YAML document."""
    features = YAMLFeatures()

    lines = text.split("\n")
    depth = 0
    max_depth = 0

    for line in lines:
        stripped = line.strip()

        # Check for document markers
        if stripped.startswith("---"):
            features.has_document_start = True
        if stripped.startswith("..."):
            features.has_document_end = True

        # Check for comments
        if stripped.startswith("#"):
            features.has_comments = True
            continue

        # Track nesting depth
        if line:
            indent = len(line) - len(line.lstrip())
            if indent % 2 == 0:  # Assuming 2-space indentation
                depth = indent // 2
                max_depth = max(max_depth, depth)

        # Check for mappings (key: value)
        if re.match(r"^\s*[a-zA-Z_][a-zA-Z0-9_]*\s*:", line):
            features.mapping_count += 1
            features.key_count += 1

        # Check for sequences (- item)
        if re.match(r"^\s*-\s+", line):
            features.sequence_count += 1

        # Check for anchors (&name)
        if "&" in line:
            features.has_anchors = True

        # Check for aliases (*name)
        if "*" in line:
            features.has_aliases = True

        # Check for tags (!tag)
        if "!" in line:
            features.has_tags = True

        # Count empty lines
        if not line.strip():
            features.empty_lines += 1

    features.nesting_depth = max_depth
    features.scalar_count = len(lines) - features.mapping_count - features.sequence_count

    return features


def coverage_yaml(feature_list: list[YAMLFeatures]) -> dict[str, Any]:
    """Aggregate YAML feature statistics across a batch of inputs."""
    if not feature_list:
        return {}

    total = len(feature_list)

    return {
        "documents_with_start": sum(1 for f in feature_list if f.has_document_start) / total,
        "documents_with_end": sum(1 for f in feature_list if f.has_document_end) / total,
        "avg_mappings": sum(f.mapping_count for f in feature_list) / total,
        "avg_sequences": sum(f.sequence_count for f in feature_list) / total,
        "avg_nesting_depth": sum(f.nesting_depth for f in feature_list) / total,
        "with_anchors": sum(1 for f in feature_list if f.has_anchors) / total,
        "with_aliases": sum(1 for f in feature_list if f.has_aliases) / total,
        "with_tags": sum(1 for f in feature_list if f.has_tags) / total,
        "with_comments": sum(1 for f in feature_list if f.has_comments) / total,
        "avg_keys": sum(f.key_count for f in feature_list) / total,
    }
```

Update your target class to use these features:

```python
from fuzzer.targets.yaml_features import YAML_PRODUCTIONS, analyze_yaml, coverage_yaml

class YAMLTarget(BaseTarget):
    # ... existing code ...
    productions: tuple[str, ...] = YAML_PRODUCTIONS

    def analyze_features(self, text: str, payload: bytes = b""):
        return analyze_yaml(text, payload)

    def summarize_structure(self, feature_list: list) -> dict:
        return coverage_yaml(feature_list)
```

### Step 6: Create or Build a Harness

You have two options for harness execution:

**Option A: Use a reference runner (Python implementation)**
The `run_reference()` method we implemented above uses PyYAML as a reference. This is sufficient for initial testing and doesn't require building a C harness.

**Option B: Build a native C/C++ harness (recommended for production)**
For better performance and sanitizer support, create a C harness:

1. Create `harness/yaml/` directory
2. Write `harness.c` following the pattern in `harness/harness.c`:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>

#define DIAG_PREFIX "DIAG\t"

int main(void) {
    char buffer[65536];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), stdin);

    if (bytes_read == 0) {
        printf(DIAG_PREFIX "Empty YAML document\n");
        return 1;  // REJECTED
    }

    yaml_parser_t parser;
    if (!yaml_parser_initialize(&parser)) {
        printf(DIAG_PREFIX "Failed to initialize YAML parser\n");
        return 2;  // HARNESS_ERROR
    }

    yaml_parser_set_input_string(&parser, buffer, bytes_read);

    yaml_document_t document;
    if (!yaml_parser_load(&parser, &document)) {
        // Parse error - emit diagnostic
        printf(DIAG_PREFIX "YAML parse error at line %d column %d\n",
               parser.problem_mark.line + 1,
               parser.problem_mark.column + 1);
        yaml_parser_delete(&parser);
        return 1;  // REJECTED
    }

    // Successfully parsed
    yaml_document_delete(&document);
    yaml_parser_delete(&parser);

    return 0;  // PARSED_CLEAN
}
```

3. Create a build script `harness/yaml/build.sh`:

```bash
#!/bin/bash
set -e

SANITIZER="${1:-asan}"
BUILD_DIR="../../build/yaml"

mkdir -p "$BUILD_DIR"

case "$SANITIZER" in
    asan)
        FLAGS="-fsanitize=address -fno-sanitize-recover=all"
        ;;
    ubsan)
        FLAGS="-fsanitize=undefined -fno-sanitize-recover=all"
        ;;
    tsan)
        FLAGS="-fsanitize=thread"
        ;;
    *)
        FLAGS=""
        ;;
esac

gcc $FLAGS -O1 -g harness.c -lyaml -o "$BUILD_DIR/harness"
echo "Built harness with $SANITIZER: $BUILD_DIR/harness"
```

4. Build the harness:

```bash
cd harness/yaml
chmod +x build.sh
./build.sh asan
```

### Step 7: Test Your Target

Write a simple test to verify your target works:

```python
# test_yaml_target.py
from fuzzer.targets import get_target

def test_yaml_target():
    target = get_target("yaml")

    # Test valid input
    valid_input = b"key: value\n"
    result = target.run(valid_input)
    print(f"Valid input: {result.outcome}")  # Should be PARSED_CLEAN

    # Test invalid input
    invalid_input = b"key: value\n  bad_indent: x\n"
    result = target.run(invalid_input)
    print(f"Invalid input: {result.outcome}")  # Should be REJECTED

    # Test feature analysis
    features = target.analyze_features(valid_input.decode("utf-8"))
    print(f"Features: {features}")

if __name__ == "__main__":
    test_yaml_target()
```

Run the test:

```bash
python test_yaml_target.py
```

### Step 8: Run a Campaign

Once your target is working, run a fuzzing campaign:

```bash
# Using replay mode (no LLM costs)
python -m fuzzer.campaign baseline --target yaml

# Using agentic loop with LLM
python -m agent.loop --target yaml --backend openai --run-id yaml-campaign
```

## Complete Example

Here's the complete file structure for a YAML target:

```
fuzzer/targets/
├── yaml_target.py       # Target implementation
├── yaml_features.py     # Feature analysis
└── __init__.py          # Updated to register YAMLTarget

grammar/
└── YAML.g4              # ANTLR grammar

harness/yaml/
├── harness.c           # C harness implementation
└── build.sh            # Build script
```

## Advanced Topics

### Adjusting Class Bounds

The default input classification bounds might not fit your target. Override them:

```python
class YAMLTarget(BaseTarget):
    class_bounds: dict[str, tuple[float, float]] = {
        "well_formed": (0.40, 1.0),   # Higher than default
        "near_miss": (0.10, 1.0),     # Lower than default
        "byte_hostile": (0.10, 0.40), # Tighter range
    }
```

### Custom Sanitizer Support

If your target requires specific sanitizer settings:

```python
def harness_for_sanitizer(self, sanitizer: str = "asan") -> Path | None:
    """Custom sanitizer selection logic."""
    if sanitizer == "custom":
        return REPO_ROOT / "build" / "custom" / "harness"
    return super().harness_for_sanitizer(sanitizer)
```

### Target-Specific Validation

Add custom validation logic in `agent/validate.py` if needed:

```python
def validate_target_specific(strategy_code: str, target: BaseTarget) -> ValidationResult:
    """Add target-specific validation checks."""
    if target.name == "yaml":
        # Check for YAML-specific constraints
        if "st.recursive" not in strategy_code:
            return ValidationResult(
                is_valid=False,
                reason="YAML strategies should use st.recursive for nested structures"
            )
    return ValidationResult(is_valid=True)
```

### Grammar Adaptations

Document any grammar adaptations needed for your target in `grammar/ADAPTATIONS.md`:

```markdown
## YAML Grammar Adaptations

- YAML 1.2 vs 1.1: Grammar follows YAML 1.2, but PyYAML implements 1.1
- Tab characters: Grammar prohibits tabs, but PyYAML accepts them
- Block scalars: Grammar is strict about indentation, but parser is lenient
```

## Troubleshooting

**Problem**: Target not found
```
KeyError: "Unknown target: 'yaml'"
```
**Solution**: Ensure you registered the target in `fuzzer/targets/__init__.py`

**Problem**: Harness binary not found
```
FileNotFoundError: harness binary does not exist
```
**Solution**: Build the harness or use the reference runner

**Problem**: Grammar file not found
```
FileNotFoundError: grammar/YAML.g4
```
**Solution**: Ensure the grammar file exists in the `grammar/` directory

**Problem**: Feature analysis returns empty results
```
features = {}
```
**Solution**: Check that your feature analysis function is correctly implemented and that the text is being passed correctly

## Next Steps

After adding your target:

1. **Add baseline strategies**: Implement a baseline strategy in `fuzzer/strategies/yaml_baseline.py`
2. **Document findings**: Document any bugs you find in `docs/findings.md`
3. **Share improvements**: Submit a pull request with your new target

## References

- [Target Base Class](../fuzzer/targets/base.py)
- [JSON Target Example](../fuzzer/targets/json_target.py)
- [HTTP Target Example](../fuzzer/targets/protocol_http.py)
- [Feature Analysis Examples](../fuzzer/targets/json_features.py)
- [ANTLR4 Grammar Repository](https://github.com/antlr/grammars-v4)
