# Harness Directory

This directory contains the C harness that interfaces between the Python fuzzing framework and the Mini-XML (mxml) parser library.

## Files

- **harness.c**: The main harness program
- **build.sh**: Build script for compiling the harness with sanitizers
- **smoke_test.sh**: Smoke test to verify the harness works correctly
- **samples/**: Sample XML inputs for testing (valid, invalid, diagnostic)

## Harness Overview

The harness is a small C program that:

1. Reads an XML document from stdin or a file
2. Calls mxml's `mxmlLoadString()` function
3. Reports results via exit codes and stdout line protocol
4. Reserves stderr for sanitizer output

### Exit Codes

| Code | Meaning | Notes |
|------|---------|-------|
| 0 | Parsed cleanly | No diagnostics |
| 3 | Parsed with diagnostics | mxml's "parsed-but-complained" state |
| 1 | Rejected | Well-formed rejection, not a crash |
| 2 | Harness error | Our fault (cannot read input, OOM) |
| Signal/Sanitizer abort | Crash | Memory safety error detected |

### Output Protocol

**Stdout** (tab-separated, machine-readable):
```
DIAG\t<message>
RESULT\tparsed|rejected\t<ndiags>
```

**Stderr**: Reserved for sanitizer output (ASan, UBSan reports)

## Building

### Quick Build

```bash
cd harness
./build.sh
```

This builds both:
- `build/asan/harness` - With AddressSanitizer and UndefinedBehaviorSanitizer
- `build/cov/harness` - With gcov coverage instrumentation (evaluation only)

### Build Options

```bash
# Build only the sanitizer version
./build.sh asan

# Build only the coverage version
./build.sh cov

# Build both (default)
./build.sh all
```

### Build Flags

The sanitizer build uses:
```
-g -O1 -fno-omit-frame-pointer
-fsanitize=address,undefined
-fno-sanitize-recover=all
```

**Flag explanations:**
- `-fno-sanitize-recover=all`: Makes UBSan abort on error instead of continuing
- `-fno-omit-frame-pointer`: Preserves stack frames for better crash signatures
- `-O1`: Optimized enough to be realistic, but keeps frames readable

The coverage build uses:
```
-g -O0 --coverage
```

No optimisation to ensure accurate line coverage mapping.

## Verification

### Smoke Test

```bash
cd harness
./smoke_test.sh
```

The smoke test:
- Tests a known crashing input (issue #350) - should detect crash
- Tests a similar non-crashing input - should pass
- Verifies basic parsing functionality

### Manual Testing

```bash
# Test with a valid XML document
echo '<root>hello</root>' | build/asan/harness

# Test with an invalid document
echo '<root>' | build/asan/harness

# Test with a file
build/asan/harness samples/valid/example.xml
```

## Design Points

### 1. Input from stdin, not argv

A single argv entry is capped at `MAX_ARG_STRLEN` (128 KiB on Linux). Large documents like deep-nesting tests would be silently truncated if passed as arguments.

### 2. Accept/reject from return value

mxml can emit a diagnostic and still return a tree (e.g., raw control characters). Classifying on "did the error callback fire?" would misreport these as rejections.

### 3. Diagnostics on stdout, stderr for sanitizers

The Python runner scans stderr for ASan/UBSan reports. Parser messages in that stream would make crash detection ambiguous.

### 4. Four-state classification

Most parsers have two states (parse/fail). mxml has four meaningful states:
- Parsed without issues
- Parsed but complained
- Rejected (well-formed)
- Harness error

This separation is important for the acceptance-rate signal used by the agentic loop.

## Integration with Python

The Python framework calls the harness via `fuzzer/runner.py`:

```python
from fuzzer.runner import run_one

result = run_one(document_bytes, harness="build/asan/harness")
# Returns RunResult with outcome, diagnostics, etc.
```

The runner:
- Feeds input via stdin
- Parses the stdout protocol
- Checks stderr for sanitizer markers
- Classifies the result as an Outcome enum

## Sanitizer Configuration

The Python runner sets these environment variables:

```python
SANITIZER_ENV = {
    "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:symbolize=1:print_stacktrace=1",
    "UBSAN_OPTIONS": "halt_on_error=1:abort_on_error=1:print_stacktrace=1",
}
```

**Key settings:**
- `detect_leaks=0`: Disabled during main campaigns (mxml leaks on `<a a>` path)
- `abort_on_error=1`: Makes sanitizers fatal rather than continuing
- `symbolize=1`: Produces function names in stack traces

For leak detection, use a separate pass with `detect_leaks=1`.

## Index Mode

The harness supports an optional `--index` flag:

```bash
build/asan/harness --index < input.xml
```

This calls `mxmlIndexNew()` after parsing, which triggers a known heap under-read bug (issue #350). This is used as a positive control to verify crash detection works.

**Note:** This mode is NOT used during normal fuzzing campaigns.

## Troubleshooting

### "Harness not found"

Ensure you've built it:
```bash
cd harness
./build.sh
```

### "asan: Shadow memory range interleaves"

This occurs when Docker's default seccomp profile blocks the `personality()` call. Fix by using the Docker flags in `run.sh`:
```bash
--security-opt seccomp=unconfined
```

### Sanitizers not triggering

Verify the symbols are linked:
```bash
nm build/asan/harness | grep -E '__asan|__ubsan'
```

Should show multiple sanitizer symbols. If not, the build failed.

### False crashes from UBSan

Ensure `-fno-sanitize-recover=all` is in the build flags. Without it, UBSan prints errors and exits 0, which the harness would classify as "no crash."

## Sample Files

The `samples/` directory contains test inputs:

- **valid/**: Well-formed XML documents
- **invalid/**: Malformed but interesting inputs
- **diag/**: Inputs that trigger diagnostics

These are useful for manual testing and debugging.

## Dependencies

- Mini-XML source code (fetched by `scripts/fetch_target.sh`)
- GCC or Clang compiler
- make build system
- libasan, libubsan (part of compiler runtime)
- For coverage build: gcov/lcov

**Platform Support:**
- **Linux**: Fully supported with gcc/make
- **macOS**: Fully supported with clang/make
- **Windows**: Requires WSL2 or MinGW-w64 with make. The harness build is primarily tested on Unix-like systems.

## See Also

- `docs/design-decisions.md` - Design decisions D3 (UBSan) and D8 (positive controls)
- `fuzzer/runner.py` - Python code that calls the harness
- `grammar/ADAPTATIONS.md` - Parser behavior that affects harness classification
