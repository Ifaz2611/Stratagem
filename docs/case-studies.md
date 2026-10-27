# Case Studies: Past Findings

This document presents detailed case studies of bugs and issues discovered through Stratagem's fuzzing campaigns. Each case study includes the discovery process, reproduction steps, impact analysis, and resolution.

## Table of Contents

- [Case Study 1: Non-ASCII Character Damage in Error Messages](#case-study-1-non-ascii-character-damage-in-error-messages)
- [Case Study 2: Attribute Leak on Error Path](#case-study-2-attribute-leak-on-error-path)
- [Case Study 3: Diagnostic Buffer Truncation](#case-study-3-diagnostic-buffer-truncation)
- [Case Study 4: Crash Triage with Known Control](#case-study-4-crash-triage-with-known-control)
- [Lessons Learned](#lessons-learned)

---

## Case Study 1: Non-ASCII Character Damage in Error Messages

### Summary

**Status**: Fixed upstream in Mini-XML v4.0.4+ (commit d986100)
**Severity**: Medium (informational, user experience impact)
**Discovery Method**: Random-text baseline strategy
**Campaign**: Historical baseline runs (pre-agentic loop)

### The Bug

Mini-XML's error callback formatted Unicode code points using `%c` instead of proper Unicode formatting. This caused two visible problems:

1. **Truncation**: Code points with a low byte of `0x00` (e.g., U+0100) inserted a NUL byte, cutting the error message short
2. **Invalid UTF-8**: Code points from U+0080 to U+00FF inserted a single high byte, producing invalid UTF-8 encoding

Both problems reached applications through the public `mxmlOptionsSetErrorCallback()` callback, potentially breaking downstream error handling or logging systems.

### Discovery Process

**Initial Detection:**
The random-text baseline strategy generated inputs with various Unicode characters before the agentic loop began. The diagnostic normalizer noticed multiple variations of the same error template with different rejected characters:

```
input          message before the fix
U+0041 'A'     XML does not start with '<' (saw 'A').
U+00E9         XML does not start with '<' (saw '\xe9').     invalid UTF-8
U+0100         XML does not start with '<' (saw '            truncated
U+1F600        XML does not start with '<' (saw '            truncated
```

**Investigation:**
The project followed the diagnostic template differences to the source code in `mxml-file.c`, identifying four error message formatting sites using `%c` for code points from `mxml_getc()`.

### Reproduction

**Minimal Reproducer:**
```bash
python3 -c "import sys; sys.stdout.buffer.write('Ā<r/>'.encode())" > t.xml
./build/asan/harness t.xml
```

**Expected Output (after fix):**
```
DIAG	XML does not start with '<' (saw 'U+0100').
```

**Actual Output (before fix):**
```
DIAG	XML does not start with '<' (saw '.
```

(Note the message is truncated after the space following "saw")

### Impact Analysis

**Affected Code Paths:**
- File: `mxml-file.c`
- Functions: 4 error message formatting sites
- Entry point: `mxmlLoadString()`, `mxmlLoadFile()`

**Affected Users:**
- Applications using Mini-XML's error callback for logging
- International users with non-ASCII characters in XML
- Systems parsing XML with embedded Unicode

**Risk Assessment:**
- **Security**: Low (no memory safety issue)
- **Correctness**: Medium (error messages garbled)
- **User Experience**: Medium (confusing error messages)

### Resolution

**Report:**
- Issue reported in [PR #357](https://github.com/michaelrsweet/mxml/pull/357)
- Explained discovery through fuzzing

**Fix:**
- Commit: [d9861001da](https://github.com/michaelrsweet/mxml/commit/d9861001da)
- Change: Format bad characters as `U+XXXX` instead of `%c`

**Code Change:**
```c
// Before
snprintf(s, sizeof(s), "XML does not start with '<' (saw '%c').", ch);

// After
snprintf(s, sizeof(s), "XML does not start with '<' (saw 'U+%04X').", ch);
```

### Lessons Learned

1. **Baseline strategies matter**: Even before the agentic loop, the random-text baseline found this issue, highlighting the value of diverse strategies.

2. **Diagnostic normalization helps**: The normalizer grouped similar error templates, making the pattern visible despite different rejected characters.

3. **Format specifier pitfalls**: Using `%c` for code points rather than bytes is a common mistake in text processing libraries.

---

## Case Study 2: Attribute Leak on Error Path

### Summary

**Status**: Independently reproduced (known upstream issue #354)
**Severity**: Low (memory leak, not a crash)
**Discovery Method**: Agentic loop strategies
**Campaign**: Historical campaigns (10,000 documents from 19 strategies)

### The Bug

Mini-XML leaks memory when parsing elements with attributes but no values (e.g., `<a a>`). The element is allocated before the pointer used by the cleanup path is assigned, so two error paths during that interval jump to cleanup without freeing the allocation.

### Discovery Process

**Initial Detection:**
LeakSanitizer detected the same stack signature in 820 of 10,000 historical documents (8.2%):

```
mxml_new -> mxmlNewElement -> mxml_load_data -> mxmlLoadString
```

**Variation Analysis:**
The leak rate varied significantly across strategies (1.9% to 18.3%), depending on how often a strategy produced attributes without values.

**Leak Pass Campaign:**
A separate replay campaign with LeakSanitizer enabled confirmed the finding:

```bash
ASAN_OPTIONS=detect_leaks=1 ./build/asan/harness < input.xml
```

### Reproduction

**Minimal Reproducer:**
```bash
printf '<a a>' | ASAN_OPTIONS=detect_leaks=1 ./build/asan/harness
```

**Output:**
```
==12345==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 90 byte(s) in 1 object(s) allocated from:
    #0 in malloc
    #1 in mxmlNewElement
    #2 in mxml_load_data
    #3 in mxmlLoadString
```

**Control Inputs:**
Nearby inputs show the leak is specific to this error path:

| input | parser result | leaked |
|-------|---------------|--------|
| `<a a>` | missing attribute value | 90 bytes |
| `<a></b>` | mismatched close tag | 0 bytes |
| `<a a="1">` | parsed | 0 bytes |

### Impact Analysis

**Affected Code Paths:**
- File: `mxml-node.c`, `mxml-file.c`
- Function: `mxmlNewElement()`, `mxml_load_data()`
- Trigger: Attribute without value during parsing

**Affected Users:**
- Long-running processes parsing many XML documents
- Applications parsing untrusted XML (potential for resource exhaustion)
- Systems with strict memory limits

**Risk Assessment:**
- **Security**: Low (no code execution, but potential for DoS via memory exhaustion)
- **Correctness**: Low (parser still functional)
- **Resource**: Medium (memory leak)

**Leak Rate in Practice:**
- Historical corpus: 8.2% of inputs triggered the leak
- Strategy-dependent: 1.9% to 18.3% depending on generation strategy
- Per-occurrence: 90 bytes

### Resolution

**Report:**
- Known upstream issue: [#354](https://github.com/michaelrsweet/mxml/issues/354)
- Reproduced independently by Stratagem
- Was open in mxml v4.0.4 and on upstream branch at time of testing

**Status:**
- Not fixed in the pinned target (v4.0.4)
- Documented as a known limitation
- Separate leak detection pass keeps results clean without affecting main campaigns

**Design Decision:**
The project uses a separate leak detection pass rather than enabling LeakSanitizer during every campaign. This prevents the known leak from dominating crash records and keeps memory-safety crashes distinct from leaks.

See [docs/design-decisions.md D4](design-decisions.md#d4-leak-detection-uses-a-separate-pass) for rationale.

### Lessons Learned

1. **Separate leak detection**: Running leak detection separately keeps crash records clean and allows targeted analysis.

2. **Leak rate matters**: A leak that occurs in 8.2% of inputs is significant for long-running processes, even if it's only 90 bytes per occurrence.

3. **Stack signatures work**: The crash triage system correctly grouped this leak with the reproducer from issue #354, supporting the match.

4. **Known bugs as controls**: Using known issues as positive controls validates the detection pipeline without claiming them as new findings.

---

## Case Study 3: Diagnostic Buffer Truncation

### Summary

**Status**: Not reported upstream (considered a limitation, not a security bug)
**Severity**: Low (bounded, memory-safe)
**Discovery Method**: Agentic loop strategy (Run D)
**Campaign**: Historical campaigns

### The Issue

Mini-XML's `_mxml_error` function uses a fixed 1,024-byte buffer for error messages. When element names are long enough, the callback receives 1,023 bytes of the name and none of the explanatory text, making the error message useless.

### Discovery Process

**Initial Detection:**
Run D of the historical campaigns generated names up to 389 characters and as many as 257 attributes on a single element. This triggered the buffer truncation case.

**Feature Analysis:**
The feature extractor tracked element name length and attribute count, revealing that strategies producing very long names could trigger the truncation.

**Diagnostic Normalization:**
The diagnostic normalizer groups messages at the buffer limit into one template, preventing multiple truncations from one error site from looking like separate parser branches.

### Reproduction

**Minimal Reproducer:**
```bash
python3 -c "print('<a/><' + 'b'*1100 + '/>', end='')" | ./build/asan/harness
```

**Output:**
```
DIAG	element 'b'*1023...
```

(Note: The actual error explanation is missing, only the truncated element name appears)

### Impact Analysis

**Affected Code Paths:**
- File: `mxml-file.c`
- Function: `_mxml_error()`
- Buffer size: 1,024 bytes
- Trigger: Element names or attributes with very long names

**Affected Users:**
- Applications parsing XML with auto-generated or malicious element names
- Systems that rely on error messages for debugging
- Users encountering edge cases with long identifiers

**Risk Assessment:**
- **Security**: Low (bounded buffer, no overflow)
- **Correctness**: Low (parser still functions correctly)
- **User Experience**: Medium (error messages become uninformative)
- **Exploitability**: Low (requires attacker control over element names)

**Practical Impact:**
- Bounded by buffer size (1,024 bytes)
- No memory safety issue (no overflow)
- Only affects error message quality, not parsing correctness

### Resolution

**Decision: Not Reported Upstream**

This issue was deliberately not reported to upstream for several reasons:

1. **Bounded**: The buffer is fixed-size and properly bounded
2. **Memory-safe**: No risk of buffer overflow
3. **Low severity**: Only affects error message quality
4. **Rare in practice**: Requires element names > 1,000 characters, which is uncommon
5. **Design trade-off**: Larger buffers would consume more memory for every error

**Alternative Approaches Considered:**

1. **Dynamic allocation**: Would increase memory allocation overhead for every error
2. **Truncation with marker**: Could add "...(truncated)" to indicate truncation
3. **Structured error reporting**: Would require API changes

### Lessons Learned

1. **Error message quality matters**: Even memory-safe issues can impact user experience when error messages become uninformative.

2. **Trade-offs in design**: Fixed buffers are a common trade-off between memory usage and functionality. This is a reasonable design choice for a small library like Mini-XML.

3. **Feature extraction value**: Tracking element name length and attribute count helped identify this edge case that might otherwise have been missed.

4. **Diagnostic normalization**: Grouping truncated messages prevents false diversity in diagnostic counts.

---

## Case Study 4: Crash Triage with Known Control

### Summary

**Status**: Known upstream issue #350 (not a new finding)
**Severity**: High (heap buffer overflow)
**Discovery Method**: Control input in smoke test
**Campaign**: All campaigns (control input)
**Purpose**: Validate crash detection pipeline

### The Bug

Mini-XML's `index_sort` function has a heap buffer overflow when `tempr` is zero, causing `tempr - 1` to wrap to `SIZE_MAX`:

```c
size_t templ, tempr;
if (left < (tempr - 1))
  index_sort(ind, left, tempr - 1);
```

### Purpose as Control

This is **not** a finding from Stratagem—it's a known upstream issue used as a positive control to validate the crash detection pipeline. The smoke test includes:

1. **Crashing input**: `<a><b/></a>` (triggers the bug)
2. **Non-crashing input**: `<a><a/><a/></a>` (similar structure, no crash)

This confirms the harness can detect a real sanitizer failure without classifying every nearby input as a crash.

### Discovery Process

**Control Design:**
The bug is in `mxmlIndexNew`, not the parse entry point used by campaigns. The harness reaches it only with `--index`, so normal fuzzing does not claim this as a new finding.

**Triage Validation:**
Three different inputs produced the same normalized signature:

```text
<a><b/></a>                  -> d8ee1ccd656a
<b><aa/><a/></b>             -> d8ee1ccd656a
<!DOCTYPE a SYSTEM ""><a/>   -> d8ee1ccd656a
```

This validates that the triage system correctly groups the same bug from different inputs.

### Reproduction

**Minimal Reproducer:**
```bash
echo '<a><b/></a>' | ./build/asan/harness --index
```

**Output:**
```
==12345==ERROR: AddressSanitizer: heap-buffer-overflow
READ index_sort@mxml-index.c
```

**Hypothesis Minimization:**
Hypothesis reduced a generated crashing case to:

```
examples before shrinking : 15
shrunk input              : '<!DOCTYPE a SYSTEM ""><a/>'   (26 bytes)
label                     : heap-buffer-overflow READ index_sort@mxml-index.c
```

**Hand-written Reproducer:**
The hand-written `<a><b/></a>` input is shorter at 11 bytes, showing that manual analysis can sometimes produce smaller reproducers than automated shrinking.

### Impact Analysis

**Affected Code Paths:**
- File: `mxml-index.c`
- Function: `index_sort()`
- Entry point: `mxmlIndexNew()` (only with `--index` flag)
- Trigger: Empty element list in index creation

**Affected Users:**
- Applications using Mini-XML's indexing feature
- Systems that build indexes from parsed XML
- Users calling `mxmlIndexNew()` with certain document structures

**Risk Assessment:**
- **Security**: High (heap buffer overflow, potential for code execution)
- **Correctness**: High (crashes on valid operations)
- **Exploitability**: Medium (requires specific document structure, but indexing is a real feature)

**Status:**
- Known and already fixed upstream
- Not a new finding from Stratagem
- Used only as a control to validate detection

### Resolution

**Upstream Status:**
- Issue: [#350](https://github.com/michaelrsweet/mxml/issues/350)
- Status: Fixed upstream
- Not present in the pinned target (v4.0.4) as a reproducible crash

**Stratagem's Use:**
- Positive control in smoke test
- Validates crash detection pipeline
- Confirms triage system groups same bug correctly
- Normal campaigns do not use `--index`, so don't claim this as a finding

### Lessons Learned

1. **Controls are essential**: Known bugs as controls validate the detection pipeline without claiming them as new findings.

2. **Triage validation**: Multiple inputs producing the same signature confirms the triage system works correctly.

3. **Minimization trade-offs**: Hypothesis minimizes the generator's draw sequence, not byte length. Manual analysis can sometimes produce smaller reproducers.

4. **Entry point isolation**: The bug is in `mxmlIndexNew`, not the parse path, so normal fuzzing campaigns don't encounter it. This shows the value of multiple entry points.

5. **Normalization rules**: The normalizer removes repeated recursive frames and address/line changes, preventing recursion depth from creating multiple signatures for one bug.

---

## Lessons Learned

### 1. Diverse Strategies Are Valuable

The random-text baseline found the non-ASCII character issue before the agentic loop even started. This highlights the importance of having multiple strategies with different generation approaches, not just relying on LLM-generated strategies.

### 2. Diagnostic Normalization is Critical

Without proper normalization, small variations in error messages (like different rejected characters) would appear as separate diagnostic templates, obscuring the underlying pattern. Grouping similar messages into canonical templates makes patterns visible.

### 3. Feature Extraction Enables Discovery

Tracking structural features (element name length, attribute count, nesting depth) helped identify edge cases like the diagnostic buffer truncation that might otherwise have been missed. Feature analysis is not just for coverage—it's for discovery.

### 4. Separate Leak Detection is Worthwhile

Running leak detection separately keeps crash records clean and allows targeted analysis of memory leaks without them dominating the results. This design decision proved valuable in practice.

### 5. Controls Validate the Pipeline

Using known bugs as positive controls validates that the detection, triage, and reporting systems work correctly. This gives confidence that new findings are genuine and not false positives from the pipeline itself.

### 6. Stack Signatures Have Limitations

Stack-based signatures are only an estimate of root cause. As Klees et al. found, common stack-hash methods can merge different bugs or split one bug. The normalization rules mitigate but don't eliminate this limitation.

### 7. Fix vs. Limitation Distinction

Not every issue found through fuzzing should be reported upstream. Bounded, memory-safe issues like the diagnostic buffer truncation are better documented as limitations rather than bugs, especially when they represent reasonable design trade-offs.

### 8. Reproducibility Enables Verification

Saving exact input bytes and replaying them through the harness enables verification of findings. The separate replay pass for the leak detection confirmed the finding across the entire historical corpus.

### 9. Entry Point Coverage Matters

The index bug was only reachable via the `--index` flag, not the normal parse path. This shows the value of testing multiple entry points and API surfaces, not just the primary parser interface.

### 10. Blackbox Feedback Can Be Effective

Despite having no code coverage signals, the agentic loop was able to generate strategies that achieved 38-45% parser coverage vs 13% for the random baseline. This demonstrates that blackbox feedback (input properties, parser results, diagnostics) can be effective for fuzzing.

---

## Statistical Summary

### Historical Campaign Results

- **Total inputs tested**: 10,000 documents
- **Strategies tested**: 19 generated strategies + 1 random baseline
- **Target**: Mini-XML v4.0.4 (commit 0d5afc42)
- **Sanitizers**: AddressSanitizer, UndefinedBehaviorSanitizer

### Findings Summary

| Finding | Type | Status | Detection Method |
|---------|------|--------|------------------|
| Non-ASCII character damage | Incorrect formatting | Fixed upstream | Random baseline |
| Attribute leak | Memory leak | Known issue #354 | Agentic strategies |
| Diagnostic truncation | UX limitation | Not reported | Agentic strategies |
| Index overflow | Heap buffer overflow | Known issue #350 | Control input |

### Coverage Results

- **Grammar-based strategies**: 38-45% parser coverage
- **Random baseline**: 13% coverage
- **Improvement**: 2.9-3.5x coverage increase

### Crash Summary

- **Memory-safety crashes**: 0 found
- **Timeouts**: 0 found
- **Leaks**: 1 known (attribute error path)
- **Correctness issues**: 1 fixed (non-ASCII formatting)

---

## References

- [Findings Document](findings.md) - Detailed technical analysis
- [Design Decisions](design-decisions.md) - Engineering rationale
- [Architecture Documentation](architecture.md) - System overview
- [Mini-XML Repository](https://github.com/michaelrsweet/mxml) - Target library
- [Issue #350](https://github.com/michaelrsweet/mxml/issues/350) - Index overflow
- [Issue #354](https://github.com/michaelrsweet/mxml/issues/354) - Attribute leak
- [PR #357](https://github.com/michaelrsweet/mxml/pull/357) - Non-ASCII fix
