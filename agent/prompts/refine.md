# Task

Revise the Hypothesis strategy below using the measured results of its last run.

## Current strategy (iteration {iteration})

```python
{strategy_source}
```

## Measured results over {examples} generated documents

### Outcomes

```
{outcomes}
```

- **Acceptance rate: {acceptance_rate}** (target band: 40-70%)
- Crashes: {crash_count}
- Documents that were XML-shaped (began with `<`): {xml_shaped_rate}

### Grammar production coverage: {productions_hit}/{productions_total}

Reached:
```
{productions_hit_detail}
```

**Never produced:**
```
{productions_missing}
```

### Nesting depth distribution

```
{depth_histogram}
```
Deepest document generated: {max_depth}

### Distinct parser diagnostics reached: {distinct_templates}

```
{diagnostic_templates}
```

Each distinct message above is a different branch inside the parser. Messages
you have never triggered are branches you have never reached.

### Document size

```
{input_len}
```

### Slowest documents

```
{slowest}
```

{crash_section}

## What to do

Diagnose, then revise. Specifically:

1. If the acceptance rate is outside 40-70%, fix that first. Below the band,
   find which production is malformed and repair it. Above the band, add
   near-miss productions that exercise error handling.
2. Any production listed as never produced is dead weight in the grammar
   vocabulary. Either generate it, or it stays untested forever.
3. Use your own knowledge of XML to reason about which parser branches you have
   NOT yet triggered, given the diagnostics you have and have not seen. Target
   those. Think about what kinds of malformed XML would produce messages absent
   from the list above.
4. If nesting depth is shallow, deepen the recursion. If it is uniform, vary it.
5. Keep everything that is working. This is a revision, not a rewrite.

Output the complete revised module as one fenced ```python block.
