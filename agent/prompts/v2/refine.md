# Task

Revise the Hypothesis strategy below using the measured results of its last run.

**Directive for this iteration: {directive}**

## Current strategy (iteration {iteration})

```python
{strategy_source}
```

## Measured results over {examples} generated documents

### Input class mixture, and acceptance within each class

```
{buckets}
```

Targets: `well_formed` ~50%, `near_miss` >=25%, `byte_hostile` >=25%.
`near_miss` and `byte_hostile` are *expected* to be mostly rejected. Do not
raise their acceptance by making them less malformed; that defeats their purpose.

Overall acceptance: **{acceptance_rate}** (target band 40-70%)

### Marginal progress: what THIS iteration found that no earlier one did

This is what you are scored on. Repeating ground already covered by an earlier
iteration counts for nothing.

```
new diagnostic templates this iteration : {new_diagnostics}
new grammar productions this iteration  : {new_productions}
```

**Target: at least 3 diagnostic templates that no previous iteration reached.**

### Diagnostics already reached by ANY iteration so far ({union_diagnostics} total)

```
{union_diagnostic_list}
```

Each of these is a branch in the parser that has already been visited. Reaching
them again adds nothing. Use your own knowledge of XML to reason about what
*other* error conditions a conforming parser must detect, which are absent from
this list, and construct documents that trigger them.

### Grammar production coverage: {productions_hit}/{productions_total}

Never produced by any iteration:
```
{productions_missing}
```

### Nesting depth distribution

```
{depth_histogram}
```
Deepest document generated: {max_depth}

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

1. **Follow the directive at the top of this prompt.** It changes each iteration
   on purpose, so that successive strategies explore different regions instead
   of converging on refinements of the same one.
2. **Fix the class mixture first** if any class is below its target share. A
   healthy overall acceptance rate can hide a class that has been abandoned.
3. **Earn marginal diagnostics.** Aim for at least 3 messages absent from the
   list above. Think about what a conforming XML parser must reject that you
   have not yet made it reject.
4. Any production listed as never produced stays untested forever unless you
   generate it.
5. Keep everything that is working. This is a revision, not a rewrite.

Output the complete revised module as one fenced ```python block.
