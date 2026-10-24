# Task

Revise the Hypothesis strategy below using the measured results of its last run.

**Directive for this iteration: {directive}**

## Current strategy (iteration {iteration})

```python
{strategy_source}
```

## Measured results over {examples} generated documents

### Boundary coverage

This is the primary objective. Each row is what the last run actually reached.
A narrow range or a small number of distinct values means that dimension is not
being swept.

```
{boundaries}
```

For every dimension above: add 0, 1 and 2 if absent, then a dense sweep in a
window around the largest value already reached, then one step beyond it. Use
`st.sampled_from` on an explicit list, not a wide `st.integers`.

### Input class mixture, and acceptance within each class

```
{buckets}
```

Minimums, **all of which must hold at once**: `well_formed` >=40%,
`near_miss` >=20%, `byte_hostile` >=20%. Raising one by dropping another below
its minimum is worse than leaving both alone.

Overall acceptance: **{acceptance_rate}** (target band 40-70%)

Note the acceptance rate *within* `byte_hostile`. If it is very low, those
documents are being rejected at the front door and are not reaching the parser.
The fix is not fewer of them; it is to place the defect deeper inside an
otherwise-valid document.

### Marginal progress: what THIS iteration found that no earlier one did

Repeating ground already covered by an earlier iteration counts for nothing.

```
new diagnostic templates this iteration : {new_diagnostics}
new grammar productions this iteration  : {new_productions}
```

**Target: at least 3 diagnostic templates that no previous iteration reached.**

### Diagnostics already reached by ANY iteration so far ({union_diagnostics} total)

```
{union_diagnostic_list}
```

Every message here is a parser branch already visited. Any message mentioning a
limit ("too long", "too deep", "EOF") marks a boundary: generate that construct
at each length around where the message starts appearing.

Use your knowledge of XML to reason about what a conforming parser must reject
that is absent from this list, and construct documents that trigger it.

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
   so that successive strategies explore different regions.
2. **Sweep the boundary dimensions.** This is the primary objective and the one
   most likely to produce a crash.
3. **Hold all three class minimums at once.** Check the mixture before you
   change weights.
4. **Place defects deep inside valid documents**, so the parser reaches them.
5. **Earn marginal diagnostics.** Aim for at least 3 messages absent from the
   list above.
6. Keep everything that is working. This is a revision, not a rewrite.

Output the complete revised module as one fenced ```python block.
