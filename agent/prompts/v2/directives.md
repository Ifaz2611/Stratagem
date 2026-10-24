# Rotating refinement directives

Run A refined a single lineage: every iteration was "improve the previous
strategy". Its coverage study showed the consequence, five strategies reaching
almost exactly the same parser lines (union beat the best single iteration by
under one percentage point).

Fuzz4All (ICSE 2024) and FunFuzz rotate a transformation instruction each round
for this reason, and a 2026 review of LLM-assisted fuzzers names the failure
directly: starting from a single shared prompt "can bias the search trajectory
early and limit semantic diversity". One directive is selected per iteration, in
order, and injected at the top of the refine prompt.

## 1. deepen

Keep the current structure and push it further along the axes it already
explores. Increase nesting depth and its variability, lengthen documents,
increase attribute counts per element, and nest malformed constructs inside
deeply nested well-formed ones rather than only at the top level.

## 2. attack-untouched

Ignore what is already working. Spend this revision entirely on error conditions
absent from the list of diagnostics already reached, and on grammar productions
never generated. Add new productions rather than tuning existing ones.

## 3. diversify

Reduce the correlation between your generated documents. Vary the shape of the
document itself, not only its contents: different orderings of prolog, DOCTYPE,
comments and processing instructions; documents dominated by one construct;
documents mixing every construct at once; very small and very large documents.
Widen the byte-level and encoding hostility in particular.
