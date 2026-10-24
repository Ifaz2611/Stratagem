# Strategy changes in run A

This file records how the v1 strategy changed across five iterations. The
feedback descriptions come from the original campaign. Coverage and the summary
table below use the corrected three-seed evaluation from
`runs/analysis/coverage_trials.json`.

## Strategy size

| iteration | lines | bytes | composite or recursive helpers | new functions |
|---:|---:|---:|---:|---:|
| 0 | 334 | 10,961 | 13 | 30 |
| 1 | 496 | 17,135 | 24 | 13 |
| 2 | 581 | 21,419 | 25 | 3 |
| 3 | 746 | 29,644 | 32 | 7 |
| 4 | 800 | 32,323 | 34 | 2 |

The strategy grew in every iteration. No helper function was removed. The
refinement prompt asked the model to keep working parts, and the model generally
added new cases instead of replacing old ones.

## Corrected measurements

Each row is the mean of three runs at seeds 11, 22, and 33. Each seed generated
500 documents.

| iteration | acceptance | diagnostics | productions | parser coverage |
|---:|---:|---:|---:|---:|
| 0 | 29.7% | 11.7 | 23.0 | 38.66% |
| 1 | 36.0% | 14.0 | 22.7 | 39.78% |
| 2 | 39.1% | 15.3 | 22.7 | 40.18% |
| 3 | 44.2% | 13.7 | 24.7 | 39.82% |
| 4 | 48.3% | 14.0 | 23.3 | 39.50% |

Coverage improved by 0.84 points from the first to the final strategy. The best
result was iteration 2 at 40.18%.

## Changes after each feedback round

### Iteration 0

The first generated strategy paired opening and closing element names and used
`st.recursive` for nested XML. It already covered most of the tracked input
features.

The original campaign measured acceptance below the 40% to 70% target. No
production was marked missing, so the next revision focused on malformed
variants.

### Iteration 1

The model added 13 helpers, including:

```text
bad_xml_decl_document
duplicate_attribute_document
comment_double_hyphen_document
empty_elem_name_document
doctype_mismatch_document
invalid_name_start_document
malformed_reference_document
missing_equals_attribute_document
```

These were chosen from the model's XML knowledge rather than from a named
missing production. The original summary then reported that deep nesting was
missing.

### Iteration 2

The next revision added:

```text
deep_nesting_document
nested_defect_document
_valid_codepoint
```

The first two additions directly addressed the missing deep-nesting feature.
The original measured depth rose from 5 to 87. Corrected coverage also reached
its highest value here, 40.18%.

The next summary marked named entities as missing.

### Iteration 3

The model added named entity cases and several attribute and DTD cases:

```text
named_entity_document
custom_entity_document
attr_reference_document
cdata_close_in_text_document
doctype_external_id_document
invalid_attr_name_document
mismatched_quote_attr_document
```

The named-entity helpers answered the missing feature. The following summary
marked unterminated input as missing.

### Iteration 4

The final revision added:

```text
truncated_document
invalid_codepoint_charref_document
```

`truncated_document` addressed the missing unterminated-input feature.

## Interpretation

The feedback changed the generated code in visible ways. Three consecutive
summaries named a missing feature, and the next strategy added a helper for that
feature.

That does not mean every added helper improved parser coverage. Acceptance rose
from 29.7% to 48.3%, while coverage peaked in iteration 2 and then fell slightly.
Production count also stayed close to its ceiling. The loop was responsive, but
some of its feedback signals were weak measures of parser behavior.

The five iterations reached 21 diagnostic templates as a union. Individual
iterations reached fewer, which shows that later strategies did not retain every
behavior of earlier ones. Keeping a pool of useful strategies would preserve
that variety better than keeping only the latest strategy.
