# Rotating refinement directives

One directive is selected per iteration, in order, and injected at the top of
the refine prompt.

## 1. sweep-boundaries

Take the length and count measurements in the report and turn each into a dense
sweep. Wherever a limit diagnostic has fired, generate that construct at every
length in a window around where it starts firing. Wherever a measurement shows a
narrow range, widen it to include 0, 1, 2 and values just below and just above
the largest already tried.

## 2. combine-extremes

Stop varying one dimension at a time. Produce documents that are extreme in two
or more dimensions at once: a deeply nested document whose innermost element has
a very long name; an element with hundreds of attributes each with a long value;
a long attribute value containing many character references; a deeply nested
document whose leaf contains a truncated construct.

## 3. corrupt-in-place

Keep documents that parse, and place a single defect deep inside them. Build a
valid, deeply nested document, then corrupt exactly one thing at one offset:
truncate one multi-byte sequence, unterminate one interior construct, put one
raw control byte inside one attribute value. The rest of the document must stay
well formed so the parser reaches the defect instead of rejecting at the front.
