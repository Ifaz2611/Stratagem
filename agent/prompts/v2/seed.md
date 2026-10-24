# Task

Write a Hypothesis strategy that generates strings in the language of the XML
grammar below, adapted to the specific parser under test.

## The formal grammar

This is `XMLParser.g4` and `XMLLexer.g4` from ANTLR's `grammars-v4`, pinned at
commit {grammar_commit}.

### XMLParser.g4

```antlr
{parser_g4}
```

### XMLLexer.g4

```antlr
{lexer_g4}
```

## How the real parser differs from that grammar

The target is Mini-XML (mxml) v4.0.4. Its accepted language is **not** the same
as the grammar above. Every item below was measured by running the actual
binary, not inferred. Ignoring these wastes your example budget on inputs that
are rejected before any interesting code runs.

### The parser REJECTS things the grammar allows

- **Tag names must match.** The grammar draws the opening and closing `Name` of
  an element independently, so it accepts `<a></b>`. The parser rejects that
  ("Mismatched close tag"). This is not a flaw in the grammar: matching tags is
  not a context-free property, so no CFG can express it. **You must thread the
  chosen element name through the production so open and close agree.** A
  generator that draws them independently is rejected on nearly every nested
  document and tests almost nothing.
- **Only four named entities exist**: `&amp;` `&lt;` `&gt;` `&quot;`.
  Notably `&apos;` is NOT supported even though XML 1.0 defines it. Any other
  name is rejected ("Entity ... not supported").
- **Character references are range-checked.** `&#0;` is rejected as a control
  character, and huge values like `&#xFFFFFFFFFFFF;` are rejected.

### The parser ACCEPTS things the grammar cannot produce

These reach code paths a grammar-faithful generator never touches:

- **Unquoted attribute values**: `<r a=1/>`. The grammar's `STRING` requires
  quotes.
- **Documents with no root element**: `<!-- just a comment -->` alone parses.
- **Empty element names**: `< />` parses.
- **XML declaration with no space**: `<?xml?>` parses.
- **Name characters outside the grammar's `NameStartChar`.** The grammar omits
  `U+00C0-U+02FF` and `U+0370-U+1FFF`, which XML 1.0 includes and the parser
  accepts: `<é/>`, `<α/>`, `<Ā/>` all parse.

### Same input, different treatment

- A raw control character in text produces a diagnostic **but the document still
  parses successfully**. Error-and-recover paths like this are among the least
  exercised code in the library.
- `<!DOCTYPE ...>` is consumed up to the first `>`, so an internal subset such
  as `<!DOCTYPE r [<!ELEMENT r EMPTY>]>` is mis-parsed but still accepted.

### What is NOT worth chasing

The parser is **iterative, not recursive**, for element nesting. Documents
nested 500,000 deep parse successfully under an 8 MiB stack. Deep nesting alone
will not exhaust the stack. Generate varied depth because the grammar is
recursive and depth shapes other behaviour, but do not expect depth by itself to
find a bug. The richer surface is entity decoding, UTF-8 handling, attribute
parsing, and the error-and-recover paths.

## What you are being optimised for

There is no coverage instrumentation. The loop steers on:

1. **The mixture of three input classes.** Every document you generate is
   classified, by inspecting the document itself, into exactly one of:

   | class | what it means | target share |
   |---|---|---|
   | `well_formed` | should parse successfully | **~50%** |
   | `near_miss` | XML-shaped but structurally wrong: mismatched tags, unknown entities, multiple roots, empty element names, no root at all | **>=25%** |
   | `byte_hostile` | hostile at the byte and encoding level: raw control characters, truncated constructs (unterminated comment, CDATA, processing instruction or tag), byte-order marks, truncated multi-byte UTF-8 sequences, mixed or lying encoding declarations | **>=25%** |

   This split is the single most important requirement. A generator that
   produces 95% well-formed documents can sit inside a healthy-looking overall
   acceptance rate while never testing the code that handles malformed bytes,
   and that is where memory-safety bugs in a C parser concentrate. Weight your
   top-level production explicitly so the shares come out near those targets.

2. **Distinct parser diagnostics reached.** Every distinct message the parser
   emits corresponds to a different branch in its source, so triggering
   messages you have not triggered before means reaching new code. You will be
   told which messages you have already triggered, and asked for ones you have
   not.

3. **Acceptance rate, reported per class as well as overall.** Overall should
   land roughly 40-70%. `well_formed` should be high. `near_miss` and
   `byte_hostile` are *expected* to be mostly rejected: that is their job.
   Do not raise their acceptance by making them less malformed.

4. **Grammar production coverage** across this vocabulary, measured by scanning
   your generated documents:
   {productions}

5. **Structural spread**: nesting depth, document length, attribute counts.

## Baseline to beat

A naive random-text strategy scored, averaged over 3 trials of 500 documents:
acceptance **0.2%**, productions **4.3/23**, max nesting depth **0.3**,
distinct diagnostics **3.3**, crashes **0**. Almost every document died on the
parser's very first check because random text does not begin with `<`.

## Required coverage

Explicitly cover: empty containers, deep nesting, duplicate attributes, extreme
numeric values in character references, unicode and escaped characters, and
near-valid-but-malformed inputs.

Under unicode and escaped characters, include **byte-level** hostility, not only
unusual code points: a UTF-8 byte-order mark, a UTF-16 byte-order mark followed
by an odd number of bytes, a multi-byte sequence truncated mid-character, a
continuation byte with no lead byte, an overlong encoding, and an `encoding=`
declaration that contradicts the actual bytes. A generator that emits only
well-formed UTF-8 leaves the decoder almost untested.

Now write the strategy.
