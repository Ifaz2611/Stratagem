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

1. **Grammar production coverage** across this vocabulary, measured by scanning
   your generated documents:
   {productions}
2. **Distinct parser diagnostics reached.** Every distinct message the parser
   emits corresponds to a different branch in its source, so triggering messages
   you have not triggered before means reaching new code.
3. **Acceptance rate held in a band, roughly 40-70%.** Too low and you never get
   past the front door. Too high and you never exercise error handling. Both
   failures are equally bad.
4. **Structural spread**: nesting depth, document length, attribute counts.

## Baseline to beat

A naive random-text strategy scored: acceptance **0.2%**, productions **6/23**,
max nesting depth **0**, distinct diagnostics **2**, crashes **0**.

## Required coverage

Explicitly cover: empty containers, deep nesting, duplicate attributes, extreme
numeric values in character references, unicode and escaped characters, and
near-valid-but-malformed inputs. Weight productions so most documents are
well-formed while a meaningful minority are deliberate near-misses.

Now write the strategy.
