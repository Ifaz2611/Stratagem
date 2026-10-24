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

The target is a memory-safety crash. Two runs of this loop have already reached
a plateau by making documents progressively more malformed, so that is not the
approach here.

**Memory bugs in a C parser live at boundaries, not at extremes.** A fixed-size
buffer overflows one byte past its end, not at a thousand. A counted loop
miscounts at zero or at exactly its limit. An index computation wraps at the
type's maximum. A document a thousand times too large is usually rejected in the
same code path as one twice too large, and teaches nothing new.

So the primary objective is **dense boundary coverage of every counted or
measured thing in an XML document**:

| dimension | sweep |
|---|---|
| element and attribute name length | 0, 1, 2, then a dense range through the low hundreds |
| entity name length between `&` and `;` | a dense range; there is a limit, find it and sit on both sides of it |
| attribute value length | 0, 1, then a dense range through the low thousands |
| attributes on one element | 0, 1, 2, then dense through the low hundreds |
| nesting depth | 0, 1, 2, then dense, and also very deep |
| numeric character reference value | 0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FF, 0x800, 0xFFFF, 0x10000, 0x10FFFF, 0x110000, and values that overflow a 32-bit and 64-bit integer |
| content length between two tags | 0, 1, then dense across power-of-two sizes and one either side of each |

Use `st.sampled_from` on explicit boundary lists for these, not a wide
`st.integers`. A random draw from 1..10000 almost never lands on 255, 256 or
257; a sampled draw lands on all three.

Where the parser reports that something is too long, too deep or otherwise past
a limit, that diagnostic tells you a boundary exists. Generate that construct at
every length in a window around where the message starts appearing.

**Second objective: a defect must be reached to matter.** You will be told the
acceptance rate per input class. In previous runs, documents hostile at the byte
level were rejected about 86% of the time, which means they died at the front
door without traversing the parser. Standalone hostile documents are cheap and
mostly wasted.

Prefer instead: a valid, deeply nested document with **exactly one** defect
placed deep inside it. One truncated multi-byte sequence in one attribute value.
One unterminated comment nested ten elements down. One entity name one character
past the limit, inside an element that is otherwise well formed. The document
should get as far into the parser as possible before the defect is met.

**Third objective: combine dimensions.** Bugs that survive single-dimension
fuzzing often need two things at once. A very long name at a very deep nesting
level. Hundreds of attributes each holding a long value. A long attribute value
that is mostly character references.

**Also measured**, and reported back each iteration:

- Which grammar productions have appeared and which never have:
  {productions}
- Distinct parser diagnostics triggered. Each distinct message comes from a
  different line of the parser, so a message you have not yet triggered is a
  branch you have not yet reached.
- Overall acceptance rate, target band 40-70%, and acceptance per input class.
- The input-class mixture. **This is checked mechanically before your strategy
  is accepted.** A sample of your documents is classified, and a strategy
  outside these bounds is rejected and sent back to you:

  | class | meaning | required share |
  |---|---|---|
  | `well_formed` | parses successfully | **at least 35%** |
  | `near_miss` | XML-shaped but structurally wrong | **at least 15%** |
  | `byte_hostile` | control bytes, truncation, bad encoding, BOMs | **15% to 45%** |

  Note the upper bound on `byte_hostile`. Two earlier runs pushed it past 50%
  and lost real coverage doing so: those documents die in the encoding and
  lexing front end and never reach the parsing code where the interesting bugs
  are. Byte-level hostility pays off when it sits *inside* a document the parser
  is willing to walk into, which is why `well_formed` has the largest floor.

  A document counts as `byte_hostile` if it carries a BOM, invalid UTF-8, an
  embedded NUL, a control character or a contradictory `encoding=` declaration.
  A long name or a deep nest is not byte hostility, so those boundary sweeps
  belong in your `well_formed` documents and cost you nothing in this mixture.

## Baseline to beat

A naive random-text strategy scored, averaged over 3 trials of 500 documents:
acceptance **0.2%**, max nesting depth **0.3**, distinct diagnostics **3.3**,
crashes **0**. Almost every document died on the parser's very first check
because random text does not begin with `<`.

Two previous grammar-seeded runs reached acceptance in the 40s, full production
coverage and nesting depth in the hundreds, and found **no crash** in 7,000
documents. Repeating that shape of generator will not help. The boundary sweeps
above are what is new.

## Required coverage

Explicitly cover: empty containers, deep nesting, duplicate attributes, extreme
numeric values in character references, unicode and escaped characters, and
near-valid-but-malformed inputs.

Under unicode and escaped characters, include **byte-level** hostility, not only
unusual code points: a UTF-8 byte-order mark, a UTF-16 byte-order mark followed
by an odd number of bytes, a multi-byte sequence truncated mid-character, a
continuation byte with no lead byte, an overlong encoding, and an `encoding=`
declaration that contradicts the actual bytes.

Place these inside otherwise-valid documents wherever you can, per the second
objective, rather than emitting them as standalone garbage. A truncated
multi-byte sequence in the middle of a long attribute value in a deeply nested
element is worth many standalone corrupt documents.

Now write the strategy.
