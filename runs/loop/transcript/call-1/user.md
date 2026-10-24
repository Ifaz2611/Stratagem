# Task

Write a Hypothesis strategy that generates strings in the language of the XML
grammar below, adapted to the specific parser under test.

## The formal grammar

This is `XMLParser.g4` and `XMLLexer.g4` from ANTLR's `grammars-v4`, pinned at
commit e756f2a2ee5565a9300666f100ba6acd874664f7.

### XMLParser.g4

```antlr
/** XML parser derived from ANTLR v4 ref guide book example */


parser grammar XMLParser;

options {
    tokenVocab = XMLLexer;
}

document
    : prolog? misc* element misc* EOF
    ;

prolog
    : XMLDeclOpen attribute* SPECIAL_CLOSE
    ;

content
    : chardata? ((element | reference | CDATA | PI | COMMENT) chardata?)*
    ;

element
    : '<' Name attribute* '>' content '<' '/' Name '>'
    | '<' Name attribute* '/>'
    ;

reference
    : EntityRef
    | CharRef
    ;

attribute
    : Name '=' STRING
    ; // Our STRING is AttValue in spec

/** ``All text that is not markup constitutes the character data of
 *  the document.''
 */
chardata
    : TEXT
    | SEA_WS
    ;

misc
    : COMMENT
    | PI
    | SEA_WS
    ;
```

### XMLLexer.g4

```antlr
/** XML lexer derived from ANTLR v4 ref guide book example */


lexer grammar XMLLexer;

// Default "mode": Everything OUTSIDE of a tag
COMMENT : '<!--' .*? '-->';
CDATA   : '<![CDATA[' .*? ']]>';
/** Scarf all DTD stuff, Entity Declarations like <!ENTITY ...>,
 *  and Notation Declarations <!NOTATION ...>
 */
DTD       : '<!' .*? '>' -> skip;
EntityRef : '&' Name ';';
CharRef   : '&#' DIGIT+ ';' | '&#x' HEXDIGIT+ ';';
SEA_WS    : (' ' | '\t' | '\r'? '\n')+;

OPEN         : '<'       -> pushMode(INSIDE);
XMLDeclOpen  : '<?xml' S -> pushMode(INSIDE);
SPECIAL_OPEN : '<?' Name -> more, pushMode(PROC_INSTR);

TEXT: ~[<&]+; // match any 16 bit char other than < and &

// ----------------- Everything INSIDE of a tag ---------------------
mode INSIDE;

CLOSE         : '>'  -> popMode;
SPECIAL_CLOSE : '?>' -> popMode; // close <?xml...?>
SLASH_CLOSE   : '/>' -> popMode;
SLASH         : '/';
EQUALS        : '=';
STRING        : '"' ~[<"]* '"' | '\'' ~[<']* '\'';
Name          : NameStartChar NameChar*;
S             : [ \t\r\n] -> skip;

fragment HEXDIGIT: [a-fA-F0-9];

fragment DIGIT: [0-9];

fragment NameChar:
    NameStartChar
    | '-'
    | '.'
    | DIGIT
    | '\u00B7'
    | '\u0300' ..'\u036F'
    | '\u203F' ..'\u2040'
;

fragment NameStartChar:
    [_:a-zA-Z]
    | '\u2070' ..'\u218F'
    | '\u2C00' ..'\u2FEF'
    | '\u3001' ..'\uD7FF'
    | '\uF900' ..'\uFDCF'
    | '\uFDF0' ..'\uFFFD'
;

// ----------------- Handle <? ... ?> ---------------------
mode PROC_INSTR;

PI     : '?>' -> popMode; // close <?...?>
IGNORE : .    -> more;
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
   g_prolog  g_element_paired  g_element_selfclose  g_attribute_dquot
   g_attribute_squot  g_chardata  g_entity_named  g_charref_dec
   g_charref_hex  g_cdata  g_comment  g_pi
   g_nesting_deep  x_attribute_unquoted  x_doctype  x_empty_elem_name
   x_rootless  x_name_nonascii  x_mismatched_tags  x_entity_unsupported
   x_multiple_roots  x_control_char  x_unterminated
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
