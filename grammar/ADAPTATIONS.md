# XML grammar and mxml adaptations

This file records the grammar source and the differences I tested against mxml.

## Source

The project uses `XMLLexer.g4` and `XMLParser.g4` from the `xml/` directory
of [antlr/grammars-v4](https://github.com/antlr/grammars-v4). The source is
pinned at commit `e756f2a2ee5565a9300666f100ba6acd874664f7`
(2026-07-20). `scripts/fetch_grammar.sh` downloads the files and checks the
hashes stored in `grammar/SOURCE.txt`.

The parser target is mxml v4.0.4 at commit `0d5afc42`.

## Main grammar rules

```antlr
document  : prolog? misc* element misc* EOF
prolog    : XMLDeclOpen attribute* SPECIAL_CLOSE
element   : '<' Name attribute* '>' content '<' '/' Name '>'
          | '<' Name attribute* '/>'
content   : chardata? ((element | reference | CDATA | PI | COMMENT) chardata?)*
attribute : Name '=' STRING
reference : EntityRef | CharRef
misc      : COMMENT | PI | SEA_WS
```

`element` and `content` are recursive. The Hypothesis strategies represent
that structure with `st.recursive` and `@composite`.

Note that `element` draws the opening and closing `Name` independently, so the
grammar accepts `<a></b>`. That is a limit of the formalism, not an error in this
file: matching a close tag to its open tag is not a context-free property, so no
context-free grammar can express it. Row 2 below records the consequence.

## How I checked the differences

I ran small inputs through a probe that calls `mxmlLoadString`, the same parse
function used by the main harness. Source reading helped identify possible
differences, but the table below records results from the built binary.

One source-based guess was wrong. The declaration parser appeared likely to
reject a DTD internal subset, but the probe accepted it. This is why the final
adaptation list is based on execution.

## Summary

| # | input feature | ANTLR grammar | mxml |
|---:|---|---|---|
| 1 | named entities such as `&apos;` | accepts any name | supports only `amp`, `lt`, `gt`, and `quot` |
| 2 | mismatched tags, `<a></b>` | accepts | rejects |
| 3 | very large character references | accepts | rejects |
| 4 | `&#0;` | accepts | rejects |
| 5 | unquoted attribute, `<r a=1/>` | rejects | accepts |
| 6 | document without a root | rejects | accepts |
| 7 | empty element name, `< />` | rejects | accepts |
| 8 | XML declaration without a space | rejects | accepts |
| 9 | several non-ASCII name ranges | cannot produce | accepts |
| 10 | raw control character in text | grammar allows it | parses and reports a diagnostic |
| 11 | DTD declaration | lexer skips it | creates a declaration node |

## Cases where mxml accepts less

### Named entities

The grammar allows `'&' Name ';'`. mxml resolves four named entities:
`amp`, `lt`, `gt`, and `quot`. It rejects `apos` and unknown names.

```text
<r>&amp;</r>   accepted
<r>&quot;</r>  accepted
<r>&apos;</r>  rejected
<r>&foo;</r>   rejected
```

The default generator uses the four accepted names. Unknown entities are
generated separately as near-valid inputs.

### Matching element names

The two `Name` symbols in the grammar are independent, so the grammar can
produce `<a></b>`. mxml checks that the names match.

The strategy draws one name and uses it for both tags. Deliberate mismatches are
kept as a separate near-valid case. This adaptation greatly increases the
number of nested documents that reach the parser body.

### Character references

The grammar does not limit the length or value of decimal and hexadecimal
references. mxml rejects NUL and values outside its accepted range.

```text
<r>&#65;</r>                    accepted
<r>&#0;</r>                     rejected
<r>&#xFFFFFFFFFFFF;</r>         rejected
<r>&#999999999999999999999;</r> rejected
```

Normal character references use reasonable values. NUL and overflow cases are
generated as targeted malformed inputs.

## Cases where mxml accepts more

### Unquoted attributes

The grammar requires matching single or double quotes. mxml also accepts a bare
value:

```text
<r a="1"/>  accepted
<r a='1'/>  accepted
<r a=1/>    accepted by mxml, outside the grammar
```

### Structural differences

mxml accepts several small documents that the grammar rejects:

```text
<!-- c -->   no root element
< />         empty element name
<?xml?><r/>  no space after <?xml
```

The adapted strategy includes all three because they are real mxml inputs.

### Non-ASCII names

The ANTLR `NameStartChar` rule omits several ranges allowed by XML 1.0. mxml
accepts names from those ranges:

```text
<é/>   U+00E9
<Ā/>   U+0100
<α/>   U+03B1
```

The strategy uses the wider XML 1.0 name range. This also exercises multi-byte
UTF-8 handling in names.

## Cases with different handling

### Control characters

A raw control character can produce a diagnostic while
`mxmlLoadString` still returns a tree:

```text
<r>\x01</r>
diagnostic: Bad control character 0x01 not allowed by XML standard.
result: parsed
```

The harness therefore uses the parser return value for acceptance and records
diagnostics separately. "Parsed with diagnostics" is a separate outcome.

### DTD declarations

The ANTLR lexer skips a declaration beginning with `<!`. mxml creates a
declaration node instead.

```text
<!DOCTYPE r><r/>                       accepted
<!DOCTYPE r [<!ELEMENT r EMPTY>]><r/>  accepted
<!DOCTYPE r SYSTEM "x.dtd"><r/>        accepted
```

The strategy includes DOCTYPE forms as an mxml-specific extension.

## Other parser behavior

mxml tracks nested elements with parent pointers instead of recursive parser
calls. Probe documents with depths up to 500,000 parsed under an 8 MiB stack.
Deep XML remains useful for testing repeated parser state, but it is not a likely
stack-exhaustion case for this target.

mxml also treats `:` as a normal name character. It does not validate namespace
declarations, so namespace mistakes are not a useful source of rejections here.

## Effect on the generator and harness

The generator:

1. reuses one name for matching start and close tags;
2. emits mismatched tags only as near-valid inputs;
3. uses the four entity names accepted by mxml and tests unknown names
   separately;
4. includes unquoted attributes, rootless documents, empty element names, and
   DOCTYPE declarations;
5. uses the wider XML 1.0 name ranges;
6. keeps NUL and overflow character references in targeted malformed cases.

The harness classifies acceptance from the return value of `mxmlLoadString`.
Diagnostics are recorded independently, including cases where parsing succeeds.
