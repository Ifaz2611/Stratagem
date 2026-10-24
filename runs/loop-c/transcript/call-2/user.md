# Task

Revise the Hypothesis strategy below using the measured results of its last run.

**Directive for this iteration: deepen**

## Current strategy (iteration 1)

```python
"""
Hypothesis document generator for fuzzing a Mini-XML (mxml v4.0.4) parser
built with ASan/UBSan.

Produces a weighted mixture of:
  - well_formed documents (~50%): valid XML-shaped input built with a
    recursive element grammar where open/close tag names always match.
  - near_miss documents (~25%): XML-shaped but structurally wrong
    (mismatched tags, unsupported entities, bad char refs, multiple or
    zero roots, empty element names).
  - byte_hostile documents (~25%): hostile at the byte/encoding level
    (BOMs, truncated multi-byte UTF-8, lone continuation bytes, overlong
    encodings, embedded NUL, raw control characters, unterminated
    constructs, lying encoding declarations).
"""

from hypothesis import strategies as st
import string

NAME = "mxml_grammar_fuzzer"
DESCRIPTION = (
    "Recursive XML-shaped generator tuned to Mini-XML v4.0.4 quirks: "
    "matched-tag element trees with entities, char refs, CDATA, comments "
    "and PIs for the well-formed slice, structural near-misses (tag "
    "mismatch, unsupported entities, bad numeric char refs, multiple or "
    "missing roots, empty names) for the near-miss slice, and byte-level "
    "hostility (BOMs, truncated/invalid UTF-8, embedded NUL, control "
    "characters, unterminated markup, lying encoding declarations) for "
    "the byte-hostile slice."
)

# ---------------------------------------------------------------------------
# Names: widened past the grammar's NameStartChar to what mxml accepts.
# ---------------------------------------------------------------------------

_NAME_START_NONASCII_RANGES = [
    (0x00C0, 0x02FF),
    (0x0370, 0x1FFF),
    (0x2070, 0x218F),
    (0x2C00, 0x2FEF),
    (0x3001, 0xD7FF),
    (0xF900, 0xFDCF),
    (0xFDF0, 0xFFFD),
]

_NAME_CHAR_EXTRA_RANGES = [
    (0x0300, 0x036F),
    (0x203F, 0x2040),
]


def _chars_from_ranges(ranges):
    return st.one_of([st.integers(lo, hi).map(chr) for lo, hi in ranges])


_ascii_name_start = st.sampled_from(list(string.ascii_letters) + ["_", ":"])
_nonascii_name_start = _chars_from_ranges(_NAME_START_NONASCII_RANGES)

name_start_char = st.one_of(
    _ascii_name_start, _ascii_name_start, _ascii_name_start, _nonascii_name_start
)

name_char = st.one_of(
    name_start_char,
    st.sampled_from(list(string.digits) + ["-", ".", "\u00b7"]),
    _chars_from_ranges(_NAME_CHAR_EXTRA_RANGES),
)


@st.composite
def xml_name(draw, max_extra=8):
    start = draw(name_start_char)
    extra = draw(st.lists(name_char, max_size=max_extra))
    return start + "".join(extra)


# ---------------------------------------------------------------------------
# Entities, char refs, chardata, CDATA, comments, processing instructions.
# ---------------------------------------------------------------------------

def entity_ref_strategy():
    return st.sampled_from(["&amp;", "&lt;", "&gt;", "&quot;"])


def charref_strategy():
    # Restricted to legal XML characters so this feeds the well-formed
    # slice reliably; illegal / out-of-range values live in bad_charref_doc.
    valid = st.one_of(
        st.integers(min_value=0x20, max_value=0xD7FF),
        st.integers(min_value=0xE000, max_value=0xFFFD),
        st.integers(min_value=0x10000, max_value=0x10FFFF),
        st.sampled_from([0x09, 0x0A, 0x0D]),
    )
    dec = valid.map(lambda n: "&#%d;" % n)
    hexr = valid.map(lambda n: "&#x%X;" % n)
    return st.one_of(dec, hexr)


def chardata_strategy():
    ws = st.sampled_from([" ", "\t", "\n", "\r\n", "   ", " \n\t"])
    text = st.text(
        alphabet=st.characters(
            exclude_characters="<&", min_codepoint=0x20, max_codepoint=0xFFFF
        ),
        max_size=15,
    )
    return st.one_of(ws, text)


def cdata_strategy():
    body = st.text(
        alphabet=st.characters(exclude_characters="]", max_codepoint=0xFFFF),
        max_size=15,
    )
    return body.map(lambda s: "<![CDATA[%s]]>" % s)


def comment_strategy():
    body = st.text(
        alphabet=st.characters(exclude_characters="-", max_codepoint=0xFFFF),
        max_size=15,
    )
    return body.map(lambda s: "<!--%s-->" % s)


def pi_strategy():
    body = st.text(
        alphabet=st.characters(exclude_characters="?", max_codepoint=0xFFFF),
        max_size=12,
    )
    return st.builds(lambda t, b: "<?%s %s?>" % (t, b), xml_name(), body)


# ---------------------------------------------------------------------------
# Attributes: double/single quoted, unquoted (mxml-only extension), dups.
# ---------------------------------------------------------------------------

@st.composite
def attribute_strategy(draw):
    aname = draw(xml_name())
    style = draw(st.sampled_from(["dquot", "dquot", "squot", "squot", "unquoted"]))
    if style == "unquoted":
        value = draw(
            st.text(
                alphabet=st.characters(
                    exclude_characters=" \t\r\n<>" + "'" + '"' + "&",
                    min_codepoint=0x21,
                    max_codepoint=0x7E,
                ),
                min_size=1,
                max_size=8,
            )
        )
        return "%s=%s" % (aname, value)
    quote = '"' if style == "dquot" else "'"
    n = draw(st.integers(min_value=0, max_value=3))
    pieces = []
    for _ in range(n):
        pieces.append(
            draw(
                st.one_of(
                    st.text(
                        alphabet=st.characters(
                            exclude_characters="<&" + quote, max_codepoint=0xFFFF
                        ),
                        min_size=1,
                        max_size=6,
                    ),
                    entity_ref_strategy(),
                    charref_strategy(),
                )
            )
        )
    value = "".join(pieces)
    return "%s=%s%s%s" % (aname, quote, value, quote)


@st.composite
def attributes_list_strategy(draw):
    n = draw(st.integers(min_value=0, max_value=4))
    attrs = [draw(attribute_strategy()) for _ in range(n)]
    if attrs and draw(st.booleans()) and draw(st.booleans()):
        idx = draw(st.integers(min_value=0, max_value=len(attrs) - 1))
        dup_name = attrs[idx].split("=", 1)[0]
        new_val = draw(
            st.text(
                alphabet=st.characters(
                    exclude_characters="<&" + '"' + "'", max_codepoint=0x7E
                ),
                max_size=5,
            )
        )
        attrs.append('%s="%s"' % (dup_name, new_val))
    return attrs


def _render_attrs(attrs):
    return "".join(" " + a for a in attrs)


# ---------------------------------------------------------------------------
# Elements: recursive, name threaded through so open/close tags match.
# ---------------------------------------------------------------------------

def _make_self_closing(name, attrs):
    return "<%s%s/>" % (name, _render_attrs(attrs))


@st.composite
def _leaf_element(draw):
    name = draw(xml_name())
    attrs = draw(attributes_list_strategy())
    return _make_self_closing(name, attrs)


def _content_item(children):
    return st.one_of(
        chardata_strategy(),
        entity_ref_strategy(),
        charref_strategy(),
        cdata_strategy(),
        comment_strategy(),
        pi_strategy(),
        children,
    )


def _extend_element(children):
    @st.composite
    def _build(draw):
        name = draw(xml_name())
        attrs = draw(attributes_list_strategy())
        n_items = draw(st.integers(min_value=0, max_value=4))
        item_strategy = _content_item(children)
        parts = [draw(item_strategy) for _ in range(n_items)]
        return "<%s%s>%s</%s>" % (name, _render_attrs(attrs), "".join(parts), name)

    return _build()


element_strategy = st.recursive(_leaf_element(), _extend_element, max_leaves=12)


# ---------------------------------------------------------------------------
# Prolog, DOCTYPE, misc, well-formed document.
# ---------------------------------------------------------------------------

@st.composite
def _full_prolog(draw):
    version = draw(st.sampled_from(["1.0", "1.0", "1.0", "1.1"]))
    parts = ['version="%s"' % version]
    if draw(st.booleans()):
        enc = draw(st.sampled_from(["UTF-8", "utf-8"]))
        parts.append('encoding="%s"' % enc)
    if draw(st.booleans()):
        sa = draw(st.sampled_from(["yes", "no"]))
        parts.append('standalone="%s"' % sa)
    return "<?xml " + " ".join(parts) + "?>"


def prolog_strategy():
    return st.one_of(st.just("<?xml?>"), _full_prolog())


def doctype_strategy():
    simple = xml_name().map(lambda n: "<!DOCTYPE %s>" % n)
    with_subset = xml_name().map(
        lambda n: "<!DOCTYPE %s [<!ELEMENT %s EMPTY>]>" % (n, n)
    )
    return st.one_of(simple, with_subset)


def misc_strategy():
    return st.one_of(
        comment_strategy(), pi_strategy(), st.sampled_from([" ", "\n", "\t\n", "  \n"])
    )


@st.composite
def well_formed_document(draw):
    parts = []
    if draw(st.booleans()):
        parts.append(draw(prolog_strategy()))
    if draw(st.integers(min_value=0, max_value=4)) == 0:
        parts.append(draw(doctype_strategy()))
    parts.extend(draw(st.lists(misc_strategy(), max_size=3)))
    parts.append(draw(element_strategy))
    parts.extend(draw(st.lists(misc_strategy(), max_size=3)))
    return "".join(parts)


# ---------------------------------------------------------------------------
# Near-miss: XML-shaped but structurally wrong.
# ---------------------------------------------------------------------------

@st.composite
def mismatched_tags_doc(draw):
    n1, n2 = draw(st.tuples(xml_name(), xml_name()).filter(lambda t: t[0] != t[1]))
    attrs = draw(attributes_list_strategy())
    body = draw(
        st.text(
            alphabet=st.characters(exclude_characters="<&", max_codepoint=0xFFFF),
            max_size=15,
        )
    )
    return "<%s%s>%s</%s>" % (n1, _render_attrs(attrs), body, n2)


@st.composite
def unknown_entity_doc(draw):
    name = draw(xml_name())
    bad = draw(st.sampled_from(["&apos;", "&foo;", "&bar123;", "&nbsp;", "&Amp;"]))
    return "<%s>%s</%s>" % (name, bad, name)


@st.composite
def bad_charref_doc(draw):
    name = draw(xml_name())
    bad = draw(
        st.sampled_from(
            [
                "&#0;",
                "&#xD800;",
                "&#xFFFFFFFFFFFF;",
                "&#99999999;",
                "&#x110000;",
                "&#8;",
            ]
        )
    )
    return "<%s>%s</%s>" % (name, bad, name)


@st.composite
def multiple_roots_doc(draw):
    e1 = draw(element_strategy)
    e2 = draw(element_strategy)
    sep = draw(st.sampled_from(["", " ", "\n"]))
    return e1 + sep + e2


def empty_elem_name_doc():
    return st.sampled_from(["< />", "<></>", "< ></ >", "</>", "<>"])


@st.composite
def rootless_doc(draw):
    parts = draw(st.lists(misc_strategy(), min_size=0, max_size=5))
    return "".join(parts)


def near_miss_document():
    return st.one_of(
        mismatched_tags_doc(),
        unknown_entity_doc(),
        bad_charref_doc(),
        multiple_roots_doc(),
        empty_elem_name_doc(),
        rootless_doc(),
    )


# ---------------------------------------------------------------------------
# Byte-hostile: hostile at the byte / encoding level.
#
# Arbitrary raw bytes are smuggled through `str` using the standard
# surrogateescape convention: byte b < 0x80 -> chr(b); byte b >= 0x80 ->
# chr(0xDC00 + b). Encoding the result with errors="surrogateescape"
# reproduces the exact intended byte sequence, including invalid UTF-8.
# ---------------------------------------------------------------------------

def _raw_bytes_to_str(byte_values):
    out = []
    for b in byte_values:
        if b < 0x80:
            out.append(chr(b))
        else:
            out.append(chr(0xDC00 + b))
    return "".join(out)


def _control_char_strategy():
    codes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0E, 0x0F, 0x1F, 0x7F]
    return st.sampled_from(codes).map(chr)


def _truncated_multibyte_strategy():
    options = [[0xE2, 0x82], [0xF0, 0x9F, 0x98], [0xC3], [0xE0, 0xA0]]
    return st.sampled_from(options).map(_raw_bytes_to_str)


def _lone_continuation_strategy():
    return st.sampled_from([0x80, 0x81, 0xBF, 0x90, 0xAD]).map(
        lambda b: _raw_bytes_to_str([b])
    )


def _overlong_strategy():
    options = [
        [0xC0, 0xAF],
        [0xE0, 0x80, 0xAF],
        [0xF0, 0x80, 0x80, 0xAF],
        [0xC1, 0xBF],
    ]
    return st.sampled_from(options).map(_raw_bytes_to_str)


def _utf16_bom_odd_strategy():
    @st.composite
    def _gen(draw):
        endian = draw(st.sampled_from([[0xFF, 0xFE], [0xFE, 0xFF]]))
        extra_len = draw(st.sampled_from([1, 3, 5]))
        extra = draw(
            st.lists(
                st.integers(min_value=0, max_value=255),
                min_size=extra_len,
                max_size=extra_len,
            )
        )
        return _raw_bytes_to_str(endian + extra)

    return _gen()


@st.composite
def byte_hostile_document(draw):
    kind = draw(
        st.sampled_from(
            [
                "bom_utf8",
                "bom_utf16_odd",
                "bom_plus_encoding_lie",
                "truncated_multibyte",
                "lone_continuation",
                "overlong",
                "embedded_nul_text",
                "embedded_nul_attr",
                "embedded_nul_name",
                "control_char_text",
                "unterminated_comment",
                "unterminated_cdata",
                "unterminated_pi",
                "unterminated_tag",
                "unterminated_attr_string",
                "truncated_valid_doc",
                "encoding_lie",
                "raw_invalid_mix",
            ]
        )
    )
    if kind == "bom_utf8":
        base = draw(well_formed_document())
        return "\ufeff" + base
    if kind == "bom_utf16_odd":
        base = draw(well_formed_document())
        return draw(_utf16_bom_odd_strategy()) + base
    if kind == "bom_plus_encoding_lie":
        return '\ufeff<?xml version="1.0" encoding="UTF-16"?><r/>'
    if kind == "truncated_multibyte":
        frag = draw(_truncated_multibyte_strategy())
        return "<r>%s</r>" % frag
    if kind == "lone_continuation":
        frag = draw(_lone_continuation_strategy())
        return "<r>%s</r>" % frag
    if kind == "overlong":
        frag = draw(_overlong_strategy())
        return "<r>%s</r>" % frag
    if kind == "embedded_nul_text":
        return "<r>before%safter</r>" % chr(0)
    if kind == "embedded_nul_attr":
        return '<r a="x%sy"/>' % chr(0)
    if kind == "embedded_nul_name":
        return "<r%sx/>" % chr(0)
    if kind == "control_char_text":
        c = draw(_control_char_strategy())
        return "<r>before%safter</r>" % c
    if kind == "unterminated_comment":
        return "<!-- this comment never closes"
    if kind == "unterminated_cdata":
        return "<r><![CDATA[ never closes</r>"
    if kind == "unterminated_pi":
        return "<?pi never closes"
    if kind == "unterminated_tag":
        name = draw(xml_name())
        return '<%s attr="val"' % name
    if kind == "unterminated_attr_string":
        name = draw(xml_name())
        return '<%s attr="never closed' % name
    if kind == "truncated_valid_doc":
        full = draw(element_strategy)
        hi = max(1, min(8, len(full)))
        cut = draw(st.integers(min_value=1, max_value=hi))
        return full[:cut]
    if kind == "encoding_lie":
        enc = draw(st.sampled_from(["UTF-16", "ISO-8859-1", "UTF-32", "ASCII"]))
        body = draw(
            st.text(
                alphabet=st.characters(min_codepoint=0x80, max_codepoint=0x2FF),
                min_size=1,
                max_size=5,
            )
        )
        return '<?xml version="1.0" encoding="%s"?><r>%s</r>' % (enc, body)
    frag = draw(
        st.one_of(
            _truncated_multibyte_strategy(),
            _lone_continuation_strategy(),
            _overlong_strategy(),
        )
    )
    return '<?xml version="1.0" encoding="UTF-8"?><r a="%s">%s</r>' % (frag, frag)


# ---------------------------------------------------------------------------
# Top level mixture: ~50% well-formed, ~25% near-miss, ~25% byte-hostile.
# ---------------------------------------------------------------------------

def documents():
    mixed = st.one_of(
        well_formed_document(),
        well_formed_document(),
        near_miss_document(),
        byte_hostile_document(),
    )
    return mixed.map(lambda s: s if len(s) <= 6000 else s[:6000])

```

## Measured results over 500 generated documents

### Input class mixture, and acceptance within each class

```
byte_hostile   share= 31.4%  acceptance= 23.6%  n=157
near_miss      share= 31.2%  acceptance= 25.0%  n=156
well_formed    share= 37.4%  acceptance= 41.7%  n=187
```

Targets: `well_formed` ~50%, `near_miss` >=25%, `byte_hostile` >=25%.
`near_miss` and `byte_hostile` are *expected* to be mostly rejected. Do not
raise their acceptance by making them less malformed; that defeats their purpose.

Overall acceptance: **30.8%** (target band 40-70%)

### Marginal progress: what THIS iteration found that no earlier one did

This is what you are scored on. Repeating ground already covered by an earlier
iteration counts for nothing.

```
new diagnostic templates this iteration : 16
  + <%s--> cannot be a second root node after <%s> on line %d.
  + <%s> cannot be a second root node after <%s> on line %d.
  + <%s?> cannot be a second root node after <%s> on line %d.
  + Bad control character 0x%x not allowed by XML standard.
  + Bad control character 0x%x under parent <%s> on line %d not allowed by XML standard.
  + Duplicate attribute '%s' in element %s on line %d.
  + Early EOF in CDATA node on line %d.
  + Early EOF in comment node on line %d.
  + Early EOF in processing instruction node on line %d.
  + Entity '%s' not supported under parent <%s> on line %d.
  + Mismatched close tag </%s> under parent <%s> on line %d.
  + Missing value for attribute '%s' Sᜅpℯ2⁀⃁ƺ⁀=v6? ᧨="" _͛ﬗ徭='%s' in element %s on line %d.
  + Missing value for attribute '%s' in element %s on line %d.
  + Missing value for attribute '%s' p͛pℯ2⁀⃁ƺ⁀=v6? ᧨="" _͛ﬗ徭='%s' in element %s on line %d.
  + Missing value for attribute '%s' pᜅpℯ2⁀⃁ƺ⁀=v6? ᧨="" _͛ﬗ徭='%s' in element %s on line %d.
  + XML does not start with '%s' (saw '%s').
new grammar productions this iteration  : 26: g_attribute_dquot, g_attribute_squot, g_cdata, g_chardata, g_charref_dec, g_charref_hex, g_comment, g_element_paired, g_element_selfclose, g_entity_named, g_pi, g_prolog, x_attribute_unquoted, x_bom, x_control_char, x_doctype, x_embedded_nul, x_empty_elem_name, x_encoding_decl, x_entity_unsupported, x_invalid_utf8, x_mismatched_tags, x_multiple_roots, x_name_nonascii, x_rootless, x_unterminated
```

**Target: at least 3 diagnostic templates that no previous iteration reached.**

### Diagnostics already reached by ANY iteration so far (16 total)

```
<%s--> cannot be a second root node after <%s> on line %d.
<%s> cannot be a second root node after <%s> on line %d.
<%s?> cannot be a second root node after <%s> on line %d.
Bad control character 0x%x not allowed by XML standard.
Bad control character 0x%x under parent <%s> on line %d not allowed by XML standard.
Duplicate attribute '%s' in element %s on line %d.
Early EOF in CDATA node on line %d.
Early EOF in comment node on line %d.
Early EOF in processing instruction node on line %d.
Entity '%s' not supported under parent <%s> on line %d.
Mismatched close tag </%s> under parent <%s> on line %d.
Missing value for attribute '%s' Sᜅpℯ2⁀⃁ƺ⁀=v6? ᧨="" _͛ﬗ徭='%s' in element %s on line %d.
Missing value for attribute '%s' in element %s on line %d.
Missing value for attribute '%s' p͛pℯ2⁀⃁ƺ⁀=v6? ᧨="" _͛ﬗ徭='%s' in element %s on line %d.
Missing value for attribute '%s' pᜅpℯ2⁀⃁ƺ⁀=v6? ᧨="" _͛ﬗ徭='%s' in element %s on line %d.
XML does not start with '%s' (saw '%s').
```

Each of these is a branch in the parser that has already been visited. Reaching
them again adds nothing. Use your own knowledge of XML to reason about what
*other* error conditions a conforming parser must detect, which are absent from
this list, and construct documents that trigger them.

### Grammar production coverage: 26/27

Never produced by any iteration:
```
g_nesting_deep
```

### Nesting depth distribution

```
{
  "0": 174,
  "1": 306,
  "2-3": 20
}
```
Deepest document generated: 2

### Document size

```
{
  "min": 0,
  "max": 526,
  "mean": 118.8,
  "median": 106.0
}
```

### Slowest documents

```
    12.2 ms  len=15     depth=1   rejected
    11.0 ms  len=4      depth=0   parsed_clean
    10.2 ms  len=15     depth=1   rejected
```

### Crashes found

None yet. Sanitizers are active and a known real bug is detected by this pipeline, so the absence is real, not a detection failure.

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
