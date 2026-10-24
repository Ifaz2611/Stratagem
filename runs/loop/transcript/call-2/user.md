# Task

Revise the Hypothesis strategy below using the measured results of its last run.

## Current strategy (iteration 1)

```python
import string

from hypothesis import strategies as st

NAME: str = "mxml_targeted_fuzzer"
DESCRIPTION: str = (
    "Generates XML-like documents tuned for Mini-XML (mxml) v4.0.4. Builds "
    "well-formed documents with real recursive nesting where the open and "
    "close tag names are threaded through so they match, plus dedicated "
    "near-miss generators for mismatched tags, unsupported entities, "
    "out-of-range character references, unterminated markup, rootless "
    "documents, and multiple top-level elements. Also covers mxml-specific "
    "accept cases the formal grammar rejects, such as unquoted attribute "
    "values, empty element names, a DOCTYPE with an internal subset, and "
    "non-ASCII name characters outside the grammar's NameStartChar ranges."
)

_ASCII_NAME_START = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_:"
_ASCII_NAME_CHAR = _ASCII_NAME_START + string.digits + ".-"
# Characters from ranges (U+00C0-02FF, U+0370-1FFF) that mxml accepts in
# names but the ANTLR grammar's NameStartChar does not cover.
_NONASCII_NAME_START = (
    "\u00e9\u00e0\u00c2\u00c0\u00d1\u00f1\u00d6\u00f6"
    "\u0100\u0101\u0103\u03b1\u03b2\u03b3\u03a9\u03bc"
)

_SAFE_TEXT_CHARS = string.ascii_letters + string.digits + " .,-_:;()"
_CONTROL_CHARS = "\x01\x02\x07\x0b\x0c\x1f"
_UNICODE_TEXT_CHARS = "\u00e9\u00fc\u00f1\u4e2d\u6587\u03b1\u6f22"
_NAMED_ENTITIES = ["amp", "lt", "gt", "quot"]
_UNSUPPORTED_ENTITIES = ["apos", "nbsp", "copy", "zzz"]

_MAX_DEPTH = 3


def _ascii_name():
    return st.builds(
        lambda f, r: f + r,
        st.sampled_from(_ASCII_NAME_START),
        st.text(alphabet=_ASCII_NAME_CHAR, min_size=0, max_size=6),
    )


def _nonascii_name():
    return st.builds(
        lambda f, r: f + r,
        st.sampled_from(_NONASCII_NAME_START),
        st.text(alphabet=_ASCII_NAME_CHAR + _NONASCII_NAME_START, min_size=0, max_size=5),
    )


def xml_name():
    return st.one_of(_ascii_name(), _ascii_name(), _ascii_name(), _nonascii_name())


def _attr_value_text(forbidden):
    alphabet = [c for c in _SAFE_TEXT_CHARS if c not in forbidden]
    return st.text(alphabet=alphabet, min_size=0, max_size=10)


def chardata_text():
    normal = st.text(alphabet=_SAFE_TEXT_CHARS, min_size=1, max_size=20)
    unicode_mix = st.builds(
        lambda a, c, b: a + c + b,
        st.text(alphabet=_SAFE_TEXT_CHARS, min_size=0, max_size=8),
        st.sampled_from(_UNICODE_TEXT_CHARS),
        st.text(alphabet=_SAFE_TEXT_CHARS, min_size=0, max_size=8),
    )
    with_control = st.builds(
        lambda a, c, b: a + c + b,
        st.text(alphabet=_SAFE_TEXT_CHARS, min_size=0, max_size=8),
        st.sampled_from(_CONTROL_CHARS),
        st.text(alphabet=_SAFE_TEXT_CHARS, min_size=0, max_size=8),
    )
    ws = st.sampled_from([" ", "\n", "\t", "  \n", "\r\n"])
    return st.one_of(normal, normal, unicode_mix, with_control, ws)


def entity_ref():
    named = st.sampled_from(_NAMED_ENTITIES).map(lambda n: "&" + n + ";")
    unsupported = st.sampled_from(_UNSUPPORTED_ENTITIES).map(lambda n: "&" + n + ";")
    return st.one_of(named, named, named, unsupported)


def charref_dec():
    normal = st.integers(min_value=1, max_value=0x10FFFF).map(lambda n: "&#%d;" % n)
    extreme = st.sampled_from([0, 0xFFFFFFFF, 999999999999, 1114112]).map(lambda n: "&#%d;" % n)
    return st.one_of(normal, normal, normal, extreme)


def charref_hex():
    normal = st.integers(min_value=1, max_value=0x10FFFF).map(lambda n: "&#x%x;" % n)
    extreme = st.sampled_from([0, 0xFFFFFFFFFFFF, 0x110000]).map(lambda n: "&#x%x;" % n)
    return st.one_of(normal, normal, normal, extreme)


def reference():
    return st.one_of(entity_ref(), charref_dec(), charref_hex())


def cdata_section():
    body = st.text(alphabet=_SAFE_TEXT_CHARS, min_size=0, max_size=30)
    return body.map(lambda b: "<![CDATA[" + b + "]]>")


def comment():
    alphabet = [c for c in _SAFE_TEXT_CHARS if c != "-"]
    body = st.text(alphabet=alphabet, min_size=0, max_size=30)
    return body.map(lambda b: "<!--" + b + "-->")


def pi():
    target = _ascii_name()
    alphabet = [c for c in _SAFE_TEXT_CHARS if c != "?"]
    body = st.text(alphabet=alphabet, min_size=0, max_size=20)
    return st.builds(lambda t, b: "<?" + t + " " + b + "?>", target, body)


def prolog():
    version = st.sampled_from(['version="1.0"', "version='1.0'"])
    encoding = st.sampled_from(["", ' encoding="UTF-8"', " encoding='utf-8'"])
    standalone = st.sampled_from(["", ' standalone="yes"', ' standalone="no"'])
    normal = st.builds(
        lambda v, e, s: "<?xml " + v + e + s + "?>", version, encoding, standalone
    )
    no_space = st.just("<?xml?>")
    return st.one_of(normal, normal, normal, no_space)


def doctype(root_name):
    simple = st.just("<!DOCTYPE " + root_name + ">")
    internal_subset = st.sampled_from(["EMPTY", "ANY", "(#PCDATA)"]).map(
        lambda e: "<!DOCTYPE " + root_name + " [<!ELEMENT " + root_name + " " + e + ">]>"
    )
    return st.one_of(simple, simple, internal_subset)


def misc_item():
    return st.one_of(
        comment(), pi(), st.sampled_from([" ", "\n", "\t\n", "  ", "\r\n"])
    )


@st.composite
def misc_list(draw, max_items=3):
    n = draw(st.integers(min_value=0, max_value=max_items))
    return "".join(draw(misc_item()) for _ in range(n))


@st.composite
def _attribute(draw):
    name = draw(xml_name())
    kind = draw(st.sampled_from(["d", "d", "s", "s", "u"]))
    if kind == "d":
        value = draw(_attr_value_text('<"'))
        return name + '="' + value + '"'
    if kind == "s":
        value = draw(_attr_value_text("<'"))
        return name + "='" + value + "'"
    value = draw(st.text(alphabet=string.ascii_letters + string.digits, min_size=1, max_size=6))
    return name + "=" + value


@st.composite
def _attribute_list(draw):
    n = draw(st.integers(min_value=0, max_value=3))
    attrs = [draw(_attribute()) for _ in range(n)]
    if attrs and draw(st.integers(min_value=0, max_value=4)) == 0:
        # deliberately duplicate an attribute name with a fresh value
        dup_name = attrs[0].split("=", 1)[0]
        value = draw(_attr_value_text('<"'))
        attrs.append(dup_name + '="' + value + '"')
    return attrs


def _render_attrs(attrs):
    return "".join(" " + a for a in attrs)


@st.composite
def element(draw, depth=0):
    if draw(st.integers(min_value=0, max_value=40)) == 0:
        return "< />"

    name = draw(xml_name())
    attrs = draw(_attribute_list())
    attr_str = _render_attrs(attrs)

    force_self_close = depth >= _MAX_DEPTH
    self_close = force_self_close or draw(st.booleans())
    if self_close:
        return "<" + name + attr_str + "/>"

    body = draw(content(depth))
    close_name = name
    if name and draw(st.integers(min_value=0, max_value=15)) == 0:
        # rare deliberate mismatch between open and close tag names
        close_name = name + "x"
    return "<" + name + attr_str + ">" + body + "</" + close_name + ">"


@st.composite
def content(draw, depth):
    n = draw(st.integers(min_value=0, max_value=3))
    parts = []
    for _ in range(n):
        choice = draw(st.integers(min_value=0, max_value=99))
        if choice < 32:
            parts.append(draw(chardata_text()))
        elif choice < 47:
            parts.append(draw(reference()))
        elif choice < 57:
            parts.append(draw(cdata_section()))
        elif choice < 67:
            parts.append(draw(comment()))
        elif choice < 75:
            parts.append(draw(pi()))
        else:
            parts.append(draw(element(depth + 1)))
    return "".join(parts)


@st.composite
def deep_chain(draw):
    depth = draw(st.integers(min_value=5, max_value=40))
    names = [draw(xml_name()) for _ in range(depth)]
    s = draw(chardata_text())
    for name in reversed(names):
        s = "<" + name + ">" + s + "</" + name + ">"
    return s


@st.composite
def well_formed_document(draw):
    parts = []
    if draw(st.integers(min_value=0, max_value=3)) == 0:
        parts.append(draw(prolog()))
        parts.append(draw(misc_list(1)))
    parts.append(draw(misc_list(2)))

    if draw(st.integers(min_value=0, max_value=4)) == 0:
        root_name = draw(xml_name())
        parts.append(draw(doctype(root_name)))
        parts.append(draw(misc_list(1)))
        attrs = draw(_attribute_list())
        parts.append("<" + root_name + _render_attrs(attrs) + "/>")
    elif draw(st.integers(min_value=0, max_value=4)) == 0:
        parts.append(draw(deep_chain()))
    else:
        parts.append(draw(element(0)))

    parts.append(draw(misc_list(2)))
    return "".join(parts)


@st.composite
def rootless_document(draw):
    body = draw(misc_list(4))
    if not body:
        body = draw(comment())
    return body


@st.composite
def multiple_roots_document(draw):
    first = draw(element(0))
    second = draw(element(0))
    sep = draw(st.sampled_from(["", " ", "\n"]))
    return first + sep + second


@st.composite
def unterminated_document(draw):
    kind = draw(st.sampled_from(["open_tag", "attr_string", "comment", "cdata", "close_tag"]))
    name = draw(xml_name())
    if kind == "open_tag":
        return "<" + name
    if kind == "attr_string":
        attr_name = draw(xml_name())
        return "<" + name + " " + attr_name + '="unterminated'
    if kind == "comment":
        body = draw(st.text(alphabet=_SAFE_TEXT_CHARS, min_size=0, max_size=15))
        return "<!--" + body
    if kind == "cdata":
        body = draw(st.text(alphabet=_SAFE_TEXT_CHARS, min_size=0, max_size=15))
        return "<![CDATA[" + body
    body = draw(chardata_text())
    return "<" + name + ">" + body


@st.composite
def mismatched_tag_document(draw):
    name = draw(xml_name())
    other = draw(xml_name())
    if other == name:
        other = other + "z"
    body = draw(chardata_text())
    return "<" + name + ">" + body + "</" + other + ">"


@st.composite
def unsupported_entity_document(draw):
    name = draw(xml_name())
    ent = draw(st.sampled_from(_UNSUPPORTED_ENTITIES))
    return "<" + name + ">&" + ent + ";</" + name + ">"


@st.composite
def extreme_charref_document(draw):
    name = draw(xml_name())
    kind = draw(st.sampled_from(["dec", "hex"]))
    if kind == "dec":
        val = draw(st.sampled_from([0, 0xFFFFFFFF, 999999999999, 1114112]))
        ref = "&#%d;" % val
    else:
        val = draw(st.sampled_from([0, 0xFFFFFFFFFFFF, 0x110000]))
        ref = "&#x%x;" % val
    return "<" + name + ">" + ref + "</" + name + ">"


def documents() -> "st.SearchStrategy[str]":
    return st.one_of(
        well_formed_document(),
        well_formed_document(),
        well_formed_document(),
        well_formed_document(),
        well_formed_document(),
        rootless_document(),
        multiple_roots_document(),
        unterminated_document(),
        mismatched_tag_document(),
        unsupported_entity_document(),
        extreme_charref_document(),
    )

```

## Measured results over 500 generated documents

### Outcomes

```
{
  "parsed_clean": 152,
  "rejected": 342,
  "parsed_diag": 6
}
```

- **Acceptance rate: 31.6%** (target band: 40-70%)
- Crashes: 0
- Documents that were XML-shaped (began with `<`): 99.4%

### Grammar production coverage: 23/23

Reached:
```
  247  g_element_selfclose
  221  g_element_paired
  201  g_chardata
  193  g_pi
  189  g_attribute_dquot
  174  g_comment
  152  g_attribute_squot
  136  x_name_nonascii
  116  x_attribute_unquoted
   92  g_prolog
   79  x_doctype
   61  x_control_char
   60  x_rootless
   46  x_multiple_roots
   39  x_mismatched_tags
   37  g_nesting_deep
   31  g_charref_hex
   26  g_cdata
   19  x_entity_unsupported
   15  g_charref_dec
   13  g_entity_named
   12  x_empty_elem_name
   12  x_unterminated
```

**Never produced:**
```
(none -- full coverage)
```

### Nesting depth distribution

```
{
  "0": 279,
  "1": 146,
  "16+": 30,
  "2-3": 30,
  "4-7": 8,
  "8-15": 7
}
```
Deepest document generated: 40

### Distinct parser diagnostics reached: 35

```
   65  <%s> cannot be a second root node after <%s> on line %d.
   47  XML does not start with '%s' (saw '%s').
   42  Early EOF in comment node on line %d.
   39  Bad control character 0x%x not allowed by XML standard.
   30  Missing close tag </%s> under parent <%s> on line %d.
   28  Entity '%s' not supported under parent <%s> on line %d.
   28  Mismatched close tag </%s> under parent <%s> on line %d.
   13  <%s?> cannot be a second root node after <%s> on line %d.
   10  <%s--> cannot be a second root node after <%s> on line %d.
    8  Bad control character 0x%x under parent <%s> on line %d not allowed by XML standard.
    7  Duplicate attribute '%s' in element O74 on line %d.
    6  Duplicate attribute '%s' in element WMSrKel on line %d.
    6  Duplicate attribute '%s' in element icC3Y on line %d.
    5  Early EOF in CDATA node on line %d.
    4  Duplicate attribute '%s' in element HKR on line %d.
    4  Duplicate attribute '%s' in element b on line %d.
    4  Duplicate attribute '%s' in element l on line %d.
    3  <%s> cannot be a second root node after <%s--><%s> on line %d.
    3  Duplicate attribute '%s' in element a on line %d.
    3  Duplicate attribute '%s' in element oxN0PbP on line %d.
```

Each distinct message above is a different branch inside the parser. Messages
you have never triggered are branches you have never reached.

### Document size

```
{
  "min": 2,
  "max": 530,
  "mean": 82.3,
  "median": 53.0
}
```

### Slowest documents

```
     8.7 ms  len=31     depth=0   parsed_clean
     8.1 ms  len=25     depth=1   rejected
     7.6 ms  len=15     depth=1   rejected
```

### Crashes found

None yet. Sanitizers are active and a known real bug is detected by this pipeline, so the absence is real, not a detection failure.

## What to do

Diagnose, then revise. Specifically:

1. If the acceptance rate is outside 40-70%, fix that first. Below the band,
   find which production is malformed and repair it. Above the band, add
   near-miss productions that exercise error handling.
2. Any production listed as never produced is dead weight in the grammar
   vocabulary. Either generate it, or it stays untested forever.
3. Use your own knowledge of XML to reason about which parser branches you have
   NOT yet triggered, given the diagnostics you have and have not seen. Target
   those. Think about what kinds of malformed XML would produce messages absent
   from the list above.
4. If nesting depth is shallow, deepen the recursion. If it is uniform, vary it.
5. Keep everything that is working. This is a revision, not a rewrite.

Output the complete revised module as one fenced ```python block.
