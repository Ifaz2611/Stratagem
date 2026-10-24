# Task

Revise the Hypothesis strategy below using the measured results of its last run.

## Current strategy (iteration 2)

```python
import string

from hypothesis import strategies as st

NAME: str = "mxml_targeted_fuzzer"
DESCRIPTION: str = (
    "Generates XML-like documents tuned for Mini-XML (mxml) v4.0.4. Builds "
    "well-formed documents with real recursive nesting where open and close "
    "tag names are threaded through so they match (duplicate attributes and "
    "mismatched tags no longer contaminate every element, so the tree stays "
    "well-formed with high probability even at depth). Dedicated near-miss "
    "generators cover mismatched tags, duplicate attributes, unsupported "
    "entities, malformed and out-of-range character/entity references, "
    "unterminated markup (tags, quoted attrs, comments, CDATA, PIs, "
    "DOCTYPE), rootless documents, multiple top-level roots, trailing "
    "content after the root, comments containing '--', unknown markup "
    "declarations, and DOCTYPE names that disagree with the root element. "
    "Also covers mxml-specific accept cases the formal grammar rejects: "
    "unquoted attribute values, valueless (boolean) attributes, missing "
    "'=' in attributes, empty/degenerate element names, names starting "
    "with digits/hyphens/periods, a DOCTYPE with an internal subset, "
    "reserved 'xml'-target processing instructions, malformed XML "
    "declarations, and non-ASCII name characters outside the grammar's "
    "NameStartChar ranges."
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
_INVALID_NAME_STARTS = "0123456789-."
_UNKNOWN_DECL_KEYWORDS = ["FOOBAR", "INCLUDE", "NOTATION", "XYZZY", "ENTITY"]
_MALFORMED_REFS = ["&#;", "&#x;", "&;", "&", "&amp", "&#xzzzz;", "& ", "&#99999999999999999999;"]

_MAX_DEPTH = 5


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
    return st.one_of(normal, normal, normal, unicode_mix, with_control, ws)


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


def malformed_reference():
    return st.sampled_from(_MALFORMED_REFS)


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
    # Kept deliberately clean (no duplicate-name injection here): that noise
    # used to be applied per-attribute across every element in the tree,
    # which made well-formedness decay exponentially with element count.
    # Duplicate attributes are now a dedicated top-level near-miss generator.
    n = draw(st.integers(min_value=0, max_value=3))
    return [draw(_attribute()) for _ in range(n)]


def _render_attrs(attrs):
    return "".join(" " + a for a in attrs)


@st.composite
def element(draw, depth=0):
    name = draw(xml_name())
    attrs = draw(_attribute_list())
    attr_str = _render_attrs(attrs)

    force_self_close = depth >= _MAX_DEPTH
    self_close = force_self_close or draw(st.integers(min_value=0, max_value=4)) == 0
    if self_close:
        return "<" + name + attr_str + "/>"

    body = draw(content(depth))
    return "<" + name + attr_str + ">" + body + "</" + name + ">"


@st.composite
def content(draw, depth):
    n = draw(st.integers(min_value=0, max_value=4))
    parts = []
    for _ in range(n):
        choice = draw(st.integers(min_value=0, max_value=99))
        if choice < 28:
            parts.append(draw(chardata_text()))
        elif choice < 40:
            parts.append(draw(reference()))
        elif choice < 50:
            parts.append(draw(cdata_section()))
        elif choice < 60:
            parts.append(draw(comment()))
        elif choice < 68:
            parts.append(draw(pi()))
        else:
            parts.append(draw(element(depth + 1)))
    return "".join(parts)


@st.composite
def deep_chain(draw):
    depth = draw(st.integers(min_value=5, max_value=60))
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
    kind = draw(st.sampled_from(
        ["open_tag", "attr_dquot", "attr_squot", "comment", "cdata", "pi", "doctype", "close_tag"]
    ))
    name = draw(xml_name())
    if kind == "open_tag":
        return "<" + name
    if kind == "attr_dquot":
        attr_name = draw(xml_name())
        return "<" + name + " " + attr_name + '="unterminated'
    if kind == "attr_squot":
        attr_name = draw(xml_name())
        return "<" + name + " " + attr_name + "='unterminated"
    if kind == "comment":
        body = draw(st.text(alphabet=_SAFE_TEXT_CHARS, min_size=0, max_size=15))
        return "<!--" + body
    if kind == "cdata":
        body = draw(st.text(alphabet=_SAFE_TEXT_CHARS, min_size=0, max_size=15))
        return "<![CDATA[" + body
    if kind == "pi":
        target = draw(_ascii_name())
        body = draw(st.text(alphabet=_SAFE_TEXT_CHARS, min_size=0, max_size=10))
        return "<?" + target + " " + body
    if kind == "doctype":
        return "<!DOCTYPE " + name
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


@st.composite
def duplicate_attribute_document(draw):
    # Pulled out of the mainline generator: previously a 1-in-5 chance was
    # applied to every attribute list in the tree, so any document with
    # several elements was almost never well-formed. Now it is a controlled,
    # standalone near-miss producer that always yields a real duplicate.
    name = draw(xml_name())
    attr_name = draw(xml_name())
    n_extra = draw(st.integers(min_value=1, max_value=3))
    attrs = [attr_name + '="' + draw(_attr_value_text('<"')) + '"']
    for _ in range(n_extra):
        attrs.append(attr_name + '="' + draw(_attr_value_text('<"')) + '"')
    return "<" + name + _render_attrs(attrs) + "/>"


def empty_elem_name_document():
    return st.sampled_from(["< />", "<>", "</>", "< ></ >", "<  />"])


@st.composite
def comment_double_hyphen_document(draw):
    body = draw(st.text(alphabet=_SAFE_TEXT_CHARS, min_size=0, max_size=15))
    pos = draw(st.sampled_from(["start", "middle", "end", "triple"]))
    if pos == "start":
        inner = "--" + body
    elif pos == "end":
        inner = body + "--"
    elif pos == "triple":
        inner = body + "---" + body
    else:
        inner = body + "--" + body
    return "<!--" + inner + "-->"


@st.composite
def malformed_reference_document(draw):
    name = draw(xml_name())
    prefix = draw(chardata_text())
    ref = draw(malformed_reference())
    return "<" + name + ">" + prefix + ref + "</" + name + ">"


@st.composite
def doctype_mismatch_document(draw):
    root_name = draw(xml_name())
    doctype_name = draw(xml_name())
    if doctype_name == root_name:
        doctype_name = doctype_name + "q"
    return "<!DOCTYPE " + doctype_name + ">" + "<" + root_name + "/>"


@st.composite
def unknown_declaration_document(draw):
    keyword = draw(st.sampled_from(_UNKNOWN_DECL_KEYWORDS))
    body = draw(st.text(alphabet=_SAFE_TEXT_CHARS, min_size=0, max_size=10))
    root = draw(xml_name())
    return "<!" + keyword + " " + body + ">" + "<" + root + "/>"


@st.composite
def trailing_content_document(draw):
    root = draw(element(0))
    kind = draw(st.sampled_from(["text", "element", "decl", "comment"]))
    if kind == "text":
        extra = draw(chardata_text())
    elif kind == "element":
        extra = draw(element(0))
    elif kind == "comment":
        extra = draw(comment())
    else:
        extra = "<!DOCTYPE x>"
    return root + extra


@st.composite
def valueless_attribute_document(draw):
    name = draw(xml_name())
    attr_name = draw(xml_name())
    if draw(st.booleans()):
        return "<" + name + " " + attr_name + "/>"
    body = draw(chardata_text())
    return "<" + name + " " + attr_name + ">" + body + "</" + name + ">"


@st.composite
def missing_equals_attribute_document(draw):
    name = draw(xml_name())
    attr_name = draw(xml_name())
    value = draw(_attr_value_text('<"'))
    return "<" + name + " " + attr_name + ' "' + value + '"/>'


@st.composite
def reserved_pi_target_document(draw):
    target = draw(st.sampled_from(["xml", "XML", "Xml", "xMl"]))
    body = draw(st.text(alphabet=_SAFE_TEXT_CHARS, min_size=0, max_size=10))
    root = draw(xml_name())
    pi_text = "<?" + target + " " + body + "?>"
    if draw(st.booleans()):
        return pi_text + "<" + root + "/>"
    return "<" + root + ">" + pi_text + "</" + root + ">"


@st.composite
def invalid_name_start_document(draw):
    bad_start = draw(st.sampled_from(_INVALID_NAME_STARTS))
    rest = draw(st.text(alphabet=_ASCII_NAME_CHAR, min_size=0, max_size=6))
    name = bad_start + rest
    if draw(st.booleans()):
        return "<" + name + "/>"
    body = draw(chardata_text())
    return "<" + name + ">" + body + "</" + name + ">"


@st.composite
def bad_xml_decl_document(draw):
    kind = draw(st.sampled_from(["leading_ws", "unquoted_version", "wrong_order", "no_space"]))
    root = draw(xml_name())
    if kind == "leading_ws":
        return " <?xml version=\"1.0\"?><" + root + "/>"
    if kind == "unquoted_version":
        return "<?xml version=1.0?><" + root + "/>"
    if kind == "wrong_order":
        return "<?xml standalone=\"yes\" version=\"1.0\"?><" + root + "/>"
    return "<?xmlversion=\"1.0\"?><" + root + "/>"


def documents() -> "st.SearchStrategy[str]":
    well_formed = well_formed_document()
    near_miss = st.one_of(
        rootless_document(),
        multiple_roots_document(),
        unterminated_document(),
        mismatched_tag_document(),
        unsupported_entity_document(),
        extreme_charref_document(),
        duplicate_attribute_document(),
        empty_elem_name_document(),
        comment_double_hyphen_document(),
        malformed_reference_document(),
        doctype_mismatch_document(),
        unknown_declaration_document(),
        trailing_content_document(),
        valueless_attribute_document(),
        missing_equals_attribute_document(),
        reserved_pi_target_document(),
        invalid_name_start_document(),
        bad_xml_decl_document(),
    )
    return st.one_of(
        well_formed, well_formed, well_formed, well_formed, well_formed,
        well_formed, well_formed, well_formed, well_formed, well_formed,
        well_formed, well_formed, well_formed, well_formed, well_formed,
        well_formed, well_formed, well_formed,
        near_miss, near_miss, near_miss, near_miss, near_miss, near_miss,
        near_miss, near_miss, near_miss, near_miss, near_miss, near_miss,
        near_miss, near_miss, near_miss, near_miss, near_miss, near_miss,
    )

```

## Measured results over 500 generated documents

### Outcomes

```
{
  "parsed_clean": 149,
  "rejected": 334,
  "parsed_diag": 17
}
```

- **Acceptance rate: 33.2%** (target band: 40-70%)
- Crashes: 0
- Documents that were XML-shaped (began with `<`): 99.8%

### Grammar production coverage: 22/23

Reached:
```
  298  g_element_paired
  246  g_element_selfclose
  234  g_chardata
  161  g_attribute_dquot
  150  x_name_nonascii
  141  g_attribute_squot
  136  g_comment
  128  x_attribute_unquoted
  107  x_multiple_roots
   78  x_doctype
   64  g_cdata
   63  g_pi
   60  x_control_char
   50  g_charref_hex
   48  g_charref_dec
   46  x_entity_unsupported
   42  g_prolog
   26  x_mismatched_tags
   24  x_rootless
   12  g_entity_named
    5  x_empty_elem_name
    2  x_unterminated
```

**Never produced:**
```
g_nesting_deep
```

### Nesting depth distribution

```
{
  "0": 202,
  "1": 193,
  "2-3": 66,
  "4-7": 39
}
```
Deepest document generated: 5

### Distinct parser diagnostics reached: 75

```
   97  <%s> cannot be a second root node after <%s> on line %d.
   33  Entity '%s' not supported under parent <%s> on line %d.
   23  Mismatched close tag </%s> under parent <%s> on line %d.
   18  Bad control character 0x%x not allowed by XML standard.
   18  Bad control character 0x%x under parent <%s> on line %d not allowed by XML standard.
   12  <%s--> cannot be a second root node after <%s> on line %d.
   11  Early EOF in comment node on line %d.
    7  <%s?> cannot be a second root node after <%s> on line %d.
    5  Duplicate attribute '%s' in element oaQkoIl on line %d.
    5  Missing value for attribute '%s' in element V8 on line %d.
    4  Duplicate attribute '%s' in element I.DrE on line %d.
    4  Duplicate attribute '%s' in element L on line %d.
    4  Duplicate attribute '%s' in element psUNlU7 on line %d.
    4  Missing value for attribute '%s' in element Pt on line %d.
    4  Missing value for attribute '%s' in element _yBGZ on line %d.
    4  Missing value for attribute '%s' in element fV.%d on line %d.
    4  Missing value for attribute '%s' in element m on line %d.
    4  Missing value for attribute '%s' in element β on line %d.
    3  <%s--> cannot be a second root node after <%s--><%s> on line %d.
    3  Duplicate attribute '%s' in element Tm5bXN on line %d.
```

Each distinct message above is a different branch inside the parser. Messages
you have never triggered are branches you have never reached.

### Document size

```
{
  "min": 2,
  "max": 950,
  "mean": 82.4,
  "median": 28.0
}
```

### Slowest documents

```
     9.1 ms  len=15     depth=1   rejected
     8.4 ms  len=28     depth=0   rejected
     8.2 ms  len=15     depth=1   parsed_clean
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
