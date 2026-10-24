import string

from hypothesis import strategies as st

NAME: str = "mxml_targeted_fuzzer"
DESCRIPTION: str = (
    "Generates XML-like documents tuned for Mini-XML (mxml) v4.0.4. Builds "
    "well-formed documents with real recursive nesting where open and close "
    "tag names are threaded through so they match (duplicate attributes and "
    "mismatched tags no longer contaminate every element, so the tree stays "
    "well-formed with high probability even at depth). Iteration 3: the "
    "well-formed content path (chardata/entity/charref used inside element "
    "bodies) is now fully decontaminated, it used to have a random chance "
    "of injecting a raw control character or an out-of-range/unsupported "
    "reference into otherwise-clean documents, which was silently dragging "
    "the well-formed bucket's true acceptance rate far below its intended "
    "share. Those defects are now only injected by dedicated near-miss "
    "generators, including a new one that plants them at a variable, real "
    "nesting depth so 'under parent <tag>' diagnostics fire at more than "
    "one level. Deep linear nesting is now drawn from four widening depth "
    "bands (3-10, 10-30, 30-70, 70-150) instead of one flat range, so the "
    "far end of the range actually gets exercised instead of Hypothesis's "
    "integer sampling clustering near the low boundary, and it is also "
    "reachable as its own always-invoked top-level document kind rather "
    "than only through a nested probability inside the well-formed "
    "generator. The bushy recursive-element depth cap is raised from 5 to "
    "8. Dedicated near-miss generators still cover mismatched tags, "
    "duplicate attributes, unsupported entities, malformed and "
    "out-of-range character/entity references, unterminated markup (tags, "
    "quoted attrs, comments, CDATA, PIs, DOCTYPE), rootless documents, "
    "multiple top-level roots, trailing content after the root, comments "
    "containing '--', unknown markup declarations, and DOCTYPE names that "
    "disagree with the root element. Also covers mxml-specific accept "
    "cases the formal grammar rejects: unquoted attribute values, "
    "valueless (boolean) attributes, missing '=' in attributes, "
    "empty/degenerate element names, names starting with digits/hyphens/"
    "periods, a DOCTYPE with an internal subset, reserved 'xml'-target "
    "processing instructions, malformed XML declarations, and non-ASCII "
    "name characters outside the grammar's NameStartChar ranges."
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

_MAX_DEPTH = 8


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
    # Clean character data only: safe ASCII, valid Unicode BMP mixes, and
    # whitespace. Raw control characters used to be injected here directly
    # (a 1-in-6 chance on every call), which meant well-formed documents had
    # a compounding chance of becoming malformed purely from body text. That
    # noise now lives only in the dedicated nested_defect_document() near
    # miss below.
    normal = st.text(alphabet=_SAFE_TEXT_CHARS, min_size=1, max_size=20)
    unicode_mix = st.builds(
        lambda a, c, b: a + c + b,
        st.text(alphabet=_SAFE_TEXT_CHARS, min_size=0, max_size=8),
        st.sampled_from(_UNICODE_TEXT_CHARS),
        st.text(alphabet=_SAFE_TEXT_CHARS, min_size=0, max_size=8),
    )
    ws = st.sampled_from([" ", "\n", "\t", "  \n", "\r\n"])
    return st.one_of(normal, normal, normal, unicode_mix, ws)


def entity_ref():
    # Only mxml-supported named entities: unsupported ones are exercised
    # exclusively by the dedicated unsupported_entity_document() and
    # nested_defect_document() near-miss generators, not mixed in here.
    return st.sampled_from(_NAMED_ENTITIES).map(lambda n: "&" + n + ";")


def _valid_codepoint():
    # XML 1.0 Char production: #x9 | #xA | #xD | [#x20-#xD7FF] |
    # [#xE000-#xFFFD] | [#x10000-#x10FFFF]. Sampling only from this set
    # keeps charrefs used in well-formed content genuinely well-formed
    # (out-of-range/invalid codepoints are a dedicated near miss instead).
    return st.one_of(
        st.just(0x9),
        st.just(0xA),
        st.just(0xD),
        st.integers(min_value=0x20, max_value=0xD7FF),
        st.integers(min_value=0xE000, max_value=0xFFFD),
        st.integers(min_value=0x10000, max_value=0x10FFFF),
    )


def charref_dec():
    return _valid_codepoint().map(lambda n: "&#%d;" % n)


def charref_hex():
    return _valid_codepoint().map(lambda n: "&#x%x;" % n)


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
    # Depth is drawn from four widening bands rather than one flat range.
    # A flat st.integers(5, 60) draw was empirically biased toward its low
    # boundary (measured "deepest document generated" stuck at 5 out of a
    # theoretical 5-60 range), so the parser's deep-recursion / node-stack
    # growth code path never actually got exercised. Banding forces real
    # coverage of the far end too, up to 150 levels of pure linear nesting
    # (which stays cheap: this is a chain, not a branching tree, so size
    # grows linearly with depth).
    band = draw(st.integers(min_value=0, max_value=3))
    if band == 0:
        depth = draw(st.integers(min_value=3, max_value=10))
    elif band == 1:
        depth = draw(st.integers(min_value=10, max_value=30))
    elif band == 2:
        depth = draw(st.integers(min_value=30, max_value=70))
    else:
        depth = draw(st.integers(min_value=70, max_value=150))
    names = [draw(xml_name()) for _ in range(depth)]
    s = draw(chardata_text())
    for name in reversed(names):
        s = "<" + name + ">" + s + "</" + name + ">"
    return s


def deep_nesting_document():
    # A top-level, unconditionally-included document kind (see documents()
    # below) so deep-nesting coverage does not depend on a chain of nested
    # probability draws inside well_formed_document lining up in practice.
    return deep_chain()


@st.composite
def well_formed_document(draw):
    parts = []
    if draw(st.integers(min_value=0, max_value=3)) == 0:
        parts.append(draw(prolog()))
        parts.append(draw(misc_list(1)))
    parts.append(draw(misc_list(2)))

    # Single weighted draw instead of chained "if / elif" probability
    # checks, so the actual mix (1/10 doctype root, 2/10 deep chain, 7/10
    # ordinary recursive element) matches what was intended.
    shape = draw(st.integers(min_value=0, max_value=9))
    if shape == 0:
        root_name = draw(xml_name())
        parts.append(draw(doctype(root_name)))
        parts.append(draw(misc_list(1)))
        attrs = draw(_attribute_list())
        parts.append("<" + root_name + _render_attrs(attrs) + "/>")
    elif shape <= 2:
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
def nested_defect_document(draw):
    # Plants a raw control character, an unsupported entity, or an
    # out-of-range charref at a variable, real nesting depth (0-5 ancestor
    # elements) instead of always at the immediate root, like the shallow
    # dedicated generators above do. This targets "... under parent <tag>"
    # diagnostic branches at more than one depth, and replaces the control
    # character coverage that chardata_text() used to provide by accident.
    depth = draw(st.integers(min_value=0, max_value=5))
    names = [draw(xml_name()) for _ in range(depth + 1)]
    kind = draw(st.sampled_from(["control", "control", "entity", "charref_dec", "charref_hex"]))
    if kind == "control":
        defect = draw(st.sampled_from(_CONTROL_CHARS))
    elif kind == "entity":
        defect = "&" + draw(st.sampled_from(_UNSUPPORTED_ENTITIES)) + ";"
    elif kind == "charref_dec":
        defect = "&#%d;" % draw(st.sampled_from([0, 0xFFFFFFFF, 999999999999, 1114112]))
    else:
        defect = "&#x%x;" % draw(st.sampled_from([0, 0xFFFFFFFFFFFF, 0x110000]))
    prefix = draw(chardata_text())
    suffix = draw(chardata_text())
    s = prefix + defect + suffix
    for name in reversed(names):
        s = "<" + name + ">" + s + "</" + name + ">"
    return s


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
    deep = deep_nesting_document()
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
        nested_defect_document(),
    )
    # 20:4:16 split (well-formed : always-deep : near-miss). The well-formed
    # and deep-chain buckets should now parse clean with high probability
    # since the content-generation contamination (control chars, out of
    # range/unsupported refs) was removed from chardata_text()/reference(),
    # so this weighting is expected to land acceptance back in the 40-70%
    # band instead of well under it.
    return st.one_of(
        *([well_formed] * 20),
        *([deep] * 4),
        *([near_miss] * 16),
    )
