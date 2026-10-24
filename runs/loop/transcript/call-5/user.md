# Task

Revise the Hypothesis strategy below using the measured results of its last run.

## Current strategy (iteration 4)

```python
import string

from hypothesis import strategies as st

NAME: str = "mxml_targeted_fuzzer"
DESCRIPTION: str = (
    "Generates XML-like documents tuned for Mini-XML (mxml) v4.0.4. Builds "
    "well-formed documents with real recursive nesting where open and close "
    "tag names are threaded through so they match (duplicate attributes and "
    "mismatched tags no longer contaminate every element, so the tree stays "
    "well-formed with high probability even at depth). Iteration 3 fully "
    "decontaminated the well-formed content path (chardata/entity/charref "
    "used inside element bodies): those used to have a random chance of "
    "injecting a raw control character or an out-of-range/unsupported "
    "reference into otherwise-clean documents, which silently dragged the "
    "well-formed bucket's true acceptance rate down. Deep linear nesting is "
    "drawn from four widening depth bands (3-10, 10-30, 30-70, 70-150) and "
    "is its own always-invoked top-level document kind. Iteration 4: the "
    "measured run showed named-entity references (&amp; &lt; &gt; &quot;) "
    "were never registering despite charref_dec/charref_hex landing ~30 "
    "hits each at equal sampling weight, so g_entity_named stayed at zero. "
    "A dedicated minimal named_entity_document() now isolates the "
    "reference in an otherwise trivial document (removing the confound of "
    "an unrelated defect elsewhere in a bigger well_formed_document tree "
    "causing rejection before the entity registers), and it is an "
    "always-invoked top-level bucket like deep nesting. A new "
    "custom_entity_document() also covers DTD-declared <!ENTITY> "
    "definitions, both referenced by their declared name and by an "
    "undeclared name. Attribute values previously never carried entity or "
    "character references, or a raw '<', at all (that code path lives only "
    "in element content); attr_reference_document() now covers valid "
    "named/char refs, unsupported entities, and literal '<' inside quoted "
    "attribute values. Other new near misses: \"]]>\" appearing in plain "
    "text (illegal outside CDATA, structurally unreachable before since "
    "chardata's alphabet had no ']' or '>'), invalid attribute name start "
    "characters, attribute quote-character mismatches, and DOCTYPE SYSTEM/"
    "PUBLIC external identifiers (doctype() previously only ever emitted a "
    "bare root name or an internal subset). bad_xml_decl_document() gained "
    "an unsupported version number, an invalid standalone value, and a "
    "missing-version-attribute variant. The control-character set now "
    "includes the null byte and more of the forbidden C0 range. A few more "
    "malformed-reference shapes were added (bare '&#', unterminated named "
    "'&lt', negative numeric '&#-5;'). The top-level mix nudges deep-chain "
    "weight up slightly (4->5) and adds the new named-entity bucket (3), "
    "since the last run's 40.6% acceptance sat right at the bottom of the "
    "40-70% target band. Dedicated near-miss generators still cover "
    "mismatched tags, duplicate attributes, unsupported entities, "
    "malformed and out-of-range character/entity references, unterminated "
    "markup (tags, quoted attrs, comments, CDATA, PIs, DOCTYPE), rootless "
    "documents, multiple top-level roots, trailing content after the root, "
    "comments containing '--', unknown markup declarations, and DOCTYPE "
    "names that disagree with the root element. Also covers mxml-specific "
    "accept cases the formal grammar rejects: unquoted attribute values, "
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
# Widened in iteration 4 to include the null byte (0x00, a classic C string
# handling landmine) and a bit more of the forbidden C0 control range,
# rather than just one representative low byte and 0x1f.
_CONTROL_CHARS = "\x00\x01\x02\x07\x08\x0b\x0c\x0e\x10\x1a\x1f"
_UNICODE_TEXT_CHARS = "\u00e9\u00fc\u00f1\u4e2d\u6587\u03b1\u6f22"
_NAMED_ENTITIES = ["amp", "lt", "gt", "quot"]
_UNSUPPORTED_ENTITIES = ["apos", "nbsp", "copy", "zzz"]
_INVALID_NAME_STARTS = "0123456789-."
_UNKNOWN_DECL_KEYWORDS = ["FOOBAR", "INCLUDE", "NOTATION", "XYZZY", "ENTITY"]
_MALFORMED_REFS = [
    "&#;", "&#x;", "&;", "&", "&amp", "&#xzzzz;", "& ",
    "&#99999999999999999999;", "&lt", "&#-5;", "&#",
]

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
def named_entity_document(draw):
    # Dedicated, minimal generator: guarantees a named-entity reference
    # (&amp; &lt; &gt; &quot;) appears in an otherwise trivial document.
    # g_entity_named was measured at zero hits in the last run despite
    # entity_ref() being sampled with the same weight as charref_dec/
    # charref_hex inside reference() (which each landed ~30 hits). The
    # likely cause: named-entity draws were buried deep inside large
    # well_formed_document trees, where an unrelated defect elsewhere in
    # the same document caused the whole thing to be rejected before the
    # entity ever registered. Isolating it here, and making it an
    # always-invoked top-level bucket (see documents()), removes that
    # confound instead of hoping it turns up by chance.
    name = draw(xml_name())
    ent = draw(st.sampled_from(_NAMED_ENTITIES))
    prefix = draw(chardata_text())
    suffix = draw(chardata_text())
    return "<" + name + ">" + prefix + "&" + ent + ";" + suffix + "</" + name + ">"


@st.composite
def custom_entity_document(draw):
    # DTD-declared <!ENTITY name "value"> definitions were never generated
    # at all (doctype() only ever emits ELEMENT declarations). Half the
    # time this references the entity it just declared (should resolve
    # through the generic named-entity lookup path); the other half it
    # references a name that was never declared (a distinct "entity not
    # defined" style error, separate from the "not supported" diagnostic
    # unsupported_entity_document() targets, since here mxml did see a
    # matching DOCTYPE/ENTITY grammar shape).
    root = draw(xml_name())
    ent_name = draw(xml_name())
    ent_value = draw(_attr_value_text('<"'))
    use_declared = draw(st.booleans())
    ref_name = ent_name if use_declared else ent_name + "zz"
    doctype_decl = "<!DOCTYPE " + root + " [<!ENTITY " + ent_name + ' "' + ent_value + '">]>'
    return doctype_decl + "<" + root + ">&" + ref_name + ";</" + root + ">"


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
def attr_reference_document(draw):
    # Entity/character references inside attribute values exercise a
    # distinct value-normalization code path from references inside
    # element content, which the generator never touched before (only
    # content() ever drew reference()). Mixes a valid, well-formed
    # reference (should resolve and parse clean) with near-miss shapes: an
    # unsupported named entity, and a raw unescaped '<' in an attribute
    # value, which XML forbids even inside quotes.
    name = draw(xml_name())
    attr_name = draw(xml_name())
    kind = draw(st.sampled_from(["valid_entity", "valid_charref", "unsupported_entity", "raw_lt"]))
    if kind == "valid_entity":
        ref = "&" + draw(st.sampled_from(_NAMED_ENTITIES)) + ";"
    elif kind == "valid_charref":
        ref = "&#%d;" % draw(_valid_codepoint())
    elif kind == "unsupported_entity":
        ref = "&" + draw(st.sampled_from(_UNSUPPORTED_ENTITIES)) + ";"
    else:
        ref = "<"
    prefix = draw(_attr_value_text('<"'))
    suffix = draw(_attr_value_text('<"'))
    return "<" + name + " " + attr_name + '="' + prefix + ref + suffix + '"/>'


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
def cdata_close_in_text_document(draw):
    # "]]>" is a well-formedness error anywhere in character data outside a
    # CDATA section (XML 1.0 sec 2.4). This was structurally unreachable
    # before: chardata_text()'s alphabet has no ']' or '>' character at
    # all, so the sequence could never appear by accident either.
    name = draw(xml_name())
    prefix = draw(chardata_text())
    suffix = draw(chardata_text())
    return "<" + name + ">" + prefix + "]]>" + suffix + "</" + name + ">"


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
def doctype_external_id_document(draw):
    # SYSTEM/PUBLIC external identifiers in DOCTYPE were never generated:
    # doctype() only ever emits a bare root name or an internal subset.
    # This exercises whatever code path handles (or rejects) external DTD
    # references, entirely untouched territory before now.
    root = draw(xml_name())
    kind = draw(st.sampled_from(["system", "public"]))
    sysid = draw(_attr_value_text('<"'))
    if kind == "system":
        decl = '<!DOCTYPE ' + root + ' SYSTEM "' + sysid + '">'
    else:
        pubid = draw(_attr_value_text('<"'))
        decl = '<!DOCTYPE ' + root + ' PUBLIC "' + pubid + '" "' + sysid + '">'
    return decl + "<" + root + "/>"


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
def mismatched_quote_attr_document(draw):
    # Opening the attribute value with one quote character and closing
    # with the other ("a='v\"" or "a=\"v'") is a shape the two dedicated
    # unterminated_document() quote variants never produce: those always
    # run to real EOF. Here the mismatch happens mid-document, so the
    # parser keeps consuming looking for the real matching quote and the
    # error (if any) surfaces somewhere past this element instead of at
    # EOF, a different code path than a simple unterminated-at-EOF case.
    name = draw(xml_name())
    attr_name = draw(xml_name())
    value = draw(_attr_value_text('<"\''))
    open_q, close_q = draw(st.sampled_from([('"', "'"), ("'", '"')]))
    return "<" + name + " " + attr_name + "=" + open_q + value + close_q + "/>"


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
def invalid_attr_name_document(draw):
    # Same invalid-name-start defect as invalid_name_start_document(), but
    # on the attribute name instead of the element name. Element and
    # attribute names are frequently validated by separate code in a hand
    # written parser, so this is not assumed to be redundant coverage.
    bad_start = draw(st.sampled_from(_INVALID_NAME_STARTS))
    rest = draw(st.text(alphabet=_ASCII_NAME_CHAR, min_size=0, max_size=5))
    attr_name = bad_start + rest
    name = draw(xml_name())
    value = draw(_attr_value_text('<"'))
    return "<" + name + " " + attr_name + '="' + value + '"/>'


@st.composite
def bad_xml_decl_document(draw):
    kind = draw(st.sampled_from([
        "leading_ws", "unquoted_version", "wrong_order", "no_space",
        "bad_version", "bad_standalone", "missing_version",
    ]))
    root = draw(xml_name())
    if kind == "leading_ws":
        return " <?xml version=\"1.0\"?><" + root + "/>"
    if kind == "unquoted_version":
        return "<?xml version=1.0?><" + root + "/>"
    if kind == "wrong_order":
        return "<?xml standalone=\"yes\" version=\"1.0\"?><" + root + "/>"
    if kind == "no_space":
        return "<?xmlversion=\"1.0\"?><" + root + "/>"
    if kind == "bad_version":
        return "<?xml version=\"2.0\"?><" + root + "/>"
    if kind == "bad_standalone":
        return "<?xml version=\"1.0\" standalone=\"maybe\"?><" + root + "/>"
    return "<?xml encoding=\"UTF-8\"?><" + root + "/>"


def documents() -> "st.SearchStrategy[str]":
    well_formed = well_formed_document()
    deep = deep_nesting_document()
    named_entity = named_entity_document()
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
        custom_entity_document(),
        attr_reference_document(),
        cdata_close_in_text_document(),
        invalid_attr_name_document(),
        mismatched_quote_attr_document(),
        doctype_external_id_document(),
    )
    # 20:5:3:16 split (well-formed : always-deep : always-named-entity :
    # near-miss). Deep-chain weight nudged 4->5 and a new small
    # always-invoked named-entity bucket added, since the last run's
    # acceptance (40.6%) sat right at the floor of the 40-70% target band;
    # both buckets are near-guaranteed clean parses, so this nudges
    # acceptance up a little without risking an overshoot above the band.
    return st.one_of(
        *([well_formed] * 20),
        *([deep] * 5),
        *([named_entity] * 3),
        *([near_miss] * 16),
    )

```

## Measured results over 500 generated documents

### Outcomes

```
{
  "parsed_clean": 252,
  "rejected": 248
}
```

- **Acceptance rate: 50.4%** (target band: 40-70%)
- Crashes: 0
- Documents that were XML-shaped (began with `<`): 99.6%

### Grammar production coverage: 22/23

Reached:
```
  310  g_element_paired
  255  g_chardata
  197  x_name_nonascii
  182  g_element_selfclose
   83  x_doctype
   77  g_attribute_dquot
   50  g_comment
   45  g_nesting_deep
   42  g_attribute_squot
   41  x_mismatched_tags
   40  g_charref_dec
   36  g_entity_named
   36  x_entity_unsupported
   31  x_multiple_roots
   30  g_pi
   27  x_rootless
   18  g_prolog
   16  g_charref_hex
   15  g_cdata
   13  x_attribute_unquoted
    7  x_control_char
    4  x_empty_elem_name
```

**Never produced:**
```
x_unterminated
```

### Nesting depth distribution

```
{
  "0": 190,
  "1": 187,
  "16+": 23,
  "2-3": 45,
  "4-7": 33,
  "8-15": 22
}
```
Deepest document generated: 144

### Distinct parser diagnostics reached: 40

```
   42  Mismatched close tag </%s> under parent <%s> on line %d.
   34  Entity '%s' not supported under parent <%s> on line %d.
   33  <%s> cannot be a second root node after <%s> on line %d.
   23  Character entity '%s' not terminated under parent <%s> on line %d.
   15  Bad control character 0x%x under parent <%s> on line %d not allowed by XML standard.
    7  Bad control character 0x%x not allowed by XML standard.
    7  Early EOF in comment node on line %d.
    7  Missing close tag </%s> under parent <%s> on line %d.
    6  <%s--> cannot be a second root node after <%s> on line %d.
    5  Duplicate attribute '%s' in element α on line %d.
    3  Duplicate attribute '%s' in element isurvey on line %d.
    3  Duplicate attribute '%s' in element j on line %d.
    3  Duplicate attribute '%s' in element tI on line %d.
    3  Duplicate attribute '%s' in element ĀsÖWQÀ on line %d.
    3  Missing value for attribute '%s' in element KOnotft on line %d.
    2  <%s?> cannot be a second root node after <%s> on line %d.
    2  Duplicate attribute '%s' in element FhA on line %d.
    2  Duplicate attribute '%s' in element Qxz-rsI on line %d.
    2  Missing value for attribute '%s' in element CINF on line %d.
    2  Missing value for attribute '%s' in element HIoIs8 on line %d.
```

Each distinct message above is a different branch inside the parser. Messages
you have never triggered are branches you have never reached.

### Document size

```
{
  "min": 2,
  "max": 1970,
  "mean": 95.9,
  "median": 29.5
}
```

### Slowest documents

```
    10.4 ms  len=46     depth=0   rejected
    10.2 ms  len=49     depth=0   rejected
     9.8 ms  len=39     depth=0   rejected
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
