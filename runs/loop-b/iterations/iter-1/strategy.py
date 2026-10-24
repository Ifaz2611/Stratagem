"""Hypothesis strategy: grammar-directed XML fuzz inputs for Mini-XML 4.0.4."""

import string

from hypothesis import strategies as st

NAME = "mxml_three_class_xml"
DESCRIPTION = (
    "XML generator aimed at Mini-XML 4.0.4 rather than at the ANTLR grammar. "
    "Element names are threaded through the recursive production so open and "
    "close tags agree in the well-formed class. This revision (directive: "
    "deepen) does two things on top of iteration 1. First, it retunes the "
    "top-level mixture from 50/25/25 to 40/32/28 (well_formed/near_miss/"
    "byte_hostile) and makes every byte_hostile branch carry at least one "
    "genuinely non-UTF-8 byte run: iteration 1's control-char, truncation and "
    "bare-BOM branches used only valid Unicode text and were measured leaking "
    "almost entirely into other classes (byte_hostile share collapsed to "
    "5.2% against a 25% selection weight). Second, it deepens recursion on "
    "purpose: a dedicated stress generator nests 100-700 levels (vs. a prior "
    "cap of 40) to probe for an absent depth guard in the recursive-descent "
    "parser, near_miss and byte_hostile defects can now be buried 5-200 "
    "levels inside a wrapper chain instead of always sitting at the document "
    "surface, and a new DOCTYPE production builds self-referential, mutually "
    "recursive and doubling-chain general entities to stress entity-expansion "
    "recursion specifically. A few purely structural near-miss additions "
    "(bare '&', literal ']]>' in content, digit-led names, reserved "
    "'xml'-prefixed PI targets, malformed DOCTYPE internals) target "
    "diagnostics no earlier iteration reached. Raw bytes that no valid UTF-8 "
    "string can hold are carried in the surrogate-escape range U+DC80..U+DCFF: "
    "s.encode('utf-8', 'surrogateescape') reproduces the exact bytes intended."
)

MAX_LEN = 19000


# --------------------------------------------------------------- byte helper

def _rawbytes(bs):
    """Represent arbitrary bytes as a str via the surrogateescape convention."""
    return "".join(chr(b) if b < 0x80 else chr(0xDC00 + b) for b in bs)


# --------------------------------------------------------------- alphabets

_NAME_START = "_:" + string.ascii_letters
_NAME_REST = _NAME_START + string.digits + "-."

# Name start chars XML 1.0 allows and mxml accepts, including the ranges the
# ANTLR grammar omits (U+00C0-U+02FF, U+0370-U+1FFF).
_NONASCII_START = (
    "\u00c0\u00c9\u00ce\u00d5\u00df\u00e7\u00e9\u00f1\u00f6\u00ff"
    "\u0100\u010d\u0141\u015a\u017e\u0192\u01c7\u0218\u0251\u0298"
    "\u0391\u03b2\u03b3\u03a9\u0416\u0438\u0439\u0444\u0462"
    "\u05d0\u05d1\u05d7\u05e9\u0628\u062a\u0635"
    "\u4e2d\u65e5\u672c\u8a9e\u6f22\u5b57\ud55c\uae00\u3072\u30ab"
    "\u215b\u2182\u2f00\ufb01\ufdfa"
)
_NONASCII_REST = _NONASCII_START + "\u00b7\u0301\u036f\u203f\u2040"

_TEXT_CHARS = (
    string.ascii_letters
    + string.digits
    + " \t\n"
    + "!\"#$%'()*+,-./:;=?@\\^_`{|}~>"
)
_UNI_TEXT = (
    "\u00e9\u00f1\u00e4\u00f6\u00fc\u00c0\u03a9\u03bb\u03b2"
    "\u4e2d\u6587\u65e5\u672c\u8a9e\ud55c\uae00"
    "\U0001f600\U0001f389\U0001d70b\u00a0\u2003"
)
_CDATA_CHARS = _TEXT_CHARS + "<&["
_COMMENT_CHARS = string.ascii_letters + string.digits + " .,:;!?()/'\"\n\t<>&"
_PI_CHARS = string.ascii_letters + string.digits + " .,:;!()/'\"=\n\t&"


# --------------------------------------------------------------- names

_ascii_name = st.builds(
    lambda a, b: a + b,
    st.sampled_from(_NAME_START),
    st.text(alphabet=_NAME_REST, max_size=5),
)
_nonascii_name = st.builds(
    lambda a, b, c: a + b + c,
    st.sampled_from(_NONASCII_START),
    st.text(alphabet=_NONASCII_REST, max_size=3),
    st.text(alphabet=_NAME_REST, max_size=3),
)
_any_name = st.one_of(_ascii_name, _ascii_name, _ascii_name, _nonascii_name)


# --------------------------------------------------------------- leaves

_text_safe = st.lists(
    st.one_of(
        st.text(alphabet=_TEXT_CHARS, min_size=1, max_size=24),
        st.sampled_from(list(_UNI_TEXT)),
    ),
    min_size=1,
    max_size=3,
).map("".join)

_entity_named = st.sampled_from(["&amp;", "&lt;", "&gt;", "&quot;"])

_CR_OK = st.one_of(
    st.integers(min_value=32, max_value=126),
    st.sampled_from([9, 10, 13, 169, 233, 955, 8212, 8364, 0x4E2D, 0x1F600]),
)
_charref_dec = _CR_OK.map(lambda c: "&#%d;" % c)
_charref_hex = st.one_of(
    _CR_OK.map(lambda c: "&#x%X;" % c),
    _CR_OK.map(lambda c: "&#x%04x;" % c),
)

_cdata_ok = st.builds(
    lambda s: "<![CDATA[" + s + "]]>",
    st.text(alphabet=_CDATA_CHARS, max_size=30),
)

_comment_ok = st.builds(
    lambda s: "<!--" + s + "-->",
    st.text(alphabet=_COMMENT_CHARS, max_size=30),
)

_pi_ok = st.one_of(
    st.builds(
        lambda n, s: "<?" + n + (" " + s if s else "") + "?>",
        _ascii_name,
        st.text(alphabet=_PI_CHARS, max_size=24),
    ),
    st.sampled_from(
        [
            '<?xml-stylesheet type="text/xsl" href="s.xsl"?>',
            "<?php echo 1; ?>",
            "<?target?>",
        ]
    ),
)

_WF_LEAF = st.one_of(
    _text_safe,
    _text_safe,
    _entity_named,
    _charref_dec,
    _charref_hex,
    _cdata_ok,
    _comment_ok,
    _pi_ok,
)


# --------------------------------------------------------------- attributes

_ATTR_PLAIN = st.text(
    alphabet=string.ascii_letters + string.digits + " ._-:/#", max_size=8
)
_ATTR_ESC = st.sampled_from(
    ["&amp;", "&lt;", "&gt;", "&quot;", "&#65;", "&#x2F;", "&#233;"]
)
_attr_value = st.lists(
    st.one_of(_ATTR_PLAIN, _ATTR_ESC, st.sampled_from(list(_UNI_TEXT))),
    max_size=3,
).map("".join)

_attr_dq = st.builds(lambda n, v: '%s="%s"' % (n, v), _any_name, _attr_value)
_attr_sq = st.builds(lambda n, v: "%s='%s'" % (n, v), _any_name, _attr_value)
_attr_uq = st.builds(
    lambda n, v: "%s=%s" % (n, v),
    _ascii_name,
    st.text(
        alphabet=string.ascii_letters + string.digits + "._-", min_size=1, max_size=6
    ),
)
_attr_ws = st.builds(lambda n, v: '%s = "%s"' % (n, v), _ascii_name, _attr_value)
_attr_one = st.one_of(_attr_dq, _attr_dq, _attr_sq, _attr_uq, _attr_ws)


@st.composite
def _attrs(draw):
    items = draw(st.lists(_attr_one, max_size=4))
    if items and draw(st.integers(min_value=0, max_value=3)) == 0:
        first = items[0]
        nm = first.split("=")[0].strip()
        if draw(st.booleans()):
            items = items + [first]
        else:
            items = items + ['%s="other"' % nm]
    return items


_ATTRS = _attrs()


# --------------------------------------------------------------- elements

_SEPS = (" ", "\n  ", "\t", "  ")


def _make_elem(name, attrs, kids, k, sepk):
    sep = _SEPS[sepk % len(_SEPS)]
    head = "<" + name
    for a in attrs:
        head += sep + a
    body = "".join(kids)
    if not body:
        if k == 0:
            return head + "/>"
        if k == 1:
            return head + " />"
    if k == 7:
        return head + ">" + body + "</" + name + " >"
    return head + ">" + body + "</" + name + ">"


def _element_of(child):
    return st.builds(
        _make_elem,
        _any_name,
        _ATTRS,
        st.lists(child, max_size=3),
        st.integers(min_value=0, max_value=7),
        st.integers(min_value=0, max_value=3),
    )


@st.composite
def _deep_chain(draw, inner):
    """Nesting whose depth is a single shrinkable integer. Bumped from a max
    of 40 (iteration 1) to 100 as part of this iteration's depth push; the
    dedicated _stress_deep below goes further still, cheaply."""
    depth = draw(st.integers(min_value=3, max_value=100))
    base = draw(_ascii_name)
    out = draw(inner)
    for i in range(depth):
        nm = "%s%d" % (base, i)
        out = "<%s>%s</%s>" % (nm, out, nm)
    return out


@st.composite
def _stress_deep(draw, inner):
    """Depth pushed far beyond anything earlier iterations produced (100-700
    levels, vs. a previous observed max of 211 arising incidentally from
    composed recursion) to probe for a missing recursion-depth guard in the
    parser's descent. Single-letter, mod-11 tag names keep the byte cost per
    level low enough that 700 levels still fits comfortably under MAX_LEN."""
    depth = draw(st.integers(min_value=100, max_value=700))
    base = draw(st.sampled_from(string.ascii_lowercase))
    out = draw(inner)
    for i in range(depth):
        nm = "%s%d" % (base, i % 11)
        out = "<%s>%s</%s>" % (nm, out, nm)
    return out


def _wrap_depth(seed, depth, body):
    """Wrap `body` in `depth` nested same-family elements (mod-7 name
    variants) so a defect can be buried well below the document surface
    instead of always sitting right at it."""
    out = body
    for i in range(depth):
        nm = "%s%d" % (seed, i % 7)
        out = "<%s>%s</%s>" % (nm, out, nm)
    return out


_WF_NODE = st.recursive(
    _WF_LEAF,
    lambda child: st.one_of(
        _element_of(child), _element_of(child), _deep_chain(child)
    ),
    max_leaves=8,
)

_WF_ROOT = st.one_of(
    _element_of(_WF_NODE),
    _element_of(_WF_NODE),
    _deep_chain(_WF_NODE),
    _stress_deep(_WF_LEAF),
)


# --------------------------------------------------------------- prolog, misc

_PROLOG = st.sampled_from(
    [
        '<?xml version="1.0"?>',
        '<?xml version="1.0" encoding="UTF-8"?>',
        "<?xml version='1.0' encoding='utf-8' standalone='yes'?>",
        '<?xml version="1.1" encoding="UTF-8" standalone="no"?>',
        '<?xml version="1.0" ?>',
        "<?xml?>",
    ]
)

_DOCTYPE = st.sampled_from(
    [
        "<!DOCTYPE r>",
        '<!DOCTYPE r SYSTEM "r.dtd">',
        '<!DOCTYPE r PUBLIC "-//X//DTD Thing//EN" "r.dtd">',
        "<!DOCTYPE r [<!ELEMENT r EMPTY>]>",
        '<!DOCTYPE r [<!ENTITY e "v">]>',
        "<!NOTATION gif SYSTEM \"gif\">",
    ]
)

_MISC = st.one_of(
    _comment_ok,
    _pi_ok,
    st.sampled_from([" ", "\n", "\t", "\r\n", "  \n  "]),
)


def _env(draw, body):
    pre = ""
    if draw(st.integers(min_value=0, max_value=2)):
        pre = draw(_PROLOG)
    return pre + body


# --------------------------------------------------------------- well formed

@st.composite
def _wf_doc(draw):
    parts = []
    if draw(st.integers(min_value=0, max_value=2)):
        parts.append(draw(_PROLOG))
    if draw(st.integers(min_value=0, max_value=3)) == 0:
        parts.append(draw(_DOCTYPE))
    parts.extend(draw(st.lists(_MISC, max_size=2)))
    parts.append(draw(_WF_ROOT))
    parts.extend(draw(st.lists(_MISC, max_size=2)))
    return "".join(parts)


_WF_DOC = _wf_doc()


# --------------------------------------------------------------- near miss

_UNSUPPORTED_ENT = st.sampled_from(
    [
        "&apos;",
        "&nbsp;",
        "&copy;",
        "&foo;",
        "&AMP;",
        "&Amp;",
        "&#bad;",
        "&amp",
        "&;",
        "&x;",
        "&a_b;",
    ]
)

_EXTREME_REF = st.sampled_from(
    [
        "&#0;",
        "&#x0;",
        "&#x00000;",
        "&#8;",
        "&#11;",
        "&#xFFFE;",
        "&#xFFFF;",
        "&#xD800;",
        "&#xDFFF;",
        "&#65536;",
        "&#1114111;",
        "&#1114112;",
        "&#x110000;",
        "&#xFFFFFFFF;",
        "&#xFFFFFFFFFFFF;",
        "&#99999999999999999999;",
        "&#-1;",
        "&#x-1;",
        "&#;",
        "&#x;",
        "&#0000000065;",
        "&#x0000041;",
    ]
)


@st.composite
def _nm_mismatch(draw):
    a = draw(_ascii_name)
    b = draw(_ascii_name)
    body = draw(_WF_NODE)
    style = draw(st.integers(min_value=0, max_value=3))
    if style == 0:
        return _env(draw, "<%s>%s</%sx>" % (a, body, a))
    if style == 1:
        return _env(draw, "<%s><%s>%s</%s></%s>" % (a, b, body, a, b))
    if style == 2:
        return _env(draw, "<%s>%s</%sZ>" % (a, body, a.upper()))
    return _env(draw, "<%s><%s>%s</%s>" % (a, b, body, a))


@st.composite
def _nm_unknown_entity(draw):
    n = draw(_ascii_name)
    ent = draw(_UNSUPPORTED_ENT)
    body = draw(_WF_NODE)
    style = draw(st.integers(min_value=0, max_value=2))
    if style == 0:
        return _env(draw, "<%s>%s%s</%s>" % (n, body, ent, n))
    if style == 1:
        return _env(draw, '<%s a="%s"/>' % (n, ent))
    return _env(draw, "<%s>%s</%s>" % (n, ent, n))


@st.composite
def _nm_multi_root(draw):
    count = draw(st.integers(min_value=2, max_value=3))
    roots = [draw(_WF_ROOT) for _ in range(count)]
    sep = draw(st.one_of(st.sampled_from(["", "\n", "  "]), _comment_ok, _pi_ok))
    return _env(draw, sep.join(roots))


@st.composite
def _nm_empty_name(draw):
    frag = draw(
        st.sampled_from(
            [
                "< />",
                "<>text</>",
                "< ></ >",
                "<>",
                "</>",
                '< a="1"/>',
                "<>x</ >",
                "<r>< /></r>",
                "<r><></></r>",
                "<r>< a='v'/></r>",
            ]
        )
    )
    return _env(draw, frag)


_nm_rootless = st.one_of(
    _comment_ok,
    _pi_ok,
    st.builds(lambda p, c: p + c, _PROLOG, _comment_ok),
    st.builds(lambda p, d: p + d, _PROLOG, _DOCTYPE),
    st.just(""),
    st.just("   \n\t  "),
    st.text(alphabet=_TEXT_CHARS, min_size=1, max_size=40),
    st.sampled_from(["&amp;", "&#65;", "<![CDATA[only cdata]]>"]),
)


@st.composite
def _nm_badref(draw):
    n = draw(_ascii_name)
    refs = "".join(draw(st.lists(_EXTREME_REF, min_size=1, max_size=3)))
    marker = draw(_UNSUPPORTED_ENT)
    style = draw(st.integers(min_value=0, max_value=2))
    if style == 0:
        return _env(draw, '<%s a="%s">%s%s</%s>' % (n, refs, refs, marker, n))
    if style == 1:
        return _env(draw, "<%s>%s%s</%s>" % (n, marker, refs, n))
    return _env(draw, "<%s><![CDATA[%s]]>%s%s</%s>" % (n, refs, refs, marker, n))


@st.composite
def _nm_bad_attr(draw):
    frag = draw(
        st.sampled_from(
            [
                "<r =v>",
                '<r ="v">',
                "<r a>",
                "<r a=>",
                '<r a=="v">',
                '<r a="v"b="w">',
                '<r "v">',
                "<r a=v w>",
                '<r a="v" a="w" a="z">',
                "<r a=<>",
                '<r a="<">',
                "<r a=1 2=b>",
                "<r/ >",
                "<r a='v\">",
            ]
        )
    )
    return _env(draw, frag + draw(_UNSUPPORTED_ENT) + "</r>")


@st.composite
def _nm_stray(draw):
    n = draw(_ascii_name)
    body = draw(_WF_NODE)
    style = draw(st.integers(min_value=0, max_value=5))
    if style == 0:
        return "<%s>%s</%s></%s>" % (n, body, n, n)
    if style == 1:
        return "</%s><%s/>" % (n, n)
    if style == 2:
        return "<%s/><%s/>" % (n, n)
    if style == 3:
        return "<%s></%s><!-- gap --><%s/>" % (n, n, n)
    if style == 4:
        return '<?xml version="1.0"?><?xml version="1.0"?><%s/><%s/>' % (n, n)
    return "%s<?xml version=\"1.0\"?><%s/><%s/>" % (draw(_text_safe), n, n)


@st.composite
def _nm_deep_defect(draw):
    """Bury an ordinary near-miss defect at a random depth (5-200 levels)
    inside nested wrapper elements, instead of always at the document
    surface -- deepens the near_miss class the same way _stress_deep deepens
    well_formed."""
    depth = draw(st.integers(min_value=5, max_value=200))
    root = draw(_ascii_name)
    kind = draw(st.integers(min_value=0, max_value=2))
    if kind == 0:
        a = draw(_ascii_name)
        body = draw(_WF_NODE)
        defect = "<%s>%s</%sx>" % (a, body, a)
    elif kind == 1:
        n = draw(_ascii_name)
        ent = draw(_UNSUPPORTED_ENT)
        defect = "<%s>%s%s</%s>" % (n, draw(_WF_NODE), ent, n)
    else:
        n = draw(_ascii_name)
        refs = "".join(draw(st.lists(_EXTREME_REF, min_size=1, max_size=2)))
        defect = "<%s>%s</%s>" % (n, refs, n)
    return _wrap_depth(root, depth, defect)


_DTD_DEEP_MISC = st.sampled_from(
    [
        "<!DOCTYPE r [<!DOCTYPE x>]>",                        # nested DOCTYPE
        "<!DOCTYPE r [<![INCLUDE[<!ELEMENT r EMPTY>]]>]>",    # cond. section in internal subset
        "<!DOCTYPE r [<![IGNORE[<!ELEMENT r EMPTY>]]>]>",
        "<!DOCTYPE r [%pe;]>",                                # bare undefined parameter entity
        '<!DOCTYPE r [<!ENTITY % pe "x"><!ELEMENT r (%pe;)>]>',
        '<!DOCTYPE r SYSTEM "a" PUBLIC "b" "c">',              # PUBLIC/SYSTEM out of order
        "<!DOCTYPE r [<!ELEMENT r (#PCDATA)*+>]>",             # bad content-model quantifier
        "<!DOCTYPE r [<!ATTLIST>]>",                           # empty ATTLIST
        "<!DOCTYPE >",                                         # missing root name
    ]
)


@st.composite
def _nm_dtd_weird(draw):
    frag = draw(_DTD_DEEP_MISC)
    return frag + "<r/>"


@st.composite
def _nm_entity_recursion(draw):
    """DOCTYPE internal subset built for entity-expansion recursion: a direct
    self-reference, a mutual a<->b cycle, or a doubling chain. A conforming
    parser must detect the cycle (or bound the expansion) rather than recurse
    or allocate without limit -- this deepens the entity-resolution path
    itself, distinct from _nm_deep_defect's structural nesting."""
    root = draw(_ascii_name)
    style = draw(st.integers(min_value=0, max_value=2))
    if style == 0:
        e = draw(_ascii_name)
        dtd = '<!DOCTYPE %s [<!ENTITY %s "&%s;">]>' % (root, e, e)
        body = "&%s;" % e
    elif style == 1:
        a = draw(_ascii_name)
        b = draw(_ascii_name)
        dtd = '<!DOCTYPE %s [<!ENTITY %s "&%s;"><!ENTITY %s "&%s;">]>' % (
            root, a, b, b, a,
        )
        body = "&%s;" % a
    else:
        n = draw(st.integers(min_value=3, max_value=12))
        defs = ['<!ENTITY e0 "x">']
        for i in range(1, n):
            defs.append('<!ENTITY e%d "&e%d;&e%d;">' % (i, i - 1, i - 1))
        dtd = "<!DOCTYPE %s [%s]>" % (root, "".join(defs))
        body = "&e%d;" % (n - 1)
    return "%s<%s>%s</%s>" % (dtd, root, body, root)


_RESERVED_PI = st.sampled_from(
    ["<?xml?>", "<?XML foo?>", '<?xMl version="1.0"?>', "<?Xml?>", "<?xML data?>"]
)


@st.composite
def _nm_reserved_pi(draw):
    n = draw(_ascii_name)
    pi = draw(_RESERVED_PI)
    style = draw(st.integers(min_value=0, max_value=1))
    if style == 0:
        return "<%s>%s</%s>" % (n, pi, n)
    return "<%s/>%s" % (n, pi)


@st.composite
def _nm_bare_amp(draw):
    n = draw(_ascii_name)
    body = draw(_text_safe)
    style = draw(st.integers(min_value=0, max_value=2))
    if style == 0:
        return "<%s>%s & %s</%s>" % (n, body, body, n)
    if style == 1:
        return "<%s>%s]]>%s</%s>" % (n, body, body, n)
    return '<%s a="&">%s</%s>' % (n, body, n)


@st.composite
def _nm_bad_name_start(draw):
    n = draw(_ascii_name)
    d = draw(st.sampled_from(string.digits))
    style = draw(st.integers(min_value=0, max_value=2))
    if style == 0:
        return "<%s%s>x</%s%s>" % (d, n, d, n)
    if style == 1:
        return '<%s %s%s="v"/>' % (n, d, n)
    return "<-%s>x</-%s>" % (n, n)


_NM_DOC = st.one_of(
    _nm_mismatch(),
    _nm_mismatch(),
    _nm_unknown_entity(),
    _nm_multi_root(),
    _nm_multi_root(),
    _nm_empty_name(),
    _nm_rootless,
    _nm_badref(),
    _nm_bad_attr(),
    _nm_bad_attr(),
    _nm_stray(),
    _nm_deep_defect(),
    _nm_deep_defect(),
    _nm_dtd_weird(),
    _nm_entity_recursion(),
    _nm_reserved_pi(),
    _nm_bare_amp(),
    _nm_bare_amp(),
    _nm_bad_name_start(),
)


# --------------------------------------------------------------- byte hostile

_CTRL = st.sampled_from(
    [chr(c) for c in list(range(0, 9)) + [11, 12] + list(range(14, 32)) + [127]]
)

_BAD_SEQS = [
    b"\xc3",                      # truncated 2 byte
    b"\xe2\x82",                  # truncated 3 byte
    b"\xf0\x9f\x98",              # truncated 4 byte
    b"\x80",                      # lone continuation
    b"\xbf",
    b"\x80\x80\x80",
    b"\xc0\xaf",                  # overlong '/'
    b"\xc0\x80",                  # overlong NUL
    b"\xe0\x80\xaf",              # overlong 3 byte
    b"\xf0\x80\x80\xaf",          # overlong 4 byte
    b"\xc1\xbf",
    b"\xfe",
    b"\xff",
    b"\xfe\xff",
    b"\xf8\x88\x80\x80\x80",      # 5 byte form
    b"\xed\xa0\x80",              # UTF-8 encoded surrogate D800
    b"\xed\xb0\x80",
    b"\xf4\x90\x80\x80",          # beyond U+10FFFF
    b"\xe2\x28\xa1",              # bad continuation
    b"\xef\xbb",                  # truncated BOM
]
_RAWBAD = st.sampled_from([_rawbytes(b) for b in _BAD_SEQS])

_TRUNC = st.sampled_from(
    [
        "<!-- unterminated comment",
        "<!--",
        "<!--->",
        "<!-- a -- b -->",
        "<![CDATA[ unterminated",
        "<![CDATA[",
        "<![CDATA[x]]",
        "<![CDATA[]]>",
        "<?pi unterminated",
        "<?",
        "<??>",
        '<?xml version="1.0"',
        "<?xml",
        '<r attr="unterminated',
        "<r attr='unterminated",
        "<r",
        "<",
        "</",
        "</r",
        "<r></r",
        "<r>text",
        "<r/",
        "<!DOCTYPE r [",
        "<!",
        "&",
        "&#",
        "&#x",
        "&amp",
        "<r>&lt",
    ]
)


@st.composite
def _bh_control(draw):
    """Every branch now also carries a genuinely invalid byte run (`bad`),
    since iteration 1 measured control-char-only documents (valid Unicode,
    merely XML-illegal) mostly leaking out of the byte_hostile class."""
    n = draw(_ascii_name)
    c = draw(_CTRL)
    c2 = draw(_CTRL)
    bad = draw(_RAWBAD)
    body = draw(_text_safe)
    style = draw(st.integers(min_value=0, max_value=5))
    if style == 0:
        return "<%s>%s%s%s%s</%s>" % (n, body, c, bad, body, n)
    if style == 1:
        return '<%s a="x%sy%s">t</%s>' % (n, c, bad, n)
    if style == 2:
        return "<%s%s>t</%s%s>%s" % (n, c, n, c, bad)
    if style == 3:
        return "%s<%s/>%s%s" % (c, n, c2, bad)
    if style == 4:
        return "<!--%s%s--><%s/>" % (c, bad, n)
    return "<%s><![CDATA[%s%s%s]]>%s</%s>" % (n, c, c2, bad, c, n)


@st.composite
def _bh_truncated(draw):
    """A genuinely bad byte run is appended about half the time to each path,
    for the same reason as _bh_control: plain truncation of valid UTF-8 text
    is a near_miss-flavored defect, not a byte-hostile one, on its own."""
    bad = draw(_RAWBAD)
    if draw(st.booleans()):
        s = draw(_WF_DOC)
        if len(s) > 1:
            cut = draw(st.integers(min_value=1, max_value=len(s) - 1))
            s = s[:cut]
        else:
            s = s + "<r"
        if draw(st.booleans()):
            s = s + bad
        return s
    pre = ""
    if draw(st.integers(min_value=0, max_value=2)) == 0:
        pre = draw(_PROLOG)
    frag = pre + draw(_TRUNC)
    if draw(st.booleans()):
        frag = frag + bad
    return frag


@st.composite
def _bh_utf8(draw):
    n = draw(_ascii_name)
    bad = draw(_RAWBAD)
    bad2 = draw(_RAWBAD)
    style = draw(st.integers(min_value=0, max_value=5))
    if style == 0:
        return "<%s>%s</%s>" % (n, bad, n)
    if style == 1:
        return '<%s a="%s"/>' % (n, bad)
    if style == 2:
        return "<%s%s/>" % (n, bad)
    if style == 3:
        return "<!--%s--><%s/>" % (bad, n)
    if style == 4:
        return "<%s><![CDATA[%s]]></%s>" % (n, bad, n)
    return bad + "<%s/>%s" % (n, bad2)


@st.composite
def _bh_bom(draw):
    """Styles that used to carry only a valid-Unicode BOM char (no invalid
    bytes at all) now also splice in a `bad` run, matching the fix applied to
    _bh_control/_bh_truncated."""
    doc = draw(_WF_DOC)
    bad = draw(_RAWBAD)
    style = draw(st.integers(min_value=0, max_value=6))
    if style == 0:
        return "\ufeff" + bad + doc
    if style == 1:
        return "\ufeff\ufeff" + bad + doc
    if style == 2:
        return _rawbytes(
            b"\xef\xbb\xbf" + b"\xef\xbb" + doc.encode("utf-8", "surrogateescape")
        )
    if style == 3:
        return _rawbytes(b"\xff\xfe" + doc.encode("utf-16-le", "surrogateescape"))
    if style == 4:
        raw = b"\xff\xfe" + doc.encode("utf-16-le", "surrogateescape")
        if len(raw) % 2 == 0:
            raw = raw[:-1]
        return _rawbytes(raw)
    if style == 5:
        raw = b"\xfe\xff" + doc.encode("utf-16-be", "surrogateescape")[:-1]
        return _rawbytes(raw)
    return "\ufeff" + bad + doc[: max(1, len(doc) // 2)]


_ENC_LIE = st.sampled_from(
    [
        '<?xml version="1.0" encoding="UTF-16"?>',
        '<?xml version="1.0" encoding="UTF-16LE"?>',
        '<?xml version="1.0" encoding="UTF-16BE"?>',
        '<?xml version="1.0" encoding="ISO-8859-1"?>',
        '<?xml version="1.0" encoding="US-ASCII"?>',
        '<?xml version="1.0" encoding="UTF-7"?>',
        '<?xml version="1.0" encoding=""?>',
        '<?xml version="1.0" encoding="x-not-a-real-charset"?>',
        '<?xml version="1.0" encoding="EBCDIC-CP-US"?>',
        "<?xml version='1.0' encoding='utf-8'?>",
        '<?xml version="9.9" encoding="UTF-8"?>',
    ]
)


@st.composite
def _bh_enc_lie(draw):
    decl = draw(_ENC_LIE)
    n = draw(_ascii_name)
    style = draw(st.integers(min_value=0, max_value=4))
    if style == 0:
        return decl + "<%s>caf\u00e9 \u4e2d\u6587 \U0001f600</%s>" % (n, n)
    if style == 1:
        return decl + _rawbytes(
            ("<%s>" % n).encode() + b"\xe9\xf1\xfc\xdf" + ("</%s>" % n).encode()
        )
    if style == 2:
        return _rawbytes(
            decl.encode() + b"\xff\xfe" + ("<%s/>" % n).encode("utf-16-le")
        )
    if style == 3:
        return decl + '<%s a="\u00c0\u00e9\u4e2d">\u00ff</%s>' % (n, n)
    return _rawbytes(b"\xef\xbb\xbf" + decl.encode() + ("<%s/>" % n).encode())


@st.composite
def _bh_mixed(draw):
    n = draw(_ascii_name)
    ctrl = draw(_CTRL)
    bad = draw(_RAWBAD)
    trunc = draw(_TRUNC)
    style = draw(st.integers(min_value=0, max_value=3))
    if style == 0:
        return "\ufeff<%s>%s%s</%s>%s" % (n, ctrl, bad, n, trunc)
    if style == 1:
        return bad + trunc
    if style == 2:
        return '<%s a="%s%s">%s' % (n, ctrl, bad, trunc)
    return "\ufeff" + trunc + ctrl + bad


@st.composite
def _bh_deep_defect(draw):
    """Bury a genuinely invalid byte sequence at a random depth (5-200
    levels) inside nested wrapper elements -- deepens the byte_hostile class
    the same way _nm_deep_defect deepens near_miss."""
    depth = draw(st.integers(min_value=5, max_value=200))
    root = draw(_ascii_name)
    n = draw(_ascii_name)
    bad = draw(_RAWBAD)
    defect = "<%s>%s</%s>" % (n, bad, n)
    return _wrap_depth(root, depth, defect)


_BH_DOC = st.one_of(
    _bh_control(),
    _bh_truncated(),
    _bh_utf8(),
    _bh_utf8(),
    _bh_bom(),
    _bh_enc_lie(),
    _bh_mixed(),
    _bh_deep_defect(),
    _bh_deep_defect(),
)


# --------------------------------------------------------------- top level

def _cap(s):
    return s if len(s) <= MAX_LEN else s[:MAX_LEN]


def _dispatch(k):
    if k < 40:
        return _WF_DOC
    if k < 72:
        return _NM_DOC
    return _BH_DOC


def documents():
    """40% well_formed, 32% near_miss, 28% byte_hostile.

    Retuned from iteration 1's 50/25/25 selection weights, which measured
    classified shares of 74.0/20.8/5.2 -- byte_hostile was leaking almost
    entirely into the other two classes because several of its branches
    carried only valid-Unicode content (bare BOM chars, control characters,
    plain truncation) with no actual invalid byte sequence. Every
    byte_hostile branch now guarantees a genuinely non-UTF-8 byte run."""
    return st.integers(min_value=0, max_value=99).flatmap(_dispatch).map(_cap)
