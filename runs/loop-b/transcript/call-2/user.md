# Task

Revise the Hypothesis strategy below using the measured results of its last run.

**Directive for this iteration: deepen**

## Current strategy (iteration 1)

```python
"""Hypothesis strategy: grammar-directed XML fuzz inputs for Mini-XML 4.0.4."""

import string

from hypothesis import strategies as st

NAME = "mxml_three_class_xml"
DESCRIPTION = (
    "XML generator aimed at Mini-XML 4.0.4 rather than at the ANTLR grammar. "
    "Element names are threaded through the recursive production so open and "
    "close tags always agree in the well-formed class, and the top level is "
    "weighted 50/25/25 into well_formed, near_miss and byte_hostile documents. "
    "Recursion depth comes from st.recursive plus a shrinkable integer chain "
    "length, so depth varies and shrinks. Raw bytes that no valid UTF-8 string "
    "can hold (truncated multi-byte sequences, lone continuation bytes, "
    "overlong forms, UTF-16 BOMs, odd-length UTF-16 payloads, latin-1 payloads "
    "under a lying encoding= declaration) are carried in the surrogate-escape "
    "range U+DC80..U+DCFF, the standard Python round-trip for arbitrary bytes: "
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
    """Nesting whose depth is a single shrinkable integer."""
    depth = draw(st.integers(min_value=3, max_value=40))
    base = draw(_ascii_name)
    out = draw(inner)
    for i in range(depth):
        nm = "%s%d" % (base, i)
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


_NM_DOC = st.one_of(
    _nm_mismatch(),
    _nm_mismatch(),
    _nm_unknown_entity(),
    _nm_unknown_entity(),
    _nm_multi_root(),
    _nm_empty_name(),
    _nm_rootless,
    _nm_badref(),
    _nm_bad_attr(),
    _nm_stray(),
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
    n = draw(_ascii_name)
    c = draw(_CTRL)
    c2 = draw(_CTRL)
    body = draw(_text_safe)
    style = draw(st.integers(min_value=0, max_value=5))
    if style == 0:
        return "<%s>%s%s%s</%s>" % (n, body, c, body, n)
    if style == 1:
        return '<%s a="x%sy">t</%s>' % (n, c, n)
    if style == 2:
        return "<%s%s>t</%s%s>" % (n, c, n, c)
    if style == 3:
        return "%s<%s/>%s" % (c, n, c2)
    if style == 4:
        return "<!--%s--><%s/>" % (c, n)
    return "<%s><![CDATA[%s%s]]>%s</%s>" % (n, c, c2, c, n)


@st.composite
def _bh_truncated(draw):
    if draw(st.booleans()):
        s = draw(_WF_DOC)
        if len(s) > 1:
            cut = draw(st.integers(min_value=1, max_value=len(s) - 1))
            return s[:cut]
        return s + "<r"
    pre = ""
    if draw(st.integers(min_value=0, max_value=2)) == 0:
        pre = draw(_PROLOG)
    return pre + draw(_TRUNC)


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
    doc = draw(_WF_DOC)
    style = draw(st.integers(min_value=0, max_value=6))
    if style == 0:
        return "\ufeff" + doc
    if style == 1:
        return "\ufeff\ufeff" + doc
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
    return "\ufeff" + doc[: max(1, len(doc) // 2)]


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


_BH_DOC = st.one_of(
    _bh_control(),
    _bh_control(),
    _bh_truncated(),
    _bh_truncated(),
    _bh_utf8(),
    _bh_utf8(),
    _bh_bom(),
    _bh_bom(),
    _bh_enc_lie(),
    _bh_mixed(),
)


# --------------------------------------------------------------- top level

def _cap(s):
    return s if len(s) <= MAX_LEN else s[:MAX_LEN]


def _dispatch(k):
    if k < 50:
        return _WF_DOC
    if k < 75:
        return _NM_DOC
    return _BH_DOC


def documents():
    """50% well_formed, 25% near_miss, 25% byte_hostile."""
    return st.integers(min_value=0, max_value=99).flatmap(_dispatch).map(_cap)

```

## Measured results over 500 generated documents

### Input class mixture, and acceptance within each class

```
byte_hostile   share=  5.2%  acceptance= 38.5%  n=26
near_miss      share= 20.8%  acceptance= 11.5%  n=104
well_formed    share= 74.0%  acceptance= 54.6%  n=370
```

Targets: `well_formed` ~50%, `near_miss` >=25%, `byte_hostile` >=25%.
`near_miss` and `byte_hostile` are *expected* to be mostly rejected. Do not
raise their acceptance by making them less malformed; that defeats their purpose.

Overall acceptance: **44.8%** (target band 40-70%)

### Marginal progress: what THIS iteration found that no earlier one did

This is what you are scored on. Repeating ground already covered by an earlier
iteration counts for nothing.

```
new diagnostic templates this iteration : 13
  + <%s> cannot be a second root node after <%s> on line %d.
  + <%s?> cannot be a second root node after <%s> on line %d.
  + Bad control character 0x%x not allowed by XML standard.
  + Bad control character 0x%x under parent <%s> on line %d not allowed by XML standard.
  + Character entity '%s' not terminated under parent <%s> on line %d.
  + Duplicate attribute '%s' in element %s on line %d.
  + Early EOF in CDATA node on line %d.
  + Early EOF in comment node on line %d.
  + Early EOF in processing instruction node on line %d.
  + Entity '%s' not supported under parent <%s> on line %d.
  + Mismatched close tag </%s> under parent <%s> on line %d.
  + Missing value for attribute '%s' in element %s on line %d.
  + XML does not start with '%s' (saw '%s').
new grammar productions this iteration  : 23: g_attribute_dquot, g_attribute_squot, g_cdata, g_chardata, g_charref_dec, g_charref_hex, g_comment, g_element_paired, g_element_selfclose, g_entity_named, g_nesting_deep, g_pi, g_prolog, x_attribute_unquoted, x_control_char, x_doctype, x_empty_elem_name, x_entity_unsupported, x_mismatched_tags, x_multiple_roots, x_name_nonascii, x_rootless, x_unterminated
```

**Target: at least 3 diagnostic templates that no previous iteration reached.**

### Diagnostics already reached by ANY iteration so far (13 total)

```
<%s> cannot be a second root node after <%s> on line %d.
<%s?> cannot be a second root node after <%s> on line %d.
Bad control character 0x%x not allowed by XML standard.
Bad control character 0x%x under parent <%s> on line %d not allowed by XML standard.
Character entity '%s' not terminated under parent <%s> on line %d.
Duplicate attribute '%s' in element %s on line %d.
Early EOF in CDATA node on line %d.
Early EOF in comment node on line %d.
Early EOF in processing instruction node on line %d.
Entity '%s' not supported under parent <%s> on line %d.
Mismatched close tag </%s> under parent <%s> on line %d.
Missing value for attribute '%s' in element %s on line %d.
XML does not start with '%s' (saw '%s').
```

Each of these is a branch in the parser that has already been visited. Reaching
them again adds nothing. Use your own knowledge of XML to reason about what
*other* error conditions a conforming parser must detect, which are absent from
this list, and construct documents that trigger them.

### Grammar production coverage: 23/23

Never produced by any iteration:
```
(none -- full coverage)
```

### Nesting depth distribution

```
{
  "0": 107,
  "1": 104,
  "16+": 204,
  "2-3": 46,
  "4-7": 17,
  "8-15": 22
}
```
Deepest document generated: 211

### Document size

```
{
  "min": 0,
  "max": 3600,
  "mean": 477.4,
  "median": 184.5
}
```

### Slowest documents

```
     8.9 ms  len=649    depth=29  parsed_clean
     8.8 ms  len=1572   depth=87  parsed_clean
     8.6 ms  len=628    depth=36  parsed_clean
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
