# Task

Revise the Hypothesis strategy below using the measured results of its last run.

**Directive for this iteration: sweep-boundaries**

## Current strategy (iteration 1)

```python
from hypothesis import strategies as st

NAME = "xml_boundary_fuzzer"
DESCRIPTION = (
    "Grammar-seeded XML generator for Mini-XML (mxml) that targets dense "
    "boundary coverage of counted constructs: name length, attribute count, "
    "attribute value length, nesting depth, entity name length, and numeric "
    "character reference value. Threads element names through open and close "
    "tags so nested documents are mostly well formed, then places a single "
    "structural or byte-level defect deep inside an otherwise valid document: "
    "a mismatched tag, an unsupported entity, a truncated UTF-8 sequence, a "
    "byte-order mark, an embedded NUL, or a control character. Also emits "
    "standalone near-miss and byte-hostile documents (doctype, multiple "
    "roots, rootless comments, unquoted attributes, non-ASCII names) to keep "
    "class coverage broad."
)

# ---------------------------------------------------------------------------
# Boundary tables. Sampled explicitly so boundary values are hit for sure,
# instead of relying on a wide st.integers() range to land on them by luck.
# ---------------------------------------------------------------------------

NAME_LENGTHS = [
    0, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
    15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129,
    191, 192, 193, 254, 255, 256, 257, 300,
]

ENTITY_NAME_LENGTHS = [
    1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
    15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257,
]

ATTR_VALUE_LENGTHS = [
    0, 0, 1, 1, 2, 3, 4, 5, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65,
    127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025,
    2047, 2048, 2049, 4095, 4096, 4097,
]

ATTR_COUNTS = [
    0, 0, 0, 1, 1, 1, 2, 2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
    16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 200, 255, 256, 257,
]

RECURSIVE_DEPTHS = [0, 1, 1, 2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 16, 17, 20, 24]

DEEP_NEST_DEPTH_POOL = [
    0, 1, 2, 3, 5, 8, 16, 32, 64, 100, 128, 250, 255, 256, 257,
    500, 1000, 2000, 3000, 4000, 5000,
]

CONTENT_LENGTHS = [
    0, 0, 1, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65,
    127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025,
    2047, 2048, 2049, 4095, 4096, 4097,
]

CHARREF_VALUES = [
    0, 1, 8, 9, 10, 13, 31, 32, 0x7E, 0x7F, 0x80,
    0xD7FF, 0xD800, 0xDFFF, 0xE000, 0xFF, 0x100, 0x7FF, 0x800,
    0xFFFD, 0xFFFE, 0xFFFF, 0x10000, 0x10FFFF, 0x110000, 0x111111,
    0xFFFFFFFF, 0x100000000, 0xFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF, 0x10000000000000000,
]

NAMED_ENTITIES = ["amp", "lt", "gt", "quot"]
UNSUPPORTED_ENTITY_NAMES = ["apos", "nbsp", "copy", "AMP", "Amp", "amp2"]

ASCII_NAME_START = (
    [chr(c) for c in range(ord("a"), ord("z") + 1)]
    + [chr(c) for c in range(ord("A"), ord("Z") + 1)]
    + ["_", ":"]
)
ASCII_NAME_CHAR_EXTRA = [chr(c) for c in range(ord("0"), ord("9") + 1)] + ["-", "."]
NONASCII_NAME_START = ["\u00e9", "\u03b1", "\u0100", "\u2070", "\u2c00", "\u3001", "\uf900"]
NONASCII_NAME_CHAR = ["\u00b7", "\u0300", "\u203f"]

SAFE_VALUE_CHARS = list(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-.:/"
)

CONTROL_CHARS = [chr(c) for c in range(0, 32) if c not in (9, 10, 13)]

ENCODING_NAMES = ["UTF-8", "UTF-16", "ISO-8859-1", "utf-8", "ASCII", "utf-16le", "Big5"]


def _raw(b):
    # Encode a raw byte 0x80-0xFF as a lone surrogate code point. A harness
    # that turns this string into bytes via encode('utf-8', 'surrogateescape')
    # gets that exact raw byte back. That is the only way to express invalid
    # UTF-8 (truncated sequences, lone continuation bytes, overlong forms, a
    # UTF-16 BOM) from a function whose contract is to return a plain str.
    return chr(0xDC00 + b)


def _overlong_slash():
    return _raw(0xC0) + _raw(0xAF)


def _truncated_seq():
    return _raw(0xE2) + _raw(0x82)


def _lone_continuation():
    return _raw(0x80)


BOM8 = "\ufeff"
RAW_BOM16_LE = _raw(0xFF) + _raw(0xFE)
RAW_BOM16_BE = _raw(0xFE) + _raw(0xFF)


def _doctype_str():
    return "<!DOCTYPE r [<!ELEMENT r EMPTY>]>"


@st.composite
def _name(draw, length_pool=None, allow_nonascii=True):
    lengths = length_pool if length_pool is not None else NAME_LENGTHS
    n = draw(st.sampled_from(lengths))
    if n == 0:
        return ""
    starts = ASCII_NAME_START + (NONASCII_NAME_START if allow_nonascii else [])
    chars_pool = ASCII_NAME_START + ASCII_NAME_CHAR_EXTRA + (
        NONASCII_NAME_CHAR if allow_nonascii else []
    )
    first = draw(st.sampled_from(starts))
    if n == 1:
        return first
    rest = draw(st.lists(st.sampled_from(chars_pool), min_size=n - 1, max_size=n - 1))
    return first + "".join(rest)


@st.composite
def _entity_ref(draw):
    choice = draw(st.sampled_from(["named", "named", "named", "unsupported", "garbage_len"]))
    if choice == "named":
        name = draw(st.sampled_from(NAMED_ENTITIES))
    elif choice == "unsupported":
        name = draw(st.sampled_from(UNSUPPORTED_ENTITY_NAMES))
    else:
        n = draw(st.sampled_from(ENTITY_NAME_LENGTHS))
        first = draw(st.sampled_from(ASCII_NAME_START))
        rest = draw(
            st.lists(
                st.sampled_from(ASCII_NAME_START + ASCII_NAME_CHAR_EXTRA),
                min_size=max(0, n - 1),
                max_size=max(0, n - 1),
            )
        )
        name = first + "".join(rest)
    return "&" + name + ";"


@st.composite
def _char_ref(draw):
    v = draw(st.sampled_from(CHARREF_VALUES))
    form = draw(st.sampled_from(["dec", "hex_lower", "hex_upper"]))
    if form == "dec":
        return "&#%d;" % v
    if form == "hex_lower":
        return "&#x%x;" % v
    return "&#x%X;" % v


@st.composite
def _attr_value_text(draw, length_pool=None, allow_hostile=True):
    n = draw(st.sampled_from(length_pool if length_pool is not None else ATTR_VALUE_LENGTHS))
    segments = []
    total = 0
    while total < n:
        remaining = n - total
        use_special = remaining >= 6 and draw(st.integers(min_value=0, max_value=3)) == 0
        if use_special:
            piece = draw(st.one_of(_entity_ref(), _char_ref()))
        else:
            piece = draw(st.sampled_from(SAFE_VALUE_CHARS))
        segments.append(piece)
        total += len(piece)
    text = "".join(segments)
    if len(text) > n:
        text = text[:n]
    if allow_hostile and n > 0 and draw(st.integers(min_value=0, max_value=7)) == 0:
        frag = draw(
            st.sampled_from(
                [_truncated_seq(), _lone_continuation(), _overlong_slash(), "\x00", BOM8]
            )
        )
        pos = draw(st.integers(min_value=0, max_value=len(text)))
        text = text[:pos] + frag + text[pos:]
    return text


@st.composite
def _attribute(draw, name_length_pool=None, value_length_pool=None):
    name = draw(_name(length_pool=name_length_pool))
    if name == "":
        name = "a"
    value = draw(_attr_value_text(length_pool=value_length_pool))
    quote_style = draw(
        st.sampled_from(["dquot", "dquot", "dquot", "squot", "squot", "unquoted"])
    )
    if quote_style == "dquot":
        val = value.replace('"', "&quot;")
        return f'{name}="{val}"'
    if quote_style == "squot":
        val = value.replace("'", "&quot;")
        return f"{name}='{val}'"
    val = "".join(ch for ch in value if ch not in " \t\r\n\"'<>/") or "1"
    return f"{name}={val}"


@st.composite
def _misc(draw):
    kind = draw(st.sampled_from(["comment", "pi", "ws"]))
    if kind == "comment":
        n = draw(st.sampled_from(CONTENT_LENGTHS[:14]))
        body = "".join(draw(st.lists(st.sampled_from(SAFE_VALUE_CHARS), min_size=n, max_size=n)))
        unterminated = draw(st.integers(min_value=0, max_value=19)) == 0
        if unterminated:
            return "<!--" + body
        return f"<!--{body}-->"
    if kind == "pi":
        target = draw(_name(length_pool=NAME_LENGTHS[:8], allow_nonascii=False))
        if target == "":
            target = "p"
        n = draw(st.sampled_from(CONTENT_LENGTHS[:10]))
        body = "".join(draw(st.lists(st.sampled_from(SAFE_VALUE_CHARS), min_size=n, max_size=n)))
        return f"<?{target} {body}?>"
    return draw(st.sampled_from([" ", "\t", "\n", "\r\n", "  ", "\n\n"]))


@st.composite
def _cdata(draw):
    n = draw(st.sampled_from(CONTENT_LENGTHS))
    body = "".join(draw(st.lists(st.sampled_from(SAFE_VALUE_CHARS), min_size=n, max_size=n)))
    unterminated = draw(st.integers(min_value=0, max_value=19)) == 0
    if unterminated:
        return "<![CDATA[" + body
    return f"<![CDATA[{body}]]>"


@st.composite
def _chardata(draw, length_pool=None):
    n = draw(st.sampled_from(length_pool if length_pool is not None else CONTENT_LENGTHS))
    if n == 0:
        return ""
    chars = draw(st.lists(st.sampled_from(SAFE_VALUE_CHARS), min_size=n, max_size=n))
    text = "".join(chars)
    if draw(st.integers(min_value=0, max_value=9)) == 0:
        c = draw(st.sampled_from(CONTROL_CHARS))
        pos = draw(st.integers(min_value=0, max_value=len(text)))
        text = text[:pos] + c + text[pos:]
    return text


@st.composite
def _content(draw, depth):
    pieces = []
    n_items = draw(st.sampled_from([0, 1, 1, 1, 2, 2, 3, 4, 5, 6, 8]))
    for _ in range(n_items):
        kind = draw(
            st.sampled_from(
                ["chardata", "chardata", "chardata", "element", "element", "element",
                 "entity", "entity", "charref", "charref", "cdata", "comment", "pi"]
            )
        )
        if kind == "element":
            pieces.append(draw(_element(depth)))
        elif kind == "chardata":
            pieces.append(draw(_chardata()))
        elif kind == "entity":
            pieces.append(draw(_entity_ref()))
        elif kind == "charref":
            pieces.append(draw(_char_ref()))
        elif kind == "cdata":
            pieces.append(draw(_cdata()))
        elif kind in ("comment", "pi"):
            pieces.append(draw(_misc()))
    return "".join(pieces)


@st.composite
def _element(draw, depth):
    name = draw(_name())
    attr_count = draw(st.sampled_from(ATTR_COUNTS))
    if attr_count > 64:
        name_pool = [0, 1, 2, 3]
        val_pool = [0, 1, 2, 4, 8, 16, 32]
    elif attr_count > 16:
        name_pool = [1, 2, 3, 4, 5, 8, 16]
        val_pool = [x for x in ATTR_VALUE_LENGTHS if x <= 256]
    else:
        name_pool = NAME_LENGTHS
        val_pool = ATTR_VALUE_LENGTHS
    attrs = draw(
        st.lists(
            _attribute(name_length_pool=name_pool, value_length_pool=val_pool),
            min_size=attr_count,
            max_size=attr_count,
        )
    )
    attr_str = "".join(" " + a for a in attrs)

    self_close = depth <= 0 or draw(st.integers(min_value=0, max_value=9)) == 0
    if self_close:
        return f"<{name}{attr_str}/>"

    inner = draw(_content(depth - 1))
    mismatch = name != "" and draw(st.integers(min_value=0, max_value=24)) == 0
    close_name = (name + "Z") if mismatch else name
    return f"<{name}{attr_str}>{inner}</{close_name}>"


@st.composite
def _prolog(draw):
    kind = draw(
        st.sampled_from(
            ["xml_decl", "xml_decl", "xml_decl_no_space", "xml_decl_encoding", "none", "none"]
        )
    )
    if kind == "none":
        return ""
    if kind == "xml_decl_no_space":
        return "<?xml?>"
    attrs = ' version="1.0"'
    if kind == "xml_decl_encoding":
        enc = draw(st.sampled_from(ENCODING_NAMES))
        attrs += f' encoding="{enc}"'
    return f"<?xml{attrs}?>"


@st.composite
def _well_formed_document(draw):
    prolog = draw(_prolog())
    lead_misc = "".join(draw(st.lists(_misc(), min_size=0, max_size=3)))
    depth = draw(st.sampled_from(RECURSIVE_DEPTHS))
    root = draw(_element(depth))
    trail_misc = "".join(draw(st.lists(_misc(), min_size=0, max_size=3)))
    return prolog + lead_misc + root + trail_misc


@st.composite
def _near_miss_document(draw):
    kind = draw(
        st.sampled_from(
            ["mismatched", "unsupported_entity", "empty_name_elem", "doctype",
             "rootless", "duplicate_attr"]
        )
    )
    prolog = draw(_prolog())
    if kind == "rootless":
        body = "".join(draw(st.lists(_misc(), min_size=1, max_size=5)))
        return prolog + body
    if kind == "doctype":
        depth = draw(st.sampled_from(RECURSIVE_DEPTHS))
        root = draw(_element(depth))
        return prolog + _doctype_str() + root
    if kind == "empty_name_elem":
        return prolog + "< />"
    depth = draw(st.sampled_from(RECURSIVE_DEPTHS))
    root = draw(_element(depth))
    if kind == "mismatched":
        outer_name = draw(_name(length_pool=[1, 2, 3]))
        if outer_name == "":
            outer_name = "r"
        other_name = outer_name + "Z"
        return prolog + f"<{outer_name}>{root}</{other_name}>"
    if kind == "unsupported_entity":
        return prolog + f"<r>&apos;{root}</r>"
    if kind == "duplicate_attr":
        aname = draw(_name(length_pool=[1, 2, 3, 4]))
        if aname == "":
            aname = "a"
        return prolog + f'<r {aname}="1" {aname}="2"/>'
    return prolog + root


@st.composite
def _multi_root_document(draw):
    prolog = draw(_prolog())
    small_depths = RECURSIVE_DEPTHS[:10]
    d1 = draw(st.sampled_from(small_depths))
    d2 = draw(st.sampled_from(small_depths))
    e1 = draw(_element(d1))
    e2 = draw(_element(d2))
    sep = draw(st.sampled_from(["", " ", "\n"]))
    return prolog + e1 + sep + e2


@st.composite
def _byte_hostile_document(draw):
    kind = draw(
        st.sampled_from(
            ["bom8", "bom16le_odd", "bom16be_odd", "truncated", "lone_continuation",
             "overlong", "invalid_encoding_decl", "embedded_nul"]
        )
    )
    depth = draw(st.sampled_from(RECURSIVE_DEPTHS[:8]))
    root = draw(_element(depth))
    if kind == "bom8":
        return BOM8 + root
    if kind == "bom16le_odd":
        extra = draw(st.sampled_from(["A", "ABC", "12345"]))
        return RAW_BOM16_LE + extra + root
    if kind == "bom16be_odd":
        extra = draw(st.sampled_from(["A", "ABC", "12345"]))
        return RAW_BOM16_BE + extra + root
    if kind == "truncated":
        return "<r>" + _truncated_seq() + "</r>"
    if kind == "lone_continuation":
        return "<r>" + _lone_continuation() + "</r>"
    if kind == "overlong":
        return "<r>" + _overlong_slash() + "</r>"
    if kind == "invalid_encoding_decl":
        enc = draw(st.sampled_from(["UTF-16", "UTF-32", "Shift-JIS"]))
        return f'<?xml version="1.0" encoding="{enc}"?>' + root
    return "<r>\x00</r>"


@st.composite
def _deep_nested_document(draw):
    depth = draw(st.sampled_from(DEEP_NEST_DEPTH_POOL))
    tag = draw(_name(length_pool=[1, 1, 2, 3]))
    if tag == "":
        tag = "a"
    defect_kind = draw(
        st.sampled_from(
            ["none", "none", "mismatched_tag", "control_char", "entity_unsupported",
             "truncated_utf8", "embedded_nul", "long_attr"]
        )
    )
    defect_level = draw(st.integers(min_value=0, max_value=depth - 1)) if depth > 0 else 0

    opens = []
    closes = []
    for level in range(depth):
        attrs = ""
        if defect_kind == "long_attr" and level == defect_level:
            n = draw(st.sampled_from([255, 256, 257, 1023, 1024, 1025, 4095, 4096, 4097]))
            attrs = ' v="' + ("x" * n) + '"'
        opens.append(f"<{tag}{attrs}>")
        close_tag = tag
        if defect_kind == "mismatched_tag" and level == defect_level:
            close_tag = tag + "Z"
        closes.append(f"</{close_tag}>")

    inner = "leaf"
    if defect_kind == "control_char":
        inner = "leaf" + "\x0b" + "leaf"
    elif defect_kind == "entity_unsupported":
        inner = "leaf&apos;leaf"
    elif defect_kind == "truncated_utf8":
        inner = "leaf" + _truncated_seq() + "leaf"
    elif defect_kind == "embedded_nul":
        inner = "leaf" + "\x00" + "leaf"

    return "".join(opens) + inner + "".join(reversed(closes))


def documents():
    return st.one_of(
        _well_formed_document(),
        _well_formed_document(),
        _well_formed_document(),
        _well_formed_document(),
        _deep_nested_document(),
        _deep_nested_document(),
        _near_miss_document(),
        _multi_root_document(),
        _byte_hostile_document(),
        _byte_hostile_document(),
    ).map(lambda d: d if len(d) <= 65000 else d[:65000])

```

## Measured results over 500 generated documents

### Boundary coverage

This is the primary objective. Each row is what the last run actually reached.
A narrow range or a small number of distinct values means that dimension is not
being swept.

```
name_len             max=389      p90=193      p50=3        distinct values=33
attrs_per_element    max=257      p90=32       p50=0        distinct values=16
entity_name_len      max=64       p90=63       p50=0        distinct values=16
attr_value_len       max=3        p90=3        p50=0        distinct values=2
depth                max=5000     p90=250      p50=1        distinct values=19
```

For every dimension above: add 0, 1 and 2 if absent, then a dense sweep in a
window around the largest value already reached, then one step beyond it. Use
`st.sampled_from` on an explicit list, not a wide `st.integers`.

### Input class mixture, and acceptance within each class

```
byte_hostile   share= 55.4%  acceptance= 28.2%  n=277
near_miss      share= 23.4%  acceptance= 15.4%  n=117
well_formed    share= 21.2%  acceptance= 82.1%  n=106
```

Minimums, **all of which must hold at once**: `well_formed` >=40%,
`near_miss` >=20%, `byte_hostile` >=20%. Raising one by dropping another below
its minimum is worse than leaving both alone.

Overall acceptance: **36.6%** (target band 40-70%)

Note the acceptance rate *within* `byte_hostile`. If it is very low, those
documents are being rejected at the front door and are not reaching the parser.
The fix is not fewer of them; it is to place the defect deeper inside an
otherwise-valid document.

### Marginal progress: what THIS iteration found that no earlier one did

Repeating ground already covered by an earlier iteration counts for nothing.

```
new diagnostic templates this iteration : 15
  + <%s--><%s?><i-bPDFa3 QP6EHfCf4EGrcx·_MQpa0J7zD9hoYY4c̀7aLZYIwyCyuemFzohFrOFw1bRWZFj5np82hcQDDUdi9IWIuiDX3XDaDhvTCIazkhZ·s67l‿̀SX_NdwqtikUMAmD9GUXd-tcmtAUdCZ2srgd9uIpu·J8qweùkICAzbmSqLMSoI·t6-·x-tyERek8Uq̀moiCwU2:='%s' B8ò:_e7vCciAm-Y·C1W._J̀KXJlg_iDzvE06DOHII6g_-bg̀aoYAWYWWyRch_Tn5=' C&amp;ZpW&#%d;N&Amp;&#xFFFFFFFFFFFF;&#x800;DEEJ6jn&#x1F;W/7J&quot;&#xfffd;O&lt;/IJG&#x20;YY1rd/qL&#x1;X95Qw3Lq&#%d;0HFKbjeB .w&#xff;FE2BwZDMJl&#x10000000000000000;&#%d;jI&amp;bc&#%d;:KKp&#xffffffffffff;9d&quot;&amp;Ohj&amp;u&#x110000;a&Kcunf;pVFecjc&amp2;DwZoj&gt;&#xFFFFFFFFFFFF;&m:HoCPnsRwQeArM.aacabad5aadbaaew:_K7xmKq6I9UXZaKZQHnjKV9XH6PzWVnvb1Ml_enkeH:NX4oY_J.N8bLIVN3dgpVS4p0QqLQQZDjv7m_qTjYks0ca1XRaKHZnJ:y8dy:YlCRx9dSD9cha7.pA2SXamfyabAccbdrbBdNaaccdoabDbcdd1bvbmcod.bod6dYdxcwd1dPabnabyaadfcqdnc4cqcGdwd0aadcc_c6ccdsbPb5c-aaabdNc;c&lt;&amp;c&quot;a&gt;&#xA;&#%d;n&quot;&amp;aA&#x10FFFF;&#%d;f&lt;&amp;vafa&#x8;&quot;&#x0;ay&gt;b&#%d
  + <%s--><%s?><i-bPDFa3 QP6EHfCf4EGrcx·_MQpa0J7zD9hoYY4c̀7aLZYIwyCyuemFzohFrOFw1bRWZFj5np82hcQDDUdi9qWIuiDX3XDaDhvTCIazkhZ·s67l‿̀SX_NdwqtikUMAmD9GUXd-tcmtAUdCZ2srgd9uIpu·J8qweùkICAzbmSqLMSoI·t6-·x-tyERek8Uq̀moiCwU2:='%s' B8ò:_e7vCciAm-Y·C1W._J̀KXJlg_iDzvE06DOHII6g_-bg̀aoYAWYWWyRch_Tn5=' C&amp;ZpW&#%d;N&Amp;&#xFFFFFFFFFFFF;&#x800;DEEJ6jn&#x1F;W/7J&quot;&#xfffd;O&lt;/IJG&#x20;YY1rd/qL&#x1;X95Qw3Lq&#%d;0HFKbjeB .w&#xff;FE2BwZDMJl&#x10000000000000000;&#%d;jI&amp;bc&#%d;:KKp&#xffffffffffff;9d&quot;&amp;Ohj&amp;u&#x110000;a&Kcunf;pVFecjc&amp2;DwZoj&gt;&#xFFFFFFFFFFFF;&m:HoCPnsRwQeArM.;&amp;/%d&nbsp;&:_K7xmKq6I9UXZaKZQHnjKV9XH6PzWVnvb1Ml_enkeH:NX4oY_J.N8bLIVN3dgpVS4p0QqLQQZDjv7m_qTjYks0ca1XRaKHZnJ:y8dy:YlCRx9dSD9cha7.pA2SXamfy;&#xFFFFFFFF;brBN&gt;o&#xffffffffffffffff;d3vmo.o8Yxw3P&#%d;y&amp2;qn6qGw2&copy;08csP7-&lt;NbW53&#x0;w&#x9;&copy;Ee-G&#%d;bM&#xFFFFFFFFFFFF;&#%d;xhr&#%d;&amp;u&#xFFFF;&#xd;&gt;K&#%d;0b&#%d
  + <%s--><%s?><i-bPDFa3 QP6EHfCf4EGrcx·_MQpa0J7zD9hoYY4c̀7aLZYIwyCyuemFzohFrOFw1bRWZFj5np82hcQDDUdi9qWIuiDX3XDaDhvTCIazkhZ·s67l‿̀SX_NdwqtikUMAmD9GUXd-tcmtAUdCZ2srgd9uIpu·J8qweùkICAzbmSqLMSoI·t6-·x-tyERek8Uq̀moiCwU2:='%s' B8ò:_e7vCciAm-Y·C1W._J̀KXJlg_iDzvE06DOHII6g_-bg̀aoYAWYWWyRch_Tn5=' C&amp;ZpW&#%d;N&Amp;&#xFFFFFFFFFFFF;&#x800;DEEJ6jn&#x1F;W/7J&quot;&#xfffd;O&lt;/IJG&#x20;YY1rd/qL&#x1;X95Qw3Lq&#%d;0HFKbjeB .w&#xff;FE2BwZDMJl&#x10000000000000000;&#%d;jI&amp;bc&#%d;:KKp&#xffffffffffff;9d&quot;&amp;Ohj&amp;u&#x110000;a&Kcunf;pVFecjc&amp2;DwZoj&gt;&#xFFFFFFFFFFFF;&m:HoCPnsRwQeArM.;&amp;/%d&nbsp;&:_K7xmKq6I9UXZaKZQHnjKV9XH6PzWVnvb1Ml_enkeH:NX4oY_J.N8bLIVN3dgpVS4p0QqLQQZDjv7m_qTjYks0ca1XRaKHZnJ:y8dy:YlCRx9dSD9cha7.pA2SXamfy;&#xFFFFFFFF;brBN&gt;o&#xffffffffffffffff;d3vmo.o8Yxw3P&#%d;y&amp2;qn6qGw2&copy;08csP7-&lt;NbW53&#x0;w&#x9;&copy;Ee-G&#xA;bM&#xFFFFFFFFFFFF;&#%d;xhr&#%d;&amp;u&#xFFFF;&#xd;&gt;K&#%d;0b&#%d
  + <%s--><%s?><i-bPDFa3 QP6EHfCf4EGrcx·_MQpa0J7zD9hoYY4c̀7aLZYIwyCyuemFzohFrOFw1bRWZFj5np82hcQDDUdi9qWIuiDX3XDaDhvTCIazkhZ·s67l‿̀SX_NdwqtikUMAmD9GUXd-tcmtAUdCZ2srgd9uIpu·J8qweùkICAzbmSqLMSoI·t6-·x-tyERek8Uq̀moiCwU2:='%s' B8ò:_e7vCciAm-Y·C1W._J̀KXJlg_iDzvE06DOHII6g_-bg̀aoYAWYWWyRch_Tn5=' C&amp;ZpW&#%d;N&Amp;&#xFFFFFFFFFFFF;&#x800;DEEJ6jn&#x1F;W/7J&quot;&#xfffd;O&lt;/IJG&#x20;YY1rd/qL&#x1;X95Qw3Lq&#%d;0HFKbjeB .w&#xff;FE2BwZDMJl&#x10000000000000000;&#%d;jI&amp;bc&#%d;:KKp&#xffffffffffff;9d&quot;&amp;Ohj&amp;u&#x110000;a&Kcunf;pVFecjc&amp2;DwZoj&gt;&#xFFFFFFFFFFFF;&m:HoCPnsRwQeArM.aacabad5aadbaaew:_K7xmKq6I9UXZaKZQHnjKV9XH6PzWVnvb1Ml_enkeH:NX4oY_J.N8bLIVN3dgpVS4p0QqLQQZDjv7m_qTjYks0ca1XRaKHZnJ:y8dy:YlCRx9dSD9cha7.pA2SXamfyabAccbdrbBdNaaccdoabDbcdd1bvbmcod.bod6dYdxcwd1dPabnabyaadfcqdnc4cqcGdwd0aadcc_c6ccdsbPb5c-aaabdNc;c&lt;&amp;c&quot;a&gt;&#xA;&#%d;n&quot;&amp;aA&#x10FFFF;&#%d;f&lt;&amp;vafa&#x8;&quot;&#x0;ay&gt;b&#%d
  + <%s> cannot be a second root node after <%s> on line %d.
  + <%s?> cannot be a second root node after <%s> on line %d.
  + Bad control character 0x%x not allowed by XML standard.
  + Bad control character 0x%x under parent <%s> on line %d not allowed by XML standard.
  + Character entity '%s' not terminated under parent <%s> on line %d.
  + Duplicate attribute '%s' in element %s on line %d.
  + Early EOF in comment node on line %d.
  + Entity '%s' not supported under parent <%s> on line %d.
  + Mismatched close tag </%s> under parent <%s> on line %d.
  + Missing close tag </%s> under parent <%s> on line %d.
  + XML does not start with '%s' (saw '%s').
new grammar productions this iteration  : 27: g_attribute_dquot, g_attribute_squot, g_cdata, g_chardata, g_charref_dec, g_charref_hex, g_comment, g_element_paired, g_element_selfclose, g_entity_named, g_nesting_deep, g_pi, g_prolog, x_attribute_unquoted, x_bom, x_control_char, x_doctype, x_embedded_nul, x_empty_elem_name, x_encoding_decl, x_entity_unsupported, x_invalid_utf8, x_mismatched_tags, x_multiple_roots, x_name_nonascii, x_rootless, x_unterminated
```

**Target: at least 3 diagnostic templates that no previous iteration reached.**

### Diagnostics already reached by ANY iteration so far (15 total)

```
<%s--><%s?><i-bPDFa3 QP6EHfCf4EGrcx·_MQpa0J7zD9hoYY4c̀7aLZYIwyCyuemFzohFrOFw1bRWZFj5np82hcQDDUdi9IWIuiDX3XDaDhvTCIazkhZ·s67l‿̀SX_NdwqtikUMAmD9GUXd-tcmtAUdCZ2srgd9uIpu·J8qweùkICAzbmSqLMSoI·t6-·x-tyERek8Uq̀moiCwU2:='%s' B8ò:_e7vCciAm-Y·C1W._J̀KXJlg_iDzvE06DOHII6g_-bg̀aoYAWYWWyRch_Tn5=' C&amp;ZpW&#%d;N&Amp;&#xFFFFFFFFFFFF;&#x800;DEEJ6jn&#x1F;W/7J&quot;&#xfffd;O&lt;/IJG&#x20;YY1rd/qL&#x1;X95Qw3Lq&#%d;0HFKbjeB .w&#xff;FE2BwZDMJl&#x10000000000000000;&#%d;jI&amp;bc&#%d;:KKp&#xffffffffffff;9d&quot;&amp;Ohj&amp;u&#x110000;a&Kcunf;pVFecjc&amp2;DwZoj&gt;&#xFFFFFFFFFFFF;&m:HoCPnsRwQeArM.aacabad5aadbaaew:_K7xmKq6I9UXZaKZQHnjKV9XH6PzWVnvb1Ml_enkeH:NX4oY_J.N8bLIVN3dgpVS4p0QqLQQZDjv7m_qTjYks0ca1XRaKHZnJ:y8dy:YlCRx9dSD9cha7.pA2SXamfyabAccbdrbBdNaaccdoabDbcdd1bvbmcod.bod6dYdxcwd1dPabnabyaadfcqdnc4cqcGdwd0aadcc_c6ccdsbPb5c-aaabdNc;c&lt;&amp;c&quot;a&gt;&#xA;&#%d;n&quot;&amp;aA&#x10FFFF;&#%d;f&lt;&amp;vafa&#x8;&quot;&#x0;ay&gt;b&#%d
<%s--><%s?><i-bPDFa3 QP6EHfCf4EGrcx·_MQpa0J7zD9hoYY4c̀7aLZYIwyCyuemFzohFrOFw1bRWZFj5np82hcQDDUdi9qWIuiDX3XDaDhvTCIazkhZ·s67l‿̀SX_NdwqtikUMAmD9GUXd-tcmtAUdCZ2srgd9uIpu·J8qweùkICAzbmSqLMSoI·t6-·x-tyERek8Uq̀moiCwU2:='%s' B8ò:_e7vCciAm-Y·C1W._J̀KXJlg_iDzvE06DOHII6g_-bg̀aoYAWYWWyRch_Tn5=' C&amp;ZpW&#%d;N&Amp;&#xFFFFFFFFFFFF;&#x800;DEEJ6jn&#x1F;W/7J&quot;&#xfffd;O&lt;/IJG&#x20;YY1rd/qL&#x1;X95Qw3Lq&#%d;0HFKbjeB .w&#xff;FE2BwZDMJl&#x10000000000000000;&#%d;jI&amp;bc&#%d;:KKp&#xffffffffffff;9d&quot;&amp;Ohj&amp;u&#x110000;a&Kcunf;pVFecjc&amp2;DwZoj&gt;&#xFFFFFFFFFFFF;&m:HoCPnsRwQeArM.;&amp;/%d&nbsp;&:_K7xmKq6I9UXZaKZQHnjKV9XH6PzWVnvb1Ml_enkeH:NX4oY_J.N8bLIVN3dgpVS4p0QqLQQZDjv7m_qTjYks0ca1XRaKHZnJ:y8dy:YlCRx9dSD9cha7.pA2SXamfy;&#xFFFFFFFF;brBN&gt;o&#xffffffffffffffff;d3vmo.o8Yxw3P&#%d;y&amp2;qn6qGw2&copy;08csP7-&lt;NbW53&#x0;w&#x9;&copy;Ee-G&#%d;bM&#xFFFFFFFFFFFF;&#%d;xhr&#%d;&amp;u&#xFFFF;&#xd;&gt;K&#%d;0b&#%d
<%s--><%s?><i-bPDFa3 QP6EHfCf4EGrcx·_MQpa0J7zD9hoYY4c̀7aLZYIwyCyuemFzohFrOFw1bRWZFj5np82hcQDDUdi9qWIuiDX3XDaDhvTCIazkhZ·s67l‿̀SX_NdwqtikUMAmD9GUXd-tcmtAUdCZ2srgd9uIpu·J8qweùkICAzbmSqLMSoI·t6-·x-tyERek8Uq̀moiCwU2:='%s' B8ò:_e7vCciAm-Y·C1W._J̀KXJlg_iDzvE06DOHII6g_-bg̀aoYAWYWWyRch_Tn5=' C&amp;ZpW&#%d;N&Amp;&#xFFFFFFFFFFFF;&#x800;DEEJ6jn&#x1F;W/7J&quot;&#xfffd;O&lt;/IJG&#x20;YY1rd/qL&#x1;X95Qw3Lq&#%d;0HFKbjeB .w&#xff;FE2BwZDMJl&#x10000000000000000;&#%d;jI&amp;bc&#%d;:KKp&#xffffffffffff;9d&quot;&amp;Ohj&amp;u&#x110000;a&Kcunf;pVFecjc&amp2;DwZoj&gt;&#xFFFFFFFFFFFF;&m:HoCPnsRwQeArM.;&amp;/%d&nbsp;&:_K7xmKq6I9UXZaKZQHnjKV9XH6PzWVnvb1Ml_enkeH:NX4oY_J.N8bLIVN3dgpVS4p0QqLQQZDjv7m_qTjYks0ca1XRaKHZnJ:y8dy:YlCRx9dSD9cha7.pA2SXamfy;&#xFFFFFFFF;brBN&gt;o&#xffffffffffffffff;d3vmo.o8Yxw3P&#%d;y&amp2;qn6qGw2&copy;08csP7-&lt;NbW53&#x0;w&#x9;&copy;Ee-G&#xA;bM&#xFFFFFFFFFFFF;&#%d;xhr&#%d;&amp;u&#xFFFF;&#xd;&gt;K&#%d;0b&#%d
<%s--><%s?><i-bPDFa3 QP6EHfCf4EGrcx·_MQpa0J7zD9hoYY4c̀7aLZYIwyCyuemFzohFrOFw1bRWZFj5np82hcQDDUdi9qWIuiDX3XDaDhvTCIazkhZ·s67l‿̀SX_NdwqtikUMAmD9GUXd-tcmtAUdCZ2srgd9uIpu·J8qweùkICAzbmSqLMSoI·t6-·x-tyERek8Uq̀moiCwU2:='%s' B8ò:_e7vCciAm-Y·C1W._J̀KXJlg_iDzvE06DOHII6g_-bg̀aoYAWYWWyRch_Tn5=' C&amp;ZpW&#%d;N&Amp;&#xFFFFFFFFFFFF;&#x800;DEEJ6jn&#x1F;W/7J&quot;&#xfffd;O&lt;/IJG&#x20;YY1rd/qL&#x1;X95Qw3Lq&#%d;0HFKbjeB .w&#xff;FE2BwZDMJl&#x10000000000000000;&#%d;jI&amp;bc&#%d;:KKp&#xffffffffffff;9d&quot;&amp;Ohj&amp;u&#x110000;a&Kcunf;pVFecjc&amp2;DwZoj&gt;&#xFFFFFFFFFFFF;&m:HoCPnsRwQeArM.aacabad5aadbaaew:_K7xmKq6I9UXZaKZQHnjKV9XH6PzWVnvb1Ml_enkeH:NX4oY_J.N8bLIVN3dgpVS4p0QqLQQZDjv7m_qTjYks0ca1XRaKHZnJ:y8dy:YlCRx9dSD9cha7.pA2SXamfyabAccbdrbBdNaaccdoabDbcdd1bvbmcod.bod6dYdxcwd1dPabnabyaadfcqdnc4cqcGdwd0aadcc_c6ccdsbPb5c-aaabdNc;c&lt;&amp;c&quot;a&gt;&#xA;&#%d;n&quot;&amp;aA&#x10FFFF;&#%d;f&lt;&amp;vafa&#x8;&quot;&#x0;ay&gt;b&#%d
<%s> cannot be a second root node after <%s> on line %d.
<%s?> cannot be a second root node after <%s> on line %d.
Bad control character 0x%x not allowed by XML standard.
Bad control character 0x%x under parent <%s> on line %d not allowed by XML standard.
Character entity '%s' not terminated under parent <%s> on line %d.
Duplicate attribute '%s' in element %s on line %d.
Early EOF in comment node on line %d.
Entity '%s' not supported under parent <%s> on line %d.
Mismatched close tag </%s> under parent <%s> on line %d.
Missing close tag </%s> under parent <%s> on line %d.
XML does not start with '%s' (saw '%s').
```

Every message here is a parser branch already visited. Any message mentioning a
limit ("too long", "too deep", "EOF") marks a boundary: generate that construct
at each length around where the message starts appearing.

Use your knowledge of XML to reason about what a conforming parser must reject
that is absent from this list, and construct documents that trigger it.

### Grammar production coverage: 27/27

Never produced by any iteration:
```
(none -- full coverage)
```

### Nesting depth distribution

```
{
  "0": 164,
  "1": 229,
  "16+": 82,
  "2-3": 13,
  "4-7": 4,
  "8-15": 8
}
```
Deepest document generated: 5000

### Document size

```
{
  "min": 3,
  "max": 45009,
  "mean": 2381.8,
  "median": 711.0
}
```

### Slowest documents

```
    11.9 ms  len=45004  depth=5000 parsed_clean
    10.7 ms  len=35014  depth=5000 parsed_clean
     9.7 ms  len=45004  depth=5000 parsed_clean
```

### Crashes found

None yet. Sanitizers are active and a known real bug is detected by this pipeline, so the absence is real, not a detection failure.

## What to do

1. **Follow the directive at the top of this prompt.** It changes each iteration
   so that successive strategies explore different regions.
2. **Sweep the boundary dimensions.** This is the primary objective and the one
   most likely to produce a crash.
3. **Hold all three class minimums at once.** Check the mixture before you
   change weights.
4. **Place defects deep inside valid documents**, so the parser reaches them.
5. **Earn marginal diagnostics.** Aim for at least 3 messages absent from the
   list above.
6. Keep everything that is working. This is a revision, not a rewrite.

Output the complete revised module as one fenced ```python block.
