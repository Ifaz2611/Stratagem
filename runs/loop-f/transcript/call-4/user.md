# Task

Revise the Hypothesis strategy below using the measured results of its last run.

**Directive for this iteration: combine-extremes**

## Current strategy (iteration 2)

```python
from hypothesis import strategies as st

NAME = "mxml_boundary_fuzzer"
DESCRIPTION = (
    "Generates XML documents for the Mini-XML (mxml) parser. Most "
    "documents are well-formed and sweep boundary lengths: name length, "
    "attribute value length, attribute count, nesting depth, and entity "
    "name length, each swept densely around the largest value the prior "
    "run actually reached (attribute value length in particular had a "
    "gap at 4-6 bytes that is now filled). A smaller share are near-miss "
    "documents built only from constructs mxml actually rejects "
    "(mismatched tags, unsupported entities, out-of-range character "
    "references, unterminated comments/CDATA/PI/attribute values, "
    "doubled hyphens in comments, a literal ']]>' in plain character "
    "data, reserved 'xml' processing-instruction targets), and another "
    "share are byte-hostile (BOM, invalid UTF-8, embedded NUL, control "
    "characters, contradictory or garbage encoding declarations). "
    "Defects are placed deep inside otherwise-valid nested shells rather "
    "than as standalone garbage, so the parser walks in before it fails."
)

NAME_LENGTHS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 17, 31, 32, 33,
                63, 64, 65, 99, 100, 101, 127, 128, 129, 199, 200, 201,
                254, 255, 256, 257, 258, 259, 260, 261]
NAME_LENGTHS_TYPICAL = [1, 2, 3, 4, 5, 8, 16, 32, 64, 100, 128, 199, 256]

ATTR_VALUE_LENGTHS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 15, 16,
                       17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255,
                       256, 257, 511, 512, 513, 1023, 1024, 1025, 2047,
                       2048, 2049]

ATTR_COUNTS = [0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 60, 61,
               62, 63, 64, 65, 66, 67, 68, 99, 100, 101, 127, 128, 129,
               255, 256, 257, 258]
ATTR_COUNTS_TYPICAL = [0, 1, 2, 3, 4, 7, 8, 16, 32]

CONTENT_LENGTHS = [0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64,
                    65, 127, 128, 129, 255, 256, 257, 511, 512, 513,
                    1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097]
CONTENT_LENGTHS_TYPICAL = [0, 1, 2, 3, 7, 8, 16, 32, 64, 128, 255, 256]

ENTITY_NAME_LENGTHS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 17, 18,
                        19, 20, 21, 22, 23, 24, 25, 31, 32, 33, 63, 64,
                        65, 66, 68, 70, 80, 96, 100, 127, 128, 129, 150,
                        199, 200, 201, 255, 256, 257, 511, 512, 513]

SAFE_CHARREF_VALUES = [1, 8, 9, 10, 13, 32, 0x41, 0x7E, 0x80, 0xFF,
                        0x100, 0x7FF, 0x800, 0xFFFD, 0x10000, 0x10FFFF]

INVALID_CHARREF_VALUES = [0, 1, 2, 5, 8, 11, 12, 14, 16, 31, 0xD800,
                           0xDBFF, 0xDC00, 0xDFFF, 0x110000, 0x111111,
                           0x7FFFFFFF, 0xFFFFFFFF, 0x100000000,
                           0xFFFFFFFFFFFFFFFF, 10 ** 18, 10 ** 20]

DEPTHS_VERY_DEEP = [64, 128, 256, 512, 1000, 1500, 2000, 2500, 3000,
                     3300, 3400, 3500, 3600, 3700, 4000, 4500, 5000]
SHELL_DEPTHS = [0, 1, 2, 3, 5, 8, 13, 21, 34, 55]

NAME_START_ASCII = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_:"
NAME_EXTRA_ASCII = "0123456789-."
NAME_NONASCII_START = ["\u00e9", "\u03b1", "\u0100", "\u00c0", "\u0370",
                        "\u2070", "\u3001", "\uf900"]
ATTR_VALUE_ALPHABET = ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR"
                        "STUVWXYZ0123456789 _-.,:;!")
CHARDATA_ALPHABET = ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                      "0123456789 .,!?\t")
COMMENT_ALPHABET = "abcdefghijklmnopqrstuvwxyz 0123456789.,"
CDATA_ALPHABET = "abcdefghijklmnopqrstuvwxyz 0123456789.,<&"
PI_ALPHABET = "abcdefghijklmnopqrstuvwxyz 0123456789=\"'"


def _raw_byte(b):
    return chr(0xDC00 + b)


@st.composite
def xml_name(draw, lengths=None):
    if lengths is None:
        lengths = NAME_LENGTHS
    length = draw(st.sampled_from(lengths))
    use_nonascii = draw(st.integers(min_value=0, max_value=9)) == 0
    if use_nonascii:
        first = draw(st.sampled_from(NAME_NONASCII_START))
    else:
        first = draw(st.sampled_from(NAME_START_ASCII))
    if length <= 1:
        return first
    rest_alphabet = NAME_START_ASCII + NAME_EXTRA_ASCII
    rest = draw(st.text(alphabet=rest_alphabet, min_size=length - 1,
                         max_size=length - 1))
    return first + rest


@st.composite
def attr_value(draw, lengths=None):
    if lengths is None:
        lengths = ATTR_VALUE_LENGTHS
    length = draw(st.sampled_from(lengths))
    if length == 0:
        return ""
    return draw(st.text(alphabet=ATTR_VALUE_ALPHABET, min_size=length,
                         max_size=length))


@st.composite
def chardata(draw, lengths=None):
    if lengths is None:
        lengths = CONTENT_LENGTHS
    length = draw(st.sampled_from(lengths))
    if length == 0:
        return ""
    return draw(st.text(alphabet=CHARDATA_ALPHABET, min_size=length,
                         max_size=length))


@st.composite
def attribute(draw, name_lengths=None, value_lengths=None,
              allow_unquoted=False):
    name = draw(xml_name(lengths=name_lengths))
    value = draw(attr_value(lengths=value_lengths))
    if (allow_unquoted and value and " " not in value and
            draw(st.integers(min_value=0, max_value=4)) == 0):
        return name + "=" + value
    quote = draw(st.sampled_from(['"', "'"]))
    return name + "=" + quote + value + quote


@st.composite
def attributes_list(draw, counts=None):
    if counts is None:
        counts = ATTR_COUNTS
    n = draw(st.sampled_from(counts))
    if n == 0:
        return ""
    bulk = n > 8
    name_lengths = [1, 2, 3, 4, 5, 8, 16] if bulk else NAME_LENGTHS
    value_lengths = ([0, 1, 2, 3, 4, 5, 6, 7, 8, 16, 32] if bulk
                      else ATTR_VALUE_LENGTHS)
    allow_unquoted = draw(st.booleans())
    attrs = []
    dup_name = None
    if n >= 2 and draw(st.integers(min_value=0, max_value=4)) == 0:
        dup_name = draw(xml_name(lengths=[1, 2, 3, 4]))
    for i in range(n):
        if dup_name is not None and i < 2:
            value = draw(attr_value(lengths=[0, 1, 2, 3, 4, 5, 6, 8]))
            quote = draw(st.sampled_from(['"', "'"]))
            attrs.append(dup_name + "=" + quote + value + quote)
        else:
            attrs.append(draw(attribute(name_lengths=name_lengths,
                                         value_lengths=value_lengths,
                                         allow_unquoted=allow_unquoted)))
    return " " + " ".join(attrs)


NAMED_ENTITY_STRATEGY = st.sampled_from(["&amp;", "&lt;", "&gt;", "&quot;"])


@st.composite
def charref_good(draw):
    val = draw(st.sampled_from(SAFE_CHARREF_VALUES))
    if draw(st.booleans()):
        return "&#" + str(val) + ";"
    return "&#x" + format(val, "X") + ";"


@st.composite
def charref_boundary(draw):
    val = draw(st.sampled_from(INVALID_CHARREF_VALUES))
    if draw(st.booleans()):
        return "&#" + str(val) + ";"
    return "&#x" + format(val, "X") + ";"


@st.composite
def cdata_section(draw):
    length = draw(st.sampled_from([0, 1, 2, 8, 16, 64, 255, 256]))
    body = draw(st.text(alphabet=CDATA_ALPHABET, min_size=length,
                         max_size=length))
    return "<![CDATA[" + body + "]]>"


@st.composite
def comment_section(draw):
    length = draw(st.sampled_from([0, 1, 2, 8, 16, 64, 255, 256]))
    body = draw(st.text(alphabet=COMMENT_ALPHABET, min_size=length,
                         max_size=length))
    return "<!--" + body + "-->"


@st.composite
def pi_section(draw):
    target = draw(xml_name(lengths=[1, 2, 3, 4, 8]))
    if target.lower() == "xml":
        target = "pit"
    length = draw(st.sampled_from([0, 1, 8, 64]))
    data = draw(st.text(alphabet=PI_ALPHABET, min_size=length,
                         max_size=length))
    sep = " " if data else ""
    return "<?" + target + sep + data + "?>"


@st.composite
def doctype_decl(draw):
    root = draw(xml_name(lengths=[1, 2, 3]))
    if draw(st.booleans()):
        return "<!DOCTYPE " + root + ">"
    return "<!DOCTYPE " + root + " [<!ELEMENT " + root + " EMPTY>]>"


@st.composite
def prolog_decl(draw):
    attrs = []
    if draw(st.booleans()):
        attrs.append('version="' +
                      draw(st.sampled_from(["1.0", "1.1"])) + '"')
    if draw(st.booleans()):
        enc = draw(st.sampled_from(["UTF-8", "utf-8", "ISO-8859-1",
                                     "US-ASCII"]))
        attrs.append('encoding="' + enc + '"')
    if draw(st.booleans()):
        attrs.append('standalone="' +
                      draw(st.sampled_from(["yes", "no"])) + '"')
    if attrs:
        return "<?xml " + " ".join(attrs) + "?>"
    space = draw(st.sampled_from([" ", ""]))
    return "<?xml" + space + "?>"


@st.composite
def whitespace_sea(draw):
    n = draw(st.integers(min_value=1, max_value=5))
    return draw(st.text(alphabet=" \t\n", min_size=n, max_size=n))


@st.composite
def misc_item(draw):
    return draw(st.one_of(comment_section(), pi_section(),
                           whitespace_sea()))


@st.composite
def leaf_element(draw):
    name = draw(xml_name(lengths=NAME_LENGTHS_TYPICAL))
    wide = draw(st.integers(min_value=0, max_value=5)) == 0
    counts = ATTR_COUNTS if wide else ATTR_COUNTS_TYPICAL
    attrs = draw(attributes_list(counts=counts))
    if draw(st.booleans()):
        return "<" + name + attrs + "/>"
    inner = draw(st.one_of(chardata(lengths=CONTENT_LENGTHS_TYPICAL),
                            st.just("")))
    return "<" + name + attrs + ">" + inner + "</" + name + ">"


@st.composite
def _extend_element(draw, children):
    name = draw(xml_name(lengths=NAME_LENGTHS_TYPICAL))
    wide = draw(st.integers(min_value=0, max_value=5)) == 0
    counts = ATTR_COUNTS if wide else ATTR_COUNTS_TYPICAL
    attrs = draw(attributes_list(counts=counts))
    pieces = []
    if draw(st.booleans()):
        pieces.append(draw(chardata(lengths=CONTENT_LENGTHS_TYPICAL)))
    n_children = draw(st.integers(min_value=1, max_value=3))
    for _ in range(n_children):
        kind = draw(st.sampled_from(["element", "element", "chardata",
                                      "entity", "charref", "cdata",
                                      "comment", "pi"]))
        if kind == "element":
            pieces.append(draw(children))
        elif kind == "chardata":
            pieces.append(draw(chardata(lengths=CONTENT_LENGTHS_TYPICAL)))
        elif kind == "entity":
            pieces.append(draw(NAMED_ENTITY_STRATEGY))
        elif kind == "charref":
            pieces.append(draw(charref_good()))
        elif kind == "cdata":
            pieces.append(draw(cdata_section()))
        elif kind == "comment":
            pieces.append(draw(comment_section()))
        else:
            pieces.append(draw(pi_section()))
        if draw(st.booleans()):
            pieces.append(draw(chardata(lengths=CONTENT_LENGTHS_TYPICAL)))
    content = "".join(pieces)
    return "<" + name + attrs + ">" + content + "</" + name + ">"


element_strategy = st.recursive(
    leaf_element(), lambda children: _extend_element(children),
    max_leaves=15)


@st.composite
def combo_boundary(draw):
    depth = draw(st.sampled_from([1, 2, 3, 5, 8, 13, 21, 34, 55]))
    tags = [draw(xml_name()) for _ in range(depth)]
    n_attr = draw(st.sampled_from(ATTR_COUNTS))
    attrs = draw(attributes_list(counts=[n_attr]))
    inner_name = draw(xml_name())
    content = draw(chardata())
    open_part = "".join("<" + t + ">" for t in tags)
    close_part = "".join("</" + t + ">" for t in reversed(tags))
    inner = ("<" + inner_name + attrs + ">" + content + "</" +
              inner_name + ">")
    return open_part + inner + close_part


@st.composite
def deep_chain(draw, allow_defect):
    depth = draw(st.sampled_from(DEPTHS_VERY_DEEP))
    tag = draw(st.sampled_from(["a", "b", "x", "n1", "el", "q9"]))
    attrs = ""
    if depth <= 256 and draw(st.booleans()):
        attrs = ' k="v"'
    defect = "none"
    if allow_defect:
        defect = draw(st.sampled_from(["none", "none", "none", "mismatch",
                                        "bad_entity", "bad_charref",
                                        "noclose"]))
    inner = draw(st.sampled_from(["", "leaf", "x", "data"]))
    if defect == "bad_entity":
        inner = "&apos;"
    elif defect == "bad_charref":
        inner = "&#x110000;"
    open_tag = "<" + tag + attrs + ">"
    close_tag = "</" + tag + ">"
    body = open_tag * depth + inner
    if defect == "noclose":
        body += close_tag * (depth - 1)
    elif defect == "mismatch":
        body += close_tag * (depth - 1) + "</" + tag + "z>"
    else:
        body += close_tag * depth
    return body


@st.composite
def _wrap_shell(draw):
    depth = draw(st.sampled_from(SHELL_DEPTHS))
    tags = [draw(xml_name(lengths=[1, 2, 3, 4])) for _ in range(depth)]
    open_part = "".join("<" + t + ">" for t in tags)
    close_part = "".join("</" + t + ">" for t in reversed(tags))
    return open_part, close_part


@st.composite
def entity_length_probe(draw):
    length = draw(st.sampled_from(ENTITY_NAME_LENGTHS))
    name = draw(st.text(alphabet="abcdefghijklmnopqrstuvwxyz",
                         min_size=length, max_size=length))
    if draw(st.booleans()):
        return "&" + name
    return "&" + name + ";"


@st.composite
def unterminated_construct(draw):
    kind = draw(st.sampled_from(["comment", "cdata", "pi", "attr_value",
                                  "tag_name", "doctype"]))
    s_open, _ = draw(_wrap_shell())
    if kind == "comment":
        body = draw(st.text(alphabet=COMMENT_ALPHABET, min_size=0,
                             max_size=32))
        return s_open + "<!--" + body
    if kind == "cdata":
        body = draw(st.text(alphabet=CDATA_ALPHABET, min_size=0,
                             max_size=32))
        return s_open + "<![CDATA[" + body
    if kind == "pi":
        target = draw(xml_name(lengths=[1, 2, 3, 4]))
        data = draw(st.text(alphabet=PI_ALPHABET, min_size=0,
                             max_size=16))
        return s_open + "<?" + target + " " + data
    if kind == "attr_value":
        ename = draw(xml_name(lengths=[1, 2, 3]))
        aname = draw(xml_name(lengths=[1, 2, 3]))
        value = draw(st.text(alphabet=ATTR_VALUE_ALPHABET, min_size=0,
                              max_size=32))
        quote = draw(st.sampled_from(['"', "'"]))
        return s_open + "<" + ename + " " + aname + "=" + quote + value
    if kind == "tag_name":
        partial = draw(st.text(alphabet=NAME_START_ASCII, min_size=1,
                                max_size=8))
        return s_open + "<" + partial
    data = draw(st.text(alphabet="abcdefghijklmnopqrstuvwxyz ",
                         min_size=0, max_size=16))
    return s_open + "<!DOCTYPE " + data


@st.composite
def comment_double_hyphen(draw):
    s_open, s_close = draw(_wrap_shell())
    pre = draw(st.text(alphabet=COMMENT_ALPHABET, min_size=0, max_size=16))
    post = draw(st.text(alphabet=COMMENT_ALPHABET, min_size=0, max_size=16))
    body = pre + "--" + post
    return s_open + "<!--" + body + "-->" + s_close


@st.composite
def cdata_end_in_chardata(draw):
    s_open, s_close = draw(_wrap_shell())
    name = draw(xml_name(lengths=[1, 2, 3]))
    pre = draw(st.text(alphabet=CHARDATA_ALPHABET, min_size=0, max_size=16))
    post = draw(st.text(alphabet=CHARDATA_ALPHABET, min_size=0, max_size=16))
    inner = "<" + name + ">" + pre + "]]>" + post + "</" + name + ">"
    return s_open + inner + s_close


@st.composite
def reserved_pi_target(draw):
    s_open, s_close = draw(_wrap_shell())
    target = draw(st.sampled_from(["xml", "XML", "Xml", "xML", "XmL",
                                    "xMl"]))
    data = draw(st.text(alphabet=PI_ALPHABET, min_size=0, max_size=16))
    return s_open + "<?" + target + " " + data + "?>" + s_close


@st.composite
def well_formed(draw):
    pieces = []
    if draw(st.integers(min_value=0, max_value=2)) == 0:
        pieces.append(draw(prolog_decl()))
    for _ in range(draw(st.integers(min_value=0, max_value=2))):
        pieces.append(draw(misc_item()))
    if draw(st.integers(min_value=0, max_value=9)) == 0:
        pieces.append(draw(doctype_decl()))
    root_kind = draw(st.sampled_from(["element", "element", "element",
                                       "deep", "deep", "combo", "combo",
                                       "emptyname", "rootless"]))
    if root_kind == "rootless":
        if not pieces:
            pieces.append(draw(comment_section()))
        return "".join(pieces)
    if root_kind == "emptyname":
        pieces.append("< />")
    elif root_kind == "deep":
        pieces.append(draw(deep_chain(False)))
    elif root_kind == "combo":
        pieces.append(draw(combo_boundary()))
    else:
        pieces.append(draw(element_strategy))
    for _ in range(draw(st.integers(min_value=0, max_value=2))):
        pieces.append(draw(misc_item()))
    return "".join(pieces)


@st.composite
def near_miss(draw):
    kind = draw(st.sampled_from([
        "mismatched_tag", "bad_entity_name", "entity_no_semi",
        "bad_charref", "attr_no_value", "second_root",
        "empty_attr_name", "deep_defect", "entity_length_probe",
        "entity_length_probe", "unterminated", "comment_double_hyphen",
        "cdata_end_in_chardata", "reserved_pi_target"]))
    if kind == "mismatched_tag":
        name1 = draw(xml_name(lengths=[1, 2, 3, 5, 8]))
        name2 = draw(xml_name(lengths=[1, 2, 3, 5, 8]))
        if name2 == name1:
            name2 = name2 + "z"
        inner = draw(chardata(lengths=[0, 1, 8]))
        s_open, s_close = draw(_wrap_shell())
        return (s_open + "<" + name1 + ">" + inner + "</" + name2 + ">" +
                s_close)
    if kind == "bad_entity_name":
        bad = draw(st.sampled_from(["&apos;", "&nbsp;", "&foo;", "&AMP;",
                                     "&Lt;"]))
        s_open, s_close = draw(_wrap_shell())
        return s_open + bad + s_close
    if kind == "entity_no_semi":
        bad = draw(st.sampled_from(["&amp", "&lt", "&gt", "&quot",
                                     "&#65", "&#x41"]))
        s_open, s_close = draw(_wrap_shell())
        return s_open + bad + " tail" + s_close
    if kind == "bad_charref":
        bad = draw(charref_boundary())
        s_open, s_close = draw(_wrap_shell())
        return s_open + bad + s_close
    if kind == "attr_no_value":
        aname = draw(xml_name(lengths=[1, 2, 3, 5]))
        ename = draw(xml_name(lengths=[1, 2, 3]))
        return "<" + ename + " " + aname + "/>"
    if kind == "second_root":
        e1 = draw(xml_name(lengths=[1, 2, 3]))
        e2 = draw(xml_name(lengths=[1, 2, 3]))
        return "<" + e1 + "/><" + e2 + "/>"
    if kind == "empty_attr_name":
        ename = draw(xml_name(lengths=[1, 2, 3]))
        value = draw(attr_value(lengths=[0, 1, 4]))
        return "<" + ename + ' ="' + value + '"/>'
    if kind == "deep_defect":
        return draw(deep_chain(True))
    if kind == "unterminated":
        return draw(unterminated_construct())
    if kind == "comment_double_hyphen":
        return draw(comment_double_hyphen())
    if kind == "cdata_end_in_chardata":
        return draw(cdata_end_in_chardata())
    if kind == "reserved_pi_target":
        return draw(reserved_pi_target())
    bad = draw(entity_length_probe())
    s_open, s_close = draw(_wrap_shell())
    return s_open + bad + s_close


@st.composite
def byte_hostile(draw):
    kind = draw(st.sampled_from(["utf8_bom", "utf16_bom_odd",
                                  "truncated_utf8", "lone_continuation",
                                  "overlong_encoding", "bad_encoding_decl",
                                  "embedded_nul", "control_char"]))
    s_open, s_close = draw(_wrap_shell())
    body = draw(chardata(lengths=[0, 1, 8, 64]))
    if kind == "utf8_bom":
        return "\ufeff" + s_open + body + s_close
    if kind == "utf16_bom_odd":
        return (_raw_byte(0xFF) + _raw_byte(0xFE) + _raw_byte(0x3C) +
                s_open + body + s_close)
    if kind == "truncated_utf8":
        lead = draw(st.sampled_from([0xE2, 0xF0, 0xC3, 0xE0]))
        cont = draw(st.sampled_from([0x82, 0x28, 0xA0]))
        bad = _raw_byte(lead) + _raw_byte(cont)
        return s_open + body + bad + body + s_close
    if kind == "lone_continuation":
        bad = _raw_byte(draw(st.sampled_from([0x80, 0x81, 0xBF, 0x90])))
        return s_open + body + bad + body + s_close
    if kind == "overlong_encoding":
        bad = draw(st.sampled_from([
            _raw_byte(0xC0) + _raw_byte(0x80),
            _raw_byte(0xC1) + _raw_byte(0xBF),
            _raw_byte(0xE0) + _raw_byte(0x80) + _raw_byte(0x80),
        ]))
        return s_open + body + bad + body + s_close
    if kind == "bad_encoding_decl":
        decl = draw(st.sampled_from([
            '<?xml version="1.0" encoding="UTF-16"?>',
            '<?xml version="1.0" encoding="US-ASCII"?>',
            '<?xml version="1.0" encoding="UTF-32"?>',
            '<?xml version="1.0" encoding=""?>',
            '<?xml version="1.0" encoding="X"?>',
            '<?xml version="1.0" encoding="' + ("Q" * 300) + '"?>',
        ]))
        return decl + s_open + "caf\u00e9" + body + s_close
    if kind == "embedded_nul":
        return s_open + body + "\x00" + body + s_close
    ctrl = chr(draw(st.sampled_from([0x01, 0x02, 0x07, 0x0B, 0x0C, 0x0E,
                                      0x1F])))
    return s_open + body + ctrl + body + s_close


def documents():
    return st.one_of(*([well_formed()] * 8 + [near_miss()] * 6 +
                        [byte_hostile()] * 6))

```

## Measured results over 500 generated documents

### Boundary coverage

This is the primary objective. Each row is what the last run actually reached.
A narrow range or a small number of distinct values means that dimension is not
being swept.

```
name_len             max=261      p90=254      p50=4        distinct values=15
attrs_per_element    max=128      p90=63       p50=0        distinct values=14
entity_name_len      max=63       p90=0        p50=0        distinct values=10
attr_value_len       max=3        p90=3        p50=0        distinct values=2
depth                max=5000     p90=55       p50=5        distinct values=26
```

For every dimension above: add 0, 1 and 2 if absent, then a dense sweep in a
window around the largest value already reached, then one step beyond it. Use
`st.sampled_from` on an explicit list, not a wide `st.integers`.

### Input class mixture, and acceptance within each class

```
byte_hostile   share= 36.0%  acceptance= 52.2%  n=180
near_miss      share= 19.0%  acceptance= 16.8%  n=95
well_formed    share= 45.0%  acceptance= 37.3%  n=225
```

Minimums, **all of which must hold at once**: `well_formed` >=40%,
`near_miss` >=20%, `byte_hostile` >=20%. Raising one by dropping another below
its minimum is worse than leaving both alone.

Overall acceptance: **38.8%** (target band 40-70%)

Note the acceptance rate *within* `byte_hostile`. If it is very low, those
documents are being rejected at the front door and are not reaching the parser.
The fix is not fewer of them; it is to place the defect deeper inside an
otherwise-valid document.

### Marginal progress: what THIS iteration found that no earlier one did

Repeating ground already covered by an earlier iteration counts for nothing.

```
new diagnostic templates this iteration : 1
  + Entity name too long under parent <%s> on line %d.
new grammar productions this iteration  : 0
```

**Target: at least 3 diagnostic templates that no previous iteration reached.**

### Diagnostics already reached by ANY iteration so far (13 total)

```
<%s--> cannot be a second root node after <%s> on line %d.
<%s> cannot be a second root node after <%s> on line %d.
<%s?> cannot be a second root node after <%s> on line %d.
Bad control character 0x%x not allowed by XML standard.
Character entity '%s' not terminated under parent <%s> on line %d.
Duplicate attribute '%s' in element %s on line %d.
Early EOF in comment node on line %d.
Entity '%s' not supported under parent <%s> on line %d.
Entity name too long under parent <%s> on line %d.
Mismatched close tag </%s> under parent <%s> on line %d.
Missing close tag </%s> under parent <%s> on line %d.
Missing value for attribute '%s' in element %s on line %d.
XML does not start with '%s' (saw '%s').
```

Every message here is a parser branch already visited. Any message mentioning a
limit ("too long", "too deep", "EOF") marks a boundary: generate that construct
at each length around where the message starts appearing.

Use your knowledge of XML to reason about what a conforming parser must reject
that is absent from this list, and construct documents that trigger it.

### Grammar production coverage: 25/27

Never produced by any iteration:
```
g_entity_named
x_unterminated
```

### Nesting depth distribution

```
{
  "0": 51,
  "1": 64,
  "16+": 137,
  "2-3": 70,
  "4-7": 93,
  "8-15": 85
}
```
Deepest document generated: 5000

### Document size

```
{
  "min": 1,
  "max": 45004,
  "mean": 2184.4,
  "median": 168.0
}
```

### Slowest documents

```
    11.2 ms  len=45004  depth=5000 parsed_clean
    10.2 ms  len=26222  depth=3700 parsed_clean
     9.8 ms  len=27009  depth=3000 parsed_clean
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
