from hypothesis import strategies as st

NAME = "mxml_boundary_fuzzer"
DESCRIPTION = (
    "Generates XML documents for the Mini-XML (mxml) parser. This "
    "iteration's directive is corrupt-in-place: instead of only building "
    "malformed structure from scratch, it now also takes a well-formed "
    "or deeply nested base document and edits it in place, either at a "
    "structural anchor (mangling a close tag name, stripping an entity's "
    "semicolon, renaming a named entity, pushing a character reference "
    "out of range, stripping an attribute's value) or blindly (flip, "
    "delete, insert a raw byte or NUL, duplicate a chunk) at a position "
    "scaled to document length. The near-miss generator is reweighted "
    "so the six violation classes the parser's classifier actually "
    "recognizes (mismatched close tag, named entity outside amp/lt/gt/"
    "quot, entity missing its semicolon, out-of-range or zero character "
    "reference, attribute with no value, second root element) dominate "
    "its draws, since the prior mixture undershot near_miss badly. New "
    "structural-defect constructs probe things absent from the "
    "diagnostics list so far: an XML declaration not at the start of "
    "the document, a repeated XML declaration, a name starting with a "
    "disallowed character, a raw '<' inside an attribute value, a "
    "DOCTYPE after the root element, a second DOCTYPE, and trailing "
    "content after the root closes. Attribute count and attribute value "
    "length each get a dedicated probe that assigns every attribute a "
    "unique name, so a large count is not silently cut short by an "
    "early duplicate-attribute rejection before the boundary is "
    "reached. Name length, attribute count, entity name length and "
    "depth boundary lists all gained a dense window around the largest "
    "value the last run actually reached, plus one step beyond it. "
    "Byte-hostile and the rest of the near-miss defects from prior "
    "iterations (unterminated comments/CDATA/PI/attribute values, "
    "doubled hyphens, ']]>' in chardata, reserved 'xml' PI targets, "
    "BOM/invalid UTF-8/NUL/control chars/bad encoding declarations, "
    "DOCTYPE entity expansion) are kept as-is."
)

NAME_LENGTHS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 17, 31, 32, 33,
                63, 64, 65, 99, 100, 101, 127, 128, 129, 199, 200, 201,
                254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264,
                265, 300, 380, 381, 382, 383, 384, 385, 386, 387, 388,
                389, 390, 400, 450, 511, 512, 513, 514, 520, 600]
NAME_LENGTHS_TYPICAL = [1, 2, 3, 4, 5, 8, 16, 32, 64, 100, 128, 199, 256]

ATTR_VALUE_LENGTHS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 15, 16,
                       17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255,
                       256, 257, 511, 512, 513, 1023, 1024, 1025, 2047,
                       2048, 2049, 4096]

ATTR_COUNTS = [0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 60, 61,
               62, 63, 64, 65, 66, 67, 68, 99, 100, 101, 127, 128, 129,
               130, 131, 132, 140, 142, 144, 146, 148, 149, 150, 151,
               152, 154, 156, 158, 160, 192, 224, 255, 256, 257, 258,
               300, 384, 512, 600, 768, 1024]
ATTR_COUNTS_TYPICAL = [0, 1, 2, 3, 4, 7, 8, 16, 32]

ATTR_COUNT_DENSE = [0, 1, 2, 3, 4, 5, 6, 7, 8, 16, 32, 64, 100, 120,
                     128, 140, 145, 148, 149, 150, 151, 152, 155, 160,
                     192, 224, 255, 256, 257, 300, 384, 450, 500, 511,
                     512, 513, 600, 700, 768, 1000, 1024]

CONTENT_LENGTHS = [0, 1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64,
                    65, 127, 128, 129, 255, 256, 257, 511, 512, 513,
                    1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097]
CONTENT_LENGTHS_TYPICAL = [0, 1, 2, 3, 7, 8, 16, 32, 64, 128, 255, 256]

ENTITY_NAME_LENGTHS_LOW = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 17, 18,
                            19, 20, 21, 22, 23, 24, 25, 31, 32, 33, 60,
                            61, 62, 63, 64, 65, 66, 67, 68, 69, 70]
ENTITY_NAME_LENGTHS_HIGH = [80, 96, 100, 127, 128, 129, 150, 199, 200,
                             201, 255, 256, 257, 511, 512, 513, 514,
                             768, 1000, 1024, 2048]

SAFE_CHARREF_VALUES = [1, 8, 9, 10, 13, 32, 0x41, 0x7E, 0x80, 0xFF,
                        0x100, 0x7FF, 0x800, 0xFFFD, 0x10000, 0x10FFFF]

INVALID_CHARREF_VALUES = [0, 1, 2, 5, 8, 11, 12, 14, 16, 31, 0xD800,
                           0xDBFF, 0xDC00, 0xDFFF, 0x110000, 0x111111,
                           0x7FFFFFFF, 0xFFFFFFFF, 0x100000000,
                           0xFFFFFFFFFFFFFFFF, 10 ** 18, 10 ** 20]

DEPTHS_VERY_DEEP = [64, 128, 256, 512, 1000, 1500, 2000, 2500, 3000,
                     3300, 3400, 3500, 3600, 3700, 4000, 4500, 4900,
                     4950, 5000, 5050, 5100, 5200, 5400]
EXTREME_OPEN_DEPTHS = [5000, 8000, 10000, 12000, 15000, 16000, 16500,
                        17000, 17500, 18000, 19000, 21000]
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


def _bulk_value_lengths(n):
    if n <= 16:
        return [0, 8, 16, 32, 64, 128, 256, 512, 1024, 2048]
    if n <= 32:
        return [0, 8, 16, 32, 64, 128, 256, 512, 1024]
    if n <= 64:
        return [0, 8, 16, 32, 64, 128, 256, 512]
    if n <= 128:
        return [0, 8, 16, 32, 64, 128, 256]
    if n <= 258:
        return [0, 4, 8, 16, 32, 64, 128]
    return [0, 4, 8, 16, 32, 64]


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
    value_lengths = _bulk_value_lengths(n) if bulk else ATTR_VALUE_LENGTHS
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


@st.composite
def attr_count_probe(draw):
    n = draw(st.sampled_from(ATTR_COUNT_DENSE))
    ename = draw(xml_name(lengths=[1, 2, 3, 4, 8]))
    vlen = draw(st.sampled_from([0, 1, 4, 8, 16]))
    parts = ["a" + str(i) + '="' + ("v" * vlen) + '"' for i in range(n)]
    attrs = (" " + " ".join(parts)) if parts else ""
    return "<" + ename + attrs + "/>"


@st.composite
def attr_value_len_probe(draw):
    length = draw(st.sampled_from(ATTR_VALUE_LENGTHS))
    ename = draw(xml_name(lengths=[1, 2, 3]))
    aname = draw(xml_name(lengths=[1, 2, 3]))
    value = draw(st.text(alphabet=ATTR_VALUE_ALPHABET, min_size=length,
                          max_size=length))
    quote = draw(st.sampled_from(['"', "'"]))
    return "<" + ename + " " + aname + "=" + quote + value + quote + "/>"


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
    wide = draw(st.integers(min_value=0, max_value=5)) == 0
    name = draw(xml_name(lengths=NAME_LENGTHS if wide
                          else NAME_LENGTHS_TYPICAL))
    counts = ATTR_COUNTS if wide else ATTR_COUNTS_TYPICAL
    attrs = draw(attributes_list(counts=counts))
    if draw(st.booleans()):
        return "<" + name + attrs + "/>"
    inner = draw(st.one_of(chardata(lengths=CONTENT_LENGTHS_TYPICAL),
                            st.just("")))
    return "<" + name + attrs + ">" + inner + "</" + name + ">"


@st.composite
def _extend_element(draw, children):
    wide = draw(st.integers(min_value=0, max_value=5)) == 0
    name = draw(xml_name(lengths=NAME_LENGTHS if wide
                          else NAME_LENGTHS_TYPICAL))
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
    if depth <= 64 and draw(st.integers(min_value=0, max_value=7)) == 0:
        tag = draw(xml_name(lengths=[64, 100, 128, 199, 256, 261]))
    attrs = ""
    if depth <= 256 and draw(st.booleans()):
        attrs = ' k="v"'
    defect = "none"
    if allow_defect:
        defect = draw(st.sampled_from(["none", "none", "none", "mismatch",
                                        "bad_entity", "bad_charref",
                                        "noclose", "long_entity_name"]))
    inner = draw(st.sampled_from(["", "leaf", "x", "data"]))
    if defect == "bad_entity":
        inner = "&apos;"
    elif defect == "bad_charref":
        inner = "&#x110000;"
    elif defect == "long_entity_name":
        length = draw(st.sampled_from(ENTITY_NAME_LENGTHS_HIGH))
        name = draw(st.text(alphabet="abcdefghijklmnopqrstuvwxyz",
                             min_size=length, max_size=length))
        inner = "&" + name + ";"
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
def deep_open_extreme(draw):
    depth = draw(st.sampled_from(EXTREME_OPEN_DEPTHS))
    tag = draw(st.sampled_from(["a", "b", "x"]))
    if draw(st.booleans()):
        long_name = draw(xml_name(lengths=[256, 300, 384, 512]))
        return ("<" + tag + ">") * (depth - 1) + "<" + long_name + ">"
    return ("<" + tag + ">") * depth


@st.composite
def _wrap_shell(draw):
    depth = draw(st.sampled_from(SHELL_DEPTHS))
    tags = [draw(xml_name(lengths=[1, 2, 3, 4])) for _ in range(depth)]
    open_part = "".join("<" + t + ">" for t in tags)
    close_part = "".join("</" + t + ">" for t in reversed(tags))
    return open_part, close_part


@st.composite
def entity_length_probe(draw):
    pool = draw(st.sampled_from([ENTITY_NAME_LENGTHS_LOW,
                                  ENTITY_NAME_LENGTHS_HIGH]))
    length = draw(st.sampled_from(pool))
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
def dtd_entity_valid(draw):
    root = draw(xml_name(lengths=[1, 2, 3, 4]))
    kind = draw(st.sampled_from(["simple", "long_value", "exponential"]))
    if kind == "simple":
        ename = draw(xml_name(lengths=[1, 2, 3, 8, 16]))
        val = draw(attr_value(lengths=[0, 1, 4, 16, 64]))
        decl = "<!ENTITY " + ename + ' "' + val + '">'
        use = "&" + ename + ";"
    elif kind == "long_value":
        ename = draw(xml_name(lengths=[32, 63, 64, 65, 128, 256]))
        length = draw(st.sampled_from([256, 512, 1024, 2048]))
        val = draw(st.text(alphabet=ATTR_VALUE_ALPHABET, min_size=length,
                            max_size=length))
        decl = "<!ENTITY " + ename + ' "' + val + '">'
        use = "&" + ename + ";"
    else:
        n = draw(st.integers(min_value=3, max_value=10))
        base = draw(st.sampled_from(["x", "lol", "aa"]))
        parts = ["<!ENTITY " + base + '0 "data">']
        for i in range(1, n):
            prev = base + str(i - 1)
            val = "&" + prev + ";&" + prev + ";"
            parts.append("<!ENTITY " + base + str(i) + ' "' + val + '">')
        decl = "".join(parts)
        use = "&" + base + str(n - 1) + ";"
    return ("<!DOCTYPE " + root + " [" + decl + "]>" +
            "<" + root + ">" + use + "</" + root + ">")


@st.composite
def dtd_entity_recursive(draw):
    root = draw(xml_name(lengths=[1, 2, 3]))
    if draw(st.booleans()):
        ename = draw(xml_name(lengths=[1, 2, 3]))
        decl = "<!ENTITY " + ename + ' "&' + ename + ';">'
        use = "&" + ename + ";"
    else:
        e1 = draw(xml_name(lengths=[1, 2]))
        e2 = draw(xml_name(lengths=[1, 2]))
        if e2 == e1:
            e2 = e2 + "z"
        decl = ("<!ENTITY " + e1 + ' "&' + e2 + ';">' +
                "<!ENTITY " + e2 + ' "&' + e1 + ';">')
        use = "&" + e1 + ";"
    return ("<!DOCTYPE " + root + " [" + decl + "]>" +
            "<" + root + ">" + use + "</" + root + ">")


@st.composite
def structural_defect(draw):
    kind = draw(st.sampled_from([
        "xml_decl_not_at_start", "xml_decl_repeated", "bad_name_start",
        "raw_lt_in_attr", "doctype_after_root", "trailing_garbage",
        "double_doctype"]))
    root = draw(xml_name(lengths=[1, 2, 3]))
    if kind == "xml_decl_not_at_start":
        pad = draw(st.sampled_from([" ", "\n", "\ufeff", "<!--x-->"]))
        return pad + '<?xml version="1.0"?><' + root + "/>"
    if kind == "xml_decl_repeated":
        return ('<?xml version="1.0"?><?xml version="1.0"?><' +
                root + "/>")
    if kind == "bad_name_start":
        bad = draw(st.sampled_from(["1", "-", ".", "#", "%", "@"]))
        return "<" + bad + root + "/>"
    if kind == "raw_lt_in_attr":
        aname = draw(xml_name(lengths=[1, 2, 3]))
        return "<" + root + " " + aname + '="<"/>'
    if kind == "doctype_after_root":
        return "<" + root + "/><!DOCTYPE " + root + ">"
    if kind == "trailing_garbage":
        tail = draw(st.sampled_from(["stray", "x", "123", ")))"]))
        return "<" + root + "/>" + tail
    return ("<!DOCTYPE " + root + "><!DOCTYPE " + root + "><" +
            root + "/>")


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
                                       "emptyname", "rootless",
                                       "dtd_entity"]))
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
    elif root_kind == "dtd_entity":
        pieces.append(draw(dtd_entity_valid()))
    else:
        pieces.append(draw(element_strategy))
    for _ in range(draw(st.integers(min_value=0, max_value=2))):
        pieces.append(draw(misc_item()))
    return "".join(pieces)


@st.composite
def truncated_document(draw):
    doc = draw(well_formed())
    if len(doc) < 2:
        return "<a"
    frac = draw(st.sampled_from([0.1, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99]))
    cut = max(1, int(len(doc) * frac))
    return doc[:cut]


@st.composite
def near_miss(draw):
    kind = draw(st.sampled_from([
        "mismatched_tag", "mismatched_tag",
        "bad_entity_name", "bad_entity_name",
        "entity_no_semi", "entity_no_semi",
        "bad_charref", "bad_charref",
        "attr_no_value", "attr_no_value",
        "second_root", "second_root",
        "entity_length_probe", "entity_length_probe", "entity_length_probe",
        "structural_defect", "structural_defect",
        "deep_open_defect", "deep_open_defect",
        "empty_attr_name", "deep_defect", "unterminated",
        "comment_double_hyphen", "cdata_end_in_chardata",
        "reserved_pi_target", "dtd_entity_recursive", "truncated"]))
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
                                     "&Lt;", "&copy;"]))
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
    if kind == "structural_defect":
        return draw(structural_defect())
    if kind == "deep_open_defect":
        return draw(deep_open_extreme())
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
    if kind == "dtd_entity_recursive":
        return draw(dtd_entity_recursive())
    if kind == "truncated":
        return draw(truncated_document())
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


@st.composite
def corrupt_in_place(draw):
    base_kind = draw(st.sampled_from(["well_formed", "well_formed",
                                       "deep", "combo"]))
    if base_kind == "well_formed":
        doc = draw(well_formed())
    elif base_kind == "deep":
        doc = draw(deep_chain(False))
    else:
        doc = draw(combo_boundary())
    op = draw(st.sampled_from([
        "mangle_close_tag", "strip_entity_semi", "rename_entity",
        "corrupt_charref_digit", "strip_attr_value", "flip_random_char",
        "delete_random_range", "insert_raw_byte", "insert_nul",
        "duplicate_chunk"]))
    if op == "mangle_close_tag":
        idx = doc.rfind("</")
        if idx == -1:
            return doc
        end = doc.find(">", idx)
        if end == -1:
            return doc
        name_start = idx + 2
        if end <= name_start:
            return doc
        cut = draw(st.integers(min_value=name_start, max_value=end - 1))
        action = draw(st.sampled_from(["delete", "append", "replace"]))
        if action == "delete":
            return doc[:cut] + doc[cut + 1:]
        if action == "append":
            extra = draw(st.sampled_from("xzq9_"))
            return doc[:end] + extra + doc[end:]
        repl = draw(st.sampled_from("xzq9_"))
        return doc[:cut] + repl + doc[cut + 1:]
    if op == "strip_entity_semi":
        amp = doc.find("&")
        if amp == -1:
            return doc
        semi = doc.find(";", amp)
        if semi == -1:
            return doc
        return doc[:semi] + doc[semi + 1:]
    if op == "rename_entity":
        amp = doc.find("&")
        while amp != -1 and doc[amp:amp + 2] == "&#":
            amp = doc.find("&", amp + 1)
        if amp == -1:
            return doc
        semi = doc.find(";", amp)
        if semi == -1 or semi - amp > 10:
            return doc
        newname = draw(st.sampled_from(["copy", "reg", "nbsp", "zzz",
                                         "Amp", "xx"]))
        return doc[:amp + 1] + newname + doc[semi:]
    if op == "corrupt_charref_digit":
        idx = doc.find("&#")
        if idx == -1:
            return doc
        semi = doc.find(";", idx)
        if semi == -1:
            return doc
        newval = draw(st.sampled_from(["x110000", "0", "xD800",
                                        "4294967296"]))
        return doc[:idx + 2] + newval + doc[semi:]
    if op == "strip_attr_value":
        eq = doc.find('="')
        alt = doc.find("='")
        if eq == -1 or (alt != -1 and alt < eq):
            eq = alt
        if eq == -1:
            return doc
        quote = doc[eq + 1]
        end_q = doc.find(quote, eq + 2)
        if end_q == -1:
            return doc
        return doc[:eq] + doc[end_q + 1:]
    if op == "flip_random_char":
        if not doc:
            return doc
        frac = draw(st.sampled_from([0.0, 0.1, 0.25, 0.5, 0.75, 0.9,
                                      0.99]))
        pos = min(len(doc) - 1, int(len(doc) * frac))
        repl = draw(st.sampled_from("<>&\"'=/"))
        return doc[:pos] + repl + doc[pos + 1:]
    if op == "delete_random_range":
        if not doc:
            return doc
        frac = draw(st.sampled_from([0.0, 0.1, 0.25, 0.5, 0.75, 0.9]))
        pos = min(len(doc) - 1, int(len(doc) * frac))
        n = draw(st.sampled_from([1, 2, 3, 5, 8]))
        return doc[:pos] + doc[pos + n:]
    if op == "insert_raw_byte":
        frac = draw(st.sampled_from([0.0, 0.25, 0.5, 0.75, 1.0]))
        pos = min(len(doc), int(len(doc) * frac))
        b = draw(st.sampled_from([0x80, 0xFF, 0xC0, 0xFE, 0xF8]))
        return doc[:pos] + _raw_byte(b) + doc[pos:]
    if op == "insert_nul":
        frac = draw(st.sampled_from([0.0, 0.25, 0.5, 0.75, 1.0]))
        pos = min(len(doc), int(len(doc) * frac))
        return doc[:pos] + "\x00" + doc[pos:]
    if not doc:
        return doc
    frac = draw(st.sampled_from([0.0, 0.25, 0.5, 0.75]))
    pos = min(len(doc) - 1, int(len(doc) * frac))
    n = draw(st.sampled_from([1, 2, 4, 8, 16, 32]))
    chunk = doc[pos:pos + n]
    return doc[:pos] + chunk + chunk + doc[pos:]


def documents():
    return st.one_of(*(
        [well_formed()] * 8 +
        [near_miss()] * 10 +
        [byte_hostile()] * 7 +
        [corrupt_in_place()] * 8 +
        [attr_count_probe()] * 2 +
        [attr_value_len_probe()] * 2
    ))
