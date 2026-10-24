from hypothesis import strategies as st
import string

NAME = "mxml_boundary_fuzzer"
DESCRIPTION = (
    "Generates XML documents targeting Mini-XML (mxml) v4.0.4. Threads a "
    "single chosen name through matching open/close tags, sweeps dense "
    "boundaries for name length, attribute count, attribute value length, "
    "content length, nesting depth and character-reference values, and "
    "mixes in near-miss (mismatched tags, unsupported entities, truncated "
    "markup) and byte-hostile constructs (BOM, invalid UTF-8, embedded NUL, "
    "control characters, contradictory encoding) most of which are planted "
    "deep inside an otherwise well-formed nested document."
)

# ---------------------------------------------------------------- pools ----

ASCII_NAME_START = list(string.ascii_letters) + ["_", ":"]
ASCII_NAME_EXTRA = list(string.digits) + ["-", "."]
NONASCII_START_CP = [
    0x00E9, 0x03B1, 0x0100, 0x00C0, 0x00FF, 0x0170, 0x02FF,
    0x0370, 0x0400, 0x1FFF, 0x2070, 0x2100, 0x218F,
    0x2C00, 0x2D00, 0x2FEF, 0x3001, 0x4E2D, 0xD7FF,
    0xF900, 0xFDCF, 0xFDF0, 0xFFFD,
]
NAME_START_POOL = ASCII_NAME_START + [chr(c) for c in NONASCII_START_CP]
NAME_EXTRA_CP = [0x00B7, 0x0300, 0x036F, 0x203F, 0x2040]
NAME_CHAR_POOL = NAME_START_POOL + ASCII_NAME_EXTRA + [chr(c) for c in NAME_EXTRA_CP]

CHARDATA_POOL = list(
    "abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,!?_"
)

NAMED_ENTITIES = ["amp", "lt", "gt", "quot"]
UNSUPPORTED_ENTITY_NAMES = ["apos", "nbsp", "copy", "reg", "AMP", "Amp"]
CONTROL_CHARS = [chr(c) for c in [0x01, 0x02, 0x07, 0x08, 0x0B, 0x0C, 0x0E, 0x1F]]

NAME_LENGTHS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 17, 31, 32, 33,
                63, 64, 65, 99, 100, 101, 127, 128, 129, 199, 200, 201, 255, 256, 257]
SMALL_NAME_LENGTHS = [1, 2, 3, 5, 8, 16]
ATTR_VALUE_LENGTHS = [0, 1, 2, 3, 4, 5, 10, 50, 100, 127, 128, 129, 255, 256, 257,
                       511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097]
SMALL_ATTR_VALUE_LENGTHS = [0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 127, 128]
ATTR_COUNTS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 17, 31, 32, 33,
               63, 64, 65, 99, 100, 101, 127, 128, 150, 200]
DEPTHS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 17, 31, 32, 33, 63, 64, 65,
          99, 100, 101, 127, 128, 129, 199, 200, 201, 255, 256, 300, 500, 750,
          1000, 1500, 2000, 3000, 4000, 6000]
SHALLOW_DEPTHS = [0, 1, 2, 3, 5, 8, 16, 32, 64, 128]
CONTENT_LENGTHS = [0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65,
                    127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025,
                    2047, 2048, 2049]
SMALL_CONTENT_LENGTHS = [0, 1, 2, 4, 8, 16, 32, 64]
ENTITY_NAME_LENGTHS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 16, 20, 24, 28,
                        31, 32, 33, 40, 48, 56, 63, 64, 65, 72, 80, 96, 100, 110,
                        120, 127, 128, 129, 150, 192, 200, 255, 256, 257, 300, 400, 512]
BENIGN_CHARREF_VALUES = [0x1, 0x20, 0x41, 0x7E, 0x7F, 0x80, 0xA0, 0xFF, 0x100,
                          0x7FF, 0x800, 0x1000, 0xFFFD, 0xFFFF, 0x10000, 0x10FFFF]
OUT_OF_RANGE_CHARREF_VALUES = [0, 0x110000, 0xD800, 0xDC00, 0xDFFF, 0xFFFFFFFF,
                                0x100000000, 0xFFFFFFFFFFFFFFFF, 0x10000000000000000]


def raw_bytes(*bs):
    # PEP-383 surrogateescape convention: bytes >=0x80 become lone low
    # surrogates so an eventual s.encode('utf-8','surrogateescape') round
    # trips to the exact (possibly invalid) byte sequence requested.
    return "".join(chr(0xDC00 + b) if b >= 0x80 else chr(b) for b in bs)


# ------------------------------------------------------------ terminals ---

@st.composite
def name_of_length(draw, n):
    if n <= 0:
        return ""
    first = draw(st.sampled_from(NAME_START_POOL))
    if n == 1:
        return first
    rest = draw(st.lists(st.sampled_from(NAME_CHAR_POOL), min_size=n - 1, max_size=n - 1))
    return first + "".join(rest)


@st.composite
def chardata_of_length(draw, n):
    if n <= 0:
        return ""
    chars = draw(st.lists(st.sampled_from(CHARDATA_POOL), min_size=n, max_size=n))
    return "".join(chars)


@st.composite
def attr_value_of_length(draw, n, quote):
    if n <= 0:
        return ""
    pool = [c for c in CHARDATA_POOL if c != quote]
    chars = draw(st.lists(st.sampled_from(pool), min_size=n, max_size=n))
    return "".join(chars)


def synth_entity_name(n):
    return "e" * n


@st.composite
def content_tokens(draw, n_tokens):
    tokens = []
    for _ in range(n_tokens):
        kind = draw(st.sampled_from(["text", "entity", "charref_dec", "charref_hex"]))
        if kind == "text":
            tokens.append(draw(chardata_of_length(draw(st.sampled_from(SMALL_CONTENT_LENGTHS)))))
        elif kind == "entity":
            tokens.append("&{};".format(draw(st.sampled_from(NAMED_ENTITIES))))
        elif kind == "charref_dec":
            tokens.append("&#{};".format(draw(st.sampled_from(BENIGN_CHARREF_VALUES))))
        else:
            tokens.append("&#x{:X};".format(draw(st.sampled_from(BENIGN_CHARREF_VALUES))))
    return "".join(tokens)


@st.composite
def prolog_str(draw):
    variant = draw(st.sampled_from(["none", "plain", "nospace", "with_encoding"]))
    if variant == "none":
        return ""
    if variant == "nospace":
        return "<?xml?>"
    if variant == "plain":
        return '<?xml version="1.0"?>'
    enc = draw(st.sampled_from(["UTF-8", "utf-8", "ISO-8859-1", "us-ascii"]))
    return '<?xml version="1.0" encoding="{}"?>'.format(enc)


@st.composite
def misc_str(draw):
    n = draw(st.integers(min_value=0, max_value=2))
    parts = []
    for _ in range(n):
        kind = draw(st.sampled_from(["ws", "comment", "pi"]))
        if kind == "ws":
            parts.append(draw(st.sampled_from([" ", "\n", "\t", "  \n\t", "\r\n"])))
        elif kind == "comment":
            payload = draw(chardata_of_length(draw(st.sampled_from([0, 1, 5, 20]))))
            parts.append("<!--{}-->".format(payload))
        else:
            tgt = draw(name_of_length(draw(st.sampled_from([1, 2, 5]))))
            parts.append("<?{}?>".format(tgt))
    return "".join(parts)


# ------------------------------------------------------------- nesting ----

@st.composite
def spine_document(draw, depth=None):
    if depth is None:
        depth = draw(st.sampled_from(DEPTHS))
    use_short = depth > 50
    content_pool = SMALL_CONTENT_LENGTHS if depth > 500 else CONTENT_LENGTHS
    leaf_kind = draw(st.sampled_from(["text", "entity", "charref", "cdata", "comment", "pi", "empty"]))
    if leaf_kind == "text":
        leaf = draw(chardata_of_length(draw(st.sampled_from(content_pool))))
    elif leaf_kind == "entity":
        leaf = "&{};".format(draw(st.sampled_from(NAMED_ENTITIES)))
    elif leaf_kind == "charref":
        v = draw(st.sampled_from(BENIGN_CHARREF_VALUES))
        leaf = "&#{};".format(v) if draw(st.booleans()) else "&#x{:X};".format(v)
    elif leaf_kind == "cdata":
        payload = draw(chardata_of_length(draw(st.sampled_from([0, 1, 2, 8, 16, 64]))))
        leaf = "<![CDATA[{}]]>".format(payload)
    elif leaf_kind == "comment":
        payload = draw(chardata_of_length(draw(st.sampled_from([0, 1, 2, 8, 16, 64]))))
        leaf = "<!--{}-->".format(payload)
    elif leaf_kind == "pi":
        target = draw(name_of_length(draw(st.sampled_from([1, 2, 3, 8]))))
        leaf = "<?{}?>".format(target)
    else:
        leaf = ""
    body = leaf
    add_attr_roll = depth < 200
    for _ in range(depth):
        if use_short:
            nm = draw(st.sampled_from(["a", "b", "c", "n"]))
        else:
            nm = draw(name_of_length(draw(st.sampled_from(SMALL_NAME_LENGTHS))))
        attrs = ""
        if add_attr_roll and draw(st.integers(min_value=0, max_value=9)) == 0:
            an = draw(name_of_length(draw(st.sampled_from([1, 2, 3]))))
            q = draw(st.sampled_from(['"', "'"]))
            av = draw(attr_value_of_length(draw(st.sampled_from(SMALL_ATTR_VALUE_LENGTHS)), q))
            attrs = " {}={}{}{}".format(an, q, av, q)
        body = "<{0}{1}>{2}</{0}>".format(nm, attrs, body)
    return body


# ------------------------------------------------------------ documents ---

@st.composite
def well_formed_document(draw):
    variant = draw(st.sampled_from([
        "spine", "spine", "attrs_sweep", "name_sweep", "content_sweep",
        "rootless", "doctype_ok", "unquoted_attr",
    ]))
    if variant == "rootless":
        payload = draw(chardata_of_length(draw(st.sampled_from([0, 1, 5, 20]))))
        return "<!--{}-->".format(payload)
    if variant == "doctype_ok":
        root = draw(name_of_length(draw(st.sampled_from(SMALL_NAME_LENGTHS))))
        internal = draw(st.sampled_from(["", " [<!ELEMENT r EMPTY>]", ' SYSTEM "foo.dtd"']))
        doctype = "<!DOCTYPE {}{}>".format(root, internal)
        body = draw(spine_document())
        return "{}{}{}".format(draw(prolog_str()), doctype, body)
    if variant == "unquoted_attr":
        name = draw(name_of_length(draw(st.sampled_from(SMALL_NAME_LENGTHS))))
        an = draw(name_of_length(draw(st.sampled_from([1, 2, 3]))))
        val = draw(st.sampled_from(["1", "0", "123", "abc", "x", "true", "42"]))
        return "{}<{} {}={}/>".format(draw(prolog_str()), name, an, val)
    if variant == "attrs_sweep":
        count = draw(st.sampled_from(ATTR_COUNTS))
        name = draw(name_of_length(draw(st.sampled_from(SMALL_NAME_LENGTHS))))
        max_val_len = max(1, 4000 // max(count, 1))
        candidates = [l for l in ATTR_VALUE_LENGTHS if l <= max_val_len] or [0, 1]
        parts = []
        for _ in range(count):
            an = draw(name_of_length(draw(st.sampled_from(SMALL_NAME_LENGTHS))))
            q = draw(st.sampled_from(['"', "'"]))
            av = draw(attr_value_of_length(draw(st.sampled_from(candidates)), q))
            parts.append(" {}={}{}{}".format(an, q, av, q))
        content = draw(content_tokens(draw(st.integers(min_value=0, max_value=3))))
        return "{}<{}{}>{}</{}>".format(draw(prolog_str()), name, "".join(parts), content, name)
    if variant == "name_sweep":
        nlen = draw(st.sampled_from(NAME_LENGTHS))
        if nlen == 0:
            return "{}< />".format(draw(prolog_str()))
        name = draw(name_of_length(nlen))
        if draw(st.booleans()):
            return "{}<{}/>".format(draw(prolog_str()), name)
        content = draw(content_tokens(draw(st.integers(min_value=0, max_value=2))))
        return "{}<{}>{}</{}>".format(draw(prolog_str()), name, content, name)
    if variant == "content_sweep":
        name = draw(name_of_length(draw(st.sampled_from(SMALL_NAME_LENGTHS))))
        text = draw(chardata_of_length(draw(st.sampled_from(CONTENT_LENGTHS))))
        return "{}<{}>{}</{}>".format(draw(prolog_str()), name, text, name)
    # spine: organic nesting through the full depth sweep with mixed leaf content
    return "{}{}{}{}".format(draw(prolog_str()), draw(misc_str()), draw(spine_document()), draw(misc_str()))


@st.composite
def near_miss_document(draw):
    variant = draw(st.sampled_from([
        "mismatched_tag", "mismatched_deep", "unsupported_entity", "truncated",
        "multiple_roots", "bad_quote", "unterminated_comment", "unterminated_cdata",
        "charref_out_of_range", "digit_start_name", "duplicate_attr", "bad_attr_syntax",
    ]))
    if variant == "mismatched_tag":
        a = draw(name_of_length(draw(st.sampled_from(SMALL_NAME_LENGTHS))))
        b = draw(name_of_length(draw(st.sampled_from(SMALL_NAME_LENGTHS))))
        content = draw(content_tokens(draw(st.integers(min_value=0, max_value=2))))
        return "<{}>{}</{}>".format(a, content, b)
    if variant == "mismatched_deep":
        depth = draw(st.sampled_from(SHALLOW_DEPTHS))
        inner = draw(name_of_length(3))
        wrong = draw(name_of_length(3))
        body = "<{0}>x</{1}>".format(inner, wrong)
        for _ in range(depth):
            nm = draw(st.sampled_from(["a", "b", "c"]))
            body = "<{0}>{1}</{0}>".format(nm, body)
        return body
    if variant == "unsupported_entity":
        kind = draw(st.sampled_from(["known_bad", "length_sweep"]))
        if kind == "known_bad":
            ename = draw(st.sampled_from(UNSUPPORTED_ENTITY_NAMES))
        else:
            ename = synth_entity_name(draw(st.sampled_from(ENTITY_NAME_LENGTHS)))
        depth = draw(st.sampled_from(SHALLOW_DEPTHS))
        nm = draw(name_of_length(3))
        body = "&{};".format(ename)
        for _ in range(depth):
            body = "<{0}>{1}</{0}>".format(nm, body)
        return body
    if variant == "truncated":
        full = draw(spine_document(depth=draw(st.sampled_from(SHALLOW_DEPTHS))))
        cut = draw(st.sampled_from([0.3, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95]))
        idx = max(1, int(len(full) * cut))
        return full[:idx]
    if variant == "multiple_roots":
        a = draw(name_of_length(3))
        b = draw(name_of_length(3))
        return "<{0}/><{1}/>".format(a, b)
    if variant == "bad_quote":
        name = draw(name_of_length(3))
        an = draw(name_of_length(2))
        if draw(st.booleans()):
            return '<{} {}="value/>'.format(name, an)
        return "<{0} {1}='value\">".format(name, an)
    if variant == "unterminated_comment":
        depth = draw(st.sampled_from(SHALLOW_DEPTHS))
        nm = draw(name_of_length(3))
        body = "<!-- never closed"
        for _ in range(depth):
            body = "<{0}>{1}</{0}>".format(nm, body)
        return body
    if variant == "unterminated_cdata":
        depth = draw(st.sampled_from(SHALLOW_DEPTHS))
        nm = draw(name_of_length(3))
        body = "<![CDATA[ never closed"
        for _ in range(depth):
            body = "<{0}>{1}</{0}>".format(nm, body)
        return body
    if variant == "charref_out_of_range":
        v = draw(st.sampled_from(OUT_OF_RANGE_CHARREF_VALUES))
        nm = draw(name_of_length(3))
        ref = "&#x{:X};".format(v) if draw(st.booleans()) else "&#{};".format(v)
        return "<{0}>{1}</{0}>".format(nm, ref)
    if variant == "digit_start_name":
        digit = draw(st.sampled_from(list(string.digits)))
        rest = draw(name_of_length(draw(st.sampled_from([0, 1, 2, 5]))))
        return "<{}{}/>".format(digit, rest)
    if variant == "duplicate_attr":
        name = draw(name_of_length(3))
        an = draw(name_of_length(3))
        v1 = draw(attr_value_of_length(draw(st.sampled_from([0, 1, 5])), '"'))
        v2 = draw(attr_value_of_length(draw(st.sampled_from([0, 1, 5])), '"'))
        return '<{0} {1}="{2}" {1}="{3}"/>'.format(name, an, v1, v2)
    # bad_attr_syntax
    name = draw(name_of_length(3))
    an = draw(name_of_length(3))
    return '<{} {} "value"/>'.format(name, an)


@st.composite
def byte_hostile_document(draw):
    variant = draw(st.sampled_from([
        "bom_prefix", "utf16_bom_odd", "truncated_utf8_attr", "truncated_utf8_text",
        "lone_continuation", "overlong_encoding", "embedded_nul_attr", "embedded_nul_text",
        "control_char_attr", "control_char_text", "contradictory_encoding", "invalid_utf8_standalone",
    ]))
    if variant == "bom_prefix":
        return "\ufeff" + draw(spine_document())
    if variant == "utf16_bom_odd":
        n_extra = draw(st.sampled_from([1, 3, 5]))
        extra = raw_bytes(*([0x00] * n_extra))
        return raw_bytes(0xFF, 0xFE) + extra + draw(spine_document())
    if variant == "contradictory_encoding":
        enc = draw(st.sampled_from(["UTF-16", "UTF-32", "ISO-2022-JP", "EBCDIC-CP-US"]))
        return '<?xml version="1.0" encoding="{}"?>'.format(enc) + draw(spine_document())
    if variant == "invalid_utf8_standalone":
        chunks = draw(st.lists(st.sampled_from([
            raw_bytes(0x80), raw_bytes(0xC0, 0xAF), raw_bytes(0xE2, 0x82), raw_bytes(0xFF),
        ]), min_size=1, max_size=5))
        return "".join(chunks)

    depth = draw(st.sampled_from(DEPTHS))
    if variant in ("truncated_utf8_attr", "truncated_utf8_text"):
        defect = raw_bytes(0xE2, 0x82)  # start of a 3-byte sequence, final byte missing
    elif variant == "lone_continuation":
        defect = raw_bytes(draw(st.sampled_from([0x80, 0x9F, 0xBF])))
    elif variant == "overlong_encoding":
        defect = raw_bytes(0xC0, 0xAF)  # overlong encoding of '/'
    elif variant in ("embedded_nul_attr", "embedded_nul_text"):
        defect = "\x00"
    else:
        defect = draw(st.sampled_from(CONTROL_CHARS))

    name = draw(name_of_length(draw(st.sampled_from([1, 2, 3]))))
    prefix = draw(chardata_of_length(draw(st.sampled_from([0, 4, 16, 64]))))
    suffix = draw(chardata_of_length(draw(st.sampled_from([0, 4, 16]))))
    if variant.endswith("_attr"):
        an = draw(name_of_length(2))
        leaf = '<{} {}="{}{}{}"/>'.format(name, an, prefix, defect, suffix)
    else:
        leaf = "<{0}>{1}{2}{3}</{0}>".format(name, prefix, defect, suffix)
    body = leaf
    for _ in range(depth):
        nm = draw(st.sampled_from(["a", "b", "c"]))
        body = "<{0}>{1}</{0}>".format(nm, body)
    return draw(prolog_str()) + body


def documents():
    strat = st.one_of(
        *([well_formed_document()] * 8 +
          [near_miss_document()] * 5 +
          [byte_hostile_document()] * 7)
    )
    return strat.map(lambda s: s if len(s) <= 60000 else s[:60000])
