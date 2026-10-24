from hypothesis import strategies as st

NAME = "mxml_grammar_fuzzer"

DESCRIPTION = (
    "Generates XML-ish documents targeting Mini-XML (mxml) v4.0.4. Threads "
    "element names through open and close tags so nesting is usually "
    "well-formed, then deliberately produces three flavors of input: "
    "well-formed documents (about half), structurally-wrong near-miss "
    "documents (mismatched tags, unknown entities, multiple roots, empty "
    "element names, no root at all), and byte-hostile documents (raw "
    "control characters, truncated constructs, byte-order marks, broken "
    "UTF-8, embedded NUL, lying encoding declarations). Covers unquoted "
    "attributes, non-ASCII names, DOCTYPE swallowing, duplicate attributes "
    "and extreme numeric character references along the way."
)

# --------------------------------------------------------------------------
# Basic alphabets
# --------------------------------------------------------------------------

NAME_START_ASCII = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_:"
NAME_CHAR_ASCII_EXTRA = "-.0123456789"

# Non-ASCII name-start code points: a mix of ones the grammar itself allows
# and ones the grammar omits but mxml accepts anyway (x_name_nonascii).
NONASCII_NAME_STARTS = [
    0x00C0, 0x00E9, 0x0100, 0x0391, 0x03B1,  # parser-only extra ranges
    0x2070, 0x2100, 0x2C00, 0x3005, 0xF900,  # grammar-legal ranges
]

TEXT_ALPHABET = (
    "abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,!?-_\t\n"
)

SAFE_INNER_ALPHABET = (
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ."
)

# Control characters, excluding tab/lf/cr which are legal XML whitespace.
CONTROL_CHARS = [chr(c) for c in list(range(0x00, 0x09)) + [0x0B, 0x0C] + list(range(0x0E, 0x20))]

NAMED_ENTITIES = ["amp", "lt", "gt", "quot"]
UNSUPPORTED_ENTITY_NAMES = ["apos", "nbsp", "copy", "foo", "unknown123", "AMP"]


def _raw_byte(b):
    # Surrogateescape convention: a lone surrogate DC80..DCFF stands in for
    # a raw byte 0x80..0xFF that a downstream encode('utf-8', 'surrogateescape'
    # or 'surrogatepass') step turns back into that exact invalid-UTF-8 byte.
    return chr(0xDC00 + b)


# --------------------------------------------------------------------------
# Leaf building blocks
# --------------------------------------------------------------------------

def plain_text(min_size, max_size):
    return st.text(alphabet=TEXT_ALPHABET, min_size=min_size, max_size=max_size)


def sea_ws():
    return st.text(alphabet=" \t\r\n", min_size=1, max_size=6)


def safe_text(min_size, max_size):
    return st.text(alphabet=SAFE_INNER_ALPHABET, min_size=min_size, max_size=max_size)


@st.composite
def xml_name(draw):
    if draw(st.integers(0, 19)) == 0:
        cp = draw(st.sampled_from(NONASCII_NAME_STARTS))
        start = chr(cp)
    else:
        start = draw(st.sampled_from(NAME_START_ASCII))
    tail_len = draw(st.integers(0, 6))
    tail = draw(
        st.text(alphabet=NAME_START_ASCII + NAME_CHAR_ASCII_EXTRA, min_size=tail_len, max_size=tail_len)
    )
    return start + tail


def entity_ref_valid():
    return st.sampled_from(NAMED_ENTITIES).map(lambda n: "&" + n + ";")


def entity_ref_unsupported():
    return st.sampled_from(UNSUPPORTED_ENTITY_NAMES).map(lambda n: "&" + n + ";")


def char_ref_dec_valid():
    return st.sampled_from([65, 97, 0x20AC, 0x1F600, 0x100, 9, 32]).map(lambda n: "&#" + str(n) + ";")


def char_ref_dec_extreme():
    return st.sampled_from([0, 1, 0xFFFFFFFF, 999999999999, 0x110000]).map(lambda n: "&#" + str(n) + ";")


def char_ref_hex_valid():
    return st.sampled_from(["41", "61", "20AC", "1F600", "100"]).map(lambda h: "&#x" + h + ";")


def char_ref_hex_extreme():
    return st.sampled_from(["0", "FFFFFFFFFFFF", "110000", "D800"]).map(lambda h: "&#x" + h + ";")


def attr_value_text():
    return st.one_of(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .-", max_size=10),
        entity_ref_valid(),
        char_ref_dec_valid(),
        char_ref_hex_valid(),
    )


@st.composite
def attribute_list(draw):
    n = draw(st.integers(0, 4))
    attrs = []
    names_used = []
    for _ in range(n):
        if names_used and draw(st.integers(0, 9)) == 0:
            name = draw(st.sampled_from(names_used))  # duplicate attribute name
        else:
            name = draw(xml_name())
            names_used.append(name)
        style = draw(st.integers(0, 9))
        value = draw(attr_value_text())
        if style < 4:
            attrs.append(name + '="' + value + '"')
        elif style < 8:
            attrs.append(name + "='" + value + "'")
        else:
            token = draw(
                st.text(alphabet=NAME_START_ASCII + NAME_CHAR_ASCII_EXTRA, min_size=0, max_size=6)
            )
            attrs.append(name + "=" + token)  # x_attribute_unquoted
    return "".join(" " + a for a in attrs)


def cdata_piece():
    return safe_text(0, 10).map(lambda t: "<![CDATA[" + t + "]]>")


def comment_piece():
    return safe_text(0, 10).map(lambda t: "<!--" + t + "-->")


def pi_piece():
    return st.tuples(xml_name(), safe_text(0, 8)).map(lambda t: "<?" + t[0] + " " + t[1] + "?>")


def leaf_content_piece():
    return st.one_of(
        plain_text(1, 12),
        sea_ws(),
        entity_ref_valid(),
        char_ref_dec_valid(),
        char_ref_hex_valid(),
        char_ref_dec_extreme(),
        char_ref_hex_extreme(),
        cdata_piece(),
        comment_piece(),
        pi_piece(),
    )


# --------------------------------------------------------------------------
# Recursive element structure. Each element carries its own name so open
# and close tags always agree by construction; nesting depth is left to
# Hypothesis via st.recursive rather than hand-unrolled.
# --------------------------------------------------------------------------

@st.composite
def _leaf_element(draw):
    name = draw(xml_name())
    attrs = draw(attribute_list())
    if draw(st.booleans()):
        xml = "<" + name + attrs + "/>"
        return {"xml": xml, "name": name, "paired": False}
    pieces = draw(st.lists(leaf_content_piece(), min_size=0, max_size=3))
    xml = "<" + name + attrs + ">" + "".join(pieces) + "</" + name + ">"
    return {"xml": xml, "name": name, "paired": True}


def _extend_element(children):
    @st.composite
    def build(draw):
        name = draw(xml_name())
        attrs = draw(attribute_list())
        n_pieces = draw(st.integers(0, 4))
        pieces = []
        for _ in range(n_pieces):
            if draw(st.integers(0, 2)) == 0:
                child = draw(children)
                pieces.append(child["xml"])
            else:
                pieces.append(draw(leaf_content_piece()))
        xml = "<" + name + attrs + ">" + "".join(pieces) + "</" + name + ">"
        return {"xml": xml, "name": name, "paired": True}

    return build()


element_recursive = st.recursive(_leaf_element(), _extend_element, max_leaves=8)


# --------------------------------------------------------------------------
# Prolog, DOCTYPE, misc
# --------------------------------------------------------------------------

@st.composite
def prolog_strategy(draw):
    if draw(st.integers(0, 9)) == 0:
        return "<?xml?>"  # parser accepts missing space
    attrs = ['version="' + draw(st.sampled_from(["1.0", "1.1", "2.0"])) + '"']
    if draw(st.booleans()):
        enc = draw(st.sampled_from(["UTF-8", "UTF-16", "ISO-8859-1", "utf-8", "ASCII"]))
        q = '"' if draw(st.booleans()) else "'"
        attrs.append("encoding=" + q + enc + q)
    if draw(st.integers(0, 4)) == 0:
        attrs.append('standalone="' + draw(st.sampled_from(["yes", "no"])) + '"')
    return "<?xml " + " ".join(attrs) + "?>"


def prolog_maybe():
    return st.one_of(st.just(""), prolog_strategy())


def doctype_piece():
    return st.sampled_from(
        [
            "<!DOCTYPE root>",
            "<!DOCTYPE r [<!ELEMENT r EMPTY>]>",
            '<!DOCTYPE note SYSTEM "note.dtd">',
        ]
    )


def misc_piece():
    return st.one_of(comment_piece(), pi_piece(), sea_ws())


# --------------------------------------------------------------------------
# well_formed
# --------------------------------------------------------------------------

@st.composite
def well_formed_document(draw):
    parts = []
    if draw(st.integers(0, 4)) != 0:
        parts.append(draw(prolog_strategy()))
    if draw(st.integers(0, 9)) == 0:
        parts.append(draw(doctype_piece()))
    parts.extend(draw(st.lists(misc_piece(), max_size=3)))
    root = draw(element_recursive)
    parts.append(root["xml"])
    parts.extend(draw(st.lists(misc_piece(), max_size=2)))
    return "".join(parts)


# --------------------------------------------------------------------------
# near_miss: XML-shaped but structurally wrong
# --------------------------------------------------------------------------

@st.composite
def near_miss_document(draw):
    kind = draw(
        st.sampled_from(
            ["mismatched_tags", "unknown_entity", "multiple_roots", "empty_elem_name", "rootless"]
        )
    )
    head = draw(prolog_maybe())

    if kind == "mismatched_tags":
        el = draw(element_recursive.filter(lambda e: e["paired"]))
        xml = el["xml"]
        close_tag = "</" + el["name"] + ">"
        idx = xml.rfind(close_tag)
        bad_name = el["name"] + "_x"
        xml = xml[:idx] + "</" + bad_name + ">" + xml[idx + len(close_tag):]
        return head + xml

    if kind == "unknown_entity":
        el = draw(element_recursive)
        bad_ent = draw(entity_ref_unsupported())
        xml = el["xml"]
        gt = xml.find(">")
        return head + xml[: gt + 1] + bad_ent + xml[gt + 1:]

    if kind == "multiple_roots":
        el1 = draw(element_recursive)
        el2 = draw(element_recursive)
        return head + el1["xml"] + el2["xml"]

    if kind == "empty_elem_name":
        if draw(st.booleans()):
            return head + "< />"
        return head + "<></>"

    # rootless: misc only, no element at all
    parts = draw(st.lists(misc_piece(), min_size=1, max_size=4))
    return head + "".join(parts)


# --------------------------------------------------------------------------
# byte_hostile: hostile at the byte / encoding level
# --------------------------------------------------------------------------

def utf16_bom_pair():
    return st.sampled_from([_raw_byte(0xFF) + _raw_byte(0xFE), _raw_byte(0xFE) + _raw_byte(0xFF)])


def truncated_multibyte():
    return st.sampled_from(
        [
            _raw_byte(0xE2),
            _raw_byte(0xE2) + _raw_byte(0x82),
            _raw_byte(0xF0) + _raw_byte(0x9F),
        ]
    )


def lone_continuation_byte():
    return st.sampled_from([_raw_byte(0x80), _raw_byte(0xBF), _raw_byte(0x81)])


def overlong_encoding():
    return st.sampled_from(
        [
            _raw_byte(0xC0) + _raw_byte(0xAF),
            _raw_byte(0xE0) + _raw_byte(0x80) + _raw_byte(0xAF),
        ]
    )


@st.composite
def unterminated_construct(draw):
    name = draw(xml_name())
    text = draw(safe_text(0, 8))
    choice = draw(st.integers(0, 5))
    if choice == 0:
        return "<!-- " + text
    if choice == 1:
        return "<![CDATA[" + text
    if choice == 2:
        return "<?" + name + " " + text
    if choice == 3:
        return "<" + name + ' a="' + text
    if choice == 4:
        return "<" + name
    return "<" + name + "><" + name + "2>"


@st.composite
def byte_hostile_document(draw):
    kind = draw(
        st.sampled_from(
            [
                "bom_utf8",
                "bom_utf16_odd",
                "truncated_multibyte",
                "lone_continuation",
                "overlong",
                "control_char",
                "embedded_nul",
                "unterminated",
                "encoding_mismatch",
            ]
        )
    )

    if kind == "unterminated":
        return draw(unterminated_construct())

    shell = draw(element_recursive)
    xml = shell["xml"]
    gt = xml.find(">")

    if kind == "bom_utf8":
        return "\ufeff" + draw(prolog_maybe()) + xml

    if kind == "bom_utf16_odd":
        bom = draw(utf16_bom_pair())
        return bom + "A" + xml  # BOM plus one stray byte breaks 16-bit alignment

    if kind == "truncated_multibyte":
        bad = draw(truncated_multibyte())
        return xml[: gt + 1] + bad + xml[gt + 1:]

    if kind == "lone_continuation":
        bad = draw(lone_continuation_byte())
        return xml[: gt + 1] + bad + xml[gt + 1:]

    if kind == "overlong":
        bad = draw(overlong_encoding())
        return xml[: gt + 1] + bad + xml[gt + 1:]

    if kind == "control_char":
        bad = draw(st.sampled_from(CONTROL_CHARS))
        return xml[: gt + 1] + bad + xml[gt + 1:]

    if kind == "embedded_nul":
        return xml[: gt + 1] + "\x00" + xml[gt + 1:]

    # encoding_mismatch: declared encoding contradicts an actual raw byte
    enc = draw(st.sampled_from(["UTF-16", "ISO-8859-1", "UTF-32", "Shift_JIS", "UTF-8"]))
    prolog = '<?xml version="1.0" encoding="' + enc + '"?>'
    bad_byte = draw(st.sampled_from([_raw_byte(0xE9), _raw_byte(0xFF), _raw_byte(0xC3)]))
    xml2 = xml[: gt + 1] + bad_byte + xml[gt + 1:]
    return prolog + xml2


# --------------------------------------------------------------------------
# Top level mixture: ~50% well_formed, ~25% near_miss, ~25% byte_hostile
# --------------------------------------------------------------------------

def documents():
    return st.one_of(
        well_formed_document(),
        well_formed_document(),
        near_miss_document(),
        byte_hostile_document(),
    )
