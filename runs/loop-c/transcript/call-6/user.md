# Task

Revise the Hypothesis strategy below using the measured results of its last run.

**Directive for this iteration: deepen**

## Current strategy (iteration 4)

```python
"""
Hypothesis document generator for fuzzing a Mini-XML (mxml v4.0.4) parser
built with ASan/UBSan.

Iteration 4 ("diversify"): two things drove this revision, matching the
measured results from iteration 3's run of 500 documents.

1. The class-mixture fix did not work, and the failure is diagnostic in
   its own right. Iteration 3 replaced a contiguous three-band split of a
   single `st.integers(0, 99)` draw (which measured 55.4/8.6/36.0 against
   a 48/26/26 target) with a 100-entry label list interleaving
   well_formed/near_miss/byte_hostile as evenly as integer counts allow,
   then drew one index into that list via `st.sampled_from`. The theory
   was that spreading each category across many indices would dilute any
   positional bias. It measured 54.6/20.2/25.2 against a 40/33/27 nominal
   split -- *worse* than the target ratio, and in the same direction as
   iteration 2's failure. The reason: `st.sampled_from` over a list is
   still backed by a single bounded-integer draw under the hood, and the
   interleaving scheduler (a largest-remainder-style allocator biased
   toward the heaviest-weighted label early) put well_formed at *both*
   index 0 and index 99 of the list -- the two positions bounded-integer
   sampling favours. near_miss, which the scheduler never placed at
   either boundary, was starved almost exactly as much as well_formed was
   inflated (33 nominal -> 20.2 actual). Same root cause as iteration 2,
   wearing a different costume: never trust a single positional draw to
   be unbiased, no matter how the positions are laid out.

   The fix this time removes position from the picture entirely.
   `_weighted_choice` draws one independent uniform float per category
   and scores it as `u ** (1/weight)` (Efraimidis-Spirakis weighted
   sampling without replacement, applied to a single pick); the category
   with the highest score wins. Whatever bias Hypothesis's float sampling
   has, it is now applied identically and independently to all three
   categories -- there is no longer any "index 0" or "index 99" for one
   category to monopolise. Nominal weights are also rebalanced to
   42/31/27 (from 40/33/27): well_formed was *over* its own ~50% target
   in the measured run (54.6%) while near_miss was the only class to miss
   its floor (20.2% < 25%), so weight moves from well_formed to near_miss
   and byte_hostile keeps a small buffer above its floor too.

2. Diversify grammar-adjacent near-misses and byte-level attacks.
   Grammar production coverage is already 27/27 (full), so this iteration
   does not chase new productions; it chases new *diagnostics* by
   attacking well-formedness constraints and implementation-level edge
   cases no earlier iteration touched, all still built from the same
   recursive element/attribute machinery so depth stays Hypothesis-
   shrinkable rather than hand-unrolled.

   New near-miss constructs: an attribute on a closing tag; whitespace
   between "</" and the tag name; non-whitespace text stray in the
   prolog or epilog (outside the single root element); a processing
   instruction with an empty or all-whitespace target; a PI target
   starting with an illegal character; a bare "&;" or "&#;"/"&#x;" with
   no name/digits at all; an entity name starting with a digit; two
   DOCTYPE declarations before the root; an internal DTD subset holding
   a syntactically-broken <!ELEMENT>/<!ATTLIST> (trailing comma in a
   content model, an unrecognised attribute-type keyword, an
   unterminated parenthesis, a garbage content specifier); two
   attributes with no whitespace separating them; a lone closing tag
   with no matching open anywhere in the document; a CDATA section
   outside any element; a comment before the XML declaration (which
   must be the very first thing in the document); and mismatched-tag
   documents built around extreme name/attribute-value lengths straddling
   common buffer-size boundaries (63/64/65, 255/256/257, 1023/1024/1025,
   2047/2048/2049 bytes) to probe fixed-size-buffer handling in the C
   implementation while still guaranteeing rejection via a tag mismatch.

   New byte-hostile constructs: UTF-8 encodings of surrogate code points
   (0xED 0xA0..0xBF 0x80..0xBF, never valid UTF-8); a UTF-32 byte-order
   mark prefix; an overlong encoding of NUL itself (0xC0 0x80, "modified
   UTF-8" style, distinct from the existing overlong-but-nonzero cases);
   very long comment bodies, PI data and attribute values at the same
   buffer-boundary lengths used above, in isolation this time rather than
   coupled to a tag mismatch; and XML declarations whose encoding name is
   syntactically broken (empty, containing a space, or starting with a
   digit) rather than merely a truthful-looking lie about the encoding.

Produces a weighted mixture of:
  - well_formed documents (~42% nominal): valid XML-shaped input built
    with a recursive element grammar (bushy or, sometimes, a deep linear
    chain) where open/close tag names always match.
  - near_miss documents (~31% nominal): XML-shaped but structurally wrong
    (mismatched tags -- including deep and buffer-boundary-length ones,
    unsupported/recursive entities, bad char refs, multiple/zero roots,
    empty/illegal element or attribute names, stray declarations,
    reserved PI targets, malformed DOCTYPEs/DTD internal subsets and
    DOCTYPE/root mismatches, malformed XML declarations, illegal
    comments, stray CDATA terminators or CDATA outside any element, raw
    "<"/"&" in the wrong place, empty entity/PI-target/char-ref syntax,
    missing inter-attribute whitespace, stray prolog/epilog content).
  - byte_hostile documents (~27% nominal): hostile at the byte/encoding
    level (BOMs including UTF-32, truncated multi-byte UTF-8, lone
    continuation bytes, overlong encodings including overlong NUL,
    surrogate-code-point UTF-8, embedded NUL in several positions, raw
    control characters, unterminated constructs including deep
    unterminated chains, lying or malformed encoding declarations, long
    tokens at buffer-boundary lengths).
"""

from hypothesis import strategies as st
import string

NAME = "mxml_grammar_fuzzer"
DESCRIPTION = (
    "Recursive XML-shaped generator tuned to Mini-XML v4.0.4 quirks: "
    "matched-tag element trees (bushy or deep linear chains) with "
    "entities, char refs, CDATA, comments and PIs for the well-formed "
    "slice; a wide spread of structural near-misses (tag mismatch "
    "including buffer-boundary-length names, unsupported/recursive "
    "entities, bad numeric char refs, multiple/missing roots, "
    "empty/illegal names, stray declarations, reserved PI targets, "
    "malformed DOCTYPEs/DTD internal subsets, malformed XML "
    "declarations, illegal comments, stray CDATA, misplaced raw '<'/'&', "
    "empty entity/PI-target/char-ref syntax, missing attribute "
    "whitespace, stray prolog/epilog content, attributes on end tags); "
    "and byte-level hostility (BOMs including UTF-32, truncated/invalid "
    "UTF-8, surrogate-code-point UTF-8, overlong encodings including "
    "overlong NUL, embedded NUL, control characters, unterminated "
    "markup, malformed/lying encoding declarations, buffer-boundary-"
    "length tokens). Class dispatch draws one independent weighted key "
    "per category (Efraimidis-Spirakis sampling) rather than mapping a "
    "single bounded-integer draw through any label table, so positional/"
    "boundary bias in the underlying draw can no longer concentrate on "
    "whichever category happens to occupy a favoured slot."
)

# ---------------------------------------------------------------------------
# Names: widened past the grammar's NameStartChar to what mxml accepts.
# ---------------------------------------------------------------------------

_NAME_START_NONASCII_RANGES = [
    (0x00C0, 0x02FF),
    (0x0370, 0x1FFF),
    (0x2070, 0x218F),
    (0x2C00, 0x2FEF),
    (0x3001, 0xD7FF),
    (0xF900, 0xFDCF),
    (0xFDF0, 0xFFFD),
]

_NAME_CHAR_EXTRA_RANGES = [
    (0x0300, 0x036F),
    (0x203F, 0x2040),
]


def _chars_from_ranges(ranges):
    return st.one_of([st.integers(lo, hi).map(chr) for lo, hi in ranges])


_ascii_name_start = st.sampled_from(list(string.ascii_letters) + ["_", ":"])
_nonascii_name_start = _chars_from_ranges(_NAME_START_NONASCII_RANGES)

name_start_char = st.one_of(
    _ascii_name_start, _ascii_name_start, _ascii_name_start, _nonascii_name_start
)

name_char = st.one_of(
    name_start_char,
    st.sampled_from(list(string.digits) + ["-", ".", "\u00b7"]),
    _chars_from_ranges(_NAME_CHAR_EXTRA_RANGES),
)


@st.composite
def xml_name(draw, max_extra=8):
    start = draw(name_start_char)
    extra = draw(st.lists(name_char, max_size=max_extra))
    return start + "".join(extra)


# ---------------------------------------------------------------------------
# Entities, char refs, chardata, CDATA, comments, processing instructions.
# ---------------------------------------------------------------------------

def entity_ref_strategy():
    return st.sampled_from(["&amp;", "&lt;", "&gt;", "&quot;"])


def charref_strategy():
    # Restricted to legal XML characters so this feeds the well-formed
    # slice reliably; illegal / out-of-range values live in bad_charref_doc.
    valid = st.one_of(
        st.integers(min_value=0x20, max_value=0xD7FF),
        st.integers(min_value=0xE000, max_value=0xFFFD),
        st.integers(min_value=0x10000, max_value=0x10FFFF),
        st.sampled_from([0x09, 0x0A, 0x0D]),
    )
    dec = valid.map(lambda n: "&#%d;" % n)
    hexr = valid.map(lambda n: "&#x%X;" % n)
    return st.one_of(dec, hexr)


def chardata_strategy():
    ws = st.sampled_from([" ", "\t", "\n", "\r\n", "   ", " \n\t"])
    text = st.text(
        alphabet=st.characters(
            exclude_characters="<&", min_codepoint=0x20, max_codepoint=0xFFFF
        ),
        max_size=15,
    )
    return st.one_of(ws, text)


def cdata_strategy():
    body = st.text(
        alphabet=st.characters(exclude_characters="]", max_codepoint=0xFFFF),
        max_size=15,
    )
    return body.map(lambda s: "<![CDATA[%s]]>" % s)


def comment_strategy():
    body = st.text(
        alphabet=st.characters(exclude_characters="-", max_codepoint=0xFFFF),
        max_size=15,
    )
    return body.map(lambda s: "<!--%s-->" % s)


def pi_strategy():
    body = st.text(
        alphabet=st.characters(exclude_characters="?", max_codepoint=0xFFFF),
        max_size=12,
    )
    return st.builds(lambda t, b: "<?%s %s?>" % (t, b), xml_name(), body)


# ---------------------------------------------------------------------------
# Attributes: double/single quoted, unquoted (mxml-only extension), dups.
# ---------------------------------------------------------------------------

@st.composite
def attribute_strategy(draw):
    aname = draw(xml_name())
    style = draw(st.sampled_from(["dquot", "dquot", "squot", "squot", "unquoted"]))
    if style == "unquoted":
        value = draw(
            st.text(
                alphabet=st.characters(
                    exclude_characters=" \t\r\n<>" + "'" + '"' + "&",
                    min_codepoint=0x21,
                    max_codepoint=0x7E,
                ),
                min_size=1,
                max_size=8,
            )
        )
        return "%s=%s" % (aname, value)
    quote = '"' if style == "dquot" else "'"
    n = draw(st.integers(min_value=0, max_value=3))
    pieces = []
    for _ in range(n):
        pieces.append(
            draw(
                st.one_of(
                    st.text(
                        alphabet=st.characters(
                            exclude_characters="<&" + quote, max_codepoint=0xFFFF
                        ),
                        min_size=1,
                        max_size=6,
                    ),
                    entity_ref_strategy(),
                    charref_strategy(),
                )
            )
        )
    value = "".join(pieces)
    return "%s=%s%s%s" % (aname, quote, value, quote)


@st.composite
def attributes_list_strategy(draw):
    n = draw(st.integers(min_value=0, max_value=4))
    attrs = [draw(attribute_strategy()) for _ in range(n)]
    if attrs and draw(st.booleans()) and draw(st.booleans()):
        idx = draw(st.integers(min_value=0, max_value=len(attrs) - 1))
        dup_name = attrs[idx].split("=", 1)[0]
        new_val = draw(
            st.text(
                alphabet=st.characters(
                    exclude_characters="<&" + '"' + "'", max_codepoint=0x7E
                ),
                max_size=5,
            )
        )
        attrs.append('%s="%s"' % (dup_name, new_val))
    return attrs


def _render_attrs(attrs):
    return "".join(" " + a for a in attrs)


# ---------------------------------------------------------------------------
# Elements: recursive, name threaded through so open/close tags match.
# ---------------------------------------------------------------------------

def _make_self_closing(name, attrs):
    return "<%s%s/>" % (name, _render_attrs(attrs))


@st.composite
def _leaf_element(draw):
    name = draw(xml_name())
    attrs = draw(attributes_list_strategy())
    return _make_self_closing(name, attrs)


def _content_item(children):
    return st.one_of(
        chardata_strategy(),
        entity_ref_strategy(),
        charref_strategy(),
        cdata_strategy(),
        comment_strategy(),
        pi_strategy(),
        children,
    )


def _extend_element(children):
    @st.composite
    def _build(draw):
        name = draw(xml_name())
        attrs = draw(attributes_list_strategy())
        n_items = draw(st.integers(min_value=0, max_value=4))
        item_strategy = _content_item(children)
        parts = [draw(item_strategy) for _ in range(n_items)]
        return "<%s%s>%s</%s>" % (name, _render_attrs(attrs), "".join(parts), name)

    return _build()


element_strategy = st.recursive(_leaf_element(), _extend_element, max_leaves=16)


# ---------------------------------------------------------------------------
# Deep linear chains: exactly one child per level, no branching, so the
# recursion budget goes entirely into depth instead of breadth.
# ---------------------------------------------------------------------------

_deep_name_strategy = st.sampled_from(list("abcdefgh"))


@st.composite
def _deep_leaf(draw):
    name = draw(_deep_name_strategy)
    return "<%s/>" % name


def _deep_extend(children):
    @st.composite
    def _build(draw):
        name = draw(_deep_name_strategy)
        child = draw(children)
        return "<%s>%s</%s>" % (name, child, name)

    return _build()


deep_element_strategy = st.recursive(_deep_leaf(), _deep_extend, max_leaves=100)


@st.composite
def deep_mismatched_doc(draw):
    """A deep, otherwise well-formed chain whose outermost closing tag is
    corrupted, so the mismatch only surfaces after a full deep descent."""
    body = draw(deep_element_strategy)
    idx = body.rfind("</")
    if idx == -1:
        # Pure self-closing leaf; fall back to a simple shallow mismatch.
        name = draw(_deep_name_strategy)
        other = draw(_deep_name_strategy.filter(lambda c: c != name))
        return "<%s>%s</%s>" % (name, body, other)
    end = body.find(">", idx)
    if end == -1:
        end = len(body)
    alt = draw(_deep_name_strategy)
    return body[: idx + 2] + alt + body[end:]


def deep_unterminated_doc():
    """A long run of open tags that are never closed at all."""
    return st.lists(_deep_name_strategy, min_size=5, max_size=300).map(
        lambda names: "".join("<%s>" % nm for nm in names)
    )


# ---------------------------------------------------------------------------
# Prolog, DOCTYPE, misc, well-formed document.
# ---------------------------------------------------------------------------

@st.composite
def _full_prolog(draw):
    version = draw(st.sampled_from(["1.0", "1.0", "1.0", "1.1"]))
    parts = ['version="%s"' % version]
    if draw(st.booleans()):
        enc = draw(st.sampled_from(["UTF-8", "utf-8"]))
        parts.append('encoding="%s"' % enc)
    if draw(st.booleans()):
        sa = draw(st.sampled_from(["yes", "no"]))
        parts.append('standalone="%s"' % sa)
    return "<?xml " + " ".join(parts) + "?>"


def prolog_strategy():
    return st.one_of(st.just("<?xml?>"), _full_prolog())


def doctype_strategy():
    simple = xml_name().map(lambda n: "<!DOCTYPE %s>" % n)
    with_subset = xml_name().map(
        lambda n: "<!DOCTYPE %s [<!ELEMENT %s EMPTY>]>" % (n, n)
    )
    return st.one_of(simple, with_subset)


def misc_strategy():
    return st.one_of(
        comment_strategy(), pi_strategy(), st.sampled_from([" ", "\n", "\t\n", "  \n"])
    )


@st.composite
def well_formed_document(draw):
    parts = []
    if draw(st.booleans()):
        parts.append(draw(prolog_strategy()))
    if draw(st.integers(min_value=0, max_value=4)) == 0:
        parts.append(draw(doctype_strategy()))
    parts.extend(draw(st.lists(misc_strategy(), max_size=3)))
    # ~30% of well-formed documents use a deep linear chain as the root
    # instead of the bushy grammar, to probe depth-related limits/crashes
    # while the tree is still fully valid XML.
    if draw(st.integers(min_value=0, max_value=9)) < 3:
        parts.append(draw(deep_element_strategy))
    else:
        parts.append(draw(element_strategy))
    parts.extend(draw(st.lists(misc_strategy(), max_size=3)))
    return "".join(parts)


# ---------------------------------------------------------------------------
# Near-miss: XML-shaped but structurally wrong.
# ---------------------------------------------------------------------------

@st.composite
def mismatched_tags_doc(draw):
    n1, n2 = draw(st.tuples(xml_name(), xml_name()).filter(lambda t: t[0] != t[1]))
    attrs = draw(attributes_list_strategy())
    body = draw(
        st.text(
            alphabet=st.characters(exclude_characters="<&", max_codepoint=0xFFFF),
            max_size=15,
        )
    )
    return "<%s%s>%s</%s>" % (n1, _render_attrs(attrs), body, n2)


@st.composite
def unknown_entity_doc(draw):
    name = draw(xml_name())
    bad = draw(st.sampled_from(["&apos;", "&foo;", "&bar123;", "&nbsp;", "&Amp;"]))
    return "<%s>%s</%s>" % (name, bad, name)


@st.composite
def bad_charref_doc(draw):
    name = draw(xml_name())
    bad = draw(
        st.sampled_from(
            [
                "&#0;",
                "&#xD800;",
                "&#xFFFFFFFFFFFF;",
                "&#99999999;",
                "&#x110000;",
                "&#8;",
            ]
        )
    )
    return "<%s>%s</%s>" % (name, bad, name)


@st.composite
def multiple_roots_doc(draw):
    e1 = draw(element_strategy)
    e2 = draw(element_strategy)
    sep = draw(st.sampled_from(["", " ", "\n"]))
    return e1 + sep + e2


def empty_elem_name_doc():
    return st.sampled_from(["< />", "<></>", "< ></ >", "</>", "<>"])


@st.composite
def rootless_doc(draw):
    parts = draw(st.lists(misc_strategy(), min_size=0, max_size=5))
    return "".join(parts)


@st.composite
def unexpected_declaration_doc(draw):
    """Declaration keywords that are only legal inside a DOCTYPE internal
    subset (or not legal at all), appearing at the top level or nested
    inside an element instead."""
    tag = draw(
        st.sampled_from(["FOO", "BAR", "ENTITY", "ATTLIST", "NOTATION", "INCLUDE"])
    )
    body = draw(
        st.text(
            alphabet=st.characters(exclude_characters="<>", max_codepoint=0x7E),
            max_size=10,
        )
    )
    decl = "<!%s %s>" % (tag, body)
    if draw(st.booleans()):
        return decl
    name = draw(xml_name())
    return "<%s>%s</%s>" % (name, decl, name)


@st.composite
def reserved_pi_target_doc(draw):
    """A processing instruction whose target is (a case variant of) the
    reserved word 'xml', appearing somewhere other than document start."""
    target = draw(st.sampled_from(["xml", "Xml", "XML", "xML"]))
    body = draw(st.sampled_from(['version="1.0"', "foo", ""]))
    name = draw(xml_name())
    return "<%s><?%s %s?></%s>" % (name, target, body, name)


@st.composite
def bad_start_char_name_doc(draw):
    """Element name whose first character is not a legal NameStartChar."""
    bad_start = draw(st.sampled_from(list(string.digits) + ["-", "."]))
    rest = draw(st.text(alphabet=string.ascii_lowercase, max_size=5))
    name = bad_start + rest
    if draw(st.booleans()):
        return "<%s/>" % name
    return "<%s></%s>" % (name, name)


@st.composite
def malformed_doctype_doc(draw):
    kind = draw(
        st.sampled_from(
            ["no_name", "digit_name", "unterminated_subset", "doctype_after_root"]
        )
    )
    if kind == "no_name":
        return "<!DOCTYPE>"
    if kind == "digit_name":
        return "<!DOCTYPE 9root>"
    if kind == "unterminated_subset":
        name = draw(xml_name())
        return "<!DOCTYPE %s [" % name
    name = draw(xml_name())
    return "<%s/><!DOCTYPE %s>" % (name, name)


@st.composite
def unsupported_entity_doc(draw):
    """General/parameter entities that reference external resources, or an
    unparsed (NDATA) entity referenced directly in content -- constructs a
    minimal DTD implementation is expected to recognise syntactically but
    reject as unsupported. Different failure mode than a plain
    undefined-entity reference (unknown_entity_doc)."""
    root = draw(xml_name())
    ename = draw(xml_name())
    ident = draw(
        st.text(alphabet=string.ascii_letters + "/.:_-", min_size=1, max_size=12)
    )
    kind = draw(st.sampled_from(["system", "public", "param", "ndata"]))
    if kind == "system":
        subset = '<!ENTITY %s SYSTEM "%s">' % (ename, ident)
        ref = "&%s;" % ename
    elif kind == "public":
        subset = '<!ENTITY %s PUBLIC "-//X//Y//EN" "%s">' % (ename, ident)
        ref = "&%s;" % ename
    elif kind == "param":
        subset = '<!ENTITY %% %s "%s">' % (ename, ident)
        doctype = "<!DOCTYPE %s [%s %%%s;]>" % (root, subset, ename)
        return "%s<%s/>" % (doctype, root)
    else:
        notation = draw(xml_name())
        subset = '<!NOTATION %s SYSTEM "%s"><!ENTITY %s SYSTEM "%s" NDATA %s>' % (
            notation,
            ident,
            ename,
            ident,
            notation,
        )
        ref = "&%s;" % ename
    doctype = "<!DOCTYPE %s [%s]>" % (root, subset)
    return "%s<%s>%s</%s>" % (doctype, root, ref, root)


@st.composite
def recursive_entity_doc(draw):
    """A general entity whose replacement text references itself (direct),
    mutually references a partner entity (indirect loop), or embeds itself
    inside other text (self_embed) -- a hardened parser must cut this off
    with a recursion/expansion-depth guard rather than looping or blowing
    the stack."""
    root = draw(xml_name())
    mode = draw(st.sampled_from(["direct", "mutual", "self_embed"]))
    e1 = draw(xml_name())
    if mode == "direct":
        subset = '<!ENTITY %s "&%s;">' % (e1, e1)
    elif mode == "mutual":
        e2 = draw(xml_name().filter(lambda n: n != e1))
        subset = '<!ENTITY %s "&%s;"><!ENTITY %s "&%s;">' % (e1, e2, e2, e1)
    else:
        subset = '<!ENTITY %s "x&%s;y">' % (e1, e1)
    ref = "&%s;" % e1
    doctype = "<!DOCTYPE %s [%s]>" % (root, subset)
    return "%s<%s>%s</%s>" % (doctype, root, ref, root)


@st.composite
def doctype_root_mismatch_doc(draw):
    """The DOCTYPE name must match the document's root element name; here
    it deliberately does not."""
    n1, n2 = draw(st.tuples(xml_name(), xml_name()).filter(lambda t: t[0] != t[1]))
    return "<!DOCTYPE %s><%s/>" % (n1, n2)


def stray_cdata_end_doc():
    """The literal sequence ']]>' is illegal in character data outside a
    CDATA section, not just as an unmatched CDATA opener."""
    return xml_name().map(lambda n: "<%s>before]]>after</%s>" % (n, n))


@st.composite
def malformed_xmldecl_doc(draw):
    """Several distinct ways to break the XML declaration's own grammar."""
    kind = draw(
        st.sampled_from(
            [
                "no_version",
                "order_swapped",
                "bad_standalone",
                "mismatched_quotes",
                "leading_whitespace",
                "duplicated",
                "unquoted_version",
                "space_after_question_mark",
            ]
        )
    )
    root = draw(xml_name())
    body = "<%s/>" % root
    if kind == "no_version":
        return '<?xml encoding="UTF-8"?>' + body
    if kind == "order_swapped":
        return '<?xml encoding="UTF-8" version="1.0"?>' + body
    if kind == "bad_standalone":
        return '<?xml version="1.0" standalone="maybe"?>' + body
    if kind == "mismatched_quotes":
        return '<?xml version="1.0\'?>' + body
    if kind == "leading_whitespace":
        return " " + '<?xml version="1.0"?>' + body
    if kind == "duplicated":
        return '<?xml version="1.0"?><?xml version="1.0"?>' + body
    if kind == "unquoted_version":
        return "<?xml version=1.0?>" + body
    return "<? xml version=\"1.0\"?>" + body


def illegal_comment_doc():
    """The literal substring '--' must never appear inside a comment
    body, only as its terminator."""
    return st.sampled_from(
        [
            "<!--a--b-->",
            "<!------>",
            "<!-- -- -->",
        ]
    )


@st.composite
def reserved_pi_at_start_doc(draw):
    """A PI whose target is a case-variant of the reserved word 'xml',
    used as the very first construct in the document."""
    target = draw(st.sampled_from(["Xml", "XML", "xML", "xmL"]))
    root = draw(xml_name())
    return '<?%s version="1.0"?><%s/>' % (target, root)


@st.composite
def bad_attr_name_doc(draw):
    """Attribute name whose first character is not a legal NameStartChar."""
    ename = draw(xml_name())
    bad_start = draw(st.sampled_from(list(string.digits) + ["-", "."]))
    rest = draw(st.text(alphabet=string.ascii_lowercase, max_size=4))
    attr = bad_start + rest
    return '<%s %s="v"/>' % (ename, attr)


def empty_attr_name_doc():
    """An '=' where an attribute name was expected: no name at all."""
    return xml_name().map(lambda n: '<%s ="v"/>' % n)


def raw_lt_in_attr_doc():
    """A raw, unescaped '<' inside a quoted attribute value."""
    return xml_name().map(lambda n: '<%s a="x<y"/>' % n)


def bare_ampersand_doc():
    """A lone '&' that starts neither a named entity nor a character
    reference."""
    return xml_name().map(lambda n: "<%s>a & b</%s>" % (n, n))


# --- new in iteration 4 ---------------------------------------------------

def unexpected_attr_on_end_tag_doc():
    """End tags may not carry attributes."""
    return xml_name().map(lambda n: '<%s></%s a="1">' % (n, n))


def space_in_end_tag_doc():
    """Whitespace between '</' and the tag name is illegal."""
    return xml_name().map(lambda n: "<%s></ %s>" % (n, n))


@st.composite
def stray_epilog_content_doc(draw):
    """Non-whitespace character data is illegal anywhere in the prolog or
    the epilog, only comments/PIs/whitespace belong there."""
    name = draw(xml_name())
    junk = draw(st.text(alphabet=string.ascii_letters, min_size=1, max_size=6))
    where = draw(st.sampled_from(["before", "after"]))
    if where == "before":
        return "%s<%s/>" % (junk, name)
    return "<%s/>%s" % (name, junk)


def empty_pi_target_doc():
    """A processing instruction with no target name at all."""
    return st.sampled_from(["<? ?>", "<?  data?>", "<?\n?>"])


def pi_target_bad_start_doc():
    """PI target whose first character is not a legal NameStartChar."""
    bad_start = st.sampled_from(list(string.digits) + ["-", "."])
    return bad_start.map(lambda c: "<?%sabc data?>" % c)


def empty_entity_ref_doc():
    """'&;' -- an entity reference with no name between '&' and ';'."""
    return xml_name().map(lambda n: "<%s>&;</%s>" % (n, n))


@st.composite
def empty_charref_doc(draw):
    """'&#;' / '&#x;' -- a character reference with no digits at all."""
    name = draw(xml_name())
    bad = draw(st.sampled_from(["&#;", "&#x;"]))
    return "<%s>%s</%s>" % (name, bad, name)


@st.composite
def digit_start_entity_name_doc(draw):
    """An entity reference whose name starts with an illegal character."""
    name = draw(xml_name())
    digit = draw(st.sampled_from(list(string.digits)))
    rest = draw(st.text(alphabet=string.ascii_lowercase, max_size=4))
    return "<%s>&%s%s;</%s>" % (name, digit, rest, name)


@st.composite
def duplicate_doctype_doc(draw):
    """A document may have at most one DOCTYPE declaration."""
    n1 = draw(xml_name())
    n2 = draw(xml_name())
    return "<!DOCTYPE %s><!DOCTYPE %s><%s/>" % (n1, n2, n1)


@st.composite
def malformed_internal_subset_doc(draw):
    """A DOCTYPE internal subset holding a syntactically-broken <!ELEMENT>
    or <!ATTLIST> declaration: trailing comma in a content model, an
    unrecognised attribute-type keyword, an unterminated parenthesis, or
    a garbage content specifier -- distinct failure shapes from the
    generic unexpected_declaration_doc, which never nests inside a real
    DOCTYPE subset."""
    root = draw(xml_name())
    kind = draw(
        st.sampled_from(
            [
                "trailing_comma",
                "bad_attlist_type",
                "unterminated_paren",
                "bad_element_keyword",
            ]
        )
    )
    if kind == "trailing_comma":
        decl = "<!ELEMENT %s (a,b,)>" % root
    elif kind == "bad_attlist_type":
        decl = "<!ATTLIST %s attr NOTATYPE #REQUIRED>" % root
    elif kind == "unterminated_paren":
        decl = "<!ELEMENT %s (a,b" % root
    else:
        decl = "<!ELEMENT %s GARBAGE>" % root
    return "<!DOCTYPE %s [%s]><%s/>" % (root, decl, root)


@st.composite
def no_whitespace_between_attrs_doc(draw):
    """Attributes must be separated by whitespace; here they are jammed
    together with none."""
    name = draw(xml_name())
    a1, a2 = draw(st.tuples(xml_name(), xml_name()).filter(lambda t: t[0] != t[1]))
    return '<%s %s="1"%s="2"/>' % (name, a1, a2)


def lone_close_tag_doc():
    """A closing tag with a well-formed name but nothing was ever opened
    anywhere in the document."""
    return xml_name().map(lambda n: "</%s>" % n)


@st.composite
def cdata_outside_element_doc(draw):
    """A CDATA section in the prolog or epilog -- legal only inside
    element content."""
    name = draw(xml_name())
    where = draw(st.sampled_from(["before", "after"]))
    cdata = "<![CDATA[x]]>"
    if where == "before":
        return "%s<%s/>" % (cdata, name)
    return "<%s/>%s" % (name, cdata)


def content_before_xmldecl_doc():
    """The XML declaration, if present, must be the very first bytes of
    the document; here a comment precedes it."""
    return xml_name().map(lambda n: '<!-- oops --><?xml version="1.0"?><%s/>' % n)


_BUFFER_BOUNDARY_LENGTHS = [
    63, 64, 65,
    127, 128, 129,
    255, 256, 257,
    511, 512, 513,
    1023, 1024, 1025,
    2047, 2048, 2049,
]


@st.composite
def long_token_mismatch_doc(draw):
    """A mismatched-tag document built around a name/attribute-name/
    attribute-value that straddles a common fixed-size-buffer boundary
    (63/64/65 ... 2047/2048/2049 bytes), to probe buffer handling in the
    C implementation while the tag mismatch still guarantees rejection."""
    length = draw(st.sampled_from(_BUFFER_BOUNDARY_LENGTHS))
    ch = draw(st.sampled_from(list(string.ascii_lowercase)))
    long_token = ch * length
    other = draw(_deep_name_strategy)
    kind = draw(st.sampled_from(["name", "attr_name", "attr_value"]))
    if kind == "name":
        return "<%s>text</%s>" % (long_token, other)
    if kind == "attr_name":
        return '<%s %s="v"></%s>' % (other, long_token, other + "x")
    return '<%s a="%s"></%s>' % (other, long_token, other + "x")


def near_miss_document():
    return st.one_of(
        mismatched_tags_doc(),
        unknown_entity_doc(),
        bad_charref_doc(),
        multiple_roots_doc(),
        empty_elem_name_doc(),
        rootless_doc(),
        deep_mismatched_doc(),
        unexpected_declaration_doc(),
        reserved_pi_target_doc(),
        bad_start_char_name_doc(),
        malformed_doctype_doc(),
        unsupported_entity_doc(),
        recursive_entity_doc(),
        doctype_root_mismatch_doc(),
        stray_cdata_end_doc(),
        malformed_xmldecl_doc(),
        illegal_comment_doc(),
        reserved_pi_at_start_doc(),
        bad_attr_name_doc(),
        empty_attr_name_doc(),
        raw_lt_in_attr_doc(),
        bare_ampersand_doc(),
        unexpected_attr_on_end_tag_doc(),
        space_in_end_tag_doc(),
        stray_epilog_content_doc(),
        empty_pi_target_doc(),
        pi_target_bad_start_doc(),
        empty_entity_ref_doc(),
        empty_charref_doc(),
        digit_start_entity_name_doc(),
        duplicate_doctype_doc(),
        malformed_internal_subset_doc(),
        no_whitespace_between_attrs_doc(),
        lone_close_tag_doc(),
        cdata_outside_element_doc(),
        content_before_xmldecl_doc(),
        long_token_mismatch_doc(),
    )


# ---------------------------------------------------------------------------
# Byte-hostile: hostile at the byte / encoding level.
#
# Arbitrary raw bytes are smuggled through `str` using the standard
# surrogateescape convention: byte b < 0x80 -> chr(b); byte b >= 0x80 ->
# chr(0xDC00 + b). Encoding the result with errors="surrogateescape"
# reproduces the exact intended byte sequence, including invalid UTF-8.
# ---------------------------------------------------------------------------

def _raw_bytes_to_str(byte_values):
    out = []
    for b in byte_values:
        if b < 0x80:
            out.append(chr(b))
        else:
            out.append(chr(0xDC00 + b))
    return "".join(out)


def _control_char_strategy():
    codes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0E, 0x0F, 0x1F, 0x7F]
    return st.sampled_from(codes).map(chr)


def _truncated_multibyte_strategy():
    options = [[0xE2, 0x82], [0xF0, 0x9F, 0x98], [0xC3], [0xE0, 0xA0]]
    return st.sampled_from(options).map(_raw_bytes_to_str)


def _lone_continuation_strategy():
    return st.sampled_from([0x80, 0x81, 0xBF, 0x90, 0xAD]).map(
        lambda b: _raw_bytes_to_str([b])
    )


def _overlong_strategy():
    options = [
        [0xC0, 0xAF],
        [0xE0, 0x80, 0xAF],
        [0xF0, 0x80, 0x80, 0xAF],
        [0xC1, 0xBF],
        [0xC0, 0x80],  # overlong-encoded NUL ("modified UTF-8" style)
    ]
    return st.sampled_from(options).map(_raw_bytes_to_str)


def _surrogate_utf8_strategy():
    """UTF-8 byte sequences that decode to a surrogate-half code point --
    never valid UTF-8, distinct from truncation/overlong/continuation
    errors."""
    options = [[0xED, 0xA0, 0x80], [0xED, 0xB0, 0x80], [0xED, 0xBF, 0xBF]]
    return st.sampled_from(options).map(_raw_bytes_to_str)


def _utf32_bom_strategy():
    options = [[0x00, 0x00, 0xFE, 0xFF], [0xFF, 0xFE, 0x00, 0x00]]
    return st.sampled_from(options).map(_raw_bytes_to_str)


def _long_body_strategy():
    """A single-character run at a common fixed-size-buffer boundary
    length, for stressing comment/PI/attribute-value handling in
    isolation from any structural malformation."""
    lengths = [255, 256, 257, 1023, 1024, 1025, 4095, 4096]
    return st.tuples(
        st.sampled_from(lengths), st.sampled_from(list(string.ascii_lowercase))
    ).map(lambda t: t[1] * t[0])


def _utf16_bom_odd_strategy():
    @st.composite
    def _gen(draw):
        endian = draw(st.sampled_from([[0xFF, 0xFE], [0xFE, 0xFF]]))
        extra_len = draw(st.sampled_from([1, 3, 5]))
        extra = draw(
            st.lists(
                st.integers(min_value=0, max_value=255),
                min_size=extra_len,
                max_size=extra_len,
            )
        )
        return _raw_bytes_to_str(endian + extra)

    return _gen()


@st.composite
def byte_hostile_document(draw):
    kind = draw(
        st.sampled_from(
            [
                "bom_utf8",
                "bom_utf16_odd",
                "bom_utf32",
                "bom_plus_encoding_lie",
                "truncated_multibyte",
                "lone_continuation",
                "overlong",
                "surrogate_utf8",
                "embedded_nul_text",
                "embedded_nul_attr",
                "embedded_nul_name",
                "embedded_nul_comment",
                "embedded_nul_pi",
                "control_char_text",
                "unterminated_comment",
                "unterminated_cdata",
                "unterminated_pi",
                "unterminated_tag",
                "unterminated_attr_string",
                "truncated_valid_doc",
                "encoding_lie",
                "malformed_encoding_name",
                "long_comment_stress",
                "long_pi_stress",
                "long_attr_value_stress",
                "raw_invalid_mix",
                "deep_unterminated",
                "deep_truncated",
            ]
        )
    )
    if kind == "bom_utf8":
        base = draw(well_formed_document())
        return "\ufeff" + base
    if kind == "bom_utf16_odd":
        base = draw(well_formed_document())
        return draw(_utf16_bom_odd_strategy()) + base
    if kind == "bom_utf32":
        base = draw(well_formed_document())
        return draw(_utf32_bom_strategy()) + base
    if kind == "bom_plus_encoding_lie":
        return '\ufeff<?xml version="1.0" encoding="UTF-16"?><r/>'
    if kind == "truncated_multibyte":
        frag = draw(_truncated_multibyte_strategy())
        return "<r>%s</r>" % frag
    if kind == "lone_continuation":
        frag = draw(_lone_continuation_strategy())
        return "<r>%s</r>" % frag
    if kind == "overlong":
        frag = draw(_overlong_strategy())
        return "<r>%s</r>" % frag
    if kind == "surrogate_utf8":
        frag = draw(_surrogate_utf8_strategy())
        return "<r>%s</r>" % frag
    if kind == "embedded_nul_text":
        return "<r>before%safter</r>" % chr(0)
    if kind == "embedded_nul_attr":
        return '<r a="x%sy"/>' % chr(0)
    if kind == "embedded_nul_name":
        return "<r%sx/>" % chr(0)
    if kind == "embedded_nul_comment":
        return "<!-- before%safter -->" % chr(0)
    if kind == "embedded_nul_pi":
        return "<?pi before%safter?>" % chr(0)
    if kind == "control_char_text":
        c = draw(_control_char_strategy())
        return "<r>before%safter</r>" % c
    if kind == "unterminated_comment":
        return "<!-- this comment never closes"
    if kind == "unterminated_cdata":
        return "<r><![CDATA[ never closes</r>"
    if kind == "unterminated_pi":
        return "<?pi never closes"
    if kind == "unterminated_tag":
        name = draw(xml_name())
        return '<%s attr="val"' % name
    if kind == "unterminated_attr_string":
        name = draw(xml_name())
        return '<%s attr="never closed' % name
    if kind == "truncated_valid_doc":
        full = draw(element_strategy)
        hi = max(1, min(8, len(full)))
        cut = draw(st.integers(min_value=1, max_value=hi))
        return full[:cut]
    if kind == "encoding_lie":
        enc = draw(st.sampled_from(["UTF-16", "ISO-8859-1", "UTF-32", "ASCII"]))
        body = draw(
            st.text(
                alphabet=st.characters(min_codepoint=0x80, max_codepoint=0x2FF),
                min_size=1,
                max_size=5,
            )
        )
        return '<?xml version="1.0" encoding="%s"?><r>%s</r>' % (enc, body)
    if kind == "malformed_encoding_name":
        # Syntactically broken encoding-name pseudo-attribute value,
        # distinct from encoding_lie (which uses a valid-looking but
        # mismatched encoding name).
        bad_enc = draw(st.sampled_from(["", "UTF 8", "123bad", "UTF-8;drop"]))
        return '<?xml version="1.0" encoding="%s"?><r/>' % bad_enc
    if kind == "long_comment_stress":
        body = draw(_long_body_strategy())
        return "<!--%s-->" % body
    if kind == "long_pi_stress":
        body = draw(_long_body_strategy())
        return "<?pi %s?>" % body
    if kind == "long_attr_value_stress":
        body = draw(_long_body_strategy())
        return '<r a="%s"/>' % body
    if kind == "deep_unterminated":
        return draw(deep_unterminated_doc())
    if kind == "deep_truncated":
        # Cut a deep, otherwise well-formed chain partway through -- early
        # EOF discovered only after descending several nesting levels.
        full = draw(deep_element_strategy)
        hi = max(1, min(len(full), 4000))
        cut = draw(st.integers(min_value=1, max_value=hi))
        return full[:cut]
    # kind == "raw_invalid_mix"
    frag = draw(
        st.one_of(
            _truncated_multibyte_strategy(),
            _lone_continuation_strategy(),
            _overlong_strategy(),
        )
    )
    return '<?xml version="1.0" encoding="UTF-8"?><r a="%s">%s</r>' % (frag, frag)


# ---------------------------------------------------------------------------
# Top level mixture: per-category weighted-key dispatch.
#
# Two prior mechanisms both concentrated bias onto whichever category
# happened to occupy a favoured *position*: a contiguous three-band split
# of one st.integers(0, 99) draw (iteration 2: measured 55.4/8.6/36.0 vs a
# 48/26/26 target -- the bands touching 0 and 99 were inflated), and a
# 100-entry evenly-interleaved label list drawn via st.sampled_from
# (iteration 3: measured 54.6/20.2/25.2 vs a 40/33/27 target -- whichever
# label the interleaving scheduler placed at index 0 *and* index 99, here
# well_formed, still soaked up the same boundary bias). Position is the
# common failure mode, so this iteration removes position from the
# mechanism entirely: each category draws its own independent uniform
# float and is scored as u ** (1/weight) (Efraimidis-Spirakis weighted
# sampling for a single pick); the highest score wins. Any bias in the
# underlying float draw now applies identically and independently to
# every category, with no positional slot for one category to
# monopolise. Nominal weights shift to 42/31/27 (from 40/33/27):
# well_formed measured *over* its own ~50% target (54.6%) last run while
# near_miss was the only class under its 25% floor (20.2%), so weight
# moves from well_formed to near_miss, and byte_hostile keeps a small
# buffer above its own floor.
# ---------------------------------------------------------------------------

_CLASS_WEIGHTS = [("well_formed", 42), ("near_miss", 31), ("byte_hostile", 27)]


def _weighted_choice(draw, weights):
    unit = st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False)
    best_label, best_score = None, None
    for label, w in weights:
        u = draw(unit)
        score = u ** (1.0 / w)
        if best_score is None or score > best_score:
            best_score = score
            best_label = label
    return best_label


@st.composite
def _documents_impl(draw):
    label = _weighted_choice(draw, _CLASS_WEIGHTS)
    if label == "well_formed":
        doc = draw(well_formed_document())
    elif label == "near_miss":
        doc = draw(near_miss_document())
    else:
        doc = draw(byte_hostile_document())
    return doc if len(doc) <= 12000 else doc[:12000]


def documents():
    return _documents_impl()

```

## Measured results over 500 generated documents

### Input class mixture, and acceptance within each class

```
byte_hostile   share= 40.0%  acceptance= 10.0%  n=200
near_miss      share= 14.2%  acceptance= 43.7%  n=71
well_formed    share= 45.8%  acceptance= 68.6%  n=229
```

Targets: `well_formed` ~50%, `near_miss` >=25%, `byte_hostile` >=25%.
`near_miss` and `byte_hostile` are *expected* to be mostly rejected. Do not
raise their acceptance by making them less malformed; that defeats their purpose.

Overall acceptance: **41.6%** (target band 40-70%)

### Marginal progress: what THIS iteration found that no earlier one did

This is what you are scored on. Repeating ground already covered by an earlier
iteration counts for nothing.

```
new diagnostic templates this iteration : 16
  + <%s--> cannot be a second root node after <%s> on line %d.
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
  + Missing close tag </%s> under parent <%s> on line %d.
  + Missing value for attribute '%s' in element %s on line %d.
  + Missing value for attribute '%s'' in element %s on line %d.
  + XML does not start with '%s' (saw '%s').
new grammar productions this iteration  : 25: g_attribute_dquot, g_attribute_squot, g_cdata, g_chardata, g_charref_dec, g_charref_hex, g_comment, g_element_paired, g_element_selfclose, g_entity_named, g_pi, g_prolog, x_attribute_unquoted, x_bom, x_control_char, x_doctype, x_embedded_nul, x_empty_elem_name, x_encoding_decl, x_entity_unsupported, x_invalid_utf8, x_mismatched_tags, x_name_nonascii, x_rootless, x_unterminated
```

**Target: at least 3 diagnostic templates that no previous iteration reached.**

### Diagnostics already reached by ANY iteration so far (16 total)

```
<%s--> cannot be a second root node after <%s> on line %d.
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
Missing close tag </%s> under parent <%s> on line %d.
Missing value for attribute '%s' in element %s on line %d.
Missing value for attribute '%s'' in element %s on line %d.
XML does not start with '%s' (saw '%s').
```

Each of these is a branch in the parser that has already been visited. Reaching
them again adds nothing. Use your own knowledge of XML to reason about what
*other* error conditions a conforming parser must detect, which are absent from
this list, and construct documents that trigger them.

### Grammar production coverage: 25/27

Never produced by any iteration:
```
g_nesting_deep
x_multiple_roots
```

### Nesting depth distribution

```
{
  "0": 210,
  "1": 239,
  "2-3": 42,
  "4-7": 9
}
```
Deepest document generated: 6

### Document size

```
{
  "min": 0,
  "max": 4104,
  "mean": 105.2,
  "median": 56.0
}
```

### Slowest documents

```
     8.0 ms  len=41     depth=0   rejected
     8.0 ms  len=8      depth=1   rejected
     8.0 ms  len=25     depth=0   rejected
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


---

# Your previous attempt was rejected

The module does not compile:

IndentationError: unexpected indent (gen_iter4.py, line 2)

Fix and resend.