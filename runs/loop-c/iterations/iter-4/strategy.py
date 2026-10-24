"""
Hypothesis document generator for fuzzing a Mini-XML (mxml v4.0.4) parser
built with ASan/UBSan.

Iteration 5 ("deepen"). Two problems drove this revision.

1. The class mixture is still broken, in a NEW way this time. Iteration 4's
   per-category weighted float draw (Efraimidis-Spirakis: draw one
   independent u in [0,1] per label, score u ** (1/weight), highest score
   wins) is mathematically unbiased for a truly uniform u, and it did
   remove the positional coupling that hurt iterations 2 and 3 (nominal
   40/33/27 -> measured 54.6/20.2/25.2, well_formed monopolising both
   ends of a 100-entry index list). But iteration 4 measured
   45.8/14.2/40.0 against a 42/31/27 target: near_miss got *worse* (14.2%
   versus 20.2%) and byte_hostile blew far past its own target (40.0%
   versus 27%). A float draw being "independent per category" only helps
   if the underlying float sampler is actually close to uniform on
   [0,1]. Hypothesis's bounded-float strategy is not: it draws from a
   curated pool of "special" values (0.0, 1.0, subnormals, etc.) with a
   fixed probability that does *not* shrink as the continuous range
   widens, unlike a bounded-integer strategy where widening the range
   dilutes the fixed number of boundary-favoured points. So floats kept
   the disease iteration 4 thought it had cured.

   This iteration drops floats entirely and goes back to integers, but
   fixes the two failure modes iterations 2-4 each demonstrated in turn:
   (a) a narrow range (0..99) lets a fixed per-value special-case bias
   dominate a big fraction of the space -> widen the modulus so any
   single favoured value is a tiny fraction of it; (b) letting one
   category sit at the literal 0 or max-value boundary of that range
   couples it directly to whatever bias remains -> smooth it out by
   summing four *independent* wide-integer draws modulo a prime and
   walking cumulative thresholds over the sum. Reproducing any bias at a
   specific sum value now requires a specific alignment across all four
   independent draws, which is a different and much weaker failure mode
   than "one draw lands on a favoured endpoint." Nominal weights also
   move to 46/29/25 (from 42/31/27): the *mechanism*, not just the
   nominal split, was always the reason near_miss and byte_hostile missed
   their targets, so this iteration trusts the smoothed mechanism to
   track the requested split more closely and sets weights near the
   actual target band (well_formed ~50%, both others >=25%).

   Separately, near_miss's own generators are also cleaned up: every
   `.filter(lambda t: t[0] != t[1])` / `.filter(lambda n: n != x)` used to
   force two names apart is replaced with a construction that is
   distinct *by build*, never by rejection (name2 = name1 + a fixed
   suffix, or a deterministic alphabet shift for the 8-letter deep
   alphabet). This costs nothing structurally, and removes any chance
   that near_miss's sub-generators are quietly more expensive to satisfy
   than the other two categories' filter-free ones.

2. Directive: deepen. The measured nesting-depth histogram was almost
   entirely 0-1 (449/500 documents) with a *maximum observed depth of 6*
   despite iteration 4 already routing ~30% of well-formed documents
   through a "deep" st.recursive chain with max_leaves=100, and
   g_nesting_deep was never produced at all. The reason is structural,
   not a tuning miss: `st.recursive(base, extend, max_leaves=N)` budgets
   *leaves*, and a strictly single-child chain (extend always wraps
   exactly one recursive child) has exactly one leaf no matter how deep
   it goes -- max_leaves cannot influence its depth at all. st.recursive
   was the wrong combinator for this shape from the start.

   This iteration replaces the linear chain with `st.lists(name_alphabet,
   min_size, max_size).map(fold_into_nested_tags)`. Depth is now the
   drawn list's length: fully Hypothesis-varied (list-length is drawn
   fresh per example) and fully shrinkable (Hypothesis's list shrinker
   specifically minimises length, so a crash found at depth 400 shrinks
   toward the shallowest depth that still reproduces it) -- exactly the
   "depth Hypothesis can vary and shrink" rule 4 asks for, just expressed
   through st.lists instead of st.recursive/recursive-composite, because
   those two are demonstrably the wrong tool for single-branch depth (and
   a naively recursive @st.composite walking hundreds of Python stack
   frames risks hitting the interpreter's own recursion limit before it
   ever reaches an interesting *C*-side depth). Each depth-bearing
   generator now draws from a shallow/deep mixture (1-40 vs 80-900) so a
   large, deliberate fraction of documents genuinely stress deep
   recursion instead of leaving it to chance. New: deep_multiple_roots_doc
   (two independently-deep chains as siblings -- targets the
   never-produced x_multiple_roots production *and* depth at once), and
   deep_mismatched_doc now corrupts one closing tag at a drawn, shrinkable
   position anywhere in the chain (root, leaf, or between) instead of
   only ever at the outermost tag.

   New near-miss constructs chasing diagnostics no earlier iteration
   reached: an undeclared namespace prefix; a name with two colons
   (illegal QName shape); an attribute name directly followed by a
   quoted value with the '=' omitted entirely; an XML declaration
   claiming an unsupported version number (2.0/1.2/0.9/10.0); a DOCTYPE
   SYSTEM literal left unquoted; a DOCTYPE PUBLIC clause missing its
   mandatory second (SYSTEM) literal; a raw '<' in content followed by
   whitespace so it cannot even be mistaken for markup; a parameter
   entity reference to a name never declared anywhere in the internal
   subset; and a couple of new malformed character references (leading
   '-'/'+' before the digits). New byte-hostile: a control character
   embedded specifically inside an attribute value (previously only
   tested in element text).

Produces a weighted mixture of:
  - well_formed documents (~46% nominal): valid XML-shaped input built
    with a recursive element grammar (bushy, or about half the time a
    genuinely deep linear chain reaching into the hundreds of levels)
    where open/close tag names always match.
  - near_miss documents (~29% nominal): XML-shaped but structurally wrong
    -- mismatched tags (including deep ones with the break at a
    shrinkable depth, and buffer-boundary-length names), unsupported or
    recursive entities, bad char refs, multiple/zero/deeply-nested roots,
    empty or illegal names (including two-colon QNames and undeclared
    namespace prefixes), stray declarations, reserved PI targets,
    malformed DOCTYPEs/DTD internal subsets/external IDs, malformed XML
    declarations (including unsupported version numbers), illegal
    comments, stray CDATA, misplaced raw '<'/'&', empty entity/PI-target/
    char-ref syntax, missing '=' or missing whitespace between
    attributes, stray prolog/epilog content, undefined parameter
    entities, attributes on end tags.
  - byte_hostile documents (~25% nominal): hostile at the byte/encoding
    level -- BOMs including UTF-32, truncated/invalid UTF-8, surrogate
    code points, overlong encodings including overlong NUL, embedded
    NUL, raw control characters (in text and now attribute values),
    unterminated constructs (including very deep unterminated chains),
    lying or malformed encoding declarations, long tokens at buffer-
    boundary lengths, deep chains truncated mid-descent.
"""

from hypothesis import strategies as st
import string

NAME = "mxml_grammar_fuzzer"
DESCRIPTION = (
    "Recursive XML-shaped generator tuned to Mini-XML v4.0.4 quirks: "
    "matched-tag element trees (bushy, or a genuinely deep linear chain "
    "built via a shrinkable st.lists fold rather than a leaf-budgeted "
    "st.recursive chain that could not exceed depth ~6 in practice) with "
    "entities, char refs, CDATA, comments and PIs for the well-formed "
    "slice; a wide spread of structural near-misses (tag mismatch at any "
    "depth, undeclared namespace prefixes, two-colon QNames, missing '=' "
    "before an attribute value, unsupported entities, bad numeric char "
    "refs, multiple/missing/deeply-nested roots, empty/illegal names, "
    "stray declarations, reserved PI targets, malformed DOCTYPEs/DTD "
    "subsets/external IDs/versions, illegal comments, stray CDATA, "
    "misplaced raw '<'/'&', missing attribute whitespace, stray "
    "prolog/epilog content, attributes on end tags); and byte-level "
    "hostility (BOMs, truncated/invalid/surrogate UTF-8, overlong "
    "encodings, embedded NUL, control characters in text and attribute "
    "values, unterminated markup including deep chains, malformed/lying "
    "encoding declarations, buffer-boundary-length tokens). Class "
    "dispatch sums four independent wide-range integer draws modulo a "
    "prime before applying cumulative thresholds, so no category is "
    "coupled to a single draw's favoured boundary value the way earlier "
    "position- or float-based mechanisms were."
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


# Bushy tree: branching factor > 1, so st.recursive's leaf budget is a
# meaningful depth/size control here (unlike the single-branch chain below).
element_strategy = st.recursive(_leaf_element(), _extend_element, max_leaves=40)


# ---------------------------------------------------------------------------
# Deep chain machinery ("deepen", iteration 5).
#
# A strictly single-child nested chain always has exactly one leaf no
# matter how deep it goes, so st.recursive's max_leaves cannot budget its
# depth at all -- iteration 4 measured a hard ceiling of depth 6 despite
# max_leaves=100. Depth here is instead the length of a list drawn from
# st.lists (fully Hypothesis-varied per example, and shrunk by
# Hypothesis's native list shrinker, which minimises length first), then
# folded into nested open/close tags. A shallow/deep mixture guarantees a
# healthy fraction of documents reach genuinely deep nesting (tens to
# ~900 levels) rather than leaving it to chance.
# ---------------------------------------------------------------------------

_DEEP_ALPHABET = "abcdefgh"
_deep_name_strategy = st.sampled_from(list(_DEEP_ALPHABET))


def _shift_letter(c):
    """Deterministically returns a different letter from _DEEP_ALPHABET.
    No draw, no filter/rejection: always succeeds in O(1)."""
    i = _DEEP_ALPHABET.index(c)
    return _DEEP_ALPHABET[(i + 1) % len(_DEEP_ALPHABET)]


def _fold_chain(names):
    opens = "".join("<%s>" % n for n in names)
    closes = "".join("</%s>" % n for n in reversed(names))
    return opens + closes


def deep_name_list_strategy(min_depth=1, shallow_max=40, deep_min=80, deep_max=900):
    shallow = st.lists(_deep_name_strategy, min_size=min_depth, max_size=shallow_max)
    deep = st.lists(_deep_name_strategy, min_size=deep_min, max_size=deep_max)
    return st.one_of(shallow, deep)


def deep_chain_strategy():
    """A well-formed, deeply nested single-child chain."""
    return deep_name_list_strategy().map(_fold_chain)


@st.composite
def deep_mismatched_doc(draw):
    """A deep, otherwise well-formed chain with exactly one closing tag
    corrupted at a drawn, shrinkable position -- so the mismatch can
    surface near the leaf, near the root, or anywhere in between,
    instead of only ever at the outermost tag as in earlier iterations."""
    names = draw(deep_name_list_strategy())
    idx = draw(st.integers(min_value=0, max_value=len(names) - 1))
    closers = list(reversed(names))
    closers[idx] = _shift_letter(closers[idx])
    opens = "".join("<%s>" % n for n in names)
    closes = "".join("</%s>" % n for n in closers)
    return opens + closes


def deep_unterminated_doc():
    """A long run of open tags that are never closed at all, spanning
    shallow to deliberately very deep."""
    return deep_name_list_strategy(
        min_depth=5, shallow_max=60, deep_min=100, deep_max=1500
    ).map(lambda names: "".join("<%s>" % n for n in names))


@st.composite
def deep_multiple_roots_doc(draw):
    """Two independently-sized deep chains concatenated as siblings: a
    document may have only one root element, and this should be caught
    only after descending (and re-ascending) a genuinely deep first tree,
    not just a shallow one. Targets the never-produced x_multiple_roots
    grammar production together with real depth."""
    names1 = draw(deep_name_list_strategy())
    names2 = draw(deep_name_list_strategy())
    sep = draw(st.sampled_from(["", " ", "\n"]))
    return _fold_chain(names1) + sep + _fold_chain(names2)


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
    # "deepen": about half of well-formed documents use a deep linear
    # chain as the root instead of the bushy grammar, drawn from the
    # shallow/deep mixture above so a large share reach genuinely deep
    # nesting while the tree stays fully valid XML.
    if draw(st.integers(min_value=0, max_value=9)) < 5:
        parts.append(draw(deep_chain_strategy()))
    else:
        parts.append(draw(element_strategy))
    parts.extend(draw(st.lists(misc_strategy(), max_size=3)))
    return "".join(parts)


# ---------------------------------------------------------------------------
# Near-miss: XML-shaped but structurally wrong.
#
# Every "these two names must differ" need below is satisfied by
# construction (name2 = name1 + a fixed suffix), never by a
# `.filter(...)` rejection loop, so none of these generators can be more
# expensive to satisfy than the filter-free well_formed/byte_hostile
# generators.
# ---------------------------------------------------------------------------

@st.composite
def mismatched_tags_doc(draw):
    n1 = draw(xml_name())
    suffix = draw(st.sampled_from(["_x", "Z", "9", "_q"]))
    n2 = n1 + suffix
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
                "&#-1;",
                "&#+5;",
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
        suffix = draw(st.sampled_from(["_b", "Z", "9"]))
        e2 = e1 + suffix
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
    n1 = draw(xml_name())
    suffix = draw(st.sampled_from(["_x", "Q", "7"]))
    n2 = n1 + suffix
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
    a1 = draw(xml_name())
    suffix = draw(st.sampled_from(["_y", "K", "3"]))
    a2 = a1 + suffix
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


# --- new in iteration 5 ----------------------------------------------------

@st.composite
def unsupported_xml_version_doc(draw):
    """mxml implements XML 1.0/1.1; a declared version outside that set
    must be rejected."""
    name = draw(xml_name())
    version = draw(st.sampled_from(["2.0", "1.2", "0.9", "10.0"]))
    return '<?xml version="%s"?><%s/>' % (version, name)


@st.composite
def doctype_unquoted_system_id_doc(draw):
    """A SYSTEM literal must be a quoted string; here it is bare."""
    name = draw(xml_name())
    return "<!DOCTYPE %s SYSTEM unquoted><%s/>" % (name, name)


@st.composite
def doctype_public_missing_system_doc(draw):
    """PUBLIC requires both a public and a system literal; the system
    literal is omitted here."""
    name = draw(xml_name())
    return '<!DOCTYPE %s PUBLIC "-//X//Y//EN"><%s/>' % (name, name)


def raw_lt_in_content_doc():
    """A raw '<' in element content that cannot even be mistaken for the
    start of a tag, comment, PI or CDATA section (followed by
    whitespace)."""
    return xml_name().map(lambda n: "<%s>a < b</%s>" % (n, n))


@st.composite
def missing_equals_in_attr_doc(draw):
    """An attribute name directly followed by a quoted value with no '='
    between them at all -- distinct from empty_attr_name_doc, where the
    '=' is present but the name is missing."""
    ename = draw(xml_name())
    aname = draw(xml_name())
    return '<%s %s"v"/>' % (ename, aname)


@st.composite
def multiple_colons_in_name_doc(draw):
    """A QName may contain at most one colon; this one has two, illegal
    under the Namespaces-in-XML constraint on NCNames."""
    a = draw(xml_name())
    b = draw(xml_name())
    c = draw(xml_name())
    return "<%s:%s:%s/>" % (a, b, c)


@st.composite
def undefined_namespace_prefix_doc(draw):
    """An element uses a namespace prefix that is never declared via any
    xmlns:prefix attribute anywhere in the document."""
    prefix = draw(xml_name())
    local = draw(xml_name())
    return "<%s:%s>text</%s:%s>" % (prefix, local, prefix, local)


@st.composite
def undefined_parameter_entity_doc(draw):
    """A parameter entity reference inside the internal DTD subset that
    names an entity never declared anywhere."""
    root = draw(xml_name())
    pename = draw(xml_name())
    return "<!DOCTYPE %s [%%%s;]><%s/>" % (root, pename, root)


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
        unsupported_xml_version_doc(),
        doctype_unquoted_system_id_doc(),
        doctype_public_missing_system_doc(),
        raw_lt_in_content_doc(),
        missing_equals_in_attr_doc(),
        multiple_colons_in_name_doc(),
        undefined_namespace_prefix_doc(),
        undefined_parameter_entity_doc(),
        deep_multiple_roots_doc(),
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
                "control_char_attr",
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
    if kind == "control_char_attr":
        c = draw(_control_char_strategy())
        return '<r a="x%sy"/>' % c
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
        full = draw(deep_chain_strategy())
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
# Top level mixture: sum four independent wide-range integer draws modulo
# a prime, then walk cumulative thresholds over the sum.
#
# Every earlier mechanism coupled one category to a single draw's
# favoured value: a contiguous three-band split of one st.integers(0, 99)
# draw (iteration 2: measured 55.4/8.6/36.0 vs 48/26/26, the bands
# touching 0 and 99 inflated), a 100-entry evenly-interleaved label list
# still drawn via one bounded index (iteration 3: measured 54.6/20.2/25.2
# vs 40/33/27, whichever label occupied both index 0 and index 99 kept
# the same advantage), and one independent float per category scored by
# Efraimidis-Spirakis weighting (iteration 4: measured 45.8/14.2/40.0 vs
# 42/31/27 -- floats carry their own fixed-probability special-value pool
# that a wider *continuous* range does nothing to dilute, unlike a
# bounded integer range).
#
# This iteration sums _MIX_DRAWS independent wide-range integer draws
# modulo a prime before thresholding. Reproducing a bias at a specific
# output value now requires a specific alignment across all of those
# independent draws simultaneously, and the modulus is wide enough
# (997) that even a single favoured integer value contributes well
# under 1% of the probability mass to any one band. Nominal weights
# move to 46/29/25 (from 42/31/27): the mechanism, not the nominal
# split, was the reason near_miss and byte_hostile kept missing their
# targets, so weights now sit close to the actual requested band
# (well_formed ~50%, near_miss/byte_hostile both >=25%).
# ---------------------------------------------------------------------------

_CLASS_WEIGHTS = [("well_formed", 46), ("near_miss", 29), ("byte_hostile", 25)]
_WEIGHT_TOTAL = sum(w for _, w in _CLASS_WEIGHTS)
_MIX_MOD = 997  # prime, wide: decorrelates from power-of-two special-value bias
_MIX_DRAWS = 4


def _smoothed_value(draw):
    total = 0
    for _ in range(_MIX_DRAWS):
        total += draw(st.integers(min_value=0, max_value=_MIX_MOD - 1))
    return total % _MIX_MOD


def _pick_category(draw):
    v = _smoothed_value(draw)
    scaled = (v * _WEIGHT_TOTAL) // _MIX_MOD
    cumulative = 0
    for label, w in _CLASS_WEIGHTS:
        cumulative += w
        if scaled < cumulative:
            return label
    return _CLASS_WEIGHTS[-1][0]


@st.composite
def _documents_impl(draw):
    label = _pick_category(draw)
    if label == "well_formed":
        doc = draw(well_formed_document())
    elif label == "near_miss":
        doc = draw(near_miss_document())
    else:
        doc = draw(byte_hostile_document())
    return doc if len(doc) <= 15000 else doc[:15000]


def documents():
    return _documents_impl()
