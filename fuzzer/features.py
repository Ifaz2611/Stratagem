"""Structural analysis of a *generated* document.

Measures structural diversity: the distribution of nesting depth, and which
grammar productions have and have not appeared in generated inputs.

Two design choices.

**Post-hoc, not generator-instrumented.** The productions present in a document
are detected by scanning the document itself, not by having the strategy report
what it drew. That keeps the contract for LLM-written strategies as small as
possible -- `documents() -> SearchStrategy[str]` and nothing else -- so the model
cannot break the measurement by forgetting bookkeeping calls, and is free to
generate however it likes. It also means the baseline and every future strategy
are measured by exactly the same yardstick.

**Blackbox-clean.** This inspects our own generated strings. It never touches
mxml, its source, or its internals, so it is available as a *steering* signal
with no caveat (see docs/design-decisions.md D2, signal 1).

The scanner is deliberately tolerant rather than a parser. Its input is mostly
malformed by design, so it must never raise and must extract what it can from
garbage.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# The production vocabulary. Names beginning with "g_" come from the ANTLR
# grammar; names beginning with "x_" are constructs the grammar cannot express
# but which mxml accepts or rejects distinctively, taken from the measured gaps
# in grammar/ADAPTATIONS.md. Keeping both in one vocabulary is what lets the
# loop report coverage of the *adapted* grammar rather than the paper one.
PRODUCTIONS: tuple[str, ...] = (
    # from the grammar
    "g_prolog",              # <?xml ... ?>
    "g_element_paired",      # <a>...</a>
    "g_element_selfclose",   # <a/>
    "g_attribute_dquot",     # a="1"
    "g_attribute_squot",     # a='1'
    "g_chardata",            # text between tags
    "g_entity_named",        # &amp;
    "g_charref_dec",         # &#65;
    "g_charref_hex",         # &#x41;
    "g_cdata",               # <![CDATA[...]]>
    "g_comment",             # <!-- ... -->
    "g_pi",                  # <?target ... ?>
    "g_nesting_deep",        # depth >= DEEP_NESTING
    # adaptations: mxml accepts, grammar cannot produce
    "x_attribute_unquoted",  # a=1
    "x_doctype",             # <!DOCTYPE ...>
    "x_empty_elem_name",     # < />
    "x_rootless",            # no element at all
    "x_name_nonascii",       # <e-acute/>, outside the grammar's NameStartChar
    # adaptations: near-miss / rejected by mxml, useful for error paths
    "x_mismatched_tags",     # <a></b>
    "x_entity_unsupported",  # &apos; and other unknown names
    "x_multiple_roots",      # <a/><b/>
    "x_control_char",        # raw control byte in content
    "x_unterminated",        # truncated comment / CDATA / PI / tag
    # Byte- and encoding-level productions. Detected from the raw payload
    # rather than the decoded text, because that is the only place they exist.
    "x_bom",                 # UTF-8 or UTF-16 byte-order mark
    "x_invalid_utf8",        # bytes that are not valid UTF-8
    "x_embedded_nul",        # NUL inside the document
    "x_encoding_decl",       # encoding= in the XML declaration
)

DEEP_NESTING = 8

_RE_PROLOG = re.compile(r"<\?xml\b", re.I)
_RE_PI = re.compile(r"<\?(?!xml\b)[^\s?>]*", re.I)
_RE_COMMENT_OPEN = re.compile(r"<!--")
_RE_CDATA_OPEN = re.compile(r"<!\[CDATA\[")
_RE_DOCTYPE = re.compile(r"<!(?!--)(?!\[CDATA\[)")
_RE_ENTITY = re.compile(r"&([^;&<\s]*);")
_RE_TAG = re.compile(r"<\s*(/?)\s*([^\s/>!?][^\s/>]*|)\s*([^>]*?)(/?)>", re.S)
_RE_ATTR_DQ = re.compile(r'[^\s=<>/]+\s*=\s*"[^"]*"')
_RE_ATTR_SQ = re.compile(r"[^\s=<>/]+\s*=\s*'[^']*'")
_RE_ATTR_VALUE = re.compile(r"""=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>/]+))""")
_RE_ATTR_BARE = re.compile(r"[^\s=<>/]+\s*=\s*[^\s\"'<>/][^\s<>/]*")

# Only the XML declaration may carry an encoding. Searching the whole payload
# for "encoding=" misfiled ordinary character data such as
# `<r>encoding=shift_jis</r>` as a contradictory declaration, which moved a
# well-formed document into byte_hostile and polluted the mixture the loop is
# steered by. The declaration must sit at the start of the document (a BOM and
# leading whitespace are allowed), exactly as XML requires.
_RE_XML_DECL = re.compile(r"^[ \t\r\n\ufeff]*<\?xml\b[^>]*\?>", re.I)
_RE_ENCODING_IN_DECL = re.compile(
    r"""encoding\s*=\s*(?:"([^"]*)"|'([^']*)'|([A-Za-z0-9._-]+))""", re.I)

KNOWN_ENTITIES = frozenset({"amp", "lt", "gt", "quot"})


# Input buckets. The loop asks the generator for a weighted mixture of these and
# reports acceptance per bucket as well as globally.
#
# A single global acceptance band can be satisfied by a generator that has
# drifted entirely into well-formed documents. Zest (ISSTA 2019) reports that
# memory-safety bugs in a parser's syntax stage are reached by syntactically
# invalid input, which such a generator stops producing, so splitting the
# measurement makes that drift visible.
#
# Classified from the productions already detected, so the strategy contract
# stays `documents() -> SearchStrategy[str]` and a generator cannot misreport
# its own mixture.
BUCKET_BYTE_HOSTILE = "byte_hostile"   # control bytes, truncation, bad encoding
BUCKET_NEAR_MISS = "near_miss"         # structurally wrong but XML-shaped
BUCKET_WELL_FORMED = "well_formed"     # should parse

_BYTE_HOSTILE = frozenset({"x_control_char", "x_unterminated", "x_bom",
                           "x_invalid_utf8", "x_embedded_nul"})
_NEAR_MISS = frozenset({"x_mismatched_tags", "x_entity_unsupported",
                        "x_multiple_roots"})


@dataclass
class Features:
    productions: set[str] = field(default_factory=set)
    max_depth: int = 0
    n_elements: int = 0
    n_attributes: int = 0
    n_entities: int = 0
    length: int = 0
    # Boundary measures. Fixed-size buffers and counted loops are where a C
    # parser tends to go wrong, and none of the production flags say how close
    # a document came to any limit. These give the loop something to sweep.
    max_name_len: int = 0
    max_attrs_per_element: int = 0
    max_entity_name_len: int = 0
    max_attr_value_len: int = 0
    # Some rootless documents are accepted extensions (comments, declarations,
    # and PIs), while arbitrary rootless text is a near miss. Keep that nuance
    # out of the public production vocabulary but use it for class assignment.
    malformed_rootless: bool = False
    encoding_mismatch: bool = False

    @property
    def bucket(self) -> str:
        """Which test bucket this document belongs to.

        Order matters: byte-hostile wins over near-miss, because a document that
        is both is exercising the lower-level path and that is the rarer, more
        interesting case.
        """
        if self.productions & _BYTE_HOSTILE:
            return BUCKET_BYTE_HOSTILE
        if self.encoding_mismatch:
            return BUCKET_BYTE_HOSTILE
        if self.productions & _NEAR_MISS:
            return BUCKET_NEAR_MISS
        if self.malformed_rootless:
            return BUCKET_NEAR_MISS
        return BUCKET_WELL_FORMED

    def to_json(self) -> dict:
        return {
            "bucket": self.bucket,
            "productions": sorted(self.productions),
            "max_depth": self.max_depth,
            "n_elements": self.n_elements,
            "n_attributes": self.n_attributes,
            "n_entities": self.n_entities,
            "length": self.length,
            "max_name_len": self.max_name_len,
            "max_attrs_per_element": self.max_attrs_per_element,
            "max_entity_name_len": self.max_entity_name_len,
            "max_attr_value_len": self.max_attr_value_len,
            "malformed_rootless": self.malformed_rootless,
            "encoding_mismatch": self.encoding_mismatch,
        }


# Regions that are NOT element tags but which a naive "<...>" scan happily
# mistakes for them. Ordered longest-opener-first so <![CDATA[ is tried before
# the generic <! declaration.
_MASKABLE: tuple[tuple[str, str], ...] = (
    ("<!--", "-->"),
    ("<![CDATA[", "]]>"),
    ("<?", "?>"),
    ("<!", ">"),
)


def _mask_non_elements(doc: str) -> str:
    """Blank out comments, CDATA, PIs and declarations, preserving length.

    Without this, "<!-- c -->" scans as an element with an empty name whose
    close tag does not match its open tag, so a document containing an ordinary
    comment falsely reports x_empty_elem_name AND x_mismatched_tags, and its
    nesting depth is overstated. Those are exactly the productions the agentic
    loop is steered by, so a false positive here becomes a false instruction to
    the LLM.

    Length is preserved (regions become spaces) so that character data detection
    between tags still sees the right gaps. An unterminated construct is masked
    to end of string, which is correct: nothing after it is an element either.
    """
    out = list(doc)
    i = 0
    n = len(doc)
    while i < n:
        if doc[i] != "<":
            i += 1
            continue
        for opener, closer in _MASKABLE:
            if doc.startswith(opener, i):
                end = doc.find(closer, i + len(opener))
                stop = n if end == -1 else end + len(closer)
                for j in range(i, stop):
                    if out[j] not in "\r\n":
                        out[j] = " "
                i = stop
                break
        else:
            i += 1
    return "".join(out)


def _declared_encoding(doc: str) -> str | None:
    """The encoding named by the XML declaration, normalised, or None.

    Read from the decoded document rather than the raw bytes: a real UTF-16
    document puts a NUL between every ASCII byte, so a byte-level regex never
    sees the word "encoding" even though the declaration is there. Reading the
    text also keeps a stray "encoding=" in character data from counting, since
    only a declaration that starts the document is considered.
    """
    m = _RE_XML_DECL.match(doc)
    if not m:
        return None
    em = _RE_ENCODING_IN_DECL.search(m.group(0))
    if not em:
        return None
    value = next((g for g in em.groups() if g is not None), "")
    return value.strip().lower().replace("_", "-") or None


def _encoding_mismatch(declared: str, payload: bytes) -> bool:
    """True when the declaration contradicts the bytes actually tested.

    A bare `utf-16` declaration is satisfied by either endianness: the BOM is
    what disambiguates it, so treating it as little-endian-only would call a
    legitimate big-endian document contradictory.
    """
    has_le_bom = payload.startswith(b"\xff\xfe")
    has_be_bom = payload.startswith(b"\xfe\xff")

    if declared in ("utf-8", "utf8"):
        return has_le_bom or has_be_bom
    if declared == "utf-16le":
        return not has_le_bom
    if declared == "utf-16be":
        return not has_be_bom
    if declared == "utf-16":
        return not (has_le_bom or has_be_bom)
    # Any other charset: XML's default is UTF-8, and the campaign only emits
    # UTF-8 or UTF-16, so another name is a deliberate contradiction.
    return True


def analyze(doc: str, payload: bytes | None = None) -> Features:
    """Detect which productions a generated document exhibits. Never raises.

    `payload` is the exact bytes written to the harness. A byte-order mark, an
    invalid UTF-8 sequence and an embedded NUL exist only at the byte level and
    are invisible in the decoded string, so they need the payload to detect.
    """
    f = Features(length=len(doc))
    p = f.productions

    if payload is not None:
        if payload.startswith(b"\xef\xbb\xbf") or payload[:2] in (b"\xff\xfe", b"\xfe\xff"):
            p.add("x_bom")
        try:
            payload.decode("utf-8")
        except UnicodeDecodeError:
            p.add("x_invalid_utf8")
        if b"\x00" in payload:
            p.add("x_embedded_nul")

    declared = _declared_encoding(doc)
    if declared is not None:
        p.add("x_encoding_decl")
        if payload is not None:
            f.encoding_mismatch = _encoding_mismatch(declared, payload)

    if _RE_PROLOG.search(doc):
        p.add("g_prolog")
    if _RE_PI.search(doc):
        p.add("g_pi")
    if _RE_COMMENT_OPEN.search(doc):
        p.add("g_comment")
    if _RE_CDATA_OPEN.search(doc):
        p.add("g_cdata")
    if _RE_DOCTYPE.search(doc):
        p.add("x_doctype")

    # Unterminated constructs: an opener with no matching closer. These are the
    # "Early EOF in ..." family of mxml diagnostics.
    for opener, closer in (("<!--", "-->"), ("<![CDATA[", "]]>"), ("<?", "?>")):
        i = doc.find(opener)
        if i != -1 and doc.find(closer, i + len(opener)) == -1:
            p.add("x_unterminated")
            break

    for m in _RE_ENTITY.finditer(doc):
        name = m.group(1)
        f.n_entities += 1
        f.max_entity_name_len = max(f.max_entity_name_len, len(name))
        if name.startswith("#x") or name.startswith("#X"):
            p.add("g_charref_hex")
        elif name.startswith("#"):
            p.add("g_charref_dec")
        elif name in KNOWN_ENTITIES:
            p.add("g_entity_named")
        else:
            p.add("x_entity_unsupported")

    if any(ord(c) < 0x20 and c not in "\t\r\n" for c in doc):
        p.add("x_control_char")

    # Walk tags to get nesting depth, tag matching, and root count. Scanned on
    # a copy with comments/CDATA/PIs/declarations blanked out, so those cannot
    # masquerade as elements. See _mask_non_elements.
    scan = _mask_non_elements(doc)
    depth = 0
    stack: list[str] = []
    roots = 0
    last_end = 0
    saw_text = False

    for m in _RE_TAG.finditer(scan):
        if scan[last_end:m.start()].strip():
            saw_text = True
        last_end = m.end()

        closing, name, attrs, selfclose = m.group(1), m.group(2), m.group(3), m.group(4)
        f.n_elements += 1

        if not name:
            p.add("x_empty_elem_name")
        elif any(ord(c) > 0x7F for c in name):
            p.add("x_name_nonascii")
        f.max_name_len = max(f.max_name_len, len(name))

        if attrs:
            here = 0
            for rx, prod in ((_RE_ATTR_DQ, "g_attribute_dquot"),
                             (_RE_ATTR_SQ, "g_attribute_squot"),
                             (_RE_ATTR_BARE, "x_attribute_unquoted")):
                hits = rx.findall(attrs)
                if hits:
                    p.add(prod)
                    f.n_attributes += len(hits)
                    here += len(hits)
            f.max_attrs_per_element = max(f.max_attrs_per_element, here)
            for v in _RE_ATTR_VALUE.findall(attrs):
                # findall returns one capture per quoting alternative. Measure
                # the selected value, not the fixed three-item tuple.
                value_len = max((len(part) for part in v), default=0)
                f.max_attr_value_len = max(f.max_attr_value_len, value_len)

        if closing:
            if stack:
                if stack[-1] != name:
                    p.add("x_mismatched_tags")
                stack.pop()
                depth -= 1
        elif selfclose:
            p.add("g_element_selfclose")
            if not stack:
                roots += 1
        else:
            p.add("g_element_paired")
            if not stack:
                roots += 1
            stack.append(name)
            depth += 1
            f.max_depth = max(f.max_depth, depth)

    # The XML declaration carries attributes too: the grammar's rule is
    # `prolog : XMLDeclOpen attribute* SPECIAL_CLOSE`. It was masked out above
    # so it could not be mistaken for an element, so its attributes are counted
    # here explicitly rather than being silently lost. Only the declaration is
    # rescanned, not comments or CDATA, whose free text would produce
    # attribute-shaped false positives.
    mp = _RE_PROLOG.search(doc)
    if mp:
        close = doc.find("?>", mp.end())
        prolog_body = doc[mp.end(): close if close != -1 else len(doc)]
        for rx, prod in ((_RE_ATTR_DQ, "g_attribute_dquot"),
                         (_RE_ATTR_SQ, "g_attribute_squot"),
                         (_RE_ATTR_BARE, "x_attribute_unquoted")):
            hits = rx.findall(prolog_body)
            if hits:
                p.add(prod)
                f.n_attributes += len(hits)

    if scan[last_end:].strip():
        saw_text = True
    if saw_text:
        p.add("g_chardata")
    if f.max_depth >= DEEP_NESTING:
        p.add("g_nesting_deep")
    if roots > 1:
        p.add("x_multiple_roots")
    if f.n_elements == 0:
        p.add("x_rootless")
        # Comments, declarations and PIs are accepted rootless extensions in
        # mxml. Non-whitespace text left after masking them is malformed.
        f.malformed_rootless = bool(scan.strip())

    return f


def coverage(feature_list: list[Features]) -> dict:
    """Aggregate production coverage and depth spread over a whole campaign."""
    seen: dict[str, int] = {}
    depths: list[int] = []
    for f in feature_list:
        depths.append(f.max_depth)
        for prod in f.productions:
            seen[prod] = seen.get(prod, 0) + 1

    hit = [p for p in PRODUCTIONS if p in seen]
    missing = [p for p in PRODUCTIONS if p not in seen]

    hist: dict[str, int] = {}
    for d in depths:
        bucket = ("0" if d == 0 else "1" if d == 1 else "2-3" if d <= 3
                  else "4-7" if d <= 7 else "8-15" if d <= 15 else "16+")
        hist[bucket] = hist.get(bucket, 0) + 1

    def spread(vals):
        vals = sorted(vals)
        if not vals:
            return {}
        return {"max": vals[-1], "p50": vals[len(vals) // 2],
                "p90": vals[int(len(vals) * 0.9)], "distinct": len(set(vals))}

    return {
        "productions_hit": len(hit),
        "productions_total": len(PRODUCTIONS),
        "boundaries": {
            "name_len": spread([f.max_name_len for f in feature_list]),
            "attrs_per_element": spread([f.max_attrs_per_element for f in feature_list]),
            "entity_name_len": spread([f.max_entity_name_len for f in feature_list]),
            "attr_value_len": spread([f.max_attr_value_len for f in feature_list]),
            "depth": spread([f.max_depth for f in feature_list]),
        },
        "hit": {p: seen[p] for p in hit},
        "missing": missing,
        "depth_histogram": dict(sorted(hist.items())),
        "max_depth_seen": max(depths) if depths else 0,
    }
