"""Structural analysis of generated JSON documents.

Follows the same design principles as fuzzer.features:
- Post-hoc scanning, tolerant of malformed input
- Blackbox-clean
- Measures production vocabulary, nesting depth, and classification buckets
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

JSON_PRODUCTIONS: tuple[str, ...] = (
    # From the grammar
    "g_object",            # { ... }
    "g_array",             # [ ... ]
    "g_pair",              # "key": value
    "g_string",            # "text"
    "g_number_int",        # 123
    "g_number_float",      # 123.456
    "g_number_exp",        # 1e10
    "g_true",              # true
    "g_false",             # false
    "g_null",              # null
    "g_escape_quote",      # \"
    "g_escape_unicode",    # \u0041
    "g_nesting_deep",      # depth >= 8
    # Adaptations / near-miss / parser errors
    "x_trailing_comma",    # [1, 2,] or {"a": 1,}
    "x_unquoted_key",      # {key: "val"}
    "x_single_quote",      # 'str'
    "x_unclosed_brace",    # {"a": 1
    "x_unclosed_bracket",  # [1, 2
    "x_unclosed_string",   # "unterminated
    "x_multiple_roots",    # {} {}
    "x_control_char",      # raw unescaped control char
    # Byte-level productions
    "x_bom",               # UTF-8 or UTF-16 BOM
    "x_invalid_utf8",      # non-UTF-8 bytes
    "x_embedded_nul",      # NUL byte
)

DEEP_NESTING = 8

BUCKET_BYTE_HOSTILE = "byte_hostile"
BUCKET_NEAR_MISS = "near_miss"
BUCKET_WELL_FORMED = "well_formed"

_BYTE_HOSTILE = frozenset({"x_control_char", "x_unclosed_string", "x_bom", "x_invalid_utf8", "x_embedded_nul"})
_NEAR_MISS = frozenset({"x_trailing_comma", "x_unquoted_key", "x_single_quote", "x_unclosed_brace", "x_unclosed_bracket", "x_multiple_roots"})

_RE_BOM_UTF8 = re.compile(rb"^\xef\xbb\xbf")
_RE_BOM_UTF16 = re.compile(rb"^(\xff\xfe|\xfe\xff)")
_RE_NUM_INT = re.compile(r"-?\b\d+\b(?!\.\d)(?![eE])")
_RE_NUM_FLOAT = re.compile(r"-?\b\d+\.\d+\b(?![eE])")
_RE_NUM_EXP = re.compile(r"-?\b\d+(\.\d+)?[eE][+-]?\d+\b")
_RE_TRAILING_COMMA = re.compile(r",\s*[}\]]")
_RE_UNQUOTED_KEY = re.compile(r"[{,]\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:")


@dataclass
class JSONFeatures:
    productions: set[str] = field(default_factory=set)
    max_depth: int = 0
    n_objects: int = 0
    n_arrays: int = 0
    n_pairs: int = 0
    n_strings: int = 0
    n_numbers: int = 0
    length: int = 0
    max_string_len: int = 0
    max_key_len: int = 0

    @property
    def bucket(self) -> str:
        if self.productions & _BYTE_HOSTILE:
            return BUCKET_BYTE_HOSTILE
        if self.productions & _NEAR_MISS:
            return BUCKET_NEAR_MISS
        return BUCKET_WELL_FORMED

    def to_json(self) -> dict:
        return {
            "bucket": self.bucket,
            "productions": sorted(self.productions),
            "max_depth": self.max_depth,
            "n_objects": self.n_objects,
            "n_arrays": self.n_arrays,
            "n_pairs": self.n_pairs,
            "n_strings": self.n_strings,
            "n_numbers": self.n_numbers,
            "length": self.length,
        }


def analyze(text: str, payload: bytes = b"") -> JSONFeatures:
    """Analyze a JSON document text and optional raw byte payload."""
    f = JSONFeatures(length=len(text))
    if not payload:
        payload = text.encode("utf-8", "surrogatepass")

    # Byte-level checks
    if _RE_BOM_UTF8.match(payload) or _RE_BOM_UTF16.match(payload):
        f.productions.add("x_bom")
    if b"\x00" in payload:
        f.productions.add("x_embedded_nul")
    try:
        payload.decode("utf-8")
    except UnicodeDecodeError:
        f.productions.add("x_invalid_utf8")

    # Control chars in text
    for ch in text:
        if ord(ch) < 0x20 and ch not in "\t\r\n":
            f.productions.add("x_control_char")
            break

    # Literals
    if "true" in text:
        f.productions.add("g_true")
    if "false" in text:
        f.productions.add("g_false")
    if "null" in text:
        f.productions.add("g_null")
    if r'\"' in text:
        f.productions.add("g_escape_quote")
    if re.search(r"\\u[0-9a-fA-F]{4}", text):
        f.productions.add("g_escape_unicode")

    # Numbers
    if _RE_NUM_INT.search(text):
        f.productions.add("g_number_int")
    if _RE_NUM_FLOAT.search(text):
        f.productions.add("g_number_float")
    if _RE_NUM_EXP.search(text):
        f.productions.add("g_number_exp")

    # Adaptations
    if _RE_TRAILING_COMMA.search(text):
        f.productions.add("x_trailing_comma")
    if _RE_UNQUOTED_KEY.search(text):
        f.productions.add("x_unquoted_key")
    if re.search(r"'[^']*'", text):
        f.productions.add("x_single_quote")

    # Structural scanning: depth, pairs, objects, arrays, strings
    depth = 0
    max_d = 0
    in_str = False
    escape = False
    str_start = 0
    open_brackets: list[str] = []

    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if in_str:
            if escape:
                escape = False
            elif c == '\\':
                escape = True
            elif c == '"':
                in_str = False
                f.n_strings += 1
                slen = i - str_start
                if slen > f.max_string_len:
                    f.max_string_len = slen
            i += 1
            continue

        if c == '"':
            in_str = True
            str_start = i
            f.productions.add("g_string")
        elif c == '{':
            f.productions.add("g_object")
            f.n_objects += 1
            depth += 1
            if depth > max_d:
                max_d = depth
            open_brackets.append('{')
        elif c == '}':
            if open_brackets and open_brackets[-1] == '{':
                open_brackets.pop()
            depth = max(0, depth - 1)
        elif c == '[':
            f.productions.add("g_array")
            f.n_arrays += 1
            depth += 1
            if depth > max_d:
                max_d = depth
            open_brackets.append('[')
        elif c == ']':
            if open_brackets and open_brackets[-1] == '[':
                open_brackets.pop()
            depth = max(0, depth - 1)
        elif c == ':':
            f.productions.add("g_pair")
            f.n_pairs += 1
        i += 1

    f.max_depth = max_d
    if max_d >= DEEP_NESTING:
        f.productions.add("g_nesting_deep")

    if in_str:
        f.productions.add("x_unclosed_string")
    if '{' in open_brackets:
        f.productions.add("x_unclosed_brace")
    if '[' in open_brackets:
        f.productions.add("x_unclosed_bracket")

    # Multiple roots check
    stripped = text.strip()
    if re.search(r"[}\]]\s*[{[\"'0-9tnf-]", stripped):
        f.productions.add("x_multiple_roots")

    return f


def coverage(feature_list: list[JSONFeatures]) -> dict:
    """Aggregate structural coverage over a batch of JSON documents."""
    seen: dict[str, int] = {}
    depths: list[int] = []
    for f in feature_list:
        depths.append(f.max_depth)
        for prod in f.productions:
            seen[prod] = seen.get(prod, 0) + 1

    hit = [p for p in JSON_PRODUCTIONS if p in seen]
    missing = [p for p in JSON_PRODUCTIONS if p not in seen]

    hist: dict[str, int] = {}
    for d in depths:
        bucket = ("0" if d == 0 else "1" if d == 1 else "2-3" if d <= 3
                  else "4-7" if d <= 7 else "8-15" if d <= 15 else "16+")
        hist[bucket] = hist.get(bucket, 0) + 1

    return {
        "productions_hit": len(hit),
        "productions_total": len(JSON_PRODUCTIONS),
        "hit": {p: seen[p] for p in hit},
        "missing": missing,
        "depth_histogram": dict(sorted(hist.items())),
        "max_depth_seen": max(depths) if depths else 0,
    }
