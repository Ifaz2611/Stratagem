"""Baseline Hypothesis strategy for JSON parser targets.

Generates structured JSON documents spanning:
- Objects with string keys and nested values
- Arrays with mixed types
- Booleans, integers, floats, nulls
- Strings with escapes and Unicode codepoints
- Controlled near-miss and byte-hostile variations
"""
from __future__ import annotations

import json
from hypothesis import strategies as st

NAME = "json_baseline"
DESCRIPTION = "Hypothesis strategy generating structured JSON documents and mutations"

_PRIMITIVES = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-1000000, max_value=1000000),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(min_size=0, max_size=50),
)


def _json_values():
    return st.recursive(
        _PRIMITIVES,
        lambda children: st.one_of(
            st.lists(children, max_size=5),
            st.dictionaries(st.text(min_size=1, max_size=20), children, max_size=5),
        ),
        max_leaves=15,
    )


@st.composite
def _well_formed_json(draw):
    val = draw(_json_values())
    return json.dumps(val)


@st.composite
def _near_miss_json(draw):
    """Syntactically invalid but JSON-shaped input."""
    base = draw(_well_formed_json())
    mutation = draw(st.sampled_from([
        "trailing_comma", "unquoted_key", "single_quote", "unclosed_brace", "unclosed_bracket"
    ]))
    if mutation == "trailing_comma":
        if "}" in base:
            return base.replace("}", ",}", 1)
        if "]" in base:
            return base.replace("]", ",]", 1)
        return base + ","
    elif mutation == "unquoted_key":
        return base.replace('"', '', 2)
    elif mutation == "single_quote":
        return base.replace('"', "'")
    elif mutation == "unclosed_brace":
        return "{" + base
    elif mutation == "unclosed_bracket":
        return "[" + base
    return base + " }"


@st.composite
def _byte_hostile_json(draw):
    """Inputs with control characters, bad UTF-8, or embedded NUL."""
    base = draw(_well_formed_json())
    kind = draw(st.sampled_from(["control", "nul", "bom", "unclosed_str"]))
    if kind == "control":
        return base + '\x01\x02'
    elif kind == "nul":
        return base + '\x00'
    elif kind == "bom":
        return '\ufeff' + base
    elif kind == "unclosed_str":
        return '{"key": "unclosed string'
    return base


def documents() -> st.SearchStrategy[str]:
    """Mixture across the three classes."""
    return st.one_of(
        st.tuples(st.just("wf"), _well_formed_json()).map(lambda t: t[1]),
        st.tuples(st.just("nm"), _near_miss_json()).map(lambda t: t[1]),
        st.tuples(st.just("bh"), _byte_hostile_json()).map(lambda t: t[1]),
    )
