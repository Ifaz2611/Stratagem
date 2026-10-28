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
from typing import Any
from hypothesis import strategies as st

from fuzzer.strategies.common import (
    inject_bom,
    inject_control_chars,
    inject_nul,
    make_mixture_documents,
)

NAME = "json_baseline"
DESCRIPTION = "Hypothesis strategy generating structured JSON documents and mutations"

_PRIMITIVES = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-1000000, max_value=1000000),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(min_size=0, max_size=50),
)


def _json_values() -> st.SearchStrategy[Any]:
    return st.recursive(
        _PRIMITIVES,
        lambda children: st.one_of(
            st.lists(children, max_size=5),
            st.dictionaries(st.text(min_size=1, max_size=20), children, max_size=5),
        ),
        max_leaves=15,
    )


@st.composite
def _well_formed_json(draw: Any) -> str:
    val = draw(_json_values())
    return json.dumps(val)


@st.composite
def _near_miss_json(draw: Any) -> str:
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
def _byte_hostile_json(draw: Any) -> str:
    """Inputs with control characters, bad UTF-8, or embedded NUL."""
    base = draw(_well_formed_json())
    kind = draw(st.sampled_from(["control", "nul", "bom", "unclosed_str"]))
    if kind == "control":
        return inject_control_chars(base, chars="\x01\x02")
    elif kind == "nul":
        return inject_nul(base)
    elif kind == "bom":
        return inject_bom(base)
    elif kind == "unclosed_str":
        return '{"key": "unclosed string'
    return base


def documents() -> st.SearchStrategy[str]:
    """Mixture across the three classes."""
    return make_mixture_documents(_well_formed_json(), _near_miss_json(), _byte_hostile_json())
