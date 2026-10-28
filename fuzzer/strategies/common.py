"""Shared helper utilities and combinators for Hypothesis fuzzing strategies.

Reduces code duplication across protocol and format-specific baseline strategies
by standardizing:
  * Byte-to-string surrogateescape encoding/decoding
  * Tri-partite mixture composition (well-formed, near-miss, byte-hostile)
  * Standard byte-level mutations (NUL injection, BOM prepend, control chars)
"""
from __future__ import annotations

from hypothesis import strategies as st

COMMON_CONTROL_CHARS: str = "\x01\x02\x07\x0b\x0c\x1f"
UTF8_BOM: str = "\ufeff"
NUL_CHAR: str = "\x00"


def bytes_to_surrogate(data: bytes) -> str:
    """Carry arbitrary bytes through the str-only strategy interface via surrogateescape."""
    return data.decode("utf-8", "surrogateescape")


def surrogate_to_bytes(text: str) -> bytes:
    """Recover original raw bytes from a surrogateescaped string."""
    return text.encode("utf-8", "surrogateescape")


def make_mixture_documents(
    well_formed: st.SearchStrategy[str],
    near_miss: st.SearchStrategy[str],
    byte_hostile: st.SearchStrategy[str],
) -> st.SearchStrategy[str]:
    """Compose a tri-partite strategy from well-formed, near-miss, and byte-hostile strategies."""
    return st.one_of(
        st.tuples(st.just("wf"), well_formed).map(lambda t: t[1]),
        st.tuples(st.just("nm"), near_miss).map(lambda t: t[1]),
        st.tuples(st.just("bh"), byte_hostile).map(lambda t: t[1]),
    )


def inject_nul(base: str) -> str:
    """Append or embed a NUL byte into the string."""
    return base + NUL_CHAR


def inject_bom(base: str) -> str:
    """Prepend a Unicode BOM to the string."""
    return UTF8_BOM + base


def inject_control_chars(base: str, target: str | None = None, chars: str = "\x01\x02") -> str:
    """Insert control characters into base string or replace a target substring."""
    if target and target in base:
        return base.replace(target, target + chars, 1)
    return base + chars
