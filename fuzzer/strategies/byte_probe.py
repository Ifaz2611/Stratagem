"""Deterministic byte-level probes for the serializer and parser front end.

This is a pipeline probe, not an LLM-generated strategy. It makes each raw-byte
case explicit so a sampled grammar strategy cannot accidentally miss UTF-16 or
malformed UTF-8 while still claiming byte-level coverage.
"""
from __future__ import annotations

from hypothesis import strategies as st

NAME = "mxml_byte_pipeline_probe"
DESCRIPTION = "explicit UTF-16 BOM, invalid UTF-8, NUL, and encoding-lie inputs"


def _raw(data: bytes) -> str:
    """Carry arbitrary bytes through the str-only strategy interface."""
    return data.decode("utf-8", "surrogateescape")


_CASES = (
    _raw(b"\xff\xfe<\x00r\x00/\x00>\x00"),
    _raw(b"\xfe\xff\x00<\x00r\x00/\x00>"),
    _raw(b"\xff\xfe<\x00r"),
    _raw(b"\xef\xbb\xbf<r/>"),
    _raw(b"<r>\xc3</r>"),
    _raw(b"<r>\xed\xa0\x80</r>"),
    _raw(b"<r>\x00</r>"),
    '<?xml version="1.0" encoding="UTF-16"?><r/>',
)


def documents() -> st.SearchStrategy[str]:
    return st.sampled_from(_CASES)
