"""Baseline strategy: intentionally naive.

Random Unicode text with no knowledge of XML. It exists to validate the pipeline
end to end (generate, serialise, run the harness, classify, log) and to give the
LLM-written strategies a before number to be measured against.

Expect near-total rejection: random text rarely begins with '<', so most
documents die on mxml's first check.

st.text() is given the full Unicode range including surrogates. The campaign
preserves U+DC80..U+DCFF as raw byte sentinels and encodes other lone surrogates
with surrogatepass, which exercises mxml's UTF-8 decoder.
"""

from __future__ import annotations

from hypothesis import strategies as st

NAME = "baseline"
DESCRIPTION = "naive random Unicode text, no XML structure whatsoever"


def documents() -> st.SearchStrategy[str]:
    return st.text(
        alphabet=st.characters(min_codepoint=1, max_codepoint=0x10FFFF),
        min_size=0,
        max_size=200,
    )
