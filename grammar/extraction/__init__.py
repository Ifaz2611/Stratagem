"""Grammar extraction package for Stratagem.

Provides automatic grammar extraction from existing C/C++ and Python parser code.
"""
from __future__ import annotations

from grammar.extraction.extractor import (
    CodeGrammarExtractor,
    ExtractionReport,
    extract_grammar,
)

__all__ = [
    "CodeGrammarExtractor",
    "ExtractionReport",
    "extract_grammar",
]
