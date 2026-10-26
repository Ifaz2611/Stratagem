"""Context-sensitive grammar package for Stratagem.

Provides:
  * GenerationContext with dynamic scope stacks and symbol tables
  * TagMatchingConstraint (matches opening & closing XML/HTML tags)
  * LengthPrefixedConstraint (calculates and binds payload lengths)
  * ScopedSymbolConstraint (declaration-before-use entity/variable tables)
  * ChecksumConstraint (computes dynamic CRCs over generated data)
  * ContextSensitiveGrammar & ContextSensitiveGenerator
"""
from __future__ import annotations

from grammar.context_sensitive.engine import (
    ChecksumConstraint,
    ContextConstraint,
    ContextSensitiveGenerator,
    ContextSensitiveGrammar,
    GenerationContext,
    LengthPrefixedConstraint,
    ScopedSymbolConstraint,
    TagMatchingConstraint,
    create_http_context_grammar,
    create_xml_context_grammar,
)

__all__ = [
    "ContextConstraint",
    "GenerationContext",
    "TagMatchingConstraint",
    "LengthPrefixedConstraint",
    "ScopedSymbolConstraint",
    "ChecksumConstraint",
    "ContextSensitiveGrammar",
    "ContextSensitiveGenerator",
    "create_xml_context_grammar",
    "create_http_context_grammar",
]
