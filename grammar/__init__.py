"""Grammar support package for Stratagem.

Provides:
  * Additional grammar formats (EBNF, Yacc/Bison, ANTLR v4)
  * Automatic grammar extraction from C/C++ and Python parser code
  * Grammar mutation capabilities for boundary and adversarial fuzzing
  * Context-sensitive grammar engine for tag matching, length prefixes, and scoped symbols
"""
from __future__ import annotations

from grammar.context_sensitive import (
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
from grammar.extraction import (
    CodeGrammarExtractor,
    ExtractionReport,
    extract_grammar,
)
from grammar.formats import (
    Grammar,
    GrammarSymbol,
    Production,
    Rule,
    SymbolType,
    convert_grammar,
    export_antlr,
    export_ebnf,
    export_grammar,
    export_yacc,
    load_grammar,
    parse_antlr,
    parse_ebnf,
    parse_yacc,
)
from grammar.mutation import (
    GrammarMutator,
    MutatedGrammar,
    MutationRecord,
    MutationType,
    mutate_grammar,
)

__all__ = [
    # Formats & Model
    "Grammar",
    "Rule",
    "Production",
    "GrammarSymbol",
    "SymbolType",
    "load_grammar",
    "export_grammar",
    "convert_grammar",
    "parse_ebnf",
    "export_ebnf",
    "parse_yacc",
    "export_yacc",
    "parse_antlr",
    "export_antlr",
    # Extraction
    "extract_grammar",
    "CodeGrammarExtractor",
    "ExtractionReport",
    # Mutation
    "mutate_grammar",
    "GrammarMutator",
    "MutatedGrammar",
    "MutationRecord",
    "MutationType",
    # Context-Sensitive
    "ContextSensitiveGrammar",
    "ContextSensitiveGenerator",
    "GenerationContext",
    "ContextConstraint",
    "TagMatchingConstraint",
    "LengthPrefixedConstraint",
    "ScopedSymbolConstraint",
    "ChecksumConstraint",
    "create_xml_context_grammar",
    "create_http_context_grammar",
]
