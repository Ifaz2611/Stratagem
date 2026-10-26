"""Grammar formats package for Stratagem.

Provides parsers and exporters for:
  * EBNF (ISO/IEC 14977 and W3C notations)
  * Yacc / Bison (.y, .yacc)
  * ANTLR v4 (.g4)
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from grammar.formats.antlr import export_antlr, parse_antlr
from grammar.formats.base import (
    Grammar,
    GrammarSymbol,
    Production,
    Rule,
    SymbolType,
)
from grammar.formats.ebnf import export_ebnf, parse_ebnf
from grammar.formats.yacc_bison import export_yacc, parse_yacc


def load_grammar(path_or_text: str | Path, format: str | None = None, name: str = "") -> Grammar:
    """Load and parse a grammar from a file path or raw string.

    Automatically detects format from file extension (.ebnf, .bnf, .y, .yacc, .g4)
    or grammar markers if format is not explicitly provided.
    """
    path = Path(path_or_text) if isinstance(path_or_text, Path) or (isinstance(path_or_text, str) and "\n" not in path_or_text and Path(path_or_text).exists()) else None

    if path and path.exists():
        text = path.read_text(encoding="utf-8", errors="replace")
        ext = path.suffix.lower()
        if not name:
            name = path.stem
        if not format:
            if ext in (".ebnf", ".bnf"):
                format = "ebnf"
            elif ext in (".y", ".yacc", ".bison"):
                format = "bison"
            elif ext == ".g4":
                format = "antlr4"
    else:
        text = str(path_or_text)

    # Content-based format autodetection if still unknown
    if not format:
        if "%%" in text or "%token" in text:
            format = "bison"
        elif "grammar " in text or "parser grammar " in text:
            format = "antlr4"
        elif "::=" in text or "(*" in text or "=" in text:
            format = "ebnf"
        else:
            format = "ebnf"

    fmt = format.lower().strip()
    if fmt in ("ebnf", "bnf"):
        return parse_ebnf(text, name=name or "EBNFGrammar")
    elif fmt in ("bison", "yacc", "y"):
        return parse_yacc(text, name=name or "BisonGrammar")
    elif fmt in ("antlr", "antlr4", "g4"):
        return parse_antlr(text, name=name or "ANTLRGrammar")
    else:
        raise ValueError(f"Unsupported grammar format: '{format}'. Supported: ebnf, bison, antlr4")


def export_grammar(grammar: Grammar, format: str) -> str:
    """Serialize a Grammar instance into the specified target format."""
    fmt = format.lower().strip()
    if fmt in ("ebnf", "bnf"):
        return export_ebnf(grammar)
    elif fmt in ("bison", "yacc", "y"):
        return export_yacc(grammar)
    elif fmt in ("antlr", "antlr4", "g4"):
        return export_antlr(grammar)
    else:
        raise ValueError(f"Unsupported export format: '{format}'. Supported: ebnf, bison, antlr4")


def convert_grammar(source: str | Path, target_format: str, source_format: str | None = None) -> str:
    """Convert a grammar from one format to another."""
    g = load_grammar(source, format=source_format)
    return export_grammar(g, target_format)


__all__ = [
    "Grammar",
    "Rule",
    "Production",
    "GrammarSymbol",
    "SymbolType",
    "parse_ebnf",
    "export_ebnf",
    "parse_yacc",
    "export_yacc",
    "parse_antlr",
    "export_antlr",
    "load_grammar",
    "export_grammar",
    "convert_grammar",
]
