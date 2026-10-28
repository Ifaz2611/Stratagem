"""ANTLR v4 (.g4) grammar parser and exporter.

Parses ANTLR grammar, parser grammar, and lexer grammar files into the unified Grammar model.
"""
from __future__ import annotations

import re

from grammar.formats.base import Grammar, GrammarSymbol, SymbolType

_RE_ANTLR_COMMENT = re.compile(r"/\*.*?\*/|//.*?$", re.DOTALL | re.MULTILINE)
_RE_ANTLR_TOKEN = re.compile(
    r"('[^']*'|\"[^\"]*\"|[a-zA-Z_0-9\-]+|[():;|*+?])"
)


def parse_antlr(text: str, name: str = "") -> Grammar:
    """Parse an ANTLR v4 (.g4) grammar string into a unified Grammar model."""
    clean_text = _RE_ANTLR_COMMENT.sub(" ", text)

    # Detect grammar name
    m_name = re.search(r"(?:grammar|parser\s+grammar|lexer\s+grammar)\s+([a-zA-Z_]\w*)\s*;", clean_text)
    g_name = name or (m_name.group(1) if m_name else "ANTLRGrammar")

    grammar = Grammar(name=g_name, format="antlr4")

    # Strip options and tokens blocks e.g. options { ... }
    clean_text = re.sub(r"\boptions\s*\{[^}]*\}", " ", clean_text)
    clean_text = re.sub(r"\bheader\s*\{[^}]*\}", " ", clean_text)
    clean_text = re.sub(r"@\w+\s*\{[^}]*\}", " ", clean_text)

    # Split into rules separated by ';'
    raw_rules = [r.strip() for r in clean_text.split(";") if r.strip()]

    for raw in raw_rules:
        # Match rule_name : RHS
        if ":" not in raw:
            continue
        lhs, rhs = raw.split(":", 1)
        lhs = lhs.strip()
        # Skip grammar declaration or keywords
        if not lhs or not lhs.replace("-", "_").isidentifier() or lhs in ("grammar", "options", "import"):
            continue

        is_lex = lhs[0].isupper()
        rule = grammar.add_rule(lhs, is_lexical=is_lex)
        if not is_lex and (not grammar.start_symbol or grammar.start_symbol == "start"):
            grammar.start_symbol = lhs

        # Alternatives separated by '|'
        alts = _split_antlr_alternatives(rhs)
        for alt in alts:
            symbols = _parse_antlr_rhs_tokens(alt)
            if symbols:
                rule.add_production(symbols)

    return grammar


def _split_antlr_alternatives(text: str) -> list[str]:
    """Split text on '|' taking grouping parentheses into account."""
    alts: list[str] = []
    cur: list[str] = []
    depth = 0
    in_quote = False

    for ch in text:
        if ch == "'" and not in_quote:
            in_quote = True
            cur.append(ch)
        elif ch == "'" and in_quote:
            in_quote = False
            cur.append(ch)
        elif not in_quote and ch == "(":
            depth += 1
            cur.append(ch)
        elif not in_quote and ch == ")":
            depth = max(0, depth - 1)
            cur.append(ch)
        elif not in_quote and ch == "|" and depth == 0:
            alts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)

    if cur:
        alts.append("".join(cur).strip())
    return [a for a in alts if a]


def _parse_antlr_rhs_tokens(alt_text: str) -> list[GrammarSymbol]:
    """Parse symbol tokens in an ANTLR alternative."""
    raw_tokens = _RE_ANTLR_TOKEN.findall(alt_text)
    symbols: list[GrammarSymbol] = []
    i = 0
    n = len(raw_tokens)

    while i < n:
        tok = raw_tokens[i]

        # Grouping ( ... )
        if tok == "(":
            block: list[str] = []
            depth = 1
            i += 1
            while i < n and depth > 0:
                if raw_tokens[i] == "(":
                    depth += 1
                elif raw_tokens[i] == ")":
                    depth -= 1
                if depth > 0:
                    block.append(raw_tokens[i])
                i += 1
            sub_syms = _parse_antlr_rhs_tokens(" ".join(block))
            mod = None
            if i < n and raw_tokens[i] in ("*", "+", "?"):
                mod = raw_tokens[i]
                i += 1
            for s in sub_syms:
                if mod == "*":
                    s.is_repeated = True
                    s.min_repeat = 0
                elif mod == "+":
                    s.is_repeated = True
                    s.min_repeat = 1
                elif mod == "?":
                    s.is_optional = True
                symbols.append(s)
            continue

        # String literal: '...' or "..."
        if (tok.startswith("'") and tok.endswith("'")) or (tok.startswith('"') and tok.endswith('"')):
            lit_val = tok[1:-1]
            mod = None
            if i + 1 < n and raw_tokens[i + 1] in ("*", "+", "?"):
                mod = raw_tokens[i + 1]
                i += 1
            sym = GrammarSymbol(
                name=lit_val,
                type=SymbolType.LITERAL,
                is_optional=(mod == "?"),
                is_repeated=(mod in ("*", "+")),
                min_repeat=1 if mod == "+" else (0 if mod == "*" else 1),
            )
            symbols.append(sym)
            i += 1
            continue

        # Identifier
        if re.match(r"^[a-zA-Z_0-9\-]+$", tok):
            mod = None
            if i + 1 < n and raw_tokens[i + 1] in ("*", "+", "?"):
                mod = raw_tokens[i + 1]
                i += 1
            is_term = tok[0].isupper()
            sym = GrammarSymbol(
                name=tok,
                type=SymbolType.TERMINAL if is_term else SymbolType.NON_TERMINAL,
                is_optional=(mod == "?"),
                is_repeated=(mod in ("*", "+")),
                min_repeat=1 if mod == "+" else (0 if mod == "*" else 1),
            )
            symbols.append(sym)
            i += 1
            continue

        i += 1

    return symbols


def export_antlr(grammar: Grammar) -> str:
    """Export a Grammar model in ANTLR v4 format."""
    return grammar.to_antlr4()
