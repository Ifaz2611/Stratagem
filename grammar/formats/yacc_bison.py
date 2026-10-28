"""Yacc / Bison (.y, .yacc) grammar parser and exporter.

Supports:
  * Token declarations (%token TOKEN_NAME ...)
  * Start symbol specification (%start name)
  * Rule syntax (nonterminal : alt1 { action } | alt2 ;)
  * Robust C-action stripping (handles nested braces, strings, comments)
  * Clean round-trip export to standard Bison format
"""
from __future__ import annotations

import re

from grammar.formats.base import Grammar, GrammarSymbol, SymbolType

_RE_C_COMMENTS = re.compile(r"/\*.*?\*/|//.*?$", re.DOTALL | re.MULTILINE)
_RE_TOKEN_DECL = re.compile(r"%token\s+([^;\n%]+)")
_RE_START_DECL = re.compile(r"%start\s+([a-zA-Z_]\w*)")


def parse_yacc(text: str, name: str = "BisonGrammar") -> Grammar:
    """Parse a Yacc/Bison grammar string into a unified Grammar model."""
    grammar = Grammar(name=name, format="bison")

    # 1. Strip C comments
    clean_text = _RE_C_COMMENTS.sub(" ", text)

    # 2. Extract declared tokens
    declared_tokens: set[str] = set()
    for m in _RE_TOKEN_DECL.finditer(clean_text):
        token_str = m.group(1).strip()
        # Remove any <type> tags e.g. <val>
        token_str = re.sub(r"<[^>]+>", " ", token_str)
        for t in token_str.split():
            t = t.strip()
            if t and t.isidentifier():
                declared_tokens.add(t)
                grammar.terminals[t] = t

    # 3. Extract start symbol
    m_start = _RE_START_DECL.search(clean_text)
    if m_start:
        grammar.start_symbol = m_start.group(1).strip()

    # 4. Isolate the rules section (between first %% and second %%)
    parts = clean_text.split("%%")
    if len(parts) >= 2:
        rules_text = parts[1]
    else:
        rules_text = clean_text

    # 5. Strip semantic actions: replace { ... } with empty string, respecting nested braces
    rules_no_actions = _strip_c_actions(rules_text)

    # 6. Parse rules (terminated by ';')
    raw_rules = [r.strip() for r in rules_no_actions.split(";") if r.strip()]

    for raw in raw_rules:
        # Match LHS : RHS
        if ":" not in raw:
            continue
        lhs, rhs = raw.split(":", 1)
        lhs = lhs.strip()
        if not lhs or not lhs.isidentifier():
            continue

        rule = grammar.add_rule(lhs)
        if not grammar.start_symbol or grammar.start_symbol == "start":
            grammar.start_symbol = lhs

        # Alternatives separated by '|'
        alts = rhs.split("|")
        for alt in alts:
            symbols = _parse_bison_symbols(alt.strip(), declared_tokens)
            rule.add_production(symbols)

    return grammar


def _strip_c_actions(text: str) -> str:
    """Remove C action blocks { ... } preserving nested braces."""
    out: list[str] = []
    i = 0
    n = len(text)
    depth = 0
    in_quote: str | None = None

    while i < n:
        ch = text[i]

        if in_quote:
            if ch == in_quote and text[i - 1] != "\\":
                in_quote = None
            if depth == 0:
                out.append(ch)
            i += 1
            continue

        if ch in ('"', "'"):
            in_quote = ch
            if depth == 0:
                out.append(ch)
            i += 1
            continue

        if ch == "{":
            depth += 1
            i += 1
            continue
        elif ch == "}":
            if depth > 0:
                depth -= 1
            i += 1
            continue

        if depth == 0:
            out.append(ch)
        i += 1

    return "".join(out)


def _parse_bison_symbols(alt_text: str, declared_tokens: set[str]) -> list[GrammarSymbol]:
    """Parse symbol tokens in a single alternative."""
    if not alt_text:
        return []

    # Tokens can be: 'c' or "str" or IDENTIFIER or punctuation
    raw_tokens = re.findall(r"'[^']*'|\"[^\"]*\"|[a-zA-Z_0-9\-]+|[^\s\w'\";|{}]+", alt_text)
    symbols: list[GrammarSymbol] = []

    for tok in raw_tokens:
        if (tok.startswith("'") and tok.endswith("'")) or (tok.startswith('"') and tok.endswith('"')):
            symbols.append(GrammarSymbol(name=tok[1:-1], type=SymbolType.LITERAL))
        elif tok in declared_tokens or tok.isupper():
            symbols.append(GrammarSymbol(name=tok, type=SymbolType.TERMINAL))
        elif re.match(r"^[a-zA-Z_]\w*$", tok):
            symbols.append(GrammarSymbol(name=tok, type=SymbolType.NON_TERMINAL))
        else:
            symbols.append(GrammarSymbol(name=tok, type=SymbolType.LITERAL))

    return symbols


def export_yacc(grammar: Grammar) -> str:
    """Export a Grammar model in Yacc/Bison format."""
    return grammar.to_bison()
