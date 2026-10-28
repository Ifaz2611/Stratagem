"""Extended Backus-Naur Form (EBNF) parser and exporter.

Supports ISO/IEC 14977 and W3C/standard EBNF notations:
  * Nonterminal declarations (rule = ... ; or rule ::= ...)
  * Alternatives (|)
  * Optionals ([ ... ] or symbol?)
  * Repetitions ({ ... }, symbol*, or symbol+)
  * Grouping (( ... ))
  * Literals ("..." or '...')
  * Comments ((* ... *), // ..., # ...)
"""
from __future__ import annotations

import re

from grammar.formats.base import Grammar, GrammarSymbol, SymbolType

_RE_EBNF_COMMENT = re.compile(r"\(\*.*?\*\)|//.*?$|#.*?$", re.DOTALL | re.MULTILINE)
_RE_TOKEN = re.compile(
    r'("[^"]*"|\'[^\']*\'|::=|[:=;,|?*+(){}\[\]]|\w+)'
)


def parse_ebnf(text: str, name: str = "EBNFGrammar") -> Grammar:
    """Parse an EBNF grammar string into a unified Grammar model."""
    grammar = Grammar(name=name, format="ebnf")
    clean_text = _RE_EBNF_COMMENT.sub(" ", text)

    # Find rule definitions: LHS (= | ::= | :) RHS (;)
    # We can split on ';' or extract rules
    raw_rules = [r.strip() for r in clean_text.split(";") if r.strip()]

    # If no semicolons, split on lines that define a rule: ^\s*([a-zA-Z_]\w*)\s*(?:=|::=|:)
    if len(raw_rules) <= 1 and (";" not in clean_text):
        lines = clean_text.splitlines()
        grouped: list[str] = []
        cur: list[str] = []
        for line in lines:
            line_s = line.strip()
            if not line_s:
                continue
            if re.match(r"^[a-zA-Z_]\w*\s*(?:=|::=|:)", line_s) and cur:
                grouped.append(" ".join(cur))
                cur = [line_s]
            else:
                cur.append(line_s)
        if cur:
            grouped.append(" ".join(cur))
        raw_rules = grouped

    for raw in raw_rules:
        # Match LHS and separator
        m = re.match(r"^\s*([a-zA-Z_0-9\-]+)\s*(=|::=|:)\s*(.*)$", raw, re.DOTALL)
        if not m:
            continue
        lhs = m.group(1).strip()
        rhs_text = m.group(3).strip()

        rule = grammar.add_rule(lhs)
        if not grammar.start_symbol or grammar.start_symbol == "start":
            grammar.start_symbol = lhs

        # Split alternatives by '|'
        # Be careful not to split inside quotes
        alternatives = _split_alternatives(rhs_text)
        for alt in alternatives:
            symbols = _parse_ebnf_rhs_tokens(alt)
            if symbols:
                rule.add_production(symbols)

    return grammar


def _split_alternatives(text: str) -> list[str]:
    """Split text on '|' not enclosed in quotes or brackets."""
    alts: list[str] = []
    cur: list[str] = []
    in_quote: str | None = None
    depth = 0

    for ch in text:
        if in_quote:
            cur.append(ch)
            if ch == in_quote:
                in_quote = None
        elif ch in ('"', "'"):
            in_quote = ch
            cur.append(ch)
        elif ch in ("(", "[", "{"):
            depth += 1
            cur.append(ch)
        elif ch in (")", "]", "}"):
            depth = max(0, depth - 1)
            cur.append(ch)
        elif ch == "|" and depth == 0:
            alts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)

    if cur:
        alts.append("".join(cur).strip())
    return [a for a in alts if a]


def _parse_ebnf_rhs_tokens(alt_text: str) -> list[GrammarSymbol]:
    """Parse symbols in an alternative clause."""
    raw_tokens = _RE_TOKEN.findall(alt_text)
    symbols: list[GrammarSymbol] = []
    i = 0
    n = len(raw_tokens)

    while i < n:
        tok = raw_tokens[i]

        # Ignore commas (EBNF concatenation operator)
        if tok == ",":
            i += 1
            continue

        # Optional block: [ ... ]
        if tok == "[":
            block: list[str] = []
            depth = 1
            i += 1
            while i < n and depth > 0:
                if raw_tokens[i] == "[":
                    depth += 1
                elif raw_tokens[i] == "]":
                    depth -= 1
                if depth > 0:
                    block.append(raw_tokens[i])
                i += 1
            sub_syms = _parse_ebnf_rhs_tokens(" ".join(block))
            for s in sub_syms:
                s.is_optional = True
                symbols.append(s)
            continue

        # Repetition block: { ... } (0 or more)
        if tok == "{":
            block = []
            depth = 1
            i += 1
            while i < n and depth > 0:
                if raw_tokens[i] == "{":
                    depth += 1
                elif raw_tokens[i] == "}":
                    depth -= 1
                if depth > 0:
                    block.append(raw_tokens[i])
                i += 1
            sub_syms = _parse_ebnf_rhs_tokens(" ".join(block))
            for s in sub_syms:
                s.is_repeated = True
                s.min_repeat = 0
                symbols.append(s)
            continue

        # Grouping block: ( ... )
        if tok == "(":
            block = []
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
            sub_syms = _parse_ebnf_rhs_tokens(" ".join(block))
            # Check for trailing modifier after group, e.g. ( ... )* or ( ... )?
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

        # String literal: "..." or '...'
        if (tok.startswith('"') and tok.endswith('"')) or (tok.startswith("'") and tok.endswith("'")):
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
            is_term = tok.isupper()
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


def export_ebnf(grammar: Grammar) -> str:
    """Export a Grammar model as an EBNF string."""
    return grammar.to_ebnf()
