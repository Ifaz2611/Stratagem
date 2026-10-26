"""Automatic grammar extraction from existing parser code.

Extracts context-free grammar specifications from C/C++ and Python parser implementations
by analyzing:
  * Recursive descent parser function call graphs (parse_*, read_*, decode_*)
  * Branching control flow (switch statements, if/else cascades -> alternatives '|')
  * Loop structures (while, for -> repetitions '*', '+')
  * Token and character comparisons (*p == '{', strcmp(tok, "GET") -> terminals/literals)
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from grammar.formats.base import Grammar, GrammarSymbol, Production, Rule, SymbolType

# Function name prefixes that typically indicate a parser rule
_PARSE_FUNC_PREFIXES = (
    "parse_",
    "read_",
    "scan_",
    "lex_",
    "consume_",
    "decode_",
    "match_",
    "mxml_",
    "json_",
    "http_",
    "xml_",
)


@dataclass
class ExtractionReport:
    """Detailed summary of the grammar extraction process."""
    source_language: str
    functions_analyzed: int
    rules_extracted: int
    productions_extracted: int
    terminals_extracted: int
    call_graph: dict[str, list[str]] = field(default_factory=dict)
    confidence_score: float = 1.0
    grammar: Grammar = field(default_factory=Grammar)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_language": self.source_language,
            "functions_analyzed": self.functions_analyzed,
            "rules_extracted": self.rules_extracted,
            "productions_extracted": self.productions_extracted,
            "terminals_extracted": self.terminals_extracted,
            "call_graph": self.call_graph,
            "confidence_score": round(self.confidence_score, 3),
            "grammar_summary": self.grammar.summary(),
        }


class CodeGrammarExtractor:
    """Extractor for recovering grammars from C/C++ and Python parser code."""

    def __init__(self, grammar_name: str = "ExtractedGrammar") -> None:
        self.grammar_name = grammar_name

    def extract_from_file(self, file_path: str | Path) -> ExtractionReport:
        """Extract a grammar from a source code file (C, C++, or Python)."""
        p = Path(file_path)
        if not p.exists():
            raise FileNotFoundError(f"Source file not found: {p}")
        code = p.read_text(encoding="utf-8", errors="replace")
        ext = p.suffix.lower()
        if ext in (".py", ".pyw"):
            return self.extract_from_python(code, source_name=p.stem)
        else:
            return self.extract_from_c(code, source_name=p.stem)

    def extract_from_python(self, code: str, source_name: str = "ExtractedGrammar") -> ExtractionReport:
        """Extract grammar rules from Python recursive descent parser code using AST."""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            # Fall back to lexical C-like extraction if Python AST fails
            return self.extract_from_c(code, source_name=source_name)

        grammar = Grammar(name=source_name, format="ebnf")
        call_graph: dict[str, list[str]] = {}
        parse_funcs: dict[str, ast.FunctionDef] = {}

        # 1. Identify all parse functions
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                fname = node.name.lower()
                if any(fname.startswith(pre) for pre in _PARSE_FUNC_PREFIXES) or "parse" in fname:
                    rule_name = self._normalize_rule_name(node.name)
                    parse_funcs[rule_name] = node

        # 2. Analyze body of each parse function
        for rule_name, func_node in parse_funcs.items():
            rule = grammar.add_rule(rule_name)
            if not grammar.start_symbol or grammar.start_symbol == "start":
                grammar.start_symbol = rule_name

            callees: list[str] = []
            literals: list[str] = []

            # Find called parse functions and string comparisons
            for child in ast.walk(func_node):
                if isinstance(child, ast.Call):
                    callee_name = ""
                    if isinstance(child.func, ast.Name):
                        callee_name = child.func.id
                    elif isinstance(child.func, ast.Attribute):
                        callee_name = child.func.attr

                    c_norm = self._normalize_rule_name(callee_name)
                    if c_norm in parse_funcs and c_norm != rule_name:
                        if c_norm not in callees:
                            callees.append(c_norm)

                # Character/string comparisons
                elif isinstance(child, ast.Compare):
                    for comp in child.comparators:
                        if isinstance(comp, ast.Constant) and isinstance(comp.value, str):
                            val = comp.value
                            if 0 < len(val) <= 16 and val not in literals:
                                literals.append(val)

            call_graph[rule_name] = callees

            # Build production alternatives
            # Alternative 1: sequence of callees and detected literals
            rhs_symbols: list[GrammarSymbol] = []
            for lit in literals[:4]:
                rhs_symbols.append(GrammarSymbol(name=lit, type=SymbolType.LITERAL))
            for c in callees:
                rhs_symbols.append(GrammarSymbol(name=c, type=SymbolType.NON_TERMINAL))

            if rhs_symbols:
                rule.add_production(rhs_symbols)
            else:
                # Leaf terminal rule
                rule.add_production([GrammarSymbol(name="TOKEN", type=SymbolType.TERMINAL)])

            # Check if function has while/for loops indicating repetition
            has_loop = any(isinstance(c, (ast.While, ast.For)) for c in ast.walk(func_node))
            if has_loop and callees:
                # Add repeated alternative
                rep_syms = [GrammarSymbol(name=c, type=SymbolType.NON_TERMINAL, is_repeated=True, min_repeat=0) for c in callees]
                rule.add_production(rep_syms)

        prod_count = grammar.production_count()
        confidence = 0.85 if prod_count > 0 else 0.2

        return ExtractionReport(
            source_language="python",
            functions_analyzed=len(parse_funcs),
            rules_extracted=len(grammar.rules),
            productions_extracted=prod_count,
            terminals_extracted=len(grammar.terminal_names()),
            call_graph=call_graph,
            confidence_score=confidence,
            grammar=grammar,
        )

    def extract_from_c(self, code: str, source_name: str = "ExtractedGrammar") -> ExtractionReport:
        """Extract grammar rules from C/C++ parser source code."""
        grammar = Grammar(name=source_name, format="ebnf")
        call_graph: dict[str, list[str]] = {}

        # 1. Strip comments
        clean_code = re.sub(r"/\*.*?\*/|//.*?$", " ", code, flags=re.DOTALL | re.MULTILINE)

        # 2. Find function definitions with balanced bodies
        # Match e.g. "static int parse_element(char *p) {" or "mxml_node_t *mxmlLoadString(...) {"
        func_pat = re.compile(
            r"(?:static\s+|inline\s+)?(?:[a-zA-Z_]\w*\s*\*?\s+)+([a-zA-Z_]\w*)\s*\([^)]*\)\s*\{",
            re.MULTILINE,
        )

        funcs: dict[str, str] = {}
        for m in func_pat.finditer(clean_code):
            fname = m.group(1)
            fname_lower = fname.lower()
            if any(fname_lower.startswith(pre) for pre in _PARSE_FUNC_PREFIXES) or "parse" in fname_lower or "load" in fname_lower:
                body_start = m.end() - 1
                body = self._extract_balanced_block(clean_code, body_start)
                if body:
                    rule_name = self._normalize_rule_name(fname)
                    funcs[rule_name] = body

        # 3. Analyze each extracted C function body
        for rule_name, body in funcs.items():
            rule = grammar.add_rule(rule_name)
            if not grammar.start_symbol or grammar.start_symbol == "start":
                grammar.start_symbol = rule_name

            callees: list[str] = []
            literals: list[str] = []

            # Check calls to other known parser functions
            for other_rule in funcs:
                if other_rule != rule_name:
                    # Look for invocation pattern
                    if re.search(r"\b" + re.escape(other_rule) + r"\s*\(", body):
                        if other_rule not in callees:
                            callees.append(other_rule)

            # Character comparisons: e.g. *p == '<' or c == '{' or case '<':
            char_matches = re.findall(r"(?:==\s*|case\s*)'([^'\\]|\\.)'", body)
            for ch in char_matches:
                if ch not in literals and len(ch) <= 2:
                    literals.append(ch)

            # String comparisons: strcmp(..., "GET") or strncmp(..., "HTTP", ...)
            str_matches = re.findall(r'(?:strcmp|strncmp|match|memcmp)\s*\([^,]+,\s*"([^"\\]+)"', body)
            for s in str_matches:
                if s not in literals and len(s) <= 16:
                    literals.append(s)

            call_graph[rule_name] = callees

            # Check for switch-case alternatives
            has_switch = "switch" in body and "case" in body
            has_loop = "while" in body or "for (" in body

            # Build production 1: sequence
            seq_symbols: list[GrammarSymbol] = []
            for lit in literals[:3]:
                seq_symbols.append(GrammarSymbol(name=lit, type=SymbolType.LITERAL))
            for c in callees:
                seq_symbols.append(GrammarSymbol(name=c, type=SymbolType.NON_TERMINAL))

            if seq_symbols:
                rule.add_production(seq_symbols)
            elif literals:
                for lit in literals[:4]:
                    rule.add_production([GrammarSymbol(name=lit, type=SymbolType.LITERAL)])
            else:
                rule.add_production([GrammarSymbol(name="TOKEN", type=SymbolType.TERMINAL)])

            # If switch-case or branches exist with multiple callees, add independent alternatives
            if (has_switch or "else if" in body) and len(callees) > 1:
                for c in callees:
                    rule.add_production([GrammarSymbol(name=c, type=SymbolType.NON_TERMINAL)])

            # If loops exist, add repeated variant
            if has_loop and callees:
                rule.add_production([
                    GrammarSymbol(name=callees[0], type=SymbolType.NON_TERMINAL, is_repeated=True, min_repeat=0)
                ])

        prod_count = grammar.production_count()
        confidence = 0.80 if prod_count > 0 else 0.15

        return ExtractionReport(
            source_language="c",
            functions_analyzed=len(funcs),
            rules_extracted=len(grammar.rules),
            productions_extracted=prod_count,
            terminals_extracted=len(grammar.terminal_names()),
            call_graph=call_graph,
            confidence_score=confidence,
            grammar=grammar,
        )

    def _normalize_rule_name(self, raw_name: str) -> str:
        """Convert a C/Python function name to a clean nonterminal rule name."""
        name = raw_name
        for pre in _PARSE_FUNC_PREFIXES:
            if name.lower().startswith(pre):
                name = name[len(pre):]
                break
        name = name.strip("_").lower()
        return name if name else raw_name.lower()

    def _extract_balanced_block(self, text: str, start_brace_idx: int) -> str:
        """Extract code enclosed within { ... } starting at start_brace_idx."""
        if start_brace_idx >= len(text) or text[start_brace_idx] != "{":
            return ""
        depth = 0
        i = start_brace_idx
        n = len(text)
        in_quote: str | None = None

        while i < n:
            ch = text[i]
            if in_quote:
                if ch == in_quote and text[i - 1] != "\\":
                    in_quote = None
                i += 1
                continue

            if ch in ('"', "'"):
                in_quote = ch
                i += 1
                continue

            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start_brace_idx:i + 1]
            i += 1
        return text[start_brace_idx:min(n, start_brace_idx + 2000)]


def extract_grammar(source: str | Path, name: str = "ExtractedGrammar") -> ExtractionReport:
    """Convenience function to extract a Grammar from file path or source text."""
    p = Path(source) if isinstance(source, Path) or (isinstance(source, str) and "\n" not in source and Path(source).exists()) else None
    extractor = CodeGrammarExtractor(grammar_name=name)
    if p and p.exists():
        return extractor.extract_from_file(p)
    else:
        text = str(source)
        if "def " in text and ("import " in text or ":" in text):
            return extractor.extract_from_python(text, source_name=name)
        else:
            return extractor.extract_from_c(text, source_name=name)
