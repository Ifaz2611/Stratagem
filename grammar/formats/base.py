"""Universal grammar model for Stratagem.

Provides representation and data structures for context-free and context-sensitive
grammars across formats (EBNF, Yacc/Bison, ANTLR v4).
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Sequence


class SymbolType(str, Enum):
    NON_TERMINAL = "non_terminal"
    TERMINAL = "terminal"
    LITERAL = "literal"
    REGEX = "regex"
    EMPTY = "empty"  # epsilon


@dataclass
class GrammarSymbol:
    """A symbol on the right-hand side of a production rule."""
    name: str
    type: SymbolType = SymbolType.NON_TERMINAL
    is_optional: bool = False
    is_repeated: bool = False  # True if * or +
    min_repeat: int = 1
    max_repeat: int = 1

    @property
    def is_terminal(self) -> bool:
        return self.type in (SymbolType.TERMINAL, SymbolType.LITERAL, SymbolType.REGEX)

    def to_ebnf(self) -> str:
        text = f'"{self.name}"' if self.type == SymbolType.LITERAL else self.name
        if self.is_repeated and self.min_repeat == 0:
            return f"{{ {text} }}"
        if self.is_repeated and self.min_repeat == 1:
            return f"{text}+"
        if self.is_optional:
            return f"[ {text} ]"
        return text

    def to_bison(self) -> str:
        if self.type == SymbolType.LITERAL:
            if len(self.name) == 1:
                return f"'{self.name}'"
            return f'"{self.name}"'
        return self.name

    def to_antlr4(self) -> str:
        text = f"'{self.name}'" if self.type == SymbolType.LITERAL else self.name
        if self.is_repeated and self.min_repeat == 0:
            return f"{text}*"
        if self.is_repeated and self.min_repeat == 1:
            return f"{text}+"
        if self.is_optional:
            return f"{text}?"
        return text

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type.value,
            "is_optional": self.is_optional,
            "is_repeated": self.is_repeated,
            "min_repeat": self.min_repeat,
            "max_repeat": self.max_repeat,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> GrammarSymbol:
        return cls(
            name=d["name"],
            type=SymbolType(d.get("type", "non_terminal")),
            is_optional=d.get("is_optional", False),
            is_repeated=d.get("is_repeated", False),
            min_repeat=d.get("min_repeat", 1),
            max_repeat=d.get("max_repeat", 1),
        )


@dataclass
class Production:
    """A single production derivation (alternative) in a grammar rule: lhs -> rhs."""
    lhs: str
    rhs: list[GrammarSymbol] = field(default_factory=list)
    action: str = ""
    precedence: int = 0

    def to_ebnf(self) -> str:
        if not self.rhs:
            return '""'
        return " ".join(s.to_ebnf() for s in self.rhs)

    def to_bison(self) -> str:
        body = " ".join(s.to_bison() for s in self.rhs) if self.rhs else "/* empty */"
        if self.action:
            return f"{body} {{ {self.action} }}"
        return body

    def to_antlr4(self) -> str:
        if not self.rhs:
            return "/* empty */"
        return " ".join(s.to_antlr4() for s in self.rhs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "lhs": self.lhs,
            "rhs": [s.to_dict() for s in self.rhs],
            "action": self.action,
            "precedence": self.precedence,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Production:
        return cls(
            lhs=d["lhs"],
            rhs=[GrammarSymbol.from_dict(s) for s in d.get("rhs", [])],
            action=d.get("action", ""),
            precedence=d.get("precedence", 0),
        )


@dataclass
class Rule:
    """A grammar nonterminal rule grouping one or more production alternatives."""
    name: str
    productions: list[Production] = field(default_factory=list)
    is_lexical: bool = False

    def add_production(self, symbols: Sequence[str | GrammarSymbol], action: str = "") -> Production:
        rhs_symbols: list[GrammarSymbol] = []
        for s in symbols:
            if isinstance(s, GrammarSymbol):
                rhs_symbols.append(s)
            elif s.startswith('"') and s.endswith('"') and len(s) >= 2:
                rhs_symbols.append(GrammarSymbol(name=s[1:-1], type=SymbolType.LITERAL))
            elif s.startswith("'") and s.endswith("'") and len(s) >= 2:
                rhs_symbols.append(GrammarSymbol(name=s[1:-1], type=SymbolType.LITERAL))
            elif s.isupper():
                rhs_symbols.append(GrammarSymbol(name=s, type=SymbolType.TERMINAL))
            else:
                rhs_symbols.append(GrammarSymbol(name=s, type=SymbolType.NON_TERMINAL))
        prod = Production(lhs=self.name, rhs=rhs_symbols, action=action)
        self.productions.append(prod)
        return prod

    def to_ebnf(self) -> str:
        if not self.productions:
            return f"{self.name} = ;"
        alts = "\n    | ".join(p.to_ebnf() for p in self.productions)
        return f"{self.name} = {alts}\n    ;"

    def to_bison(self) -> str:
        if not self.productions:
            return f"{self.name} : /* empty */ ;"
        alts = "\n    | ".join(p.to_bison() for p in self.productions)
        return f"{self.name} : {alts}\n    ;"

    def to_antlr4(self) -> str:
        if not self.productions:
            return f"{self.name} : ;"
        alts = "\n    | ".join(p.to_antlr4() for p in self.productions)
        return f"{self.name} : {alts}\n    ;"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "is_lexical": self.is_lexical,
            "productions": [p.to_dict() for p in self.productions],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Rule:
        r = cls(name=d["name"], is_lexical=d.get("is_lexical", False))
        r.productions = [Production.from_dict(p) for p in d.get("productions", [])]
        return r


@dataclass
class Grammar:
    """The universal grammar model supporting conversion, mutation, and analysis."""
    name: str = "Grammar"
    format: str = "generic"
    start_symbol: str = "start"
    rules: dict[str, Rule] = field(default_factory=dict)
    terminals: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_rule(self, name: str, is_lexical: bool = False) -> Rule:
        if name not in self.rules:
            self.rules[name] = Rule(name=name, is_lexical=is_lexical)
        return self.rules[name]

    def get_rule(self, name: str) -> Rule | None:
        return self.rules.get(name)

    def nonterminals(self) -> list[str]:
        return [r for r, rule in self.rules.items() if not rule.is_lexical]

    def terminal_names(self) -> list[str]:
        terms = set(self.terminals.keys())
        for rule in self.rules.values():
            if rule.is_lexical:
                terms.add(rule.name)
            for prod in rule.productions:
                for sym in prod.rhs:
                    if sym.is_terminal:
                        terms.add(sym.name)
        return sorted(terms)

    def production_count(self) -> int:
        return sum(len(r.productions) for r in self.rules.values())

    def clone(self) -> Grammar:
        return copy.deepcopy(self)

    def to_ebnf(self) -> str:
        lines = [f"(* Grammar: {self.name} in EBNF format *)", ""]
        for rule in self.rules.values():
            lines.append(rule.to_ebnf())
            lines.append("")
        return "\n".join(lines)

    def to_bison(self) -> str:
        lines = [
            f"/* Grammar: {self.name} in Yacc/Bison format */",
            "%{",
            '#include <stdio.h>',
            '#include <stdlib.h>',
            "%}",
            "",
        ]
        # Token declarations
        term_names = [t for t in self.terminal_names() if t.isupper()]
        if term_names:
            lines.append(f"%token {' '.join(sorted(term_names))}")
        if self.start_symbol and self.start_symbol in self.rules:
            lines.append(f"%start {self.start_symbol}")
        lines.extend(["", "%%", ""])

        for rule in self.rules.values():
            if not rule.is_lexical:
                lines.append(rule.to_bison())
                lines.append("")

        lines.extend(["%%", "/* epilogue */"])
        return "\n".join(lines)

    def to_antlr4(self) -> str:
        lines = [
            f"grammar {self.name};",
            "",
            "// Parser rules",
        ]
        for rule in self.rules.values():
            if not rule.is_lexical:
                lines.append(rule.to_antlr4())
                lines.append("")

        lines.append("// Lexer rules")
        for rule in self.rules.values():
            if rule.is_lexical:
                lines.append(rule.to_antlr4())
                lines.append("")
        for tname, tpat in self.terminals.items():
            if tname not in self.rules:
                lines.append(f"{tname} : '{tpat}' ;")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "format": self.format,
            "start_symbol": self.start_symbol,
            "rules": {k: v.to_dict() for k, v in self.rules.items()},
            "terminals": self.terminals,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Grammar:
        g = cls(
            name=d.get("name", "Grammar"),
            format=d.get("format", "generic"),
            start_symbol=d.get("start_symbol", "start"),
            terminals=d.get("terminals", {}),
            metadata=d.get("metadata", {}),
        )
        for k, rd in d.get("rules", {}).items():
            g.rules[k] = Rule.from_dict(rd)
        return g

    def summary(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "format": self.format,
            "start_symbol": self.start_symbol,
            "nonterminals_count": len(self.nonterminals()),
            "productions_count": self.production_count(),
            "terminals_count": len(self.terminal_names()),
            "rules": list(self.rules.keys()),
        }
