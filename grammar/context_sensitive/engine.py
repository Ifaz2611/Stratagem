"""Context-sensitive grammar engine for Stratagem.

Supports properties beyond context-free grammars (Chomsky Type-1):
  * Tag matching constraints: Opening and closing tags must match (e.g. <a>...</a> vs <a>...</b>)
  * Length-prefixed protocols: Payload length dynamically calculated and prepended
  * Scoped symbol tables: Identifier declarations before references (variables, entities, namespaces)
  * Checksum & digest constraints: Automated CRC/checksum calculation over generated payloads
  * Controlled constraint violation: Injecting near-miss or malformed violations for boundary fuzzing
"""
from __future__ import annotations

import binascii
import copy
import random
import struct
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from grammar.formats.base import Grammar, GrammarSymbol, Production, Rule, SymbolType


class GenerationContext:
    """Dynamic context state maintaining bindings, scope stack, and symbol tables."""

    def __init__(self, rng: random.Random | None = None, corrupt_prob: float = 0.0) -> None:
        self.rng = rng or random.Random()
        self.corrupt_prob = corrupt_prob
        self.scope_stack: list[dict[str, Any]] = [{}]
        self.symbol_table: set[str] = set()

    def push_scope(self) -> None:
        self.scope_stack.append({})

    def pop_scope(self) -> dict[str, Any]:
        if len(self.scope_stack) > 1:
            return self.scope_stack.pop()
        return self.scope_stack[0]

    def bind(self, key: str, value: Any) -> None:
        """Bind a variable in the current innermost scope."""
        self.scope_stack[-1][key] = value

    def lookup(self, key: str) -> Any:
        """Lookup a variable searching from innermost to outermost scope."""
        for scope in reversed(self.scope_stack):
            if key in scope:
                return scope[key]
        return None

    def declare_symbol(self, symbol: str) -> None:
        self.symbol_table.add(symbol)

    def has_symbol(self, symbol: str) -> bool:
        return symbol in self.symbol_table


class ContextConstraint:
    """Base class for semantic constraints in context-sensitive rules."""

    def evaluate(self, ctx: GenerationContext, generator: ContextSensitiveGenerator) -> str | bytes:
        raise NotImplementedError


class TagMatchingConstraint(ContextConstraint):
    """Enforces that closing tag matches opening tag: <tag>...</tag>.

    Supports controlled near-miss violation (e.g. <a></b>) when corrupt_prob > 0.
    """

    def __init__(
        self,
        tag_symbols: Sequence[str] = ("div", "span", "p", "a", "b", "item", "node", "root"),
        content_rule: str = "content",
    ) -> None:
        self.tag_symbols = list(tag_symbols)
        self.content_rule = content_rule

    def evaluate(self, ctx: GenerationContext, generator: ContextSensitiveGenerator) -> str:
        tag = ctx.rng.choice(self.tag_symbols)
        ctx.push_scope()
        ctx.bind("current_tag", tag)

        # Generate inner content
        content = generator.generate_symbol(self.content_rule, ctx)
        closing_tag = tag

        # Controlled mutation/corruption check
        if ctx.rng.random() < ctx.corrupt_prob:
            # Mismatch: choose a different tag
            other_tags = [t for t in self.tag_symbols if t != tag]
            if other_tags:
                closing_tag = ctx.rng.choice(other_tags)

        ctx.pop_scope()
        return f"<{tag}>{content}</{closing_tag}>"


class LengthPrefixedConstraint(ContextConstraint):
    """Generates a payload and prepends its length formatted as ASCII decimal or binary integer."""

    def __init__(
        self,
        payload_rule: str,
        format_type: str = "ascii_header",  # "ascii_header", "ascii_decimal", "uint16_be", "uint32_be", "uint8"
        header_name: str = "Content-Length",
    ) -> None:
        self.payload_rule = payload_rule
        self.format_type = format_type
        self.header_name = header_name

    def evaluate(self, ctx: GenerationContext, generator: ContextSensitiveGenerator) -> str | bytes:
        payload = generator.generate_symbol(self.payload_rule, ctx)
        payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else payload
        length = len(payload_bytes)

        # Deliberate corruption for boundary/overflow testing
        if ctx.rng.random() < ctx.corrupt_prob:
            length_choice = ctx.rng.choice(["off_by_one", "underflow", "huge_overflow", "zero"])
            if length_choice == "off_by_one":
                length += ctx.rng.choice([-1, 1])
            elif length_choice == "underflow":
                length = max(0, length // 2)
            elif length_choice == "huge_overflow":
                length = length * 100 + 9999
            elif length_choice == "zero":
                length = 0

        if self.format_type == "ascii_header":
            return f"{self.header_name}: {length}\r\n\r\n{payload}"
        elif self.format_type == "ascii_decimal":
            return f"{length}:{payload}"
        elif self.format_type == "uint8":
            return bytes([min(255, length)]) + payload_bytes
        elif self.format_type == "uint16_be":
            return struct.pack(">H", min(65535, length)) + payload_bytes
        elif self.format_type == "uint32_be":
            return struct.pack(">I", length) + payload_bytes
        else:
            return f"{length}:{payload}"


class ScopedSymbolConstraint(ContextConstraint):
    """Enforces declaration-before-use or references to declared entities/variables."""

    def __init__(
        self,
        action: str = "reference",  # "declare" or "reference"
        symbol_pool: Sequence[str] = ("alpha", "beta", "gamma", "delta", "epsilon"),
    ) -> None:
        self.action = action
        self.symbol_pool = list(symbol_pool)

    def evaluate(self, ctx: GenerationContext, generator: ContextSensitiveGenerator) -> str:
        if self.action == "declare":
            sym = ctx.rng.choice(self.symbol_pool)
            ctx.declare_symbol(sym)
            return f'<!ENTITY {sym} "val_{sym}">'
        else:
            # Reference
            if ctx.symbol_table and ctx.rng.random() >= ctx.corrupt_prob:
                sym = ctx.rng.choice(list(ctx.symbol_table))
            else:
                # Undefined symbol reference (corrupt / undeclared)
                undeclared = [s for s in self.symbol_pool if s not in ctx.symbol_table]
                sym = ctx.rng.choice(undeclared) if undeclared else "undefined_sym"
            return f"&{sym};"


class ChecksumConstraint(ContextConstraint):
    """Appends an automated CRC32 or Adler32 checksum over the payload."""

    def __init__(self, payload_rule: str, algorithm: str = "crc32") -> None:
        self.payload_rule = payload_rule
        self.algorithm = algorithm

    def evaluate(self, ctx: GenerationContext, generator: ContextSensitiveGenerator) -> bytes:
        payload = generator.generate_symbol(self.payload_rule, ctx)
        data = payload.encode("utf-8") if isinstance(payload, str) else payload

        if self.algorithm == "adler32":
            chk = binascii.crc32(data) & 0xFFFFFFFF
        else:
            chk = binascii.crc32(data) & 0xFFFFFFFF

        if ctx.rng.random() < ctx.corrupt_prob:
            chk ^= 0xFFFFFFFF

        return data + struct.pack(">I", chk)


class ContextSensitiveGrammar(Grammar):
    """Extends standard Grammar with semantic context constraints and attribute actions."""

    def __init__(self, name: str = "ContextSensitiveGrammar") -> None:
        super().__init__(name=name, format="context_sensitive")
        self.constraints: dict[str, ContextConstraint] = {}

    def add_constraint_rule(self, name: str, constraint: ContextConstraint) -> None:
        """Register a rule whose production is governed by a context-sensitive constraint."""
        self.constraints[name] = constraint
        self.add_rule(name)


class ContextSensitiveGenerator:
    """Document generator driven by a ContextSensitiveGrammar."""

    def __init__(self, grammar: ContextSensitiveGrammar | Grammar, seed: int | None = None) -> None:
        self.grammar = grammar
        self.rng = random.Random(seed)

    def generate(self, start_symbol: str | None = None, corrupt_prob: float = 0.0, max_depth: int = 10) -> str:
        """Generate a concrete text document, optionally injecting near-miss corruptions."""
        sym = start_symbol or self.grammar.start_symbol
        ctx = GenerationContext(rng=self.rng, corrupt_prob=corrupt_prob)
        res = self.generate_symbol(sym, ctx, depth=0, max_depth=max_depth)
        return res if isinstance(res, str) else res.decode("utf-8", "replace")

    def generate_bytes(self, start_symbol: str | None = None, corrupt_prob: float = 0.0, max_depth: int = 10) -> bytes:
        """Generate a concrete binary document."""
        sym = start_symbol or self.grammar.start_symbol
        ctx = GenerationContext(rng=self.rng, corrupt_prob=corrupt_prob)
        res = self.generate_symbol(sym, ctx, depth=0, max_depth=max_depth)
        return res if isinstance(res, bytes) else res.encode("utf-8")

    def generate_symbol(
        self,
        symbol_name: str,
        ctx: GenerationContext,
        depth: int = 0,
        max_depth: int = 10,
    ) -> str | bytes:
        # 1. Check if symbol is governed by a semantic context constraint
        if isinstance(self.grammar, ContextSensitiveGrammar) and symbol_name in self.grammar.constraints:
            return self.grammar.constraints[symbol_name].evaluate(ctx, self)

        # 2. Check if rule exists in grammar
        rule = self.grammar.get_rule(symbol_name)
        if not rule or not rule.productions:
            # Terminal literal or token
            if symbol_name in self.grammar.terminals:
                return self.grammar.terminals[symbol_name]
            return symbol_name

        # Prevent runaway recursion
        if depth >= max_depth:
            # Pick non-recursive alternative if available
            non_rec = [p for p in rule.productions if not any(s.name == symbol_name for s in p.rhs)]
            prod = self.rng.choice(non_rec) if non_rec else rule.productions[0]
        else:
            prod = self.rng.choice(rule.productions)

        chunks: list[str] = []
        for s in prod.rhs:
            if s.is_optional and self.rng.random() < 0.5:
                continue

            repeat_count = 1
            if s.is_repeated:
                repeat_count = self.rng.randint(s.min_repeat, s.min_repeat + 2)

            for _ in range(repeat_count):
                if s.type == SymbolType.LITERAL:
                    chunks.append(s.name)
                elif s.type == SymbolType.NON_TERMINAL:
                    sub = self.generate_symbol(s.name, ctx, depth=depth + 1, max_depth=max_depth)
                    chunks.append(sub if isinstance(sub, str) else sub.decode("utf-8", "replace"))
                else:
                    chunks.append(s.name)

        return "".join(chunks)


def create_xml_context_grammar() -> ContextSensitiveGrammar:
    """Pre-configured ContextSensitiveGrammar for XML with matching tags and entity declarations."""
    g = ContextSensitiveGrammar("XML_Context_Sensitive")
    g.start_symbol = "document"

    # Rules
    doc = g.add_rule("document")
    doc.add_production(["entity_decl", "element"])
    doc.add_production(["element"])

    content = g.add_rule("content")
    content.add_production(["TEXT"])
    content.add_production(["entity_ref"])
    content.add_production(["element"])

    g.terminals["TEXT"] = "Sample content inside XML element."

    # Context constraints
    g.add_constraint_rule("element", TagMatchingConstraint())
    g.add_constraint_rule("entity_decl", ScopedSymbolConstraint(action="declare"))
    g.add_constraint_rule("entity_ref", ScopedSymbolConstraint(action="reference"))

    return g


def create_http_context_grammar() -> ContextSensitiveGrammar:
    """Pre-configured ContextSensitiveGrammar for HTTP with matching Content-Length header."""
    g = ContextSensitiveGrammar("HTTP_Context_Sensitive")
    g.start_symbol = "http_request"

    req = g.add_rule("http_request")
    req.add_production(["request_line", "length_body"])

    req_line = g.add_rule("request_line")
    req_line.add_production(["POST /api/upload HTTP/1.1\r\nHost: example.com\r\n"])

    body = g.add_rule("body")
    body.add_production(["name=antigravity&token=secure123456"])
    body.add_production(['{"status": "ok", "action": "fuzz"}'])

    g.add_constraint_rule(
        "length_body",
        LengthPrefixedConstraint(payload_rule="body", format_type="ascii_header", header_name="Content-Length")
    )

    return g
