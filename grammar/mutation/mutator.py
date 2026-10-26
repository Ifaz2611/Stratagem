"""Grammar mutation capabilities for adversarial and boundary fuzzing.

Mutates grammar definitions across multiple operators to generate corner-case,
negative, malformed, and stack-stressing input structures:
  * INJECT_ALTERNATIVE: Adds unexpected structural alternatives to rules
  * REMOVE_ALTERNATIVE: Prunes productions to test omission handling
  * INJECT_RECURSION: Induces left/right/mutual recursion to test stack depth
  * MUTATE_TERMINAL: Injects control bytes, boundary characters, format strings
  * FLIP_OPTIONALITY: Toggles optional vs mandatory symbols
  * EXPAND_REPETITION: Modifies repetition constraints (* <-> +)
  * SWAP_SYMBOLS: Inverts sequence order of adjacent symbols
"""
from __future__ import annotations

import copy
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Sequence

from grammar.formats.base import Grammar, GrammarSymbol, Production, Rule, SymbolType


class MutationType(str, Enum):
    INJECT_ALTERNATIVE = "inject_alternative"
    REMOVE_ALTERNATIVE = "remove_alternative"
    INJECT_RECURSION = "inject_recursion"
    MUTATE_TERMINAL = "mutate_terminal"
    FLIP_OPTIONALITY = "flip_optionality"
    EXPAND_REPETITION = "expand_repetition"
    SWAP_SYMBOLS = "swap_symbols"


# Common adversarial tokens and boundary mutations
_ADVERSARIAL_TERMINALS = [
    "",
    "\x00",
    " ",
    "\t",
    "\r\n",
    "%s%s%s%n",
    "../../etc/passwd",
    "99999999999999999999999999999999",
    "-1",
    "0",
    "NaN",
    "Infinity",
    "<script>",
    "&amp;",
    "\udc80",
]


@dataclass
class MutationRecord:
    """Record of an individual mutation applied to a grammar."""
    operator: MutationType
    target_rule: str
    description: str
    before: str = ""
    after: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "operator": self.operator.value,
            "target_rule": self.target_rule,
            "description": self.description,
            "before": self.before,
            "after": self.after,
        }


@dataclass
class MutatedGrammar:
    """Container for a mutated grammar alongside its audit trail of applied mutations."""
    grammar: Grammar
    mutations: list[MutationRecord] = field(default_factory=list)

    @property
    def mutation_count(self) -> int:
        return len(self.mutations)

    def to_diff(self) -> str:
        """Render a readable diff of applied mutations."""
        lines = [f"# Grammar Mutations Applied ({self.mutation_count}):"]
        for m in self.mutations:
            lines.append(f"  * [{m.operator.value}] Rule '{m.target_rule}': {m.description}")
            if m.before and m.after:
                lines.append(f"      - Before: {m.before}")
                lines.append(f"      + After:  {m.after}")
        return "\n".join(lines)


class GrammarMutator:
    """Configurable grammar mutator engine for adversarial generation."""

    def __init__(
        self,
        seed: int | None = None,
        allowed_operators: Sequence[MutationType] | None = None,
    ) -> None:
        self.rng = random.Random(seed)
        self.allowed_operators = list(allowed_operators) if allowed_operators else list(MutationType)

    def mutate(self, grammar: Grammar, count: int = 1) -> MutatedGrammar:
        """Apply `count` random mutations to a clone of the grammar."""
        g = grammar.clone()
        mutations: list[MutationRecord] = []

        rules = list(g.rules.values())
        if not rules:
            return MutatedGrammar(grammar=g, mutations=[])

        attempts = 0
        max_attempts = count * 10
        while len(mutations) < count and attempts < max_attempts:
            attempts += 1
            op = self.rng.choice(self.allowed_operators)
            rule = self.rng.choice(rules)

            rec = None
            if op == MutationType.INJECT_ALTERNATIVE:
                rec = self._inject_alternative(g, rule)
            elif op == MutationType.REMOVE_ALTERNATIVE:
                rec = self._remove_alternative(rule)
            elif op == MutationType.INJECT_RECURSION:
                rec = self._inject_recursion(g, rule)
            elif op == MutationType.MUTATE_TERMINAL:
                rec = self._mutate_terminal(rule)
            elif op == MutationType.FLIP_OPTIONALITY:
                rec = self._flip_optionality(rule)
            elif op == MutationType.EXPAND_REPETITION:
                rec = self._expand_repetition(rule)
            elif op == MutationType.SWAP_SYMBOLS:
                rec = self._swap_symbols(rule)

            if rec:
                mutations.append(rec)

        return MutatedGrammar(grammar=g, mutations=mutations)

    def generate_adversarial_grammar(self, grammar: Grammar, intensity: float = 0.3) -> MutatedGrammar:
        """Generate an adversarial grammar with multiple simultaneous mutations."""
        n_rules = max(1, len(grammar.rules))
        num_mutations = max(1, int(n_rules * intensity))
        return self.mutate(grammar, count=num_mutations)

    def _inject_alternative(self, grammar: Grammar, rule: Rule) -> MutationRecord | None:
        """Add a mutated alternative to a rule."""
        before = rule.to_ebnf()
        # Create an alternative: either a boundary literal, an empty production, or a truncated sibling
        choice = self.rng.choice(["empty", "adversarial_literal", "partial"])

        if choice == "empty":
            prod = rule.add_production([])
            desc = "Injected epsilon / empty alternative"
        elif choice == "adversarial_literal":
            adv = self.rng.choice(_ADVERSARIAL_TERMINALS)
            prod = rule.add_production([GrammarSymbol(name=adv, type=SymbolType.LITERAL)])
            desc = f"Injected adversarial literal {adv!r}"
        else:
            # Partial: pick existing production and drop half symbols
            if rule.productions:
                base = self.rng.choice(rule.productions)
                shrunk_rhs = base.rhs[:max(1, len(base.rhs) // 2)]
                prod = rule.add_production(shrunk_rhs)
                desc = "Injected truncated production alternative"
            else:
                prod = rule.add_production([GrammarSymbol(name="MUTATED", type=SymbolType.TERMINAL)])
                desc = "Injected generic fallback alternative"

        return MutationRecord(
            operator=MutationType.INJECT_ALTERNATIVE,
            target_rule=rule.name,
            description=desc,
            before=before,
            after=rule.to_ebnf(),
        )

    def _remove_alternative(self, rule: Rule) -> MutationRecord | None:
        """Remove a production alternative from a rule if more than one exists."""
        if len(rule.productions) <= 1:
            return None
        before = rule.to_ebnf()
        idx = self.rng.randrange(len(rule.productions))
        removed = rule.productions.pop(idx)
        return MutationRecord(
            operator=MutationType.REMOVE_ALTERNATIVE,
            target_rule=rule.name,
            description=f"Removed alternative: {removed.to_ebnf()}",
            before=before,
            after=rule.to_ebnf(),
        )

    def _inject_recursion(self, grammar: Grammar, rule: Rule) -> MutationRecord | None:
        """Inject left or right self-recursion into a rule to test recursion handling."""
        before = rule.to_ebnf()
        if not rule.productions:
            rule.add_production([
                GrammarSymbol(name=rule.name, type=SymbolType.NON_TERMINAL),
                GrammarSymbol(name="RECURSE", type=SymbolType.TERMINAL),
            ])
        else:
            base = self.rng.choice(rule.productions)
            self_sym = GrammarSymbol(name=rule.name, type=SymbolType.NON_TERMINAL)
            if self.rng.random() < 0.5:
                # Left recursion: A -> A rhs
                new_rhs = [self_sym] + list(base.rhs)
                desc = "Injected left-recursion"
            else:
                # Right recursion: A -> rhs A
                new_rhs = list(base.rhs) + [self_sym]
                desc = "Injected right-recursion"
            rule.add_production(new_rhs)

        return MutationRecord(
            operator=MutationType.INJECT_RECURSION,
            target_rule=rule.name,
            description=desc,
            before=before,
            after=rule.to_ebnf(),
        )

    def _mutate_terminal(self, rule: Rule) -> MutationRecord | None:
        """Mutate a terminal or literal within a rule's productions."""
        candidates = []
        for p in rule.productions:
            for s in p.rhs:
                if s.is_terminal:
                    candidates.append((p, s))

        if not candidates:
            # Add a mutated terminal
            adv = self.rng.choice(_ADVERSARIAL_TERMINALS)
            rule.add_production([GrammarSymbol(name=adv, type=SymbolType.LITERAL)])
            return MutationRecord(
                operator=MutationType.MUTATE_TERMINAL,
                target_rule=rule.name,
                description=f"Added boundary terminal {adv!r}",
                before=rule.to_ebnf(),
                after=rule.to_ebnf(),
            )

        before = rule.to_ebnf()
        p, s = self.rng.choice(candidates)
        orig_name = s.name
        new_name = self.rng.choice(_ADVERSARIAL_TERMINALS)
        s.name = new_name
        return MutationRecord(
            operator=MutationType.MUTATE_TERMINAL,
            target_rule=rule.name,
            description=f"Replaced terminal {orig_name!r} with {new_name!r}",
            before=before,
            after=rule.to_ebnf(),
        )

    def _flip_optionality(self, rule: Rule) -> MutationRecord | None:
        """Toggle optionality on a symbol in rule."""
        symbols = [s for p in rule.productions for s in p.rhs]
        if not symbols:
            return None
        before = rule.to_ebnf()
        s = self.rng.choice(symbols)
        s.is_optional = not s.is_optional
        status = "optional" if s.is_optional else "mandatory"
        return MutationRecord(
            operator=MutationType.FLIP_OPTIONALITY,
            target_rule=rule.name,
            description=f"Flipped symbol '{s.name}' to {status}",
            before=before,
            after=rule.to_ebnf(),
        )

    def _expand_repetition(self, rule: Rule) -> MutationRecord | None:
        """Modify repetition constraints (* <-> +)."""
        symbols = [s for p in rule.productions for s in p.rhs]
        if not symbols:
            return None
        before = rule.to_ebnf()
        s = self.rng.choice(symbols)
        s.is_repeated = not s.is_repeated
        if s.is_repeated:
            s.min_repeat = self.rng.choice([0, 1])
        return MutationRecord(
            operator=MutationType.EXPAND_REPETITION,
            target_rule=rule.name,
            description=f"Toggled repetition on symbol '{s.name}'",
            before=before,
            after=rule.to_ebnf(),
        )

    def _swap_symbols(self, rule: Rule) -> MutationRecord | None:
        """Swap adjacent symbols in a multi-symbol production."""
        multi_prods = [p for p in rule.productions if len(p.rhs) >= 2]
        if not multi_prods:
            return None
        before = rule.to_ebnf()
        p = self.rng.choice(multi_prods)
        idx = self.rng.randrange(len(p.rhs) - 1)
        p.rhs[idx], p.rhs[idx + 1] = p.rhs[idx + 1], p.rhs[idx]
        return MutationRecord(
            operator=MutationType.SWAP_SYMBOLS,
            target_rule=rule.name,
            description=f"Swapped adjacent symbols at indices {idx} and {idx+1}",
            before=before,
            after=rule.to_ebnf(),
        )


def mutate_grammar(
    grammar: Grammar,
    count: int = 1,
    seed: int | None = None,
    allowed_operators: Sequence[MutationType] | None = None,
) -> MutatedGrammar:
    """Convenience function to apply mutations to a grammar."""
    mutator = GrammarMutator(seed=seed, allowed_operators=allowed_operators)
    return mutator.mutate(grammar, count=count)
