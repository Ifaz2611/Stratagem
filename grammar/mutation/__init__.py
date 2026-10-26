"""Grammar mutation package for Stratagem.

Provides mutation operators and adversarial grammar generation.
"""
from __future__ import annotations

from grammar.mutation.mutator import (
    GrammarMutator,
    MutatedGrammar,
    MutationRecord,
    MutationType,
    mutate_grammar,
)

__all__ = [
    "GrammarMutator",
    "MutatedGrammar",
    "MutationRecord",
    "MutationType",
    "mutate_grammar",
]
