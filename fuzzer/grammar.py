"""Grammar support re-export for the fuzzer package.

Aliases the top-level grammar package for unified access via `fuzzer.grammar`.
"""
from __future__ import annotations

import grammar
from grammar import *

__all__ = grammar.__all__
