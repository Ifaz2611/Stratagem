"""Base class for all XML parser targets."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from fuzzer import features
from fuzzer.targets.base import BaseTarget, REPO_ROOT


class XMLTarget(BaseTarget):
    """Abstract base target for XML parsers."""

    category: str = "xml"
    grammar_file: Path | None = REPO_ROOT / "grammar" / "XMLParser.g4"
    productions: tuple[str, ...] = features.PRODUCTIONS

    def is_valid_shape(self, payload: bytes) -> bool:
        """XML documents superficially begin with '<'."""
        return payload.lstrip()[:1] == b"<"

    def analyze_features(self, text: str, payload: bytes = b"") -> features.Features:
        return features.analyze(text, payload)

    def summarize_structure(self, feature_list: list[features.Features]) -> dict:
        return features.coverage(feature_list)
