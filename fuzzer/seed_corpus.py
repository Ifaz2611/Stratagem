"""Seed corpus management and parser cross-fertilization.

Provides curated real-world XML samples and known regression cases from various
parsers (libxml2, expat, mxml) to cross-seed fuzzing campaigns across targets.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

# Built-in real-world XML samples representing diverse schemas
REAL_WORLD_SAMPLES: list[tuple[str, bytes]] = [
    (
        "svg_vector",
        b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
        b'<circle cx="50" cy="50" r="40" stroke="green" stroke-width="4" fill="yellow" />'
        b'<text x="50" y="55" font-size="20" text-anchor="middle" fill="black">SVG</text>'
        b'</svg>',
    ),
    (
        "rss_feed",
        b'<?xml version="1.0" encoding="UTF-8" ?>'
        b'<rss version="2.0">'
        b'<channel>'
        b'  <title>Sample RSS Feed</title>'
        b'  <link>https://example.com</link>'
        b'  <description>Sample feed for fuzzer seed</description>'
        b'  <item>'
        b'    <title>Article 1</title>'
        b'    <description><![CDATA[Content with <b>HTML</b> tags]]></description>'
        b'  </item>'
        b'</channel>'
        b'</rss>',
    ),
    (
        "xhtml_doc",
        b'<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" '
        b'"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">'
        b'<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">'
        b'<head><title>Virtual Title</title></head>'
        b'<body><p id="main">Paragraph with entities: &amp; &lt; &gt;</p></body>'
        b'</html>',
    ),
    (
        "soap_envelope",
        b'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        b'<soap:Header><auth:Token xmlns:auth="http://auth.example.com">XYZ123</auth:Token></soap:Header>'
        b'<soap:Body><m:GetPrice xmlns:m="http://stock.example.com"><m:Item>Widget</m:Item></m:Body>'
        b'</soap:Envelope>',
    ),
]

# Historical regression samples and CVE triggers from XML parsers
KNOWN_REGRESSION_SEEDS: list[tuple[str, bytes]] = [
    (
        "mxml_leak_354",
        b'<a a>',  # Triggers mxml issue #354 attribute leak
    ),
    (
        "mxml_index_350",
        b'<a><b/></a>',  # Triggers mxml index_sort heap under-read with --index
    ),
    (
        "libxml2_cve_2017_9047",
        b'<!DOCTYPE root [\n'
        b'<!ELEMENT root (ANY)>\n'
        b'<!ATTLIST root id ID #REQUIRED>\n'
        b']><a></a>',
    ),
    (
        "expat_cve_2022_25315",
        b'<!DOCTYPE r [<!ENTITY % a "<!--"><!ENTITY % b "-->">%a;%b;]><r/>',
    ),
    (
        "bom_nonascii_damaged_f1",
        b'\xc4\x80<r/>',  # Non-ASCII UTF-8 code point before '<' (PR #357)
    ),
]


@dataclass
class SeedEntry:
    name: str
    origin_parser: str
    payload: bytes
    category: str = "real_world"
    sha256: str = ""

    def __post_init__(self):
        if not self.sha256:
            self.sha256 = hashlib.sha256(self.payload).hexdigest()

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "origin_parser": self.origin_parser,
            "category": self.category,
            "sha256": self.sha256,
            "size": len(self.payload),
        }


class SeedCorpusManager:
    """Manages curated seed collections and cross-fertilization across parsers."""

    def __init__(self):
        self.seeds: dict[str, SeedEntry] = {}
        self._load_defaults()

    def _load_defaults(self):
        for name, payload in REAL_WORLD_SAMPLES:
            self.add_seed(name, payload, origin_parser="general", category="real_world")
        for name, payload in KNOWN_REGRESSION_SEEDS:
            self.add_seed(name, payload, origin_parser=name.split("_")[0], category="regression")

    def add_seed(self, name: str, payload: bytes, origin_parser: str = "unknown", category: str = "custom") -> None:
        entry = SeedEntry(name=name, origin_parser=origin_parser, payload=payload, category=category)
        self.seeds[entry.sha256] = entry

    def get_seeds_for_target(self, target_name: str, cross_fertilize: bool = True) -> list[bytes]:
        """Retrieve seed payloads appropriate for `target_name`.

        If `cross_fertilize` is True, includes regressions and samples from OTHER parsers
        to test cross-parser resilience.
        """
        result = []
        for s in self.seeds.values():
            if cross_fertilize or s.origin_parser in (target_name, "general"):
                result.append(s.payload)
        return result

    def export_seeds(self, out_dir: Path) -> int:
        """Export all seeds to disk as .xml and .meta.json files."""
        out_dir.mkdir(parents=True, exist_ok=True)
        count = 0
        for sha, seed in self.seeds.items():
            base = out_dir / f"{seed.name}_{sha[:8]}"
            (base.with_suffix(".xml")).write_bytes(seed.payload)
            (base.with_suffix(".meta.json")).write_text(json.dumps(seed.to_json(), indent=2), encoding="utf-8")
            count += 1
        return count
