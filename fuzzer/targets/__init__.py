"""Targets package for Stratagem.

Provides the target abstraction layer and pre-registered targets for:
- XML parsers: mxml, libxml2, expat, tinyxml2
- Non-XML grammars: json
- Network protocols: http, dns, smtp
"""
from __future__ import annotations

from fuzzer.targets.base import (
    BaseTarget,
    get_default_target,
    get_target,
    list_targets,
    register_target,
)
from fuzzer.targets.json_target import JSONTarget
from fuzzer.targets.protocol_dns import DNSTarget
from fuzzer.targets.protocol_http import HTTPTarget
from fuzzer.targets.protocol_smtp import SMTPTarget
from fuzzer.targets.xml_expat import ExpatTarget
from fuzzer.targets.xml_libxml2 import Libxml2Target
from fuzzer.targets.xml_mxml import MxmlTarget
from fuzzer.targets.xml_tinyxml2 import Tinyxml2Target

# Register all built-in targets
register_target(MxmlTarget())
register_target(Libxml2Target())
register_target(ExpatTarget())
register_target(Tinyxml2Target())
register_target(JSONTarget())
register_target(HTTPTarget())
register_target(DNSTarget())
register_target(SMTPTarget())

__all__ = [
    "BaseTarget",
    "register_target",
    "get_target",
    "list_targets",
    "get_default_target",
    "MxmlTarget",
    "Libxml2Target",
    "ExpatTarget",
    "Tinyxml2Target",
    "JSONTarget",
    "HTTPTarget",
    "DNSTarget",
    "SMTPTarget",
]
