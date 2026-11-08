"""Adversarial XML generator targeting known parser bug classes.

Generates hostile payloads specifically crafted to expose memory safety and resource bugs:
  * Entity expansion bombs (Billion Laughs exponential & quadratic blowup)
  * UTF-8 / UTF-16 boundary conditions & surrogate mismatches
  * Extreme nesting depths (stack and recursion limit stress)
  * Huge attribute lists (allocation and quadratic lookup stress)
  * Extreme identifier lengths (fixed buffer truncation testing)
  * Malformed DOCTYPE structures and '%' parameter entity injection
  * CDATA edge cases (unclosed blocks, embedded NULs)
"""
from __future__ import annotations


class AdversarialXMLGenerator:
    """Generates targeted hostile payloads for XML parser stress testing."""

    @staticmethod
    def billion_laughs(depth: int = 5, expansion: int = 10) -> bytes:
        """Generate classic exponential entity expansion bomb."""
        lines = ['<?xml version="1.0"?>', '<!DOCTYPE lolz [', '  <!ENTITY lol "lol">']
        for i in range(1, depth + 1):
            prev = f"lol{i - 1}" if i > 1 else "lol"
            body = "".join(f"&{prev};" for _ in range(expansion))
            lines.append(f'  <!ENTITY lol{i} "{body}">')
        lines.append(']>')
        lines.append(f'<lolz>&lol{depth};</lolz>')
        return "\n".join(lines).encode("utf-8")

    @staticmethod
    def quadratic_blowup(n_entities: int = 200, size: int = 500) -> bytes:
        """Generate quadratic entity expansion payload."""
        lines = ['<?xml version="1.0"?>', '<!DOCTYPE root [']
        chunk = "A" * size
        for i in range(n_entities):
            lines.append(f'  <!ENTITY e{i} "{chunk}">')
        lines.append(']>')
        refs = "".join(f"&e{i};" for i in range(n_entities))
        lines.append(f'<root>{refs}</root>')
        return "\n".join(lines).encode("utf-8")

    @staticmethod
    def deep_nesting(depth: int = 1000) -> bytes:
        """Generate deeply nested XML tags to test recursion or iterative limits."""
        tags = [f"tag{i}" for i in range(depth)]
        opens = "".join(f"<{t}>" for t in tags)
        closes = "".join(f"</{t}>" for t in reversed(tags))
        return f"{opens}content{closes}".encode("utf-8")

    @staticmethod
    def huge_attributes(count: int = 1500) -> bytes:
        """Generate a single element with thousands of attributes."""
        attrs = " ".join(f'attr{i}="val{i}"' for i in range(count))
        return f'<root {attrs} />'.encode("utf-8")

    @staticmethod
    def long_element_name(length: int = 4000) -> bytes:
        """Generate an element name far exceeding the typical 1024-byte buffer."""
        name = "A" * length
        return f'<{name} attr="1">content</{name}>'.encode("utf-8")

    @staticmethod
    def utf8_boundary_cases() -> list[bytes]:
        """Generate UTF-8 decoding boundary cases (overlong, surrogates, truncations)."""
        return [
            # Overlong 2-byte slash (0xC0 0xAF)
            b'<\xc0\xafroot></root>',
            # Overlong 3-byte sequence (0xE0 0x80 0xAF)
            b'<root val="\xe0\x80\xaf"/>',
            # Lone UTF-16 surrogate half in UTF-8 (0xED 0xA0 0x80 = U+D800)
            b'<root val="\xed\xa0\x80"/>',
            # Lone high surrogate (0xED 0xBF 0xBF = U+DFFF)
            b'<root val="\xed\xbf\xbf"/>',
            # Truncated 4-byte sequence (missing 3 continuation bytes)
            b'<root val="\xf0"/>',
            # Stray continuation bytes
            b'<root val="\x80\x81\x82"/>',
            # Invalid UTF-8 leading bytes 0xFE, 0xFF
            b'<root val="\xfe\xff"/>',
        ]

    @staticmethod
    def utf16_boundary_cases() -> list[bytes]:
        """Generate UTF-16 byte order mark and odd length edge cases."""
        return [
            # UTF-16LE BOM with odd byte count
            b'\xff\xfe' + b'<\x00r\x00o\x00o\x00t\x00>\x00' + b'X',
            # UTF-16BE BOM with odd byte count
            b'\xfe\xff' + b'\x00<\x00r\x00o\x00o\x00t\x00>' + b'Y',
            # Contradictory encoding declaration
            b'\xff\xfe' + '<?xml version="1.0" encoding="UTF-8"?><root/>'.encode("utf-16le"),
        ]

    @staticmethod
    def malformed_doctype() -> list[bytes]:
        """Generate malformed and parameter-entity DOCTYPE declarations."""
        return [
            # Unclosed DOCTYPE bracket
            b'<!DOCTYPE root [ <element a> <root/>',
            # Nested DOCTYPE
            b'<!DOCTYPE a [ <!DOCTYPE b [ <a/> ]> ]>',
            # Parameter entity % in DOCTYPE
            b'<!DOCTYPE root [ <!ENTITY % pe "<!ENTITY test \'val\'>"> %pe; ]><root>&test;</root>',
            # Recursive parameter entity
            b'<!DOCTYPE root [ <!ENTITY % a "%b;"> <!ENTITY % b "%a;"> %a; ]><root/>',
            # Raw percent without name
            b'<!DOCTYPE root [ % % % ]><root/>',
        ]

    @staticmethod
    def cdata_edge_cases() -> list[bytes]:
        """Generate CDATA boundary cases."""
        return [
            # Unclosed CDATA section
            b'<root><![CDATA[ unclosed content without end marker',
            # Embedded NUL inside CDATA
            b'<root><![CDATA[before\x00after]]></root>',
            # Nested CDATA markers
            b'<root><![CDATA[ first <![CDATA[ nested ]]> trailing ]]></root>',
        ]

    @classmethod
    def all_adversarial_cases(cls) -> list[bytes]:
        """Aggregate a suite of diverse adversarial payloads."""
        cases: list[bytes] = [
            cls.billion_laughs(depth=4, expansion=5),
            cls.quadratic_blowup(n_entities=50, size=100),
            cls.deep_nesting(depth=200),
            cls.huge_attributes(count=500),
            cls.long_element_name(length=1500),
        ]
        cases.extend(cls.utf8_boundary_cases())
        cases.extend(cls.utf16_boundary_cases())
        cases.extend(cls.malformed_doctype())
        cases.extend(cls.cdata_edge_cases())
        return cases
