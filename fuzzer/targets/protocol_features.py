"""Structural analysis of network protocol messages (HTTP, DNS, SMTP).

Extracts productions, anomalies, and classification buckets for protocol fuzzing.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

# =====================================================================
# HTTP Features
# =====================================================================
HTTP_PRODUCTIONS: tuple[str, ...] = (
    "g_http_request",
    "g_method_standard",           # GET, POST, PUT, DELETE, HEAD, OPTIONS
    "g_method_custom",             # FOO, PURGE, etc.
    "g_header",                    # Any Name: Value
    "g_header_host",               # Host: ...
    "g_header_content_length",     # Content-Length: ...
    "g_header_transfer_encoding",  # Transfer-Encoding: chunked
    "g_chunked_body",              # Hex size\r\n...\r\n0\r\n\r\n
    "g_query_string",              # /path?foo=bar
    # Anomalies and request smuggling probes
    "x_smuggling_cl_te",           # Both Content-Length and Transfer-Encoding present
    "x_invalid_version",           # Not HTTP/1.0 or HTTP/1.1 or HTTP/2
    "x_missing_crlf",              # Bare \n without \r
    "x_unterminated_headers",      # Missing final \r\n\r\n
    "x_invalid_header_name",       # Space in header name (RFC 7230 violation)
    "x_control_char",              # Control character in header
    "x_bom",                       # BOM before request line
    "x_invalid_utf8",              # Non-UTF-8 bytes
    "x_embedded_nul",              # NUL in request
)

_HTTP_STANDARD_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"})


@dataclass
class HTTPFeatures:
    productions: set[str] = field(default_factory=set)
    n_headers: int = 0
    method: str = ""
    uri_len: int = 0
    length: int = 0

    @property
    def bucket(self) -> str:
        hostile = {"x_control_char", "x_bom", "x_invalid_utf8", "x_embedded_nul", "x_unterminated_headers"}
        if self.productions & hostile:
            return "byte_hostile"
        near_miss = {"x_smuggling_cl_te", "x_invalid_version", "x_missing_crlf", "x_invalid_header_name"}
        if self.productions & near_miss:
            return "near_miss"
        return "well_formed"

    def to_json(self) -> dict:
        return {
            "bucket": self.bucket,
            "productions": sorted(self.productions),
            "n_headers": self.n_headers,
            "method": self.method,
            "uri_len": self.uri_len,
            "length": self.length,
        }


def analyze_http(text: str, payload: bytes = b"") -> HTTPFeatures:
    f = HTTPFeatures(length=len(text))
    if not payload:
        payload = text.encode("utf-8", "surrogatepass")

    if payload.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        f.productions.add("x_bom")
    if b"\x00" in payload:
        f.productions.add("x_embedded_nul")
    try:
        payload.decode("utf-8")
    except UnicodeDecodeError:
        f.productions.add("x_invalid_utf8")

    for ch in text:
        if ord(ch) < 0x20 and ch not in "\r\n\t":
            f.productions.add("x_control_char")
            break

    if "\n" in text and "\r\n" not in text:
        f.productions.add("x_missing_crlf")

    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    first_line = lines[0].strip() if lines else ""

    parts = first_line.split(" ")
    if len(parts) >= 3:
        f.productions.add("g_http_request")
        method, uri, version = parts[0], parts[1], parts[2]
        f.method = method
        f.uri_len = len(uri)
        if method.upper() in _HTTP_STANDARD_METHODS:
            f.productions.add("g_method_standard")
        else:
            f.productions.add("g_method_custom")

        if "?" in uri:
            f.productions.add("g_query_string")

        if version in ("HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/2"):
            pass
        else:
            f.productions.add("x_invalid_version")

    has_cl = False
    has_te = False
    in_headers = True

    for line in lines[1:]:
        if not line:
            in_headers = False
            continue
        if in_headers:
            if ":" in line:
                f.productions.add("g_header")
                f.n_headers += 1
                name, val = line.split(":", 1)
                if " " in name or "\t" in name:
                    f.productions.add("x_invalid_header_name")
                name_lower = name.strip().lower()
                if name_lower == "host":
                    f.productions.add("g_header_host")
                elif name_lower == "content-length":
                    f.productions.add("g_header_content_length")
                    has_cl = True
                elif name_lower == "transfer-encoding":
                    f.productions.add("g_header_transfer_encoding")
                    has_te = True
                    if "chunked" in val.lower():
                        f.productions.add("g_chunked_body")

    if has_cl and has_te:
        f.productions.add("x_smuggling_cl_te")

    if "\r\n\r\n" not in text and "\n\n" not in text:
        f.productions.add("x_unterminated_headers")

    return f


def coverage_http(feature_list: list[HTTPFeatures]) -> dict:
    seen: dict[str, int] = {}
    for f in feature_list:
        for p in f.productions:
            seen[p] = seen.get(p, 0) + 1
    hit = [p for p in HTTP_PRODUCTIONS if p in seen]
    missing = [p for p in HTTP_PRODUCTIONS if p not in seen]
    return {
        "productions_hit": len(hit),
        "productions_total": len(HTTP_PRODUCTIONS),
        "hit": {p: seen[p] for p in hit},
        "missing": missing,
    }


# =====================================================================
# DNS Features
# =====================================================================
DNS_PRODUCTIONS: tuple[str, ...] = (
    "g_dns_header",              # 12-byte header
    "g_qr_query",                # Standard query (QR=0)
    "g_qr_response",             # Response (QR=1)
    "g_opcode_standard",         # Opcode 0
    "g_question",                # QDCOUNT >= 1
    "g_answer",                  # ANCOUNT >= 1
    "g_compressed_label",        # 0xC0 pointer
    "x_compression_loop",        # Pointer loop (DoS / Hang vulnerability)
    "x_truncated_header",        # Length < 12
    "x_label_overflow",          # Label length > 63
    "x_pointer_out_of_bounds",   # Compression offset >= packet length
    "x_truncated_rr",            # RDATA length mismatch
)


@dataclass
class DNSFeatures:
    productions: set[str] = field(default_factory=set)
    qdcount: int = 0
    ancount: int = 0
    length: int = 0

    @property
    def bucket(self) -> str:
        hostile = {"x_truncated_header", "x_compression_loop", "x_pointer_out_of_bounds"}
        if self.productions & hostile:
            return "byte_hostile"
        near_miss = {"x_label_overflow", "x_truncated_rr"}
        if self.productions & near_miss:
            return "near_miss"
        return "well_formed"

    def to_json(self) -> dict:
        return {
            "bucket": self.bucket,
            "productions": sorted(self.productions),
            "qdcount": self.qdcount,
            "ancount": self.ancount,
            "length": self.length,
        }


def analyze_dns(text: str, payload: bytes = b"") -> DNSFeatures:
    if not payload:
        payload = text.encode("utf-8", "surrogatepass")
    f = DNSFeatures(length=len(payload))

    if len(payload) < 12:
        f.productions.add("x_truncated_header")
        return f

    f.productions.add("g_dns_header")
    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", payload[:12])
    f.qdcount = qdcount
    f.ancount = ancount

    qr = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xF
    if qr == 0:
        f.productions.add("g_qr_query")
    else:
        f.productions.add("g_qr_response")
    if opcode == 0:
        f.productions.add("g_opcode_standard")

    if qdcount > 0:
        f.productions.add("g_question")
    if ancount > 0:
        f.productions.add("g_answer")

    # Label scanning
    offset = 12
    seen_ptrs = set()
    while offset < len(payload):
        b = payload[offset]
        if b == 0:
            break
        elif (b & 0xC0) == 0xC0:
            f.productions.add("g_compressed_label")
            if offset + 1 >= len(payload):
                f.productions.add("x_pointer_out_of_bounds")
                break
            ptr_offset = ((b & 0x3F) << 8) | payload[offset + 1]
            if ptr_offset >= len(payload):
                f.productions.add("x_pointer_out_of_bounds")
            if ptr_offset in seen_ptrs or ptr_offset == offset:
                f.productions.add("x_compression_loop")
                break
            seen_ptrs.add(ptr_offset)
            offset += 2
            break
        elif b > 63:
            f.productions.add("x_label_overflow")
            offset += 1
            break
        else:
            offset += 1 + b

    return f


def coverage_dns(feature_list: list[DNSFeatures]) -> dict:
    seen: dict[str, int] = {}
    for f in feature_list:
        for p in f.productions:
            seen[p] = seen.get(p, 0) + 1
    hit = [p for p in DNS_PRODUCTIONS if p in seen]
    missing = [p for p in DNS_PRODUCTIONS if p not in seen]
    return {
        "productions_hit": len(hit),
        "productions_total": len(DNS_PRODUCTIONS),
        "hit": {p: seen[p] for p in hit},
        "missing": missing,
    }


# =====================================================================
# SMTP Features
# =====================================================================
SMTP_PRODUCTIONS: tuple[str, ...] = (
    "g_helo_ehlo",               # HELO / EHLO
    "g_mail_from",               # MAIL FROM:<...>
    "g_rcpt_to",                 # RCPT TO:<...>
    "g_data",                    # DATA
    "g_data_body",               # Body ending with \r\n.\r\n
    "g_quit",                    # QUIT
    "g_rset",                    # RSET
    # Anomalies
    "x_line_too_long",           # Line > 1000 octets (RFC 5321 limit)
    "x_unknown_command",         # Unknown SMTP verb
    "x_invalid_address",         # Malformed path
    "x_missing_crlf",            # Bare \n
    "x_control_char",            # Control chars in parameters
    "x_embedded_nul",            # Embedded NUL
)

_SMTP_KNOWN_CMDS = frozenset({"HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "NOOP", "QUIT", "VRFY", "EXPN", "HELP"})


@dataclass
class SMTPFeatures:
    productions: set[str] = field(default_factory=set)
    n_commands: int = 0
    max_line_len: int = 0
    length: int = 0

    @property
    def bucket(self) -> str:
        hostile = {"x_line_too_long", "x_control_char", "x_embedded_nul"}
        if self.productions & hostile:
            return "byte_hostile"
        near_miss = {"x_unknown_command", "x_invalid_address", "x_missing_crlf"}
        if self.productions & near_miss:
            return "near_miss"
        return "well_formed"

    def to_json(self) -> dict:
        return {
            "bucket": self.bucket,
            "productions": sorted(self.productions),
            "n_commands": self.n_commands,
            "max_line_len": self.max_line_len,
            "length": self.length,
        }


def analyze_smtp(text: str, payload: bytes = b"") -> SMTPFeatures:
    f = SMTPFeatures(length=len(text))
    if not payload:
        payload = text.encode("utf-8", "surrogatepass")

    if b"\x00" in payload:
        f.productions.add("x_embedded_nul")

    for ch in text:
        if ord(ch) < 0x20 and ch not in "\r\n\t":
            f.productions.add("x_control_char")
            break

    if "\n" in text and "\r\n" not in text:
        f.productions.add("x_missing_crlf")

    if "\r\n.\r\n" in text:
        f.productions.add("g_data_body")

    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    for line in lines:
        if len(line) > f.max_line_len:
            f.max_line_len = len(line)
        if len(line) > 1000:
            f.productions.add("x_line_too_long")

        stripped = line.strip()
        if not stripped:
            continue
        verb = stripped.split()[0].upper()
        if verb in ("HELO", "EHLO"):
            f.productions.add("g_helo_ehlo")
            f.n_commands += 1
        elif verb == "MAIL":
            f.productions.add("g_mail_from")
            f.n_commands += 1
            if "<" not in line or ">" not in line:
                f.productions.add("x_invalid_address")
        elif verb == "RCPT":
            f.productions.add("g_rcpt_to")
            f.n_commands += 1
            if "<" not in line or ">" not in line:
                f.productions.add("x_invalid_address")
        elif verb == "DATA":
            f.productions.add("g_data")
            f.n_commands += 1
        elif verb == "QUIT":
            f.productions.add("g_quit")
            f.n_commands += 1
        elif verb == "RSET":
            f.productions.add("g_rset")
            f.n_commands += 1
        elif verb not in _SMTP_KNOWN_CMDS:
            f.productions.add("x_unknown_command")

    return f


def coverage_smtp(feature_list: list[SMTPFeatures]) -> dict:
    seen: dict[str, int] = {}
    for f in feature_list:
        for p in f.productions:
            seen[p] = seen.get(p, 0) + 1
    hit = [p for p in SMTP_PRODUCTIONS if p in seen]
    missing = [p for p in SMTP_PRODUCTIONS if p not in seen]
    return {
        "productions_hit": len(hit),
        "productions_total": len(SMTP_PRODUCTIONS),
        "hit": {p: seen[p] for p in hit},
        "missing": missing,
    }
