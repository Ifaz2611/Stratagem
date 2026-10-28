"""Baseline Hypothesis strategy for DNS binary wire format protocol target."""
from __future__ import annotations

import struct
from typing import Any
from hypothesis import strategies as st

from fuzzer.strategies.common import (
    bytes_to_surrogate,
    make_mixture_documents,
    surrogate_to_bytes,
)

NAME = "dns_baseline"
DESCRIPTION = "Hypothesis strategy generating binary DNS packets (RFC 1035)"

_to_str = bytes_to_surrogate


@st.composite
def _well_formed_dns(draw: Any) -> str:
    tx_id = draw(st.integers(min_value=0, max_value=0xFFFF))
    # Standard query: QR=0, Opcode=0, RD=1 -> flags = 0x0100
    flags = 0x0100
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0
    hdr = struct.pack("!HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)

    domain = draw(st.sampled_from(["example.com", "google.com", "target.local", "a.org"]))
    labels = domain.split(".")
    qname = bytearray()
    for lab in labels:
        qname.append(len(lab))
        qname.extend(lab.encode("ascii"))
    qname.append(0)

    qtype = draw(st.sampled_from([1, 28, 15, 16]))  # A, AAAA, MX, TXT
    qclass = 1  # IN
    question = bytes(qname) + struct.pack("!HH", qtype, qclass)
    return _to_str(hdr + question)


@st.composite
def _near_miss_dns(draw: Any) -> str:
    base_bytes = surrogate_to_bytes(draw(_well_formed_dns()))
    kind = draw(st.sampled_from(["label_overflow", "truncated_qtype", "bad_qclass"]))
    if kind == "label_overflow":
        # Label length byte > 63
        pkt = bytearray(base_bytes)
        if len(pkt) > 12:
            pkt[12] = 70
        return _to_str(bytes(pkt))
    elif kind == "truncated_qtype":
        # Cut last 2 bytes
        return _to_str(base_bytes[:-2])
    elif kind == "bad_qclass":
        # Change QCLASS to 9999
        pkt = bytearray(base_bytes)
        if len(pkt) >= 16:
            pkt[-2:] = b"\x27\x0f"
        return _to_str(bytes(pkt))
    return _to_str(base_bytes)


@st.composite
def _byte_hostile_dns(draw: Any) -> str:
    kind = draw(st.sampled_from(["trunc_header", "ptr_loop", "ptr_oob", "nul"]))
    if kind == "trunc_header":
        return _to_str(b"\x12\x34\x01\x00\x00")  # Only 5 bytes
    elif kind == "ptr_loop":
        # Header (12 bytes) + pointer 0xC00C pointing back to offset 12!
        hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        loop_ptr = b"\xc0\x0c" + struct.pack("!HH", 1, 1)
        return _to_str(hdr + loop_ptr)
    elif kind == "ptr_oob":
        # Pointer to offset 0x3FFF
        hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        oob_ptr = b"\xc0\xff" + struct.pack("!HH", 1, 1)
        return _to_str(hdr + oob_ptr)
    return _to_str(b"\x00" * 12)


def documents() -> st.SearchStrategy[str]:
    return make_mixture_documents(_well_formed_dns(), _near_miss_dns(), _byte_hostile_dns())
