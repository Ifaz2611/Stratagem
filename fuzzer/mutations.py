"""Byte-level mutation engine for grammar and payload fuzzing.

Supplements grammar-based generation with byte-level fuzzing mutations:
  * Bit flips (single-bit, 2-bit, byte inversion)
  * Byte insertions, replacements, deletions
  * Arbitrary position truncations (premature EOF testing)
  * Integer overflow injections in numeric/length slots
  * NUL byte injections at delimiter boundaries
"""
from __future__ import annotations

import random
from typing import Callable, Sequence

INTERESTING_INTEGERS = (
    b"2147483647",       # INT_MAX (32-bit)
    b"-2147483648",      # INT_MIN (32-bit)
    b"4294967295",       # UINT_MAX (32-bit)
    b"9223372036854775807", # LLONG_MAX (64-bit)
    b"-9223372036854775808", # LLONG_MIN (64-bit)
    b"18446744073709551615", # ULLONG_MAX / SIZE_MAX
    b"0",
    b"-1",
    b"65535",
    b"65536",
    b"1024",
    b"1023",
)

XML_DELIMITERS = (b"<", b">", b"</", b"/>", b"\"", b"'", b"=", b"&", b";", b"%", b"-->", b"]]>")


def flip_bit(data: bytes, rng: random.Random | None = None) -> bytes:
    """Flip a single random bit in data."""
    if not data:
        return data
    r = rng or random
    idx = r.randint(0, len(data) - 1)
    bit = 1 << r.randint(0, 7)
    ba = bytearray(data)
    ba[idx] ^= bit
    return bytes(ba)


def flip_byte(data: bytes, rng: random.Random | None = None) -> bytes:
    """Invert a single random byte in data."""
    if not data:
        return data
    r = rng or random
    idx = r.randint(0, len(data) - 1)
    ba = bytearray(data)
    ba[idx] ^= 0xFF
    return bytes(ba)


def delete_bytes(data: bytes, max_len: int = 4, rng: random.Random | None = None) -> bytes:
    """Delete a small contiguous chunk of bytes."""
    if len(data) <= 1:
        return data
    r = rng or random
    chunk = r.randint(1, min(max_len, len(data) - 1))
    pos = r.randint(0, len(data) - chunk)
    return data[:pos] + data[pos + chunk:]


def insert_bytes(data: bytes, max_len: int = 4, rng: random.Random | None = None) -> bytes:
    """Insert random bytes at a random position."""
    r = rng or random
    chunk = bytes(r.randint(0, 255) for _ in range(r.randint(1, max_len)))
    pos = r.randint(0, len(data)) if data else 0
    return data[:pos] + chunk + data[pos:]


def truncate_bytes(data: bytes, rng: random.Random | None = None) -> bytes:
    """Truncate the payload at a random position to simulate premature EOF."""
    if len(data) <= 1:
        return data
    r = rng or random
    pos = r.randint(1, len(data) - 1)
    return data[:pos]


def inject_integer_overflow(data: bytes, rng: random.Random | None = None) -> bytes:
    """Inject an extreme integer boundary value into the payload."""
    r = rng or random
    val = r.choice(INTERESTING_INTEGERS)
    pos = r.randint(0, len(data)) if data else 0
    return data[:pos] + val + data[pos:]


def inject_nul_bytes(data: bytes, rng: random.Random | None = None) -> bytes:
    """Inject NUL bytes at random or delimiter positions."""
    if not data:
        return b"\x00"
    r = rng or random
    ba = bytearray(data)
    # Prefer near XML delimiters if present
    delims = [i for i, b in enumerate(ba) if bytes([b]) in XML_DELIMITERS]
    if delims and r.random() < 0.7:
        target = r.choice(delims)
        ba.insert(target, 0)
    else:
        target = r.randint(0, len(ba))
        ba.insert(target, 0)
    return bytes(ba)


MUTATION_OPS: tuple[Callable[..., bytes], ...] = (
    flip_bit,
    flip_byte,
    delete_bytes,
    insert_bytes,
    truncate_bytes,
    inject_integer_overflow,
    inject_nul_bytes,
)


class ByteMutator:
    """Configurable byte-level mutation pipeline for payloads."""

    def __init__(self, seed: int | None = None):
        self.rng = random.Random(seed)

    def mutate(self, payload: bytes, intensity: int = 1) -> bytes:
        """Apply 1 to `intensity` mutations to payload."""
        result = payload
        ops = self.rng.choices(MUTATION_OPS, k=max(1, intensity))
        for op in ops:
            result = op(result, rng=self.rng)
        return result

    def mutate_many(self, payload: bytes, count: int = 10, intensity: int = 1) -> list[bytes]:
        """Produce `count` mutated variants of payload."""
        return [self.mutate(payload, intensity) for _ in range(count)]
