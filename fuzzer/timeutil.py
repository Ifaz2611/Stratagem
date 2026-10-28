"""Time-zone-explicit timestamp helpers.

Reports, checkpoints and debug logs are often compared across machines in
different time zones. ``time.time()`` is unambiguous (epoch seconds), but the
human-readable fields next to it used to be formatted with whatever local time
the machine had, or with an offset spelling (``+00:00``) that some consumers
did not accept as UTC.

Everything user-facing here is UTC and ends in ``Z``, the form ISO 8601
consumers treat as unambiguous. Parsing accepts both ``Z`` and an explicit
offset so older artifacts remain readable.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

UTC = timezone.utc


def utc_now() -> datetime:
    """Current time as a timezone-aware UTC datetime."""
    return datetime.now(UTC)


def utc_iso(
    timestamp: float | None = None,
    *,
    timespec: str = "seconds",
) -> str:
    """Format an epoch timestamp (default: now) as UTC ISO 8601 with ``Z``."""
    dt = (utc_now() if timestamp is None
          else datetime.fromtimestamp(float(timestamp), UTC))
    return dt.isoformat(timespec=timespec).replace("+00:00", "Z")


def parse_utc(text: str) -> datetime:
    """Parse an ISO 8601 timestamp, treating ``Z`` as UTC.

    ``datetime.fromisoformat`` accepts ``Z`` from Python 3.11 onwards; doing the
    substitution explicitly keeps artifacts readable on the 3.10 runtime the
    project still supports. A value without an offset is assumed UTC rather
    than local time, because that is what this module writes.
    """
    value = text.strip()
    if value.endswith(("Z", "z")):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def epoch_seconds() -> float:
    """The monotonic wall-clock value stored alongside ``utc_iso`` in JSON."""
    return time.time()
