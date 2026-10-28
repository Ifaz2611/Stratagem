"""Small portability helpers shared by the fuzzer and the agent.

The project is developed on Unix-like systems but native Windows is a supported
fallback (README: MinGW-w64). Two Windows differences keep biting callers:

  * a compiled harness is named ``harness.exe``, while the Unix builds call it
    plain ``harness``;
  * ``os.replace`` can fail with ``PermissionError`` while another process (an
    antivirus scanner, a reader, the previous run) still has the destination
    open. Unix renames an open file silently, Windows does not.

Keeping both rules here means a new caller cannot forget them, and the
Unix behaviour stays a single ``os.replace`` rather than a retry loop.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

IS_WINDOWS = os.name == "nt"

# Enough for a transient scanner/lock to clear, short enough that a genuinely
# stuck file still fails the run rather than hanging it.
_REPLACE_ATTEMPTS = 8
_REPLACE_BACKOFF_S = 0.02


def native_binary(path: Path | str) -> Path:
    """Return the path a native executable actually has on this platform.

    On Windows the ``.exe`` suffix is added even when the file does not exist
    yet, so error messages name the path that the build is expected to create.
    A caller that already supplied ``.exe`` is left alone.
    """
    p = Path(path)
    if IS_WINDOWS and p.suffix.lower() != ".exe":
        return p.with_name(p.name + ".exe")
    return p


def replace_file(tmp: Path | str, dest: Path | str) -> None:
    """Atomically replace ``dest`` with ``tmp``, tolerating Windows locks.

    ``tmp`` and ``dest`` must be on the same filesystem for the rename to be
    atomic. Retries only ``PermissionError`` (the Windows sharing-violation
    case); a missing source or a cross-device move still fails immediately.
    """
    src, dst = Path(tmp), Path(dest)
    attempts = _REPLACE_ATTEMPTS if IS_WINDOWS else 1
    for attempt in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt + 1 >= attempts:
                raise
            time.sleep(_REPLACE_BACKOFF_S * (attempt + 1))


def atomic_write_text(
    path: Path | str,
    text: str,
    encoding: str = "utf-8",
) -> None:
    """Write ``text`` to ``path`` without exposing a half-written file."""
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(
        f".{dest.name}.{os.getpid()}.{time.monotonic_ns()}.tmp")
    try:
        with tmp.open("w", encoding=encoding, newline="") as fh:
            fh.write(text)
        replace_file(tmp, dest)
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
