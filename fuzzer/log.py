"""Consistent logging and tagged output for Stratagem.

Provides:
  * Standard Python `logging.Logger` integration
  * Tagged message formatting matching Stratagem's conventions (`    [tag] message`)
  * Environment-controlled log levels via `STRATAGEM_LOG_LEVEL`
  * Structured hint and section formatting
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Any, TextIO

DEFAULT_INDENT: int = 4
HINT_INDENT: int = 6

_LEVEL_MAP: dict[str, int] = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "WARN": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
    "OFF": logging.CRITICAL + 10,
}


def _resolve_log_level() -> int:
    env_val = os.environ.get("STRATAGEM_LOG_LEVEL", "INFO").strip().upper()
    return _LEVEL_MAP.get(env_val, logging.INFO)


class StratagemLogger:
    """Unified logger that produces consistent tagged console output while

    mirroring to Python's standard logging infrastructure.
    """

    def __init__(self, name: str = "stratagem", stream: TextIO | None = None) -> None:
        self.name = name
        self.logger = logging.getLogger(name)
        self.stream = stream or sys.stdout
        self.level = _resolve_log_level()
        self.logger.setLevel(self.level)

    def is_enabled_for(self, level: int) -> bool:
        return level >= self.level

    def log(self, level: int, msg: str, *args: Any, **kwargs: Any) -> None:
        if self.is_enabled_for(level):
            formatted = msg % args if args else msg
            print(formatted, file=self.stream, flush=True)
            self.logger.log(level, msg, *args, **kwargs)

    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self.log(logging.DEBUG, msg, *args, **kwargs)

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self.log(logging.INFO, msg, *args, **kwargs)

    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self.log(logging.WARNING, msg, *args, **kwargs)

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self.log(logging.ERROR, msg, *args, **kwargs)

    def tag(self, tag_name: str, msg: str, indent: int = DEFAULT_INDENT, level: int = logging.INFO) -> None:
        """Emit a standard tagged line: `' ' * indent + f'[{tag_name}] {msg}'`."""
        prefix = " " * indent
        line = f"{prefix}[{tag_name}] {msg}"
        self.log(level, line)

    def section(self, title: str) -> None:
        """Emit a major section separator line."""
        self.log(logging.INFO, f"\n=== {title} ===")

    def hint(self, text: str, indent: int = HINT_INDENT) -> None:
        """Emit an indented actionable hint."""
        prefix = " " * indent
        self.log(logging.INFO, f"{prefix}hint: {text}")


_LOGGERS: dict[str, StratagemLogger] = {}


def get_logger(name: str = "stratagem", stream: TextIO | None = None) -> StratagemLogger:
    """Retrieve or create a cached StratagemLogger for the given subsystem."""
    if name not in _LOGGERS:
        _LOGGERS[name] = StratagemLogger(name=name, stream=stream)
    return _LOGGERS[name]
