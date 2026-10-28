"""Progress bars and real-time status lines for long-running runs.

The loop and the campaign runner can spend minutes between visible events: an
LLM call, then hundreds of harness invocations. Without feedback a healthy run
and a wedged one look the same. This module supplies two small, dependency-free
reporters:

  * :class:`ProgressBar` -- a single-line bar for a countable workload
    (inputs in a campaign, iterations in a loop).
  * :class:`StatusLine` -- structured event lines for things that are not a
    simple count (LLM calls, budget, acceptance rate).
  * :class:`RunStatus` -- the loop's coordinator, tying an iteration bar to a
    status line.

All output goes to stderr so stdout stays machine-readable. Rendering is
disabled automatically when stderr is not a TTY (CI logs, redirected output),
or when ``CI``/``NO_COLOR`` is set, and can be forced with ``on`` or suppressed
with ``off``. A bar forced on in a non-TTY stream emits coarse milestone lines
instead of control characters, which keeps CI logs readable.

The module deliberately has no third-party dependency: ``tqdm`` is convenient
but it is one more thing a replay-only reader would have to install just to
watch a bar move.
"""
from __future__ import annotations

import os
import shutil
import sys
import threading
import time
import types
from dataclasses import dataclass, field
from typing import Any, TextIO

ProgressMode = str | bool
VALID_MODES = ("auto", "on", "off")

# A redraw more often than this is wasted work: terminals cannot show it and
# the harness is the bottleneck anyway.
DEFAULT_MIN_INTERVAL_S = 0.1
# How many coarse updates a forced-on non-TTY bar emits.
PLAIN_MILESTONES = 10


def normalize_mode(mode: ProgressMode | None) -> str:
    """Map the many ways a caller can say yes/no onto auto|on|off."""
    if mode is None:
        return "auto"
    if mode is True:
        return "on"
    if mode is False:
        return "off"
    value = str(mode).strip().lower()
    if value in ("1", "true", "yes", "always"):
        return "on"
    if value in ("0", "false", "no", "never", "none"):
        return "off"
    if value not in VALID_MODES:
        raise ValueError(
            f"progress mode must be one of auto, on, off (got {mode!r})")
    return value


def _env_disables_progress() -> bool:
    if os.environ.get("STRATAGEM_NO_PROGRESS", "").strip().lower() in (
            "1", "true", "yes", "on"):
        return True
    # NO_COLOR is a user preference about styling, not output. Respecting it
    # here would hide a bar the user explicitly asked for, so only CI counts.
    return os.environ.get("CI", "").strip().lower() in ("1", "true", "yes", "on")


def _is_tty(stream: TextIO) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def resolve_enabled(mode: ProgressMode | None, stream: TextIO | None = None) -> bool:
    """Decide whether to render, preserving an explicit choice over auto-detect."""
    value = normalize_mode(mode)
    if value == "on":
        return True
    if value == "off":
        return False
    stream = stream or sys.stderr
    return _is_tty(stream) and not _env_disables_progress()


def format_duration(seconds: float | None) -> str:
    """Compact human duration: 0.4s, 9.2s, 2m03s, 1h04m."""
    if seconds is None or seconds != seconds or seconds < 0:
        return "--"
    if seconds < 10:
        return f"{seconds:.1f}s"
    if seconds < 60:
        return f"{seconds:.0f}s"
    total = int(seconds)
    if total < 3600:
        return f"{total // 60}m{total % 60:02d}s"
    return f"{total // 3600}h{(total % 3600) // 60:02d}m"


def _terminal_width(default: int = 80) -> int:
    try:
        return shutil.get_terminal_size((default, 24)).columns
    except OSError:
        return default


def _truncate(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


class ProgressBar:
    """A single-line, throttled progress bar.

    ``enabled`` accepts the same values as :func:`resolve_enabled`. The bar is
    cheap when disabled: every method is a no-op.
    """

    def __init__(
        self,
        total: int,
        desc: str = "",
        *,
        enabled: ProgressMode | None = "auto",
        stream: TextIO | None = None,
        width: int = 28,
        unit: str = "",
        initial: int = 0,
        min_interval: float = DEFAULT_MIN_INTERVAL_S,
    ):
        if total < 0:
            raise ValueError(f"total must be >= 0, got {total}")
        self.total = max(0, int(total))
        self.desc = desc
        self.unit = unit
        self.stream = stream or sys.stderr
        self.enabled = resolve_enabled(enabled, self.stream)
        self._tty = _is_tty(self.stream)
        self._width = max(10, int(width))
        self._n = min(max(0, int(initial)), self.total)
        self._started = time.monotonic()
        self._last_draw = 0.0
        self._last_plain_pct = -1
        self._postfix: dict[str, Any] = {}
        self._prev_len = 0
        self._closed = False
        self._lock = threading.Lock()
        self._min_interval = max(0.0, float(min_interval))

    # ------------------------------------------------------------- properties
    @property
    def n(self) -> int:
        return self._n

    @property
    def elapsed(self) -> float:
        return max(0.0, time.monotonic() - self._started)

    @property
    def rate(self) -> float:
        elapsed = self.elapsed
        return self._n / elapsed if elapsed > 0 and self._n else 0.0

    @property
    def eta(self) -> float | None:
        rate = self.rate
        if rate <= 0:
            return None
        return max(0.0, (self.total - self._n) / rate)

    @property
    def percent(self) -> float:
        return (self._n / self.total) if self.total else 1.0

    # ----------------------------------------------------------------- update
    def set_description(self, desc: str) -> None:
        self.desc = desc
        self._maybe_draw(force=True)

    def set_postfix(self, **fields: Any) -> None:
        self._postfix.update(fields)
        self._maybe_draw()

    def update(self, n: int = 1) -> None:
        if self._closed:
            return
        self._n = max(0, min(self.total, self._n + int(n)))
        self._maybe_draw(force=self._n >= self.total)

    def tick(self, n: int = 1) -> None:
        self.update(n)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.enabled:
            if self._tty:
                self._draw_tty(final=True)
                self.stream.write("\n")
            else:
                self._draw_plain(final=True)
            self._flush()

    # ------------------------------------------------------------- rendering
    def __enter__(self) -> "ProgressBar":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: types.TracebackType | None,
    ) -> None:
        self.close()

    def _maybe_draw(self, force: bool = False) -> None:
        if not self.enabled or self._closed:
            return
        now = time.monotonic()
        if not force and (now - self._last_draw) < self._min_interval:
            return
        self._last_draw = now
        if self._tty:
            self._draw_tty()
        else:
            self._draw_plain()
        self._flush()

    def _draw_plain(self, final: bool = False) -> None:
        """Forced-on non-TTY output: a handful of milestone lines, not noise."""
        pct = self.percent
        milestone = int(pct * PLAIN_MILESTONES)
        if not final and milestone <= self._last_plain_pct:
            return
        if not final and milestone == 0 and self._n != 0:
            return
        self._last_plain_pct = milestone
        fields = " ".join(f"{k}={v}" for k, v in self._postfix.items())
        line = (f"[progress] {self.desc} {self._n}/{self.total} "
                f"({pct:.0%})")
        if fields:
            line += f" {fields}"
        self.stream.write(line + "\n")

    def _draw_tty(self, final: bool = False) -> None:
        pct = self.percent
        rate = self.rate
        eta = self.eta
        width = self._width
        cols = _terminal_width()
        # Keep the whole line inside the terminal, shrinking the bar first.
        available = max(24, cols - 1)
        fixed = len(f"{self.desc} [] {self._n}/{self.total} {pct:3.0%} ")
        width = min(width, max(8, available - fixed - 18))
        filled = int(width * pct)
        bar = "#" * filled + "-" * (width - filled)
        line = f"{self.desc} [{bar}] {self._n}/{self.total} {pct:3.0%}"
        if rate:
            line += f" {rate:.1f}/s"
        if eta is not None and not final and self._n < self.total:
            line += f" ETA {format_duration(eta)}"
        for key, value in self._postfix.items():
            line += f" {key}={value}"
        if len(line) < available:
            line = line + " " * (self._prev_len - len(line))
        else:
            line = _truncate(line, available)
        self._prev_len = len(line)
        self.stream.write("\r" + line)

    def _flush(self) -> None:
        try:
            self.stream.flush()
        except (AttributeError, ValueError):
            pass


class NullProgress(ProgressBar):
    """A progress bar that renders nothing, for explicitly quiet callers."""

    def __init__(self, total: int = 0, desc: str = "", **kwargs: Any):
        kwargs["enabled"] = "off"
        super().__init__(total, desc, **kwargs)


def make_progress(
    total: int,
    desc: str = "",
    *,
    enabled: ProgressMode | None = "auto",
    stream: TextIO | None = None,
    unit: str = "",
    initial: int = 0,
) -> ProgressBar:
    """Return a usable bar even when disabled, so callers need no branch."""
    if normalize_mode(enabled) == "off":
        return ProgressBar(total, desc, enabled="off", stream=stream,
                           unit=unit, initial=initial)
    return ProgressBar(total, desc, enabled=enabled, stream=stream,
                       unit=unit, initial=initial)


# Order matters for a stable, scannable line. Unknown fields are appended.
_STATUS_ORDER = (
    "run", "iteration", "phase", "calls", "cost", "accept", "productions",
    "crashes", "last_call", "elapsed", "message",
)


class StatusLine:
    """Structured ``[status] key=value`` lines for event-shaped progress.

    Unlike a bar, each update is a complete line. That is deliberate: status
    events are infrequent (one per LLM call or iteration) and interleaving
    them with an in-place bar would corrupt both.
    """

    def __init__(
        self,
        *,
        enabled: ProgressMode | None = "auto",
        stream: TextIO | None = None,
        prefix: str = "[status]",
        min_interval: float = 0.0,
    ):
        self.stream = stream or sys.stderr
        self.enabled = resolve_enabled(enabled, self.stream)
        self.prefix = prefix
        self.min_interval = max(0.0, float(min_interval))
        self.fields: dict[str, Any] = {}
        self._last_emit = 0.0
        self._lock = threading.Lock()

    def update(self, *, force: bool = False, **fields: Any) -> None:
        self.fields.update(fields)
        if not self.enabled:
            return
        now = time.monotonic()
        if not force and (now - self._last_emit) < self.min_interval:
            return
        self._last_emit = now
        self._emit()

    def event(self, message: str, *, force: bool = False,
              **fields: Any) -> None:
        """Emit a one-off message with the current fields plus any overrides."""
        payload = dict(self.fields)
        payload.update(fields)
        payload["message"] = message
        if not self.enabled:
            return
        self._emit(payload)

    def _emit(self, fields: dict[str, Any] | None = None) -> None:
        fields = fields if fields is not None else self.fields
        keys = [k for k in _STATUS_ORDER if k in fields]
        keys += [k for k in fields if k not in keys]
        parts = []
        for key in keys:
            value = fields[key]
            if value is None or value == "":
                continue
            text = " ".join(str(value).split())
            if len(text) > 80:
                text = text[:77] + "..."
            parts.append(f"{key}={text}")
        with self._lock:
            self.stream.write(self.prefix + " " + " ".join(parts) + "\n")
            try:
                self.stream.flush()
            except (AttributeError, ValueError):
                pass


@dataclass
class RunStatus:
    """The loop's progress coordinator.

    It owns an iteration bar and a status line, and exposes the handful of
    events the loop actually has. Keeping the event names here means the loop
    does not grow a second progress vocabulary of its own.
    """

    run_id: str
    total_iterations: int
    mode: ProgressMode | None = "auto"
    status_mode: ProgressMode | None = "auto"
    stream: TextIO | None = None
    bar: ProgressBar = field(init=False)
    status: StatusLine = field(init=False)

    def __post_init__(self) -> None:
        self.bar = ProgressBar(
            self.total_iterations,
            desc=f"run {self.run_id}",
            enabled=self.mode,
            stream=self.stream,
            unit="iter",
        )
        self.status = StatusLine(
            enabled=self.status_mode,
            stream=self.stream,
            min_interval=0.0,
        )

    def start(self) -> None:
        self.status.update(run=self.run_id,
                           iteration=f"0/{self.total_iterations}",
                           phase="starting", force=True)
        self.bar._maybe_draw(force=True)

    def iteration_started(self, iteration: int) -> None:
        self.bar.set_description(f"run {self.run_id} iter {iteration}")
        self.status.update(
            iteration=f"{iteration}/{self.total_iterations}",
            phase="generating",
            force=True,
        )

    def phase(self, name: str) -> None:
        self.status.update(phase=name)

    def llm_call(self, call: int, tag: str, elapsed_s: float,
                 cost_usd: float | None) -> None:
        cost = f"${cost_usd:.4f}" if cost_usd is not None else "n/a"
        self.status.update(calls=call, cost=cost,
                           last_call=f"{tag} {elapsed_s:.1f}s")

    def iteration_finished(
        self,
        iteration: int,
        *,
        acceptance: float | None = None,
        productions: str | None = None,
        crashes: int | None = None,
        cost_usd: float | None = None,
    ) -> None:
        fields: dict[str, Any] = {
            "iteration": f"{iteration}/{self.total_iterations}",
            "phase": "finished",
            "force": True,
        }
        if acceptance is not None:
            fields["accept"] = f"{acceptance:.1%}"
        if productions is not None:
            fields["productions"] = productions
        if crashes is not None:
            fields["crashes"] = crashes
        if cost_usd is not None:
            fields["cost"] = f"${cost_usd:.2f}"
        self.status.update(**fields)
        self.bar.update(1)

    def note(self, message: str, **fields: Any) -> None:
        self.status.event(message, **fields)

    def finish(self) -> None:
        self.bar.close()
        self.status.event("run finished", force=True)
