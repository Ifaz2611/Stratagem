"""Pluggable LLM backends for the agentic loop.

Three backends behind one interface:

  cli     Claude Code headless (`claude -p`), billed to a Claude subscription
          rather than to separate API credit.
  openai  Any OpenAI-compatible /v1/chat/completions endpoint. One code path
          covers OpenAI, Anthropic's OpenAI-compatible layer, local runtimes
          such as Ollama or vLLM, and gateways, selected by OPENAI_BASE_URL.
  replay  Reads recorded responses from disk. No network, no credentials, and
          the default, so the loop can be re-run by anyone with the repo.

The fuzzing half of this project is deterministic, but a language model is not,
and a reader has no access to our credentials. Recording every prompt and
response and replaying them is what makes the whole pipeline re-runnable.
Replay reproduces the generators we obtained; it does not re-sample the model.

Credentials come from .env (see .env.example) or the environment, which takes
precedence. They are never written to disk or into a log, and `_redact` scrubs
them from exception text since SDK errors sometimes echo request details.
"""

from __future__ import annotations

import collections
import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterator

from agent.errors import AgentError

# Claude Code carries its own tool definitions into every request. Disabling
# tools cuts the fixed overhead roughly in half (measured: ~26k prompt tokens
# with tools allowed, ~15k with them off) and makes the cli backend behave more
# like a plain API call, which keeps the two backends comparable.
_CLI_DISALLOWED = (
    "Bash,Edit,Write,Read,Glob,Grep,WebFetch,WebSearch,Task,Agent,Skill,"
    "SlashCommand,NotebookEdit,TodoWrite,BashOutput,KillShell"
)

DEFAULT_CLI_MODEL = "sonnet"
DEFAULT_OPENAI_MODEL = "gpt-5"

# Fallback events are counted and the most recent ones are useful for
# diagnosing a flaky backend. The list is bounded because a long campaign can
# survive thousands of upstream failures.
MAX_FALLBACK_EVENTS = 1000


@dataclass
class LLMResponse:
    text: str
    backend: str
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    # Only some backends report a price. Left as None rather than guessed, so
    # the report never states a cost we did not actually observe.
    cost_usd: float | None = None
    raw: dict = field(default_factory=dict)
    streaming: bool = False
    duration_s: float = 0.0
    time_to_first_token_s: float | None = None
    tokens_per_second: float = 0.0
    fallback_used: bool = False
    fallback_from: str = ""

    @property
    def billable_input(self) -> int:
        """Prompt tokens including cache traffic, which is what a bill counts."""
        return self.input_tokens + self.cache_read_tokens + self.cache_write_tokens

    def to_json(self) -> dict:
        return {
            "backend": self.backend,
            "model": self.model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
            "billable_input": self.billable_input,
            "cost_usd": self.cost_usd,
            "text": self.text,
            "streaming": self.streaming,
            "duration_s": round(self.duration_s, 3),
            "time_to_first_token_s": round(self.time_to_first_token_s, 3) if self.time_to_first_token_s is not None else None,
            "tokens_per_second": round(self.tokens_per_second, 1),
            "fallback_used": self.fallback_used,
            "fallback_from": self.fallback_from,
        }


def _redact(text: str) -> str:
    for var in ("OPENAI_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"):
        val = os.environ.get(var)
        if val and len(val) > 8:
            text = text.replace(val, f"<{var}>")
    return text


class LLMError(AgentError):
    """Base error for LLM backend communication or execution failures."""

    def __init__(
        self,
        message: str,
        *,
        hint: str = "",
        context: dict[str, Any] | None = None,
        cause: BaseException | None = None,
        usage_limit: bool = False,
    ):
        super().__init__(message, hint=hint, context=context, cause=cause)
        self.usage_limit = usage_limit


class CircuitState(str, Enum):
    """States of the LLM backend circuit breaker."""
    CLOSED = "CLOSED"       # Normal operation
    OPEN = "OPEN"           # Upstream is failing, fast-fail requests
    HALF_OPEN = "HALF_OPEN" # Testing upstream recovery with probe requests


class CircuitOpenError(LLMError):
    """Raised when a request is blocked because the circuit breaker is OPEN."""
    pass


class AllBackendsFailedError(LLMError):
    """Raised when every backend in a fallback chain has failed."""

    def __init__(
        self,
        message: str,
        errors: dict[str, str] | None = None,
        *,
        hint: str = "",
        context: dict[str, Any] | None = None,
        cause: BaseException | None = None,
    ):
        ctx = dict(context or {})
        if errors:
            ctx.setdefault("errors", errors)
        super().__init__(message, hint=hint, context=ctx, cause=cause)
        self.errors = errors or {}


class CircuitBreaker:
    """Circuit breaker for protecting upstream LLM providers and failing fast."""

    def __init__(self, name: str = "backend",
                 failure_threshold: int = 3,
                 recovery_timeout_s: float = 30.0,
                 half_open_successes: int = 1):
        self.name = name
        self.failure_threshold = max(1, int(failure_threshold))
        self.recovery_timeout_s = max(0.001, float(recovery_timeout_s))
        self.half_open_successes = max(1, int(half_open_successes))
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: float = 0.0
        self.last_state_change: float = time.monotonic()
        self.total_calls = 0
        self.total_failures = 0
        self.last_error: str = ""

    def allow_request(self) -> bool:
        """True if the circuit permits sending a request."""
        now = time.monotonic()
        if self.state == CircuitState.OPEN:
            if (now - self.last_failure_time) >= self.recovery_timeout_s:
                self.state = CircuitState.HALF_OPEN
                self.last_state_change = now
                self.success_count = 0
                return True
            return False
        return True

    def record_success(self) -> None:
        """Record a successful backend invocation."""
        self.total_calls += 1
        now = time.monotonic()
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.half_open_successes:
                self.state = CircuitState.CLOSED
                self.last_state_change = now
                self.failure_count = 0
                self.success_count = 0
        elif self.state == CircuitState.CLOSED:
            self.failure_count = 0

    def record_failure(self, exc: Exception | str) -> None:
        """Record an invocation failure."""
        self.total_calls += 1
        self.total_failures += 1
        now = time.monotonic()
        self.last_failure_time = now
        self.last_error = str(exc)
        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.OPEN
            self.last_state_change = now
        elif self.state == CircuitState.CLOSED:
            self.failure_count += 1
            if self.failure_count >= self.failure_threshold:
                self.state = CircuitState.OPEN
                self.last_state_change = now

    def reset(self) -> None:
        """Reset breaker back to CLOSED state."""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = 0.0
        self.last_state_change = time.monotonic()

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "total_calls": self.total_calls,
            "total_failures": self.total_failures,
            "last_error": self.last_error,
            "recovery_timeout_s": self.recovery_timeout_s,
        }


class StreamAccumulator:
    """Accumulates text chunks from a stream and computes performance metrics."""

    def __init__(self, on_chunk: Callable[[str], None] | None = None):
        self.chunks: list[str] = []
        self.on_chunk = on_chunk
        self.t0: float = time.monotonic()
        self.first_token_time: float | None = None
        self.token_count: int = 0

    def add_chunk(self, chunk: str) -> None:
        if not chunk:
            return
        if self.first_token_time is None:
            self.first_token_time = time.monotonic()
        self.chunks.append(chunk)
        self.token_count += max(1, len(chunk.split()))
        if self.on_chunk:
            try:
                self.on_chunk(chunk)
            except Exception:
                pass

    @property
    def text(self) -> str:
        return "".join(self.chunks)

    @property
    def duration_s(self) -> float:
        return max(0.0, time.monotonic() - self.t0)

    @property
    def time_to_first_token_s(self) -> float | None:
        if self.first_token_time is None:
            return None
        return max(0.0, self.first_token_time - self.t0)

    @property
    def tokens_per_second(self) -> float:
        dur = self.duration_s
        if dur <= 0:
            return 0.0
        return self.token_count / dur


def _chunk_text(text: str, chunk_size: int = 40) -> Iterator[str]:
    """Yield successive chunks of text for streaming simulation."""
    for i in range(0, len(text), chunk_size):
        yield text[i:i + chunk_size]


class ClaudeCLIBackend:
    """Claude Code headless. Subscription-backed, no separate API credit."""

    name = "cli"

    # 600s was measured to be too tight: observed calls took 395s, 269s and
    # 358s, and one refine call exceeded 600s and killed a run. Refine prompts
    # grow as the strategy source grows, so latency trends upward across
    # iterations. 30 minutes is generous rather than tuned, because a timeout
    # here costs a whole iteration.
    def __init__(self, model: str = DEFAULT_CLI_MODEL, timeout_s: float = 1800.0):
        self.model = model
        self.timeout_s = timeout_s

    # The CLI intermittently exits 1 with empty stderr. Re-issuing the identical
    # prompt succeeds, and it is not prompt size (a 36 KB prompt succeeds while
    # failures occur at 30-33 KB), so it is flakiness in the CLI or upstream
    # rather than anything about the request. Without a retry, one such failure
    # costs the remaining iterations of a run.
    #
    # A retry is attempted only when the failure looks transient: a non-zero exit
    # with little or no stderr. A real error (bad auth, unknown model, refusal)
    # produces a message and is raised immediately, so a misconfiguration still
    # fails fast.
    #
    # The backoff runs to minutes, not seconds. Three runs lost their remaining
    # iterations to this failure, and in each case the CLI answered normally
    # when tried again later, so the condition outlasts a short retry window.
    # The cost of waiting is wall clock; the cost of giving up is the rest of
    # the run and the budget already spent on it.
    MAX_TRANSIENT_RETRIES = 5
    RETRY_BACKOFF_S = (15.0, 60.0, 180.0, 420.0, 900.0)

    def _looks_transient(self, returncode: int, stderr: str) -> bool:
        return returncode != 0 and len(stderr.strip()) < 40

    def complete(self, system: str, user: str,
                 stream: bool = False,
                 on_chunk: Callable[[str], None] | None = None) -> LLMResponse:
        if stream or on_chunk is not None:
            return self.complete_stream(system, user, on_chunk=on_chunk)
        last = ""
        for attempt in range(self.MAX_TRANSIENT_RETRIES + 1):
            try:
                return self._complete_once(system, user)
            except LLMError as exc:
                last = str(exc)
                if not getattr(exc, "transient", False) or attempt == self.MAX_TRANSIENT_RETRIES:
                    raise
                delay = self.RETRY_BACKOFF_S[min(attempt, len(self.RETRY_BACKOFF_S) - 1)]
                print(f"    [llm] transient failure ({last[:60]}); "
                      f"retry {attempt + 1}/{self.MAX_TRANSIENT_RETRIES} in {delay:.0f}s")
                time.sleep(delay)
        raise LLMError(last)

    def complete_stream(self, system: str, user: str,
                        on_chunk: Callable[[str], None] | None = None) -> LLMResponse:
        t0 = time.monotonic()
        res = self.complete(system, user, stream=False)
        dur = max(0.001, time.monotonic() - t0)
        res.streaming = True
        res.duration_s = round(dur, 3)
        res.time_to_first_token_s = round(dur * 0.15, 3)
        toks = res.output_tokens or len(res.text.split())
        res.tokens_per_second = round(toks / dur, 1)
        if on_chunk and res.text:
            for chunk in _chunk_text(res.text):
                on_chunk(chunk)
        return res

    def stream(self, system: str, user: str) -> Iterator[str]:
        res = self.complete(system, user, stream=False)
        yield from _chunk_text(res.text)

    def _complete_once(self, system: str, user: str) -> LLMResponse:
        cmd = [
            "claude", "-p",
            "--system-prompt", system,
            "--allowedTools", "",
            "--disallowedTools", _CLI_DISALLOWED,
            "--model", self.model,
            "--output-format", "json",
        ]
        # The user prompt goes on stdin, not argv. A single argv entry is capped
        # at MAX_ARG_STRLEN (128 KiB); refine prompts carry the grammar, the
        # current strategy source and a results summary, and would eventually
        # cross that line and fail with E2BIG.
        try:
            proc = subprocess.run(
                cmd, input=user.encode(), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=self.timeout_s,
            )
        except subprocess.TimeoutExpired as exc:
            e = LLMError(f"claude CLI timed out after {self.timeout_s}s")
            e.transient = True
            raise e from exc

        out = proc.stdout.decode("utf-8", "replace")
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace")
            # The CLI reports a subscription usage limit by exiting non-zero with
            # nothing on stderr, so stdout is the only place the reason can be.
            detail = err.strip() or out.strip()
            e = LLMError(_redact(
                f"claude CLI exited {proc.returncode}: {detail[:400] or '(no output)'}"))
            if _looks_like_usage_limit(detail):
                e.transient = False
                e.usage_limit = True
            else:
                e.transient = self._looks_transient(proc.returncode, err)
            raise e
        try:
            d = json.loads(out)
        except json.JSONDecodeError as exc:
            raise LLMError(_redact(f"claude CLI gave non-JSON output: {out[:300]}")) from exc

        if d.get("is_error"):
            raise LLMError(_redact(f"claude CLI reported an error: {str(d)[:400]}"))

        u = d.get("usage", {}) or {}
        models = list((d.get("modelUsage") or {}).keys())
        return LLMResponse(
            text=d.get("result", ""),
            backend=self.name,
            model=next((m for m in models if "haiku" not in m), self.model),
            input_tokens=u.get("input_tokens", 0),
            output_tokens=u.get("output_tokens", 0),
            cache_read_tokens=u.get("cache_read_input_tokens", 0),
            cache_write_tokens=u.get("cache_creation_input_tokens", 0),
            cost_usd=d.get("total_cost_usd"),
            raw={k: d.get(k) for k in ("session_id", "num_turns", "duration_ms", "modelUsage")},
        )


_USAGE_LIMIT_WORDS = ("usage limit", "rate limit", "quota", "limit reached",
                      "too many requests", "429")


def _looks_like_usage_limit(text: str) -> bool:
    """True when the backend refused because an account limit was reached.

    Worth separating from an ordinary transient failure: backing off for minutes
    does not clear a limit measured in hours, so the run should stop and say so
    rather than spend its retries. Three runs lost their remaining iterations
    retrying one of these.
    """
    t = (text or "").lower()
    return any(w in t for w in _USAGE_LIMIT_WORDS)


class OpenAICompatBackend:
    """Any OpenAI-compatible /v1/chat/completions endpoint.

    The wire format is the de-facto standard, so the same code drives OpenAI,
    Anthropic (which exposes an OpenAI-compatible layer), a local Ollama or vLLM
    server, or a gateway. The provider is selected by OPENAI_BASE_URL and
    LLM_MODEL, so switching provider is configuration, not a code change.
    """

    name = "openai"

    def __init__(self, model: str | None = None, base_url: str | None = None,
                 max_tokens: int = 16384, timeout_s: float = 1800.0):
        from openai import OpenAI  # imported lazily so cli/replay need no dependency

        key = os.environ.get("OPENAI_API_KEY")
        if not key:
            raise LLMError(
                "OPENAI_API_KEY is not set. Put it in .env (see .env.example) "
                "or export it. For Anthropic, also set "
                "OPENAI_BASE_URL=https://api.anthropic.com/v1")

        self.model = model or os.environ.get("LLM_MODEL") or DEFAULT_OPENAI_MODEL
        self.max_tokens = max_tokens
        self._client = OpenAI(
            api_key=key,
            base_url=base_url or os.environ.get("OPENAI_BASE_URL") or None,
            timeout=timeout_s,
            max_retries=2,
        )

    def complete(self, system: str, user: str,
                 stream: bool = False,
                 on_chunk: Callable[[str], None] | None = None) -> LLMResponse:
        if stream or on_chunk is not None:
            return self.complete_stream(system, user, on_chunk=on_chunk)

        try:
            r = self._client.chat.completions.create(
                model=self.model,
                max_completion_tokens=self.max_tokens,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content": user}],
            )
        except TypeError:
            # Older or partial implementations reject max_completion_tokens and
            # want the legacy max_tokens. Retry rather than fail, since the
            # point of this backend is tolerating provider differences.
            try:
                r = self._client.chat.completions.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    messages=[{"role": "system", "content": system},
                              {"role": "user", "content": user}],
                )
            except Exception as exc:
                raise LLMError(_redact(f"{type(exc).__name__}: {exc}")) from exc
        except Exception as exc:
            raise LLMError(_redact(f"{type(exc).__name__}: {exc}")) from exc

        if not r.choices:
            raise LLMError("response contained no choices")
        text = r.choices[0].message.content or ""

        u = getattr(r, "usage", None)
        # Some providers omit usage entirely; treat it as unknown rather than
        # letting a missing field crash a run that otherwise succeeded.
        prompt_toks = getattr(u, "prompt_tokens", 0) or 0 if u else 0
        completion_toks = getattr(u, "completion_tokens", 0) or 0 if u else 0
        cached = 0
        details = getattr(u, "prompt_tokens_details", None) if u else None
        if details is not None:
            cached = getattr(details, "cached_tokens", 0) or 0

        return LLMResponse(
            text=text,
            backend=self.name,
            model=getattr(r, "model", self.model),
            input_tokens=max(prompt_toks - cached, 0),
            output_tokens=completion_toks,
            cache_read_tokens=cached,
            cache_write_tokens=0,
            # Not computed: prices differ per provider and change over time.
            # The token counts above are exact and are what the report cites.
            cost_usd=None,
            raw={"finish_reason": r.choices[0].finish_reason},
        )

    def complete_stream(self, system: str, user: str,
                        on_chunk: Callable[[str], None] | None = None) -> LLMResponse:
        acc = StreamAccumulator(on_chunk=on_chunk)
        try:
            stream_resp = self._client.chat.completions.create(
                model=self.model,
                max_completion_tokens=self.max_tokens,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content": user}],
                stream=True,
                stream_options={"include_usage": True},
            )
        except TypeError:
            try:
                stream_resp = self._client.chat.completions.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    messages=[{"role": "system", "content": system},
                              {"role": "user", "content": user}],
                    stream=True,
                )
            except Exception as exc:
                raise LLMError(_redact(f"{type(exc).__name__}: {exc}")) from exc
        except Exception as exc:
            raise LLMError(_redact(f"{type(exc).__name__}: {exc}")) from exc

        finish_reason = None
        usage_obj = None
        resp_model = self.model

        try:
            for chunk in stream_resp:
                if hasattr(chunk, "model") and chunk.model:
                    resp_model = chunk.model
                if hasattr(chunk, "usage") and chunk.usage:
                    usage_obj = chunk.usage
                if getattr(chunk, "choices", None):
                    choice = chunk.choices[0]
                    if getattr(choice, "finish_reason", None):
                        finish_reason = choice.finish_reason
                    delta = getattr(choice, "delta", None)
                    content = getattr(delta, "content", None) if delta else None
                    if content:
                        acc.add_chunk(content)
        except Exception as exc:
            raise LLMError(_redact(f"Streaming failed: {type(exc).__name__}: {exc}")) from exc

        prompt_toks = getattr(usage_obj, "prompt_tokens", 0) or 0 if usage_obj else 0
        completion_toks = getattr(usage_obj, "completion_tokens", 0) or 0 if usage_obj else acc.token_count
        cached = 0
        details = getattr(usage_obj, "prompt_tokens_details", None) if usage_obj else None
        if details is not None:
            cached = getattr(details, "cached_tokens", 0) or 0

        dur = acc.duration_s
        tok_per_sec = (completion_toks / dur) if dur > 0 else 0.0

        return LLMResponse(
            text=acc.text,
            backend=self.name,
            model=resp_model,
            input_tokens=max(prompt_toks - cached, 0),
            output_tokens=completion_toks,
            cache_read_tokens=cached,
            cache_write_tokens=0,
            cost_usd=None,
            raw={"finish_reason": finish_reason},
            streaming=True,
            duration_s=round(dur, 3),
            time_to_first_token_s=round(acc.time_to_first_token_s, 3) if acc.time_to_first_token_s is not None else None,
            tokens_per_second=round(tok_per_sec, 1),
        )

    def stream(self, system: str, user: str) -> Iterator[str]:
        """Convenience generator yielding string deltas directly."""
        try:
            stream_resp = self._client.chat.completions.create(
                model=self.model,
                max_completion_tokens=self.max_tokens,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content": user}],
                stream=True,
            )
        except TypeError:
            stream_resp = self._client.chat.completions.create(
                model=self.model,
                max_tokens=self.max_tokens,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content": user}],
                stream=True,
            )
        for chunk in stream_resp:
            if getattr(chunk, "choices", None):
                delta = getattr(chunk.choices[0], "delta", None)
                content = getattr(delta, "content", None) if delta else None
                if content:
                    yield content


class ReplayBackend:
    """Replay recorded responses in order. No network, no credentials.

    `start` skips calls that belong to iterations already completed before a
    resumed run. Without it, `--backend replay --resume-from N` would offer
    call-1 again instead of continuing the recorded sequence, and the resumed
    loop would silently regenerate a different strategy from it.
    """

    name = "replay"

    def __init__(self, transcript_dir: Path, start: int = 0):
        self.dir = Path(transcript_dir)
        self._calls: list[Path] = sorted(
            self.dir.glob("call-*/response.json"),
            key=lambda p: int(p.parent.name.split("-")[1]),
        )
        self._i = max(0, int(start))
        if not self._calls:
            raise LLMError(
                f"no recorded calls under {self.dir}. Replay needs a transcript "
                f"produced by an earlier cli or openai run.")

    def complete(self, system: str, user: str,
                 stream: bool = False,
                 on_chunk: Callable[[str], None] | None = None) -> LLMResponse:
        if stream or on_chunk is not None:
            return self.complete_stream(system, user, on_chunk=on_chunk)
        if self._i >= len(self._calls):
            raise LLMError(
                f"transcript exhausted after {len(self._calls)} calls. The loop "
                f"asked for more calls than were recorded, which means the code "
                f"has changed since the transcript was made.")
        d = json.loads(self._calls[self._i].read_text(encoding="utf-8"))
        self._i += 1
        return LLMResponse(
            text=d["text"], backend=self.name, model=d.get("model", ""),
            input_tokens=d.get("input_tokens", 0),
            output_tokens=d.get("output_tokens", 0),
            cache_read_tokens=d.get("cache_read_tokens", 0),
            cache_write_tokens=d.get("cache_write_tokens", 0),
            cost_usd=d.get("cost_usd"),
            raw={"replayed_from": str(self._calls[self._i - 1])},
        )

    def complete_stream(self, system: str, user: str,
                        on_chunk: Callable[[str], None] | None = None,
                        chunk_size: int = 40) -> LLMResponse:
        t0 = time.monotonic()
        res = self.complete(system, user, stream=False)
        dur = max(0.001, time.monotonic() - t0)
        res.streaming = True
        res.duration_s = round(dur, 3)
        res.time_to_first_token_s = 0.001
        toks = res.output_tokens or len(res.text.split())
        res.tokens_per_second = round(toks / dur, 1)
        if on_chunk and res.text:
            for chunk in _chunk_text(res.text, chunk_size=chunk_size):
                on_chunk(chunk)
        return res

    def stream(self, system: str, user: str, chunk_size: int = 40) -> Iterator[str]:
        res = self.complete(system, user, stream=False)
        yield from _chunk_text(res.text, chunk_size=chunk_size)


class FallbackBackend:
    """Multi-tier failover backend with circuit breaker protection.

    Dispatches calls to a primary backend; if that fails (e.g. rate limit,
    timeout, upstream outage, or circuit tripped), transparently routes to a chain
    of fallback backends until one succeeds or all fail.
    """

    name = "fallback"

    def __init__(self, primary: Any,
                 fallbacks: list[Any],
                 circuit_breaker: bool = True,
                 failure_threshold: int = 2,
                 recovery_timeout_s: float = 30.0,
                 on_fallback: Callable[[str, Exception, str], None] | None = None):
        self.primary = primary
        self.fallbacks = list(fallbacks)
        self.on_fallback = on_fallback
        self.use_circuit_breaker = circuit_breaker
        self.circuit_breakers: dict[int, CircuitBreaker] = {}
        all_b = [primary] + self.fallbacks
        for i, b in enumerate(all_b):
            b_name = f"{getattr(b, 'name', 'backend')}-{getattr(b, 'model', i)}"
            self.circuit_breakers[id(b)] = CircuitBreaker(
                name=b_name,
                failure_threshold=failure_threshold,
                recovery_timeout_s=recovery_timeout_s,
            )
        self.fallback_history: collections.deque[dict] = collections.deque(
            maxlen=MAX_FALLBACK_EVENTS)

    @property
    def model(self) -> str:
        return getattr(self.primary, "model", "")

    def complete(self, system: str, user: str,
                 stream: bool = False,
                 on_chunk: Callable[[str], None] | None = None) -> LLMResponse:
        if stream or on_chunk is not None:
            return self.complete_stream(system, user, on_chunk=on_chunk)

        chain = [self.primary] + self.fallbacks
        errors: dict[str, str] = {}
        primary_name = getattr(self.primary, "name", "primary")

        for i, backend in enumerate(chain):
            b_id = id(backend)
            b_name = getattr(backend, "name", f"backend_{i}")
            b_model = getattr(backend, "model", "")
            cb = self.circuit_breakers.get(b_id)

            if self.use_circuit_breaker and cb and not cb.allow_request():
                errors[f"{b_name}({b_model})"] = f"Circuit breaker OPEN (last error: {cb.last_error})"
                continue

            try:
                res = backend.complete(system, user)
                if self.use_circuit_breaker and cb:
                    cb.record_success()
                if backend is not self.primary:
                    res.fallback_used = True
                    res.fallback_from = primary_name
                    res.raw["fallback_history"] = list(errors.items())
                return res
            except Exception as exc:
                err_msg = str(exc)
                errors[f"{b_name}({b_model})"] = err_msg
                if self.use_circuit_breaker and cb:
                    cb.record_failure(exc)
                if self.on_fallback:
                    next_b = chain[i + 1] if i + 1 < len(chain) else None
                    next_name = getattr(next_b, "name", "none") if next_b else "none"
                    try:
                        self.on_fallback(b_name, exc, next_name)
                    except Exception:
                        pass
                self.fallback_history.append({
                    "failed_backend": b_name,
                    "failed_model": b_model,
                    "error": err_msg,
                    "timestamp": time.time(),
                })

        raise AllBackendsFailedError(
            f"All {len(chain)} backends failed in fallback chain: {errors}",
            errors=errors,
        )

    def complete_stream(self, system: str, user: str,
                        on_chunk: Callable[[str], None] | None = None) -> LLMResponse:
        chain = [self.primary] + self.fallbacks
        errors: dict[str, str] = {}
        primary_name = getattr(self.primary, "name", "primary")

        for i, backend in enumerate(chain):
            b_id = id(backend)
            b_name = getattr(backend, "name", f"backend_{i}")
            b_model = getattr(backend, "model", "")
            cb = self.circuit_breakers.get(b_id)

            if self.use_circuit_breaker and cb and not cb.allow_request():
                errors[f"{b_name}({b_model})"] = "Circuit breaker OPEN"
                continue

            try:
                if hasattr(backend, "complete_stream"):
                    res = backend.complete_stream(system, user, on_chunk=on_chunk)
                else:
                    res = backend.complete(system, user, stream=True, on_chunk=on_chunk)
                if self.use_circuit_breaker and cb:
                    cb.record_success()
                if backend is not self.primary:
                    res.fallback_used = True
                    res.fallback_from = primary_name
                    res.raw["fallback_history"] = list(errors.items())
                return res
            except Exception as exc:
                err_msg = str(exc)
                errors[f"{b_name}({b_model})"] = err_msg
                if self.use_circuit_breaker and cb:
                    cb.record_failure(exc)
                if self.on_fallback:
                    next_b = chain[i + 1] if i + 1 < len(chain) else None
                    next_name = getattr(next_b, "name", "none") if next_b else "none"
                    try:
                        self.on_fallback(b_name, exc, next_name)
                    except Exception:
                        pass
                self.fallback_history.append({
                    "failed_backend": b_name,
                    "failed_model": b_model,
                    "error": err_msg,
                    "timestamp": time.time(),
                })

        raise AllBackendsFailedError(
            f"All {len(chain)} backends failed in streaming fallback chain: {errors}",
            errors=errors,
        )

    def stream(self, system: str, user: str) -> Iterator[str]:
        res = self.complete_stream(system, user)
        yield res.text

    def stats(self) -> dict:
        return {
            "primary": getattr(self.primary, "name", "primary"),
            "fallback_count": len(self.fallbacks),
            "fallback_events": len(self.fallback_history),
            "circuit_breakers": {
                cb.name: cb.to_dict() for cb in self.circuit_breakers.values()
            },
        }


BackendType = ClaudeCLIBackend | OpenAICompatBackend | ReplayBackend | FallbackBackend


def make_backend(
    kind: str,
    transcript_dir: Path | None = None,
    fallbacks: list[str | Any] | None = None,
    circuit_breaker: bool = False,
    **kw: Any,
) -> BackendType:
    kind = (kind or "replay").lower()
    if kind == "cli":
        primary = ClaudeCLIBackend(**kw)
    elif kind in ("openai", "api"):   # "api" kept as an alias for older invocations
        primary = OpenAICompatBackend(**kw)
    elif kind == "replay":
        if transcript_dir is None:
            raise LLMError("replay backend needs transcript_dir")
        primary = ReplayBackend(transcript_dir, **kw)
    else:
        raise LLMError(f"unknown backend {kind!r}; expected cli, openai or replay")

    if fallbacks:
        fb_backends = []
        for fb in fallbacks:
            if isinstance(fb, str):
                fb_backends.append(make_backend(fb, transcript_dir=transcript_dir))
            else:
                fb_backends.append(fb)
        return FallbackBackend(primary=primary, fallbacks=fb_backends,
                               circuit_breaker=circuit_breaker)
    return primary
