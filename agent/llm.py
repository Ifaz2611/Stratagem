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

import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

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
        }


def _redact(text: str) -> str:
    for var in ("OPENAI_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"):
        val = os.environ.get(var)
        if val and len(val) > 8:
            text = text.replace(val, f"<{var}>")
    return text


class LLMError(RuntimeError):
    pass


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

    def complete(self, system: str, user: str) -> LLMResponse:
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

    def complete(self, system: str, user: str) -> LLMResponse:
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

    def complete(self, system: str, user: str) -> LLMResponse:
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


def make_backend(kind: str, transcript_dir: Path | None = None, **kw):
    kind = (kind or "replay").lower()
    if kind == "cli":
        return ClaudeCLIBackend(**kw)
    if kind in ("openai", "api"):   # "api" kept as an alias for older invocations
        return OpenAICompatBackend(**kw)
    if kind == "replay":
        if transcript_dir is None:
            raise LLMError("replay backend needs transcript_dir")
        return ReplayBackend(transcript_dir, **kw)
    raise LLMError(f"unknown backend {kind!r}; expected cli, openai or replay")
