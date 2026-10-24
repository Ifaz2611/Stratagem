"""Minimal .env loader.

Format: `KEY=value` per line, `#` comments, blank lines ignored, optional
`export ` prefix, optional surrounding single or double quotes. A trailing
comment after an unquoted value is stripped, matching what run.sh's Docker
env-file normaliser does; without that, `LLM_BACKEND=replay  # default` would
arrive as the value "replay  # default".

Values already present in the real environment win, so
`LLM_BACKEND=openai ./run.sh` overrides the file without editing it.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_EXPORT = re.compile(r"^export\s+")
_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_UNQUOTED_COMMENT = re.compile(r"(?:^|\s)#")


def _parse_line(raw: str) -> tuple[str, str] | None:
    """Split one .env line into (key, value), or None if it carries no setting."""
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    line = _EXPORT.sub("", line, count=1).lstrip()
    if "=" not in line:
        return None

    key, _, rest = line.partition("=")
    key = key.strip()
    if not _KEY.match(key):
        return None

    value = rest.strip()
    if value[:1] in ('"', "'"):
        quote = value[0]
        chars: list[str] = []
        escaped = False
        for ch in value[1:]:
            if escaped:
                chars.append(ch)
                escaped = False
            elif ch == "\\" and quote == '"':
                escaped = True
            elif ch == quote:
                break
            else:
                chars.append(ch)
        return key, "".join(chars)

    # A '#' begins a comment only at the start of the value or after
    # whitespace, so an unquoted value may still contain a bare '#'.
    m = _UNQUOTED_COMMENT.search(value)
    if m:
        value = value[:m.start()]
    return key, value.strip()


def load_env(path: Path | None = None, override: bool = False) -> dict[str, str]:
    """Read .env into os.environ. Returns the keys it set (values not logged)."""
    p = Path(path) if path else REPO_ROOT / ".env"
    if not p.exists():
        return {}

    applied: dict[str, str] = {}
    for raw in p.read_text(encoding="utf-8").splitlines():
        parsed = _parse_line(raw)
        if parsed is None:
            continue
        key, val = parsed
        # Real environment wins unless explicitly overridden, so a one-off
        # `VAR=x` on the command line beats the file.
        if override or key not in os.environ:
            os.environ[key] = val
        applied[key] = val
    return applied


def describe_env() -> str:
    """Which credential-bearing variables are set, WITHOUT printing values."""
    watched = ("LLM_BACKEND", "LLM_MODEL", "OPENAI_API_KEY", "OPENAI_BASE_URL",
               "CLAUDE_CODE_OAUTH_TOKEN")
    out = []
    for k in watched:
        v = os.environ.get(k)
        if not v:
            out.append(f"{k}=<unset>")
        elif "KEY" in k or "TOKEN" in k:
            out.append(f"{k}=<set, {len(v)} chars>")
        else:
            out.append(f"{k}={v}")
    return "  ".join(out)
