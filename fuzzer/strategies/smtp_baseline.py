"""Baseline Hypothesis strategy for SMTP protocol target."""
from __future__ import annotations

from hypothesis import strategies as st

NAME = "smtp_baseline"
DESCRIPTION = "Hypothesis strategy generating SMTP command sessions and mutations (RFC 5321)"

_DOMAINS = st.sampled_from(["example.com", "mail.test", "localhost", "sub.domain.org"])
_USERS = st.sampled_from(["alice", "bob", "postmaster", "admin"])


@st.composite
def _well_formed_smtp(draw):
    dom = draw(_DOMAINS)
    u1 = draw(_USERS)
    u2 = draw(_USERS)
    lines = [
        f"EHLO {dom}",
        f"MAIL FROM:<{u1}@{dom}>",
        f"RCPT TO:<{u2}@{dom}>",
        "DATA",
        "Subject: Fuzz Test",
        "",
        "Hello SMTP world.",
        ".",
        "QUIT",
    ]
    return "\r\n".join(lines) + "\r\n"


@st.composite
def _near_miss_smtp(draw):
    base = draw(_well_formed_smtp())
    kind = draw(st.sampled_from(["bad_verb", "bad_addr", "bare_newline", "no_param"]))
    if kind == "bad_verb":
        return base.replace("EHLO", "INVALID_COMMAND")
    elif kind == "bad_addr":
        return base.replace("<alice@", "alice@")  # missing angle brackets
    elif kind == "bare_newline":
        return base.replace("\r\n", "\n")
    elif kind == "no_param":
        return base.replace(f"EHLO {draw(_DOMAINS)}", "EHLO")
    return base


@st.composite
def _byte_hostile_smtp(draw):
    base = draw(_well_formed_smtp())
    kind = draw(st.sampled_from(["long_line", "control", "nul"]))
    if kind == "long_line":
        # RFC 5321 max line length is 1000 octets
        long_str = "A" * 1200
        return f"NOOP {long_str}\r\n" + base
    elif kind == "control":
        return base.replace("Hello", "Hello\x01\x02")
    elif kind == "nul":
        return base + "\x00"
    return base


def documents() -> st.SearchStrategy[str]:
    return st.one_of(
        st.tuples(st.just("wf"), _well_formed_smtp()).map(lambda t: t[1]),
        st.tuples(st.just("nm"), _near_miss_smtp()).map(lambda t: t[1]),
        st.tuples(st.just("bh"), _byte_hostile_smtp()).map(lambda t: t[1]),
    )
