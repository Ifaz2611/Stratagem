"""Baseline Hypothesis strategy for HTTP protocol parser target."""
from __future__ import annotations

from hypothesis import strategies as st

NAME = "http_baseline"
DESCRIPTION = "Hypothesis strategy generating structured HTTP requests and mutations"

_METHODS = st.sampled_from(["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])
_PATHS = st.sampled_from(["/", "/index.html", "/api/v1/resource", "/search?q=test", "/admin"])
_VERSIONS = st.sampled_from(["HTTP/1.1", "HTTP/1.0"])
_HEADERS = st.dictionaries(
    keys=st.sampled_from(["Host", "User-Agent", "Accept", "Content-Type", "Connection"]),
    values=st.sampled_from(["localhost", "curl/7.68.0", "*/*", "application/json", "close", "keep-alive"]),
    max_size=4,
)


@st.composite
def _well_formed_http(draw):
    method = draw(_METHODS)
    path = draw(_PATHS)
    version = draw(_VERSIONS)
    headers = draw(_HEADERS)
    lines = [f"{method} {path} {version}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    return "\r\n".join(lines) + "\r\n\r\n"


@st.composite
def _near_miss_http(draw):
    base = draw(_well_formed_http())
    kind = draw(st.sampled_from(["smuggle", "bad_version", "bad_header", "bare_newline"]))
    if kind == "smuggle":
        return base.replace("\r\n\r\n", "\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
    elif kind == "bad_version":
        return base.replace("HTTP/1.1", "HTTP/9.9")
    elif kind == "bad_header":
        return base.replace("Host:", "Host :")
    elif kind == "bare_newline":
        return base.replace("\r\n", "\n")
    return base


@st.composite
def _byte_hostile_http(draw):
    base = draw(_well_formed_http())
    kind = draw(st.sampled_from(["control", "nul", "bom", "unterminated"]))
    if kind == "control":
        return base.replace("Host: ", "Host: \x01\x02")
    elif kind == "nul":
        return base + "\x00"
    elif kind == "bom":
        return "\ufeff" + base
    elif kind == "unterminated":
        return base.rstrip("\r\n")
    return base


def documents() -> st.SearchStrategy[str]:
    return st.one_of(
        st.tuples(st.just("wf"), _well_formed_http()).map(lambda t: t[1]),
        st.tuples(st.just("nm"), _near_miss_http()).map(lambda t: t[1]),
        st.tuples(st.just("bh"), _byte_hostile_http()).map(lambda t: t[1]),
    )
