"""Regression suite for the measurement layer.

The agentic loop is steered by what this layer reports. A bug here does not
crash anything; it feeds the model false claims about what its generator
produced, and the run degrades in a way that is invisible in the output. These
checks exist to catch that.

Run:  .venv/bin/python -m fuzzer.selftest
"""
from __future__ import annotations

import sys

from fuzzer.diagnostics import normalize
from fuzzer.features import analyze, coverage, PRODUCTIONS
from fuzzer.triage import parse_report

_passed = 0
_failed: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    global _passed
    if cond:
        _passed += 1
    else:
        _failed.append(f"{name}{(': ' + detail) if detail else ''}")


# ---------------------------------------------------------------- diagnostics
def test_diagnostics() -> None:
    # Same code site, different interpolated data -> one template.
    same = ["Missing close tag </u> under parent <r> on line 1.",
            "Missing close tag </zzz> under parent <qq> on line 412."]
    check("diag/merge same site", len({normalize(s) for s in same}) == 1)

    # mxml has four distinct "second root" sites differing only by the trailing
    # marker. They must NOT merge, or reached-branch counts are understated.
    roots = ["<b> cannot be a second root node after <a> on line 1.",
             "<b--> cannot be a second root node after <a> on line 1.",
             "<b?> cannot be a second root node after <a> on line 1.",
             "<b]]> cannot be a second root node after <a> on line 1."]
    check("diag/keep 4 root sites distinct", len({normalize(s) for s in roots}) == 4)

    # Open-tag and close-tag slots must stay distinguishable.
    check("diag/open vs close slot",
          normalize("Missing close tag </u> under parent <r> on line 1.")
          != normalize("Mismatched close tag <u> under parent <r> on line 1."))

    # Bare slots. mxml interpolates some values with no quotes or brackets, so
    # none of the quote/bracket rules match them. Left unhandled they inflate
    # the distinct-template count, which the agentic loop is steered by.
    bare = ["Duplicate attribute 'a' in element O74 on line 1.",
            "Duplicate attribute 'b' in element WMSrKel on line 9."]
    check("diag/bare element name merges", len({normalize(s) for s in bare}) == 1,
          str({normalize(s) for s in bare}))
    check("diag/bare slot matches mxml template",
          normalize(bare[0]) == "Duplicate attribute '%s' in element %s on line %d.",
          normalize(bare[0]))
    check("diag/bare 'of type' slot",
          normalize("Unable to add value node of type CDATA to parent <r> on line 5.")
          == "Unable to add value node of type %s to parent <%s> on line %d.")
    check("diag/bare 'Bad X value' slot",
          normalize("Bad integer value '99' in parent <r> on line 6.")
          == "Bad %s value '%s' in parent <%s> on line %d.")
    check("diag/bare slots do not over-merge",
          normalize(bare[0]) != normalize("Missing value for attribute 'x' in element z on line 2."))

    # A quoted slot whose content is itself a quote must not leave a stray quote.
    quote_char = normalize("XML does not start with '<' (saw ''').")
    check("diag/quote-as-content", quote_char.count("'") % 2 == 0, quote_char)
    check("diag/quote-as-content merges",
          quote_char == normalize("XML does not start with '<' (saw 'n')."))

    # Messages that fill mxml's 1024-byte buffer lose the text that says which
    # call site they came from, so they must all land in one bucket instead of
    # each becoming its own template.
    long_a = "<" + "a" * 1100 + "> cannot be a second root node after <r> on line 1."
    long_b = "<" + "b" * 1100 + "> cannot be a second root node after <r> on line 2."
    trunc_a = long_a.encode()[:1023].decode()
    trunc_b = long_b.encode()[:1023].decode()
    check("diag/buffer-truncated merge", normalize(trunc_a) == normalize(trunc_b))
    check("diag/buffer-truncated distinct from intact",
          normalize(trunc_a)
          != normalize("<x> cannot be a second root node after <r> on line 1."))
    # A message that merely contains multi-byte characters must not be mistaken
    # for a truncated one; the test is byte length, not character count.
    short_utf8 = "Bad control character 0x9 under parent <·̀x> on line 1 not allowed by XML standard."
    check("diag/multibyte not treated as truncated",
          "truncated" not in normalize(short_utf8), normalize(short_utf8))


# ------------------------------------------------------------------- features
POSITIVE = [
    ('<r/>', "g_element_selfclose"), ('<a>hi</a>', "g_element_paired"),
    ('<a>hi</a>', "g_chardata"), ('<?xml version="1.0"?><r/>', "g_prolog"),
    ('<?xml version="1.0"?><r/>', "g_attribute_dquot"),
    ("<r a='1'/>", "g_attribute_squot"), ('<r a=1/>', "x_attribute_unquoted"),
    ('<r>&amp;</r>', "g_entity_named"), ('<r>&apos;</r>', "x_entity_unsupported"),
    ('<r>&#65;</r>', "g_charref_dec"), ('<r>&#x41;</r>', "g_charref_hex"),
    ('<r><!-- c --></r>', "g_comment"), ('<r><![CDATA[x]]></r>', "g_cdata"),
    ('<?pi t?><r/>', "g_pi"), ('<!DOCTYPE r><r/>', "x_doctype"),
    ('<a></b>', "x_mismatched_tags"), ('<a/><b/>', "x_multiple_roots"),
    ('< />', "x_empty_elem_name"), ('<é/>', "x_name_nonascii"),
    ('just text', "x_rootless"), ('<r>\x01</r>', "x_control_char"),
    ('<r><!-- oops', "x_unterminated"), ('<a>' * 10 + '</a>' * 10, "g_nesting_deep"),
]

# Byte-level productions exist only in the raw payload, so they are tested with
# explicit bytes rather than text.
POSITIVE_BYTES = [
    ("\ufeff<r/>", "\ufeff<r/>".encode(), "x_bom"),
    ("<r>x</r>", b"<r>\xc3\x28</r>", "x_invalid_utf8"),
    ("<r/>", b"<r>\x00</r>", "x_embedded_nul"),
    ("<?xml encoding='x'?><r/>", b"<?xml encoding='x'?><r/>", "x_encoding_decl"),
]

# Constructs that a naive "<...>" scan mistakes for elements. Each of these
# would otherwise report a phantom element with an empty name whose close tag
# does not match, i.e. two false productions plus an inflated nesting depth.
NEGATIVE = [
    ('<?xml version="1.0"?><r/>', ("x_empty_elem_name", "x_mismatched_tags", "g_element_paired")),
    ('<r><!-- c --></r>', ("x_empty_elem_name", "x_mismatched_tags")),
    ('<r><![CDATA[x]]></r>', ("x_empty_elem_name", "x_mismatched_tags")),
    ('<!DOCTYPE r><r/>', ("x_empty_elem_name", "x_mismatched_tags", "g_element_paired")),
    ('<?pi t?><r/>', ("x_empty_elem_name", "x_mismatched_tags", "g_element_paired")),
    # Free text inside a comment or CDATA must not register as an attribute.
    ('<r><!-- a="1" --></r>', ("g_attribute_dquot",)),
    ('<r><![CDATA[b="2"]]></r>', ("g_attribute_dquot",)),
]


def test_features() -> None:
    for doc, prod in POSITIVE:
        check(f"feat/{prod}", prod in analyze(doc).productions, repr(doc))
    for doc, forbidden in NEGATIVE:
        got = analyze(doc).productions
        bad = set(forbidden) & got
        check(f"feat/no-false-positive {doc[:22]!r}", not bad, f"got {sorted(bad)}")

    for txt, pay, prod in POSITIVE_BYTES:
        check(f"feat/{prod}", prod in analyze(txt, pay).productions, repr(pay))
    # A byte-level production must put the document in the byte_hostile bucket,
    # since that bucket drives the mixture the loop steers on.
    for txt, pay, prod in POSITIVE_BYTES:
        if prod == "x_encoding_decl":
            continue  # a declaration alone is not hostile
        check(f"feat/{prod} -> byte_hostile",
              analyze(txt, pay).bucket == "byte_hostile", analyze(txt, pay).bucket)

    feats = [analyze(d) for d, _ in POSITIVE] + [analyze(t, b) for t, b, _ in POSITIVE_BYTES]
    check("feat/vocabulary fully reachable",
          coverage(feats)["productions_hit"] == len(PRODUCTIONS),
          str(coverage(feats)["missing"]))
    check("feat/depth", analyze('<a><b><c/></b></a>').max_depth == 2)
    check("feat/never raises", analyze("<<<>>>&;&#;<!--<![CDATA[").length > 0)


# --------------------------------------------------------------------- triage
ASAN_WRITE = """==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60 at pc 0x1
WRITE of size 4 at 0x60 thread T0
    #0 0x111 in mxml_add_char /src/mxml-file.c:2100
    #1 0x222 in mxml_load_data /src/mxml-file.c:950
    #2 0x333 in main /src/harness/harness.c:157
    #3 0x444 in __libc_start_main /csu/libc-start.c:360
"""
RECURSIVE = """==3==ERROR: AddressSanitizer: stack-overflow on address 0x7f (pc 0x1)
    #0 0x1 in mxml_walk /src/mxml-node.c:50
    #1 0x2 in mxml_walk /src/mxml-node.c:60
    #2 0x3 in mxml_walk /src/mxml-node.c:50
    #3 0x4 in mxml_walk /src/mxml-node.c:60
    #4 0x5 in mxmlDelete /src/mxml-node.c:120
"""
UBSAN = """f.c:1:1: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented
    #0 0x5555 in mxml_get_entity /src/mxml-file.c:1234
    #1 0x5556 in mxml_load_data /src/mxml-file.c:900
"""


def test_triage() -> None:
    w = parse_report(ASAN_WRITE)
    check("triage/asan type", w.bug_type == "heap-buffer-overflow", w.bug_type)
    check("triage/asan access", w.access == "WRITE", str(w.access))
    check("triage/drops harness+libc frames",
          all("main" not in f and "libc" not in f for f in w.signature_frames),
          str(w.signature_frames))

    r = parse_report(ASAN_WRITE.replace("WRITE of size 4", "READ of size 4"))
    check("triage/READ vs WRITE distinct", w.signature != r.signature)

    # The case that motivated the rule: recursion must not fake up many bugs.
    rec = parse_report(RECURSIVE)
    raw = [f.func for f in rec.frames]
    check("triage/recursion collapsed",
          raw.count("mxml_walk") > 1
          and rec.signature_frames.count("mxml_walk@mxml-node.c") == 1,
          f"raw={raw} sig={rec.signature_frames}")

    # Same bug reached at a different recursion depth = same signature.
    deeper = RECURSIVE.replace(
        "    #4 0x5 in mxmlDelete",
        "    #4 0x9 in mxml_walk /src/mxml-node.c:50\n    #5 0x5 in mxmlDelete")
    check("triage/depth-invariant", parse_report(deeper).signature == rec.signature)

    u = parse_report(UBSAN)
    check("triage/ubsan parsed", u is not None and "overflow" in u.bug_type, str(u and u.bug_type))
    check("triage/ubsan distinct from asan", u.signature != w.signature)
    check("triage/no report -> None", parse_report("just some text") is None)


LEAK = """=================================================================
==1==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 88 byte(s) in 1 object(s) allocated from:
    #0 0x1 in calloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:77
    #1 0x2 in mxml_new /src/mxml-node.c:931
    #2 0x3 in mxmlNewElement /src/mxml-node.c:541
    #3 0x4 in mxml_load_data /src/mxml-file.c:1328
    #4 0x5 in main /src/harness/harness.c:157
    #5 0x6 in __libc_start_main_impl ../csu/libc-start.c:360
"""


def test_leak_reports() -> None:
    r = parse_report(LEAK)
    check("leak/class named", r.bug_type == "memory-leak", r.bug_type)
    # The allocator interceptor is identified by its FILE, not a __asan_ prefix,
    # so a name-only filter lets "calloc" become the top frame and every leak in
    # the library collapses into one signature.
    check("leak/drops allocator frame",
          not any("calloc" in f for f in r.signature_frames), str(r.signature_frames))
    check("leak/top frame is target code",
          r.signature_frames and r.signature_frames[0].startswith("mxml_new@"),
          str(r.signature_frames))
    check("leak/drops libc frames",
          not any("libc" in f for f in r.signature_frames), str(r.signature_frames))


# ------------------------------------------------------- response extraction
WHOLE_MODULE = """from hypothesis import strategies as st

NAME = "x"
DESCRIPTION = "y"


def documents():
    return st.text()
"""


def test_extraction() -> None:
    from agent.validate import extract_code, looks_truncated

    code = extract_code("prose\n```python\n" + WHOLE_MODULE + "```\nmore prose")
    check("extract/pulls the block", code is not None and "def documents" in code)
    check("extract/whole module not truncated", not looks_truncated(code))

    # The two shapes seen when the CLI returns only the final assistant message
    # of a multi-message response: the block opens mid-body, or it opens at
    # column zero but below the import line.
    check("extract/indented first line is truncated",
          looks_truncated("    return draw(st.integers())\n"))
    check("extract/uses st with no import is truncated",
          looks_truncated('NAMES = ["a"]\n\n\ndef documents():\n    return st.text()\n'))
    # A module that never mentions st needs no import, so absence is not proof.
    check("extract/no st reference is not truncated",
          not looks_truncated('NAME = "x"\n\n\ndef documents():\n    return None\n'))
    check("extract/empty is not truncated", not looks_truncated("   \n"))
    # Prefer the module over an inline snippet when the response has both.
    two = ("```python\nst.text()\n```\n```python\n" + WHOLE_MODULE + "```")
    check("extract/prefers the module block", "def documents" in (extract_code(two) or ""))


def test_class_bounds() -> None:
    from agent.validate import CLASS_BOUNDS, CLASS_MARGIN, out_of_bounds

    # Real mixtures observed in the runs, pinned so a change to CLASS_BOUNDS has
    # to be deliberate. These assert the gate's behaviour, not that any of these
    # mixtures is better for coverage: see design-decisions D12.
    check("mix/run B seed passes",
          not out_of_bounds({"well_formed": 0.642, "near_miss": 0.204,
                             "byte_hostile": 0.154}))
    check("mix/run C seed passes",
          not out_of_bounds({"well_formed": 0.374, "near_miss": 0.312,
                             "byte_hostile": 0.314}))
    # Outside both bounds, so two violations are reported, worst first.
    check("mix/run D seed fails on both bounds",
          set(out_of_bounds({"well_formed": 0.212, "near_miss": 0.234,
                             "byte_hostile": 0.554}))
          == {"well_formed", "byte_hostile"})
    # A class the strategy never emits must fail its floor, not pass unnoticed.
    check("mix/absent class fails its floor",
          out_of_bounds({"well_formed": 0.8, "near_miss": 0.2}) == ["byte_hostile"])
    # Sampling slack: a share one margin outside a bound is tolerated, two is not.
    lo, hi = CLASS_BOUNDS["byte_hostile"]
    inside = {"well_formed": 0.5, "near_miss": 0.2, "byte_hostile": hi + CLASS_MARGIN / 2}
    outside = {"well_formed": 0.5, "near_miss": 0.2, "byte_hostile": hi + CLASS_MARGIN * 2}
    check("mix/within margin tolerated", not out_of_bounds(inside))
    check("mix/beyond margin rejected", out_of_bounds(outside) == ["byte_hostile"])
    # A class starved by another is a generator problem, not a weighting one, so
    # the repair has to name the generator rather than send the model to its
    # st.one_of weights.
    from agent.validate import Validation
    starved = Validation(False, "mixture",
                         mixture={"well_formed": 0.66, "near_miss": 0.06,
                                  "byte_hostile": 0.28}).feedback()
    check("mix/starved class names what the parser rejects",
          "<a></b>" in starved and "&amp" in starved)
    check("mix/starved class warns about tolerance",
          "tolerant" in starved)
    over = Validation(False, "mixture",
                      mixture={"well_formed": 0.40, "near_miss": 0.02,
                               "byte_hostile": 0.58}).feedback()
    check("mix/byte-hostile overshoot keeps its own advice", "BOM" in over)

    # Worst violation is reported first so the repair text leads with it. Here
    # byte_hostile is 40 points over its ceiling and well_formed 30 under its
    # floor, so byte_hostile leads.
    worst = out_of_bounds({"well_formed": 0.05, "near_miss": 0.10, "byte_hostile": 0.85})
    check("mix/worst violation first", worst == ["byte_hostile", "well_formed"], str(worst))


def test_budget_guard() -> None:
    from agent.loop import Budget

    # Checked before a call, not after, so a repair cannot push past the cap.
    b = Budget(5, 5.00)
    check("budget/first call always allowed", not b.would_overrun())
    b.cost_usd, b.calls = 3.04, 4
    check("budget/room for another call", not b.would_overrun())
    b.cost_usd, b.calls = 4.79, 6
    check("budget/refuses a call it cannot pay for", b.would_overrun())
    b.cost_usd, b.calls = 5.20, 6
    check("budget/already over stays over", b.would_overrun())


def test_usage_limit() -> None:
    from agent.llm import _looks_like_usage_limit as is_limit

    # An account limit lasts hours, so retrying through it wastes the run's
    # remaining wall clock. It has to be told apart from an ordinary blip.
    check("limit/plain wording", is_limit("Claude usage limit reached"))
    check("limit/http status", is_limit("HTTP 429 Too Many Requests"))
    check("limit/quota wording", is_limit("You have exceeded your quota"))
    check("limit/blank is not a limit", not is_limit(""))
    check("limit/network blip is not a limit", not is_limit("connection reset by peer"))


def test_review_regressions() -> None:
    from unittest.mock import patch
    from fuzzer.campaign import _encode
    from fuzzer.minimize import Minimized, verify
    from fuzzer.runner import Outcome, RunResult
    from fuzzer.triage import group

    check("bytes/raw UTF16 BOM", _encode("\udcff\udcfe<\x00") == b"\xff\xfe<\x00")
    check("bytes/mixed surrogates", _encode("\udcff\ud800") == b"\xff\xed\xa0\x80")
    check("features/long attribute", analyze('<r a="' + 'x' * 1000 + '"/>').max_attr_value_len == 1000)
    check("features/long entity", analyze('<r>&' + 'x' * 100 + ';</r>').max_entity_name_len == 100)
    check("bucket/comment extension", analyze('<!-- c -->').bucket == "well_formed")
    check("bucket/rootless text", analyze('garbage').bucket == "near_miss")
    doc = '<?xml encoding="UTF-16"?><r/>'
    check("bucket/encoding mismatch", analyze(doc, doc.encode()).bucket == "byte_hostile")
    groups = group([{"signal": "SIGSEGV"}, {"signal": "SIGABRT"}])
    check("triage/distinct fatal signals", len(groups) == 2)
    m = Minimized(found=True, signature="expected-sanitizer-signature")
    with patch("fuzzer.minimize.run_one", return_value=RunResult(Outcome.CRASH, -11)):
        verify(m, runs=1)
    check("verify/unparsed crash is not same fault", m.verified_ok == 0)


# --------------------------------------------------------------- env loading
def test_env_loader() -> None:
    import os
    import tempfile
    from pathlib import Path

    from agent.env import load_env

    text = "\n".join([
        "# comment",
        "",
        "GREP_PROBE_PLAIN=replay  # trailing comment",
        'GREP_PROBE_QUOTED="a # b"',
        "GREP_PROBE_SINGLE='c # d'",
        "export\tGREP_PROBE_EXPORT=openai",
        "GREP_PROBE_BARE_HASH=sk-abc#def",
        "not a setting",
        "=novalue",
    ])
    keys = [k for k in os.environ if k.startswith("GREP_PROBE_")]
    saved = {k: os.environ.pop(k) for k in keys}
    try:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".env"
            p.write_text(text, encoding="utf-8")
            got = load_env(p)
        check("env/trailing comment stripped",
              got.get("GREP_PROBE_PLAIN") == "replay", repr(got.get("GREP_PROBE_PLAIN")))
        check("env/double-quoted hash kept", got.get("GREP_PROBE_QUOTED") == "a # b")
        check("env/single-quoted hash kept", got.get("GREP_PROBE_SINGLE") == "c # d")
        check("env/export with tab", got.get("GREP_PROBE_EXPORT") == "openai")
        check("env/bare hash inside value kept",
              got.get("GREP_PROBE_BARE_HASH") == "sk-abc#def")
        check("env/junk lines ignored", "not a setting" not in got and "" not in got)
        # The real environment wins over the file unless override is asked for.
        os.environ["GREP_PROBE_PLAIN"] = "cli"
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / ".env"
            p.write_text("GREP_PROBE_PLAIN=replay\n", encoding="utf-8")
            load_env(p)
            check("env/environment wins", os.environ["GREP_PROBE_PLAIN"] == "cli")
            load_env(p, override=True)
            check("env/override wins", os.environ["GREP_PROBE_PLAIN"] == "replay")
    finally:
        for k in [k for k in os.environ if k.startswith("GREP_PROBE_")]:
            del os.environ[k]
        os.environ.update(saved)


# --------------------------------------------------- encoding declaration
def test_encoding_declaration() -> None:
    # "encoding=" in character data is not a declaration. Treating it as one
    # moved an ordinary well-formed document into byte_hostile, which polluted
    # the class mixture the loop is steered by.
    doc = "<r>encoding=shift_jis</r>"
    f = analyze(doc, doc.encode())
    check("encoding/text is not a declaration", "x_encoding_decl" not in f.productions,
          str(sorted(f.productions)))
    check("encoding/text is not hostile", f.bucket == "well_formed", f.bucket)

    # A declaration inside the body is a processing instruction, not a
    # document-level declaration, so it must not be read as one either.
    late = '<r><?xml encoding="UTF-8"?></r>'
    check("encoding/late declaration ignored",
          "x_encoding_decl" not in analyze(late, late.encode()).productions)

    prolog = '<?xml version="1.0" encoding="UTF-8"?><r/>'
    f = analyze(prolog, prolog.encode())
    check("encoding/prolog declaration found", "x_encoding_decl" in f.productions)
    check("encoding/utf8 declaration matches", not f.encoding_mismatch)

    # A bare UTF-16 declaration is disambiguated by the BOM, so a big-endian
    # document is legitimate. The old code demanded a little-endian BOM and
    # called every big-endian document contradictory.
    xml = '<?xml version="1.0" encoding="UTF-16"?><r/>'
    for label, payload in (
            ("be", b"\xfe\xff" + xml.encode("utf-16-be")),
            ("le", b"\xff\xfe" + xml.encode("utf-16-le"))):
        text = payload.decode("utf-16")
        f = analyze(text, payload)
        check(f"encoding/utf16-{label} declaration found",
              "x_encoding_decl" in f.productions, str(sorted(f.productions)))
        check(f"encoding/utf16-{label} not contradictory", not f.encoding_mismatch)

    # A UTF-8 body claiming UTF-16 is still a contradiction.
    lie = '<?xml version="1.0" encoding="UTF-16"?><r/>'
    check("encoding/utf16 lie detected", analyze(lie, lie.encode()).encoding_mismatch)


# ------------------------------------------------------------- replay offset
def test_replay_offset() -> None:
    import json
    import tempfile
    from pathlib import Path

    from agent.llm import ReplayBackend

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        for n, text in ((1, "first"), (2, "second")):
            d = root / f"call-{n}"
            d.mkdir()
            (d / "response.json").write_text(json.dumps({
                "text": text, "backend": "replay", "model": "m",
                "input_tokens": 0, "output_tokens": 0,
                "cache_read_tokens": 0, "cache_write_tokens": 0,
                "billable_input": 0, "cost_usd": 0.0,
            }), encoding="utf-8")
        check("replay/starts at the beginning", ReplayBackend(root).complete("", "").text == "first")
        check("replay/resume skips recorded calls",
              ReplayBackend(root, start=1).complete("", "").text == "second")
        check("replay/negative start is clamped",
              ReplayBackend(root, start=-3).complete("", "").text == "first")


# --------------------------------------------------------- transcript grouping
def _write_call(root, n, tag, iteration=None, user=None, cost=0.0) -> None:
    import json
    from pathlib import Path

    d = Path(root) / f"call-{n}"
    d.mkdir()
    rec = {"text": "", "backend": "cli", "tag": tag, "cost_usd": cost}
    if iteration is not None:
        rec["iteration"] = iteration
    (d / "response.json").write_text(json.dumps(rec), encoding="utf-8")
    if user is not None:
        (d / "user.md").write_text(user, encoding="utf-8")


def _loop_shell(root, kind="replay", resume=0):
    from pathlib import Path

    from agent.loop import Budget, Loop

    loop = Loop.__new__(Loop)
    loop.transcript = Path(root)
    loop.backend_kind = kind
    loop.resume_from = resume
    loop.budget = Budget(max_iterations=5, max_usd=5.0)
    loop._calls_cache = None
    return loop


def test_call_grouping() -> None:
    import tempfile

    def grouped(root):
        return [len(g) for g in _loop_shell(root)._grouped_calls()]

    # Legacy transcript: the tag alone cannot tell a resend from a new
    # iteration, so the iteration must come from the refine prompt.
    with tempfile.TemporaryDirectory() as td:
        _write_call(td, 1, "seed")
        _write_call(td, 2, "seed-repair1")
        _write_call(td, 3, "refine", user="## Current strategy (iteration 1)")
        _write_call(td, 4, "refine", user="## Current strategy (iteration 1)")
        got = grouped(td)
        check("group/resend stays in its iteration", got == [2, 2], str(got))

    # New transcripts record the iteration, which also covers resends and
    # campaign repairs without parsing the prompt.
    with tempfile.TemporaryDirectory() as td:
        _write_call(td, 1, "seed", iteration=0)
        _write_call(td, 2, "refine", iteration=1)
        _write_call(td, 3, "refine", iteration=1)
        _write_call(td, 4, "refine-repair1", iteration=1)
        _write_call(td, 5, "refine", iteration=2)
        got = grouped(td)
        check("group/recorded iteration wins", got == [1, 3, 1], str(got))

    # A resumed transcript can skip an iteration; the index must still mean
    # the iteration number, not the position in the list.
    with tempfile.TemporaryDirectory() as td:
        _write_call(td, 1, "seed", iteration=0)
        _write_call(td, 3, "refine", iteration=2)
        got = grouped(td)
        check("group/gap is padded", got == [1, 0, 1], str(got))


def test_resume_budget() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        _write_call(td, 1, "seed", iteration=0, cost=1.0)
        _write_call(td, 2, "refine", iteration=1, cost=2.0)
        _write_call(td, 3, "refine", iteration=2, cost=4.0)

        # Replay re-reads calls from iteration 2 onward and charges them as it
        # goes, so restoring them here would count the same money twice.
        replay = _loop_shell(td, "replay", resume=2)
        replay._restore_budget()
        check("resume/replay does not double-charge", replay.budget.cost_usd == 3.0,
              str(replay.budget.cost_usd))
        check("resume/replay keeps numbering", replay.budget.calls == 3,
              str(replay.budget.calls))

        # A live backend is not re-reading anything: every recorded call is
        # spend that already happened.
        live = _loop_shell(td, "cli", resume=2)
        live._restore_budget()
        check("resume/live charges every recorded call", live.budget.cost_usd == 7.0,
              str(live.budget.cost_usd))


def main() -> int:
    test_diagnostics()
    test_features()
    test_triage()
    test_leak_reports()
    test_extraction()
    test_class_bounds()
    test_budget_guard()
    test_usage_limit()
    test_review_regressions()
    test_env_loader()
    test_encoding_declaration()
    test_replay_offset()
    test_call_grouping()
    test_resume_budget()

    from fuzzer import test_targets
    test_targets.test_target_registry()
    test_targets.test_xml_targets()
    test_targets.test_json_target()
    test_targets.test_protocol_targets()
    test_targets.test_campaign_with_targets()

    from fuzzer import test_improvements
    test_improvements.test_parallel_fuzzing()
    test_improvements.test_adaptive_batch_sizing()
    test_improvements.test_corpus_management()
    test_improvements.test_timeout_and_slow_inputs()
    test_improvements.test_incremental_persistence()

    total_passed = _passed + test_targets._passed + test_improvements._passed
    all_failed = _failed + test_targets._failed + test_improvements._failed
    print(f"passed={total_passed} failed={len(all_failed)}")
    for f in all_failed:
        print(f"  FAIL {f}")
    return 1 if all_failed else 0


if __name__ == "__main__":
    sys.exit(main())
