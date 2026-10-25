"""Comprehensive tests for the Stratagem Target Abstraction Layer.

Covers:
- Target registry and discovery
- XML parser targets: mxml, libxml2, expat, tinyxml2
- JSON parser target (proof-of-concept for non-XML grammars)
- Protocol parser targets: HTTP, DNS, SMTP
- Diagnostic normalization and feature analysis across targets
- Campaign execution across targets
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from fuzzer.campaign import Campaign
from fuzzer.runner import Outcome
from fuzzer.targets import (
    BaseTarget,
    get_default_target,
    get_target,
    list_targets,
    register_target,
)
from fuzzer.targets.json_features import analyze as analyze_json, coverage as coverage_json
from fuzzer.targets.protocol_features import (
    analyze_dns,
    analyze_http,
    analyze_smtp,
    coverage_dns,
    coverage_http,
    coverage_smtp,
)

_passed = 0
_failed: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    global _passed
    if cond:
        _passed += 1
    else:
        _failed.append(f"{name}{(': ' + detail) if detail else ''}")


# -------------------------------------------------------------------- Registry
def test_target_registry() -> None:
    targets = list_targets()
    expected = {"mxml", "libxml2", "expat", "tinyxml2", "json", "http", "dns", "smtp"}
    check("registry/all_expected_registered", expected.issubset(set(targets.keys())), str(targets.keys()))

    for name in expected:
        t = get_target(name)
        check(f"registry/get_{name}", t.name == name)
        check(f"registry/{name}_has_category", bool(t.category))
        check(f"registry/{name}_has_productions", len(t.productions) > 0)

    check("registry/default_is_mxml", get_default_target().name == "mxml")

    # Custom registration
    class DummyTarget(BaseTarget):
        name = "dummy"
        category = "custom"
        def is_valid_shape(self, payload: bytes) -> bool: return True
        def normalize_diagnostic(self, message: str) -> str: return message
        def analyze_features(self, text: str, payload: bytes = b""): return None
        def summarize_structure(self, feature_list: list) -> dict: return {}

    dummy = DummyTarget()
    register_target(dummy)
    check("registry/register_custom", get_target("dummy") is dummy)

    try:
        get_target("nonexistent_target_12345")
        check("registry/unknown_raises", False)
    except KeyError:
        check("registry/unknown_raises", True)


# ----------------------------------------------------------------- XML Targets
def test_xml_targets() -> None:
    valid_xml = b"<root><child attr='val'>hello</child></root>"
    invalid_xml = b"<root><child>unclosed</root>"

    # 1. expat
    expat_t = get_target("expat")
    check("expat/shape_valid", expat_t.is_valid_shape(valid_xml))
    check("expat/shape_invalid", not expat_t.is_valid_shape(b"not xml"))
    r_clean = expat_t.run(valid_xml)
    check("expat/parse_valid", r_clean.outcome == Outcome.PARSED_CLEAN, str(r_clean))
    r_bad = expat_t.run(invalid_xml)
    check("expat/parse_invalid", r_bad.outcome == Outcome.REJECTED, str(r_bad))
    check("expat/diag_norm", "%d" in expat_t.normalize_diagnostic("mismatched tag on line 12, column 34"))

    # 2. libxml2
    libxml2_t = get_target("libxml2")
    check("libxml2/shape_valid", libxml2_t.is_valid_shape(valid_xml))
    check("libxml2/shape_invalid", not libxml2_t.is_valid_shape(b"plain text"))
    r_lx_clean = libxml2_t.run(valid_xml)
    check("libxml2/parse_valid", r_lx_clean.outcome == Outcome.PARSED_CLEAN, str(r_lx_clean))
    r_lx_bad = libxml2_t.run(invalid_xml)
    check("libxml2/parse_invalid", r_lx_bad.outcome == Outcome.REJECTED, str(r_lx_bad))
    check("libxml2/diag_norm", "%s" in libxml2_t.normalize_diagnostic("Opening and ending tag mismatch: tag foo line 12"))

    # 3. tinyxml2
    tiny_t = get_target("tinyxml2")
    check("tinyxml2/shape_valid", tiny_t.is_valid_shape(valid_xml))
    check("tinyxml2/shape_invalid", not tiny_t.is_valid_shape(b"plain text"))
    r_ty_clean = tiny_t.run(valid_xml)
    check("tinyxml2/parse_valid", r_ty_clean.outcome == Outcome.PARSED_CLEAN, str(r_ty_clean))
    r_ty_bad = tiny_t.run(invalid_xml)
    check("tinyxml2/parse_invalid", r_ty_bad.outcome == Outcome.REJECTED, str(r_ty_bad))
    check("tinyxml2/diag_norm", "%d" in tiny_t.normalize_diagnostic("XML_ERROR_MISMATCHED_ELEMENT on line 5"))

    # 4. mxml
    mxml_t = get_target("mxml")
    check("mxml/shape_valid", mxml_t.is_valid_shape(valid_xml))
    check("mxml/shape_invalid", not mxml_t.is_valid_shape(b"plain text"))
    r_mx_clean = mxml_t.run(valid_xml)
    check("mxml/parse_valid", r_mx_clean.outcome == Outcome.PARSED_CLEAN, str(r_mx_clean))
    r_mx_bad = mxml_t.run(invalid_xml)
    check("mxml/parse_invalid", r_mx_bad.outcome == Outcome.REJECTED, str(r_mx_bad))


# ---------------------------------------------------------------- JSON Target
def test_json_target() -> None:
    json_t = get_target("json")
    valid_json = b'{"name": "test", "items": [1, 2.5, true, null], "nested": {"key": "val"}}'
    invalid_json = b'{"name": "test", "items": [1, 2,]}'

    check("json/category", json_t.category == "json")
    check("json/shape_brace", json_t.is_valid_shape(b'{"a": 1}'))
    check("json/shape_bracket", json_t.is_valid_shape(b'[1, 2, 3]'))
    check("json/shape_quote", json_t.is_valid_shape(b'"string"'))
    check("json/shape_number", json_t.is_valid_shape(b'-123'))
    check("json/shape_invalid", not json_t.is_valid_shape(b'<xml/>'))

    r_clean = json_t.run(valid_json)
    check("json/parse_clean", r_clean.outcome == Outcome.PARSED_CLEAN, str(r_clean))

    r_bad = json_t.run(invalid_json)
    check("json/parse_rejected", r_bad.outcome == Outcome.REJECTED, str(r_bad))
    check("json/has_diagnostic", len(r_bad.diagnostics) > 0)

    # Diagnostic normalization
    norm_diag = json_t.normalize_diagnostic("Expecting property name enclosed in double quotes: line 12 column 34 (char 56)")
    check("json/diag_norm", "%d" in norm_diag and "line %d" in norm_diag, norm_diag)

    # Structural feature analysis
    f = analyze_json(valid_json.decode("utf-8"), valid_json)
    check("json/feat_object", "g_object" in f.productions)
    check("json/feat_array", "g_array" in f.productions)
    check("json/feat_pair", "g_pair" in f.productions)
    check("json/feat_string", "g_string" in f.productions)
    check("json/feat_int", "g_number_int" in f.productions)
    check("json/feat_float", "g_number_float" in f.productions)
    check("json/feat_true", "g_true" in f.productions)
    check("json/feat_null", "g_null" in f.productions)
    check("json/feat_depth", f.max_depth == 2)
    check("json/feat_bucket_wf", f.bucket == "well_formed")

    # Near-miss feature analysis
    f_nm = analyze_json('{"key": [1, 2,]}')
    check("json/feat_trailing_comma", "x_trailing_comma" in f_nm.productions)
    check("json/feat_bucket_nm", f_nm.bucket == "near_miss")

    # Byte-hostile feature analysis
    f_bh = analyze_json('{"key": "test\x01"}', b'{"key": "test\x01"}')
    check("json/feat_control", "x_control_char" in f_bh.productions)
    check("json/feat_bucket_bh", f_bh.bucket == "byte_hostile")

    cov = coverage_json([f, f_nm, f_bh])
    check("json/coverage_hits", cov["productions_hit"] >= 8)


# ------------------------------------------------------------ Protocol Targets
def test_protocol_targets() -> None:
    # 1. HTTP Target
    http_t = get_target("http")
    valid_http = b"GET /index.html?search=fuzz HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
    invalid_http = b"NOT_A_VALID_REQUEST_LINE\r\n\r\n"
    smuggle_http = b"POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"

    check("http/category", http_t.category == "protocol")
    check("http/shape_valid", http_t.is_valid_shape(valid_http))
    check("http/shape_invalid", not http_t.is_valid_shape(b"<?xml?>"))

    r_http_clean = http_t.run(valid_http)
    check("http/parse_clean", r_http_clean.outcome == Outcome.PARSED_CLEAN, str(r_http_clean))

    r_http_bad = http_t.run(invalid_http)
    check("http/parse_bad", r_http_bad.outcome == Outcome.REJECTED, str(r_http_bad))

    r_http_smuggle = http_t.run(smuggle_http)
    check("http/parse_smuggle_diag", r_http_smuggle.outcome == Outcome.PARSED_DIAG, str(r_http_smuggle))

    f_http = analyze_http(valid_http.decode("latin1"), valid_http)
    check("http/feat_request", "g_http_request" in f_http.productions)
    check("http/feat_method", "g_method_standard" in f_http.productions)
    check("http/feat_query", "g_query_string" in f_http.productions)
    check("http/feat_header_host", "g_header_host" in f_http.productions)

    f_smuggle = analyze_http(smuggle_http.decode("latin1"), smuggle_http)
    check("http/feat_smuggle", "x_smuggling_cl_te" in f_smuggle.productions)
    check("http/feat_bucket_nm", f_smuggle.bucket == "near_miss")

    cov_h = coverage_http([f_http, f_smuggle])
    check("http/coverage_hit", cov_h["productions_hit"] >= 5)

    # 2. DNS Target
    dns_t = get_target("dns")
    # Standard DNS query for example.com (type A, class IN)
    valid_dns = (
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07example\x03com\x00\x00\x01\x00\x01"
    )
    truncated_dns = b"\x12\x34\x01"
    loop_dns = (
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\xc0\x0c\x00\x01\x00\x01"
    )

    check("dns/category", dns_t.category == "protocol")
    check("dns/shape_valid", dns_t.is_valid_shape(valid_dns))
    check("dns/shape_invalid", not dns_t.is_valid_shape(b"short"))

    r_dns_clean = dns_t.run(valid_dns)
    check("dns/parse_clean", r_dns_clean.outcome == Outcome.PARSED_CLEAN, str(r_dns_clean))

    r_dns_trunc = dns_t.run(truncated_dns)
    check("dns/parse_trunc", r_dns_trunc.outcome == Outcome.REJECTED, str(r_dns_trunc))

    r_dns_loop = dns_t.run(loop_dns)
    check("dns/detects_compression_loop", r_dns_loop.outcome == Outcome.CRASH, str(r_dns_loop))

    f_dns = analyze_dns("", valid_dns)
    check("dns/feat_header", "g_dns_header" in f_dns.productions)
    check("dns/feat_query", "g_qr_query" in f_dns.productions)
    check("dns/feat_question", "g_question" in f_dns.productions)

    f_dns_loop = analyze_dns("", loop_dns)
    check("dns/feat_loop", "x_compression_loop" in f_dns_loop.productions)
    check("dns/feat_bucket_bh", f_dns_loop.bucket == "byte_hostile")

    cov_d = coverage_dns([f_dns, f_dns_loop])
    check("dns/coverage_hit", cov_d["productions_hit"] >= 4)

    # 3. SMTP Target
    smtp_t = get_target("smtp")
    valid_smtp = (
        b"EHLO client.example.com\r\n"
        b"MAIL FROM:<sender@example.com>\r\n"
        b"RCPT TO:<recipient@example.com>\r\n"
        b"DATA\r\n"
        b"Subject: Test\r\n\r\n"
        b"Fuzzing message body\r\n"
        b".\r\n"
        b"QUIT\r\n"
    )
    invalid_smtp = b"BOGUS_COMMAND parameters\r\n"
    oversize_smtp = b"NOOP " + b"A" * 1200 + b"\r\n"

    check("smtp/category", smtp_t.category == "protocol")
    check("smtp/shape_valid", smtp_t.is_valid_shape(valid_smtp))
    check("smtp/shape_invalid", not smtp_t.is_valid_shape(b"random"))

    r_smtp_clean = smtp_t.run(valid_smtp)
    check("smtp/parse_clean", r_smtp_clean.outcome == Outcome.PARSED_CLEAN, str(r_smtp_clean))

    r_smtp_bad = smtp_t.run(invalid_smtp)
    check("smtp/parse_bad", r_smtp_bad.outcome == Outcome.REJECTED, str(r_smtp_bad))

    r_smtp_long = smtp_t.run(oversize_smtp)
    check("smtp/parse_line_too_long", r_smtp_long.outcome == Outcome.REJECTED, str(r_smtp_long))

    f_smtp = analyze_smtp(valid_smtp.decode("latin1"), valid_smtp)
    check("smtp/feat_ehlo", "g_helo_ehlo" in f_smtp.productions)
    check("smtp/feat_mail", "g_mail_from" in f_smtp.productions)
    check("smtp/feat_rcpt", "g_rcpt_to" in f_smtp.productions)
    check("smtp/feat_data", "g_data" in f_smtp.productions)
    check("smtp/feat_body", "g_data_body" in f_smtp.productions)
    check("smtp/feat_quit", "g_quit" in f_smtp.productions)

    f_smtp_long = analyze_smtp(oversize_smtp.decode("latin1"), oversize_smtp)
    check("smtp/feat_long_line", "x_line_too_long" in f_smtp_long.productions)
    check("smtp/feat_bucket_bh", f_smtp_long.bucket == "byte_hostile")

    cov_s = coverage_smtp([f_smtp, f_smtp_long])
    check("smtp/coverage_hit", cov_s["productions_hit"] >= 6)


# ------------------------------------------------------------- Campaign trials
def test_campaign_with_targets() -> None:
    targets_and_strats = [
        ("expat", "baseline"),
        ("json", "json_baseline"),
        ("http", "http_baseline"),
        ("dns", "dns_baseline"),
        ("smtp", "smtp_baseline"),
    ]

    for t_name, strat in targets_and_strats:
        with tempfile.TemporaryDirectory() as td:
            c = Campaign(strat, 10, Path(td), mode="survey", target=t_name)
            s = c.run()
            check(f"campaign/{t_name}_examples", s["examples"] == 10)
            check(f"campaign/{t_name}_has_target", s["target"] == t_name)
            check(f"campaign/{t_name}_has_structure", "productions_hit" in s["structure"])
            check(f"campaign/{t_name}_has_outcomes", len(s["outcomes"]) > 0)


def main() -> int:
    test_target_registry()
    test_xml_targets()
    test_json_target()
    test_protocol_targets()
    test_campaign_with_targets()
    print(f"passed={_passed} failed={len(_failed)}")
    for f in _failed:
        print(f"  FAIL {f}")
    return 1 if _failed else 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
