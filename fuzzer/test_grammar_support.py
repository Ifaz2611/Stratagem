"""Comprehensive test suite for Grammar Support:
  1. Additional grammar formats (EBNF, Yacc/Bison, ANTLR v4)
  2. Automatic grammar extraction from existing code
  3. Grammar mutation capabilities
  4. Context-sensitive grammar engine
"""
from __future__ import annotations

import re
from pathlib import Path

from grammar import (
    ChecksumConstraint,
    ContextSensitiveGenerator,
    ContextSensitiveGrammar,
    GenerationContext,
    Grammar,
    GrammarMutator,
    MutationType,
    ScopedSymbolConstraint,
    convert_grammar,
    create_http_context_grammar,
    create_xml_context_grammar,
    export_ebnf,
    export_yacc,
    extract_grammar,
    load_grammar,
    mutate_grammar,
    parse_ebnf,
    parse_yacc,
)

_passed = 0
_failed: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    global _passed
    if cond:
        _passed += 1
    else:
        _failed.append(f"{name}{(': ' + detail) if detail else ''}")


# =====================================================================
# 1. Grammar Formats Tests (EBNF, Yacc/Bison, ANTLR v4)
# =====================================================================
def test_grammar_formats() -> None:
    # 1. Model basics
    g = Grammar(name="Calc", start_symbol="expr")
    r_expr = g.add_rule("expr")
    r_expr.add_production(["term", "+", "expr"])
    r_expr.add_production(["term"])
    r_term = g.add_rule("term")
    r_term.add_production(["NUMBER"])

    check("formats/model_nonterminals", set(g.nonterminals()) == {"expr", "term"})
    check("formats/model_prod_count", g.production_count() == 3)
    check("formats/model_to_dict", "rules" in g.to_dict())

    # 2. EBNF Parsing
    ebnf_sample = """
    (* Expression grammar in EBNF *)
    expr = term , [ "+" , expr ] ;
    term = factor , { "*" , factor } ;
    factor = "(" , expr , ")" | IDENTIFIER | NUMBER ;
    """
    g_ebnf = parse_ebnf(ebnf_sample, name="EBNF_Calc")
    check("formats/ebnf_rules_count", len(g_ebnf.rules) == 3)
    check("formats/ebnf_nonterminals", "factor" in g_ebnf.rules and "term" in g_ebnf.rules)
    check("formats/ebnf_start_symbol", g_ebnf.start_symbol == "expr")

    factor_rule = g_ebnf.get_rule("factor")
    check("formats/ebnf_factor_alts", factor_rule is not None and len(factor_rule.productions) == 3)

    # EBNF Export
    ebnf_exported = export_ebnf(g_ebnf)
    check("formats/ebnf_exported_str", "expr =" in ebnf_exported and "factor =" in ebnf_exported)

    # 3. Yacc / Bison Parsing
    bison_sample = """
    %{
    #include <stdio.h>
    %}
    %token NUMBER IDENTIFIER
    %start program
    %%
    program : statement_list { printf("done\\n"); }
            ;
    statement_list : statement
                   | statement_list ';' statement
                   ;
    statement : IDENTIFIER '=' NUMBER
              ;
    %%
    int main() { return 0; }
    """
    g_bison = parse_yacc(bison_sample, name="Bison_Prog")
    check("formats/bison_rules_count", len(g_bison.rules) == 3)
    check("formats/bison_start_symbol", g_bison.start_symbol == "program")
    check("formats/bison_terminals", "NUMBER" in g_bison.terminals and "IDENTIFIER" in g_bison.terminals)

    stmt_rule = g_bison.get_rule("statement")
    check("formats/bison_action_stripped", stmt_rule is not None and len(stmt_rule.productions) == 1)

    # Bison Export
    bison_exported = export_yacc(g_bison)
    check("formats/bison_exported_tokens", "%token" in bison_exported)
    check("formats/bison_exported_rules", "statement_list :" in bison_exported)

    # 4. ANTLR v4 Parsing
    antlr_path = Path("grammar/JSON.g4")
    if antlr_path.exists():
        g_antlr = load_grammar(antlr_path)
        check("formats/antlr_loaded", len(g_antlr.rules) >= 4)
        check("formats/antlr_rules_present", "json" in g_antlr.rules or "value" in g_antlr.rules)

    # 5. Round-trip conversion
    converted_bison = convert_grammar(ebnf_sample, target_format="bison", source_format="ebnf")
    check("formats/convert_ebnf_to_bison", "%%" in converted_bison and "expr :" in converted_bison)

    converted_ebnf = convert_grammar(bison_sample, target_format="ebnf", source_format="bison")
    check("formats/convert_bison_to_ebnf", "program =" in converted_ebnf)


# =====================================================================
# 2. Grammar Extraction Tests
# =====================================================================
def test_grammar_extraction() -> None:
    # 1. C parser extraction on harness/json/harness.c
    json_c_path = Path("harness/json/harness.c")
    if json_c_path.exists():
        report = extract_grammar(json_c_path, name="ExtractedJSON")
        check("extraction/c_report_lang", report.source_language == "c")
        check("extraction/c_rules_extracted", report.rules_extracted >= 4, f"got {report.rules_extracted}")
        check("extraction/c_has_value_rule", "value" in report.grammar.rules)
        check("extraction/c_has_string_rule", "string" in report.grammar.rules)
        check("extraction/c_has_terminals", len(report.grammar.terminal_names()) > 0)
        check("extraction/c_confidence", report.confidence_score > 0.5)

    # 2. Python parser code extraction
    python_parser_code = """
class MiniXMLParser:
    def parse_document(self):
        self.parse_element()

    def parse_element(self):
        if self.peek() == '<':
            self.parse_name()
            self.parse_attributes()
            self.parse_content()

    def parse_attributes(self):
        while self.peek() != '>':
            self.parse_attribute()

    def parse_attribute(self):
        pass

    def parse_content(self):
        pass

    def parse_name(self):
        pass
"""
    py_report = extract_grammar(python_parser_code, name="PyXML")
    check("extraction/py_report_lang", py_report.source_language == "python")
    check("extraction/py_rules_extracted", py_report.rules_extracted >= 3)
    check("extraction/py_has_document", "document" in py_report.grammar.rules)
    check("extraction/py_has_element", "element" in py_report.grammar.rules)
    check("extraction/py_call_graph", "element" in py_report.call_graph.get("document", []))


# =====================================================================
# 3. Grammar Mutation Tests
# =====================================================================
def test_grammar_mutation() -> None:
    sample = """
    doc = header , body , footer ;
    header = "TITLE" ;
    body = item , { item } ;
    item = "entry" ;
    footer = "END" ;
    """
    g = parse_ebnf(sample, name="MutTest")
    orig_prods = g.production_count()

    # 1. Single-operator mutations
    mutator = GrammarMutator(seed=123)

    # Inject alternative
    mut_alt = mutator.mutate(g, count=1)
    check("mutation/applied_records", len(mut_alt.mutations) == 1)
    check("mutation/diff_generated", len(mut_alt.to_diff()) > 0)

    # Specific operators
    mut_rec = mutate_grammar(g, count=2, allowed_operators=[MutationType.INJECT_RECURSION], seed=42)
    check("mutation/inject_recursion", any(m.operator == MutationType.INJECT_RECURSION for m in mut_rec.mutations))

    mut_term = mutate_grammar(g, count=2, allowed_operators=[MutationType.MUTATE_TERMINAL], seed=42)
    check("mutation/mutate_terminal", any(m.operator == MutationType.MUTATE_TERMINAL for m in mut_term.mutations))

    mut_flip = mutate_grammar(g, count=2, allowed_operators=[MutationType.FLIP_OPTIONALITY], seed=42)
    check("mutation/flip_optionality", any(m.operator == MutationType.FLIP_OPTIONALITY for m in mut_flip.mutations))

    # Adversarial grammar generation
    adv = mutator.generate_adversarial_grammar(g, intensity=0.5)
    check("mutation/adversarial_has_mutations", adv.mutation_count >= 2)


# =====================================================================
# 4. Context-Sensitive Grammar Tests
# =====================================================================
def test_context_sensitive_grammar() -> None:
    # 1. XML Matching Tags Constraint
    xml_csg = create_xml_context_grammar()
    gen = ContextSensitiveGenerator(xml_csg, seed=101)

    # Valid generation (corrupt_prob = 0.0) -> opening tag must match closing tag!
    for _ in range(5):
        doc = gen.generate(start_symbol="element", corrupt_prob=0.0)
        m = re.match(r"^<([a-zA-Z_]\w*)>.*</([a-zA-Z_]\w*)>$", doc)
        check("csg/xml_matching_tags_valid", m is not None and m.group(1) == m.group(2), f"doc={doc}")

    # Corrupt generation (corrupt_prob = 1.0) -> tags must deliberately mismatch!
    mismatches = 0
    for _ in range(10):
        doc = gen.generate(start_symbol="element", corrupt_prob=1.0)
        m = re.match(r"^<([a-zA-Z_]\w*)>.*</([a-zA-Z_]\w*)>$", doc)
        if m and m.group(1) != m.group(2):
            mismatches += 1
    check("csg/xml_mismatch_injected", mismatches > 0, f"mismatches={mismatches}")

    # 2. HTTP Length-Prefixed Constraint
    http_csg = create_http_context_grammar()
    gen_http = ContextSensitiveGenerator(http_csg, seed=202)

    # Valid HTTP request -> Content-Length must exactly match body length!
    valid_req = gen_http.generate(start_symbol="http_request", corrupt_prob=0.0)
    m_len = re.search(r"Content-Length:\s*(\d+)\r\n\r\n(.*)$", valid_req, re.DOTALL)
    check("csg/http_has_content_length", m_len is not None)
    if m_len:
        claimed_len = int(m_len.group(1))
        actual_len = len(m_len.group(2).encode("utf-8"))
        check("csg/http_length_matches_payload", claimed_len == actual_len, f"claimed={claimed_len}, actual={actual_len}")

    # 3. Scoped Symbol Constraint (Entity declaration and reference)
    ctx = GenerationContext(corrupt_prob=0.0)
    decl_c = ScopedSymbolConstraint(action="declare")
    ref_c = ScopedSymbolConstraint(action="reference")

    decl_str = decl_c.evaluate(ctx, gen)
    check("csg/scoped_declares_symbol", len(ctx.symbol_table) == 1)
    ref_str = ref_c.evaluate(ctx, gen)
    # The referenced entity must be the one that was declared
    declared_sym = list(ctx.symbol_table)[0]
    check("csg/scoped_reference_matches_decl", f"&{declared_sym};" == ref_str)

    # 4. Checksum Constraint
    csg_bin = ContextSensitiveGrammar("BinaryCSG")
    payload_rule = csg_bin.add_rule("payload")
    payload_rule.add_production(["TEST_PAYLOAD_BYTES"])
    csg_bin.add_constraint_rule("chk_packet", ChecksumConstraint(payload_rule="payload", algorithm="crc32"))

    gen_bin = ContextSensitiveGenerator(csg_bin, seed=303)
    packet = gen_bin.generate_bytes(start_symbol="chk_packet", corrupt_prob=0.0)
    check("csg/checksum_packet_length", len(packet) > 4)


def main() -> None:
    print("Running Grammar Support Test Suite...")
    test_grammar_formats()
    test_grammar_extraction()
    test_grammar_mutation()
    test_context_sensitive_grammar()

    print(f"passed={_passed} failed={len(_failed)}")
    if _failed:
        print("Failures:")
        for f in _failed:
            print(f"  * {f}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
