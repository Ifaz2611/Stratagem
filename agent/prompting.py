"""Prompt construction helpers for the agentic loop."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from agent.reporting import (
    format_boundaries,
    format_buckets,
    format_crashes,
    format_diagnostics,
)
from fuzzer.features import PRODUCTIONS

GRAMMAR_COMMIT = "e756f2a2ee5565a9300666f100ba6acd874664f7"


def build_seed_prompt(
    prompt_version: Any,
    target_obj: Any,
    grammar_body: Callable[[str | Path], str],
) -> str:
    g_file = getattr(target_obj, "grammar_file", None)
    if g_file:
        g_path = Path(g_file)
        parser_body = grammar_body(g_path)
        is_xml = getattr(target_obj, "category", "") == "xml" or "XML" in g_path.name
        lexer_body = grammar_body("XMLLexer.g4") if is_xml else ""
    else:
        parser_body = grammar_body("XMLParser.g4")
        lexer_body = grammar_body("XMLLexer.g4")
    prods = tuple(getattr(target_obj, "productions", ()) or PRODUCTIONS)
    return prompt_version.render_seed(
        grammar_commit=GRAMMAR_COMMIT,
        parser_g4=parser_body,
        lexer_g4=lexer_body,
        productions=list(prods),
    )


def build_refine_prompt(
    prompt_version: Any,
    target_obj: Any,
    union_diagnostics: set[str],
    union_productions: set[str],
    directives: list[str],
    it: int,
    source: str,
    summary: dict,
    results: list[dict],
    directive_override: str | None = None,
) -> str:
    st = summary["structure"]
    crash_txt = format_crashes(summary)
    diag = format_diagnostics(summary)
    this_diags = set(summary.get("diagnostic_templates", {}))
    this_prods = set(st.get("hit", {}))
    new_diags = sorted(this_diags - union_diagnostics)
    new_prods = sorted(this_prods - union_productions)
    union_diagnostics |= this_diags
    union_productions |= this_prods
    prods = tuple(getattr(target_obj, "productions", ()) or PRODUCTIONS)
    never_produced = [p for p in prods if p not in union_productions]
    bound_txt = format_boundaries(st.get("boundaries", {}))
    bucket_txt = format_buckets(summary.get("buckets", {}))

    directive = (directive_override
                 or (directives[(it - 1) % len(directives)]
                     if directives else "improve the strategy"))

    return prompt_version.render_refine(
        it=it,
        source=source,
        summary=summary,
        results=results,
        directive=directive,
        boundaries=bound_txt,
        buckets=bucket_txt,
        outcomes=json.dumps(summary["outcomes"], indent=2),
        union_diagnostic_list="\n".join(sorted(union_diagnostics)) or "(none)",
        union_diagnostics=str(len(union_diagnostics)),
        new_diagnostics=(
            f"{len(new_diags)}\n" + "\n".join(f"  + {d}" for d in new_diags)
            if new_diags else "0  (nothing new -- this is the problem to fix)"),
        new_productions=f"{len(new_prods)}: " + ", ".join(new_prods) if new_prods else "0",
        productions_missing="\n".join(never_produced)
        or "(none -- full coverage across all iterations)",
        crash_count=summary["crash_count"],
        xml_shaped_rate=f"{summary['xml_shaped_rate']:.1%}",
        productions_hit_detail="\n".join(
            f"{v:5d}  {k}" for k, v in sorted(st["hit"].items(), key=lambda kv: -kv[1])) or "(none)",
        depth_histogram=json.dumps(st["depth_histogram"], indent=2),
        distinct_templates=str(summary["distinct_diagnostic_templates"]),
        diagnostic_templates=diag,
        input_len=json.dumps(summary["input_len"], indent=2),
        crash_section=crash_txt,
    )
