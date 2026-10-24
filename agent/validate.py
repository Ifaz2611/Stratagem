"""Validate an LLM-written strategy before spending the example budget on it.

A generator rejected almost every time by the parser's front door tests nothing,
so the strategy is checked before any example budget is spent on it.

Four gates, cheapest first, so a broken strategy fails fast:

  1. extract   pull the python block out of the response
  1b. truncated  reject a block whose head was lost in transport
  2. syntax    compile() it
  3. interface import it and draw sample documents
  4. smoke     run a small batch through the real harness and measure the
               acceptance rate

Gate 4 costs ~50 examples, a tenth of an iteration's budget, and catches the
rejected-at-the-front-door failure before 500 examples are spent on it. On
failure the loop issues one cheap repair call instead of burning an iteration.

Gates 3 and 4 run the generated code in a subprocess with a timeout, since a
generator with runaway recursion or an accidental infinite loop would otherwise
hang the run. This is containment against accident, not a security sandbox.

Gate 1b exists because `claude -p --output-format json` reports only the final
assistant message. When a response spans several messages the head of the module
is missing, and what arrives is a syntactically broken fragment of correct code.
Sending that back as a repair asks the model to fix something it did not get
wrong, so a truncated block is reported separately and the caller retries the
same prompt instead.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Below this, the generator is not testing the parser so much as bouncing off it.
MIN_ACCEPTANCE = 0.10
# Above this, nothing exercises error handling.
MAX_ACCEPTANCE = 0.95

# Bounds on the input-class mixture, checked on the smoke batch.
#
# Asking for a mixture in the prompt did not hold: two runs pushed byte_hostile
# past 50% while well_formed fell to 21%, and measured line coverage fell with
# it, because byte-hostile documents are rejected in the encoding and lexing
# front end before the parser walks them. The ceiling is what the prompt alone
# failed to enforce. Empty bounds disable the check.
CLASS_BOUNDS: dict[str, tuple[float, float]] = {
    "well_formed": (0.35, 1.0),
    "near_miss": (0.15, 1.0),
    "byte_hostile": (0.15, 0.45),
}
# The mixture is estimated from SMOKE_EXAMPLES documents, so a share near a
# bound lands either side of it by chance: at 50 documents one standard error is
# about 7 points. The gate allows that much slack so sampling noise cannot cost
# a repair call, which means it fires on clear violations only and leaves
# borderline mixtures to the refinement feedback.
CLASS_MARGIN = 0.07

DRAW_SAMPLES = 12
SMOKE_EXAMPLES = 50

_FENCE = re.compile(r"```(?:python|py)?\s*\n(.*?)```", re.S)


@dataclass
class Validation:
    ok: bool
    stage: str                       # extract | truncated | syntax | interface | smoke | mixture | ok
    error: str = ""
    code: str = ""
    samples: list[str] = field(default_factory=list)
    acceptance: float | None = None
    outcomes: dict = field(default_factory=dict)
    mixture: dict = field(default_factory=dict)

    def _mixture_advice(self) -> str:
        """Advice aimed at whichever class is out of bounds, and which way.

        A class under its floor while another is over is usually not a weighting
        problem: the generator for that class is producing documents that
        classify as something else. Saying "adjust your weights" sends the model
        the wrong way, which cost one run its whole seed budget.
        """
        parts = []
        for cls in out_of_bounds(self.mixture):
            lo, _ = CLASS_BOUNDS[cls]
            text = _advice_for(cls, low=self.mixture.get(cls, 0.0) < lo)
            if text and text not in parts:
                parts.append(text)
        parts.append("Fix the generator for the class that is short, then adjust "
                     "the weights in your top-level st.one_of, and resend.")
        return "\n\n".join(parts)

    def feedback(self) -> str:
        """A short, specific repair instruction for the model."""
        if self.stage == "extract":
            return ("Your response contained no ```python code block. Reply with "
                    "exactly one fenced python block and no prose.")
        if self.stage == "truncated":
            return ("Your response arrived without the start of the module. Reply "
                    "with exactly one fenced python block, complete from its "
                    "first import line.")
        if self.stage == "syntax":
            return f"The module does not compile:\n\n{self.error}\n\nFix and resend."
        if self.stage == "interface":
            return (f"The module failed to load or draw examples:\n\n{self.error}\n\n"
                    "It must define NAME, DESCRIPTION and "
                    "documents() -> SearchStrategy[str], importing only hypothesis "
                    "and the standard library. Fix and resend.")
        if self.stage == "mixture":
            got = "\n".join(
                f"  {k:13} {self.mixture.get(k, 0.0):>6.0%}   required "
                f"{lo:.0%}{f' to {hi:.0%}' if hi < 1.0 else ' or more'}"
                for k, (lo, hi) in CLASS_BOUNDS.items())
            return ("Your input-class mixture is outside the required bounds.\n\n"
                    f"{got}\n\n" + self._mixture_advice())
        if self.stage == "smoke":
            pct = f"{self.acceptance:.1%}" if self.acceptance is not None else "?"
            if self.acceptance is not None and self.acceptance > MAX_ACCEPTANCE:
                return (
                    f"The parser accepted {pct} of {SMOKE_EXAMPLES} documents "
                    f"(outcomes: {self.outcomes}). This leaves almost no malformed "
                    "input or error handling in the campaign. Add targeted near "
                    "misses while keeping open and close tag names matched in the "
                    "well-formed class.")
            return (
                f"The parser accepted only {pct} of {SMOKE_EXAMPLES} documents "
                f"(outcomes: {self.outcomes}). A generator rejected at the front "
                f"door tests nothing.\n\nSample documents your strategy produced:\n"
                + "\n".join(f"  {s[:160]!r}" for s in self.samples[:6])
                + "\n\nDiagnose which production is malformed and fix it. Remember "
                  "open and close tag names must match exactly.")
        return ""


# What separates the three classes, restated for a repair. Which of these the
# parser actually rejects is measured in grammar/ADAPTATIONS.md, not read out of
# its source, so this stays inside the blackbox line (design-decisions D2).
_NEAR_MISS_HINT = """The parser is far more tolerant than the grammar, so most
ways of being malformed are accepted and land in well_formed instead. It does
reject these, and they are what near_miss documents have to be built from:

  - a close tag whose name differs from its open tag, <a></b>
  - a named entity outside amp, lt, gt and quot, such as &apos; or &copy;
  - an entity with no terminating semicolon, &amp
  - a character reference out of range or zero, &#x110000; or &#0;
  - an attribute with no value, <a b>
  - a second root element after the first has closed, <a/><b/>

Documents it accepts despite the grammar rejecting them (unquoted attribute
values, no root element, an empty element name, an xml declaration with no
space) count as well_formed, not near_miss."""

_BYTE_HOSTILE_HINT = """A document counts as byte_hostile if it carries a BOM,
invalid UTF-8, an embedded NUL, a control character or a contradictory encoding
declaration. Long names and deep nesting are not byte hostility, so those sweeps
belong in documents that parse."""


def extract_code(response_text: str) -> str | None:
    blocks = _FENCE.findall(response_text or "")
    if not blocks:
        return None
    # Prefer the block that looks like the module, not an inline snippet.
    for b in blocks:
        if "def documents" in b:
            return b.strip() + "\n"
    return blocks[0].strip() + "\n"


def looks_truncated(code: str) -> bool:
    """True when a block is a fragment of a module rather than a whole one.

    A complete module opens at column zero and imports hypothesis before using
    it. A block that begins indented, or that references `st` with no import,
    lost its head in transport rather than being written wrong.
    """
    if not code.strip():
        return False
    first = next((ln for ln in code.splitlines() if ln.strip()), "")
    if first[:1].isspace():
        return True
    return "st." in code and not re.search(r"^\s*(import|from)\s", code, re.M)


_PROBE = r'''
import json, sys
sys.path.insert(0, {root!r})
out = {{"ok": False, "error": "", "samples": []}}
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("candidate", {path!r})
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for attr in ("NAME", "DESCRIPTION", "documents"):
        if not hasattr(mod, attr):
            raise AttributeError("module is missing required attribute " + attr)
    from hypothesis import strategies as st
    strat = mod.documents()
    if not isinstance(strat, st.SearchStrategy):
        raise TypeError("documents() must return a SearchStrategy, got "
                        + type(strat).__name__)
    import warnings
    warnings.filterwarnings("ignore")
    samples = []
    for _ in range({n}):
        v = strat.example()
        if not isinstance(v, str):
            raise TypeError("strategy produced " + type(v).__name__ + ", expected str")
        samples.append(v)
    out["samples"] = samples
    out["ok"] = True
except Exception as exc:
    import traceback
    out["error"] = "".join(traceback.format_exception_only(type(exc), exc)).strip()
    tb = traceback.format_exc().splitlines()
    out["error"] += "\n" + "\n".join(tb[-6:])
print("@@PROBE@@" + json.dumps(out))
'''


def check_interface(path: Path, timeout_s: float = 120.0) -> tuple[bool, str, list[str]]:
    """Import the module and draw sample documents, in a subprocess."""
    src = _PROBE.format(root=str(REPO_ROOT), path=str(path), n=DRAW_SAMPLES)
    try:
        proc = subprocess.run([sys.executable, "-c", src], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return False, (f"drawing {DRAW_SAMPLES} examples did not finish within "
                       f"{timeout_s:.0f}s; the strategy is too slow or does not "
                       f"terminate"), []
    out = proc.stdout.decode("utf-8", "replace")
    marker = out.rfind("@@PROBE@@")
    if marker == -1:
        err = proc.stderr.decode("utf-8", "replace")[-600:]
        return False, f"probe produced no result. stderr:\n{err}", []
    d = json.loads(out[marker + len("@@PROBE@@"):].strip())
    return d["ok"], d.get("error", ""), d.get("samples", [])


def validate(response_text: str, dest: Path) -> Validation:
    """Run all four gates. `dest` is where the accepted module is written."""
    code = extract_code(response_text)
    if not code:
        return Validation(False, "extract")
    if looks_truncated(code):
        return Validation(False, "truncated", code=code,
                          error="block does not begin at the start of a module")

    try:
        compile(code, str(dest), "exec")
    except SyntaxError as exc:
        return Validation(False, "syntax", error=f"{type(exc).__name__}: {exc}", code=code)

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(code, encoding="utf-8")

    ok, err, samples = check_interface(dest)
    if not ok:
        return Validation(False, "interface", error=err, code=code)

    # Gate 4: does the parser actually accept any of this?
    from fuzzer.campaign import Campaign
    tmp = REPO_ROOT / "runs" / ".validate"
    c = Campaign(dest.stem, SMOKE_EXAMPLES, tmp, mode="survey")
    summary = c.run()
    acc = summary["acceptance_rate"]

    mixture = {k: e["share"] for k, e in summary.get("buckets", {}).items()}

    v = Validation(True, "ok", code=code, samples=samples,
                   acceptance=acc, outcomes=summary["outcomes"], mixture=mixture)
    if acc < MIN_ACCEPTANCE:
        v.ok, v.stage = False, "smoke"
    elif acc > MAX_ACCEPTANCE:
        v.ok, v.stage = False, "smoke"
    elif out_of_bounds(mixture):
        v.ok, v.stage = False, "mixture"
    return v


def _advice_for(cls: str, low: bool) -> str:
    """Repair text for one out-of-bounds class."""
    if cls == "near_miss" and low:
        return _NEAR_MISS_HINT
    if cls == "byte_hostile":
        return _BYTE_HOSTILE_HINT
    if cls == "well_formed" and low:
        return ("Too few documents parse cleanly. Most of the parser's code runs "
                "only after a document is accepted, so this is the class that "
                "reaches the most of it.")
    return ""


def out_of_bounds(mixture: dict[str, float]) -> list[str]:
    """Classes whose share falls outside CLASS_BOUNDS, worst first.

    A class the strategy never produces counts as a share of zero, so an absent
    class fails its floor rather than passing by omission.
    """
    bad = []
    for cls, (lo, hi) in CLASS_BOUNDS.items():
        share = mixture.get(cls, 0.0)
        if share < lo - CLASS_MARGIN:
            bad.append((lo - share, cls))
        elif share > hi + CLASS_MARGIN:
            bad.append((share - hi, cls))
    return [c for _, c in sorted(bad, reverse=True)]
