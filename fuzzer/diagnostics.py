"""Normalise mxml diagnostic messages into stable templates.

mxml's messages interpolate variable data:

    Missing close tag </unclosed> under parent <root> on line 1.
    Missing close tag </foo> under parent <bar> on line 97.

Those are the same code location, so counting raw strings would report two
distinct "error sites" for one branch and inflate any diversity measure built on
top. Normalising both to

    Missing close tag </%s> under parent <%s> on line %d.

makes the count mean "how many distinct parser branches did we reach".

Templates are derived by pattern-substituting messages observed at runtime
through the public error callback. They are not matched against any list
extracted from mxml's source; that list exists but is used only for post-hoc
evaluation (docs/design-decisions.md D2).

mxml truncates its own messages in two situations, and both have to be handled
here or they inflate the template count. A message whose offending character has
a zero low byte is cut short (docs/findings.md F1). A message formatted into
mxml's 1024-byte buffer is cut at 1023 bytes, which happens when a long element
name is interpolated ahead of the descriptive text, and the text identifying the
call site is then gone entirely. Messages of the second kind all collapse to one
template, since nothing survives to tell them apart.
"""
from __future__ import annotations

import re

# Order matters. Each rule can see what earlier rules wrote, so anything that
# emits a placeholder must not be re-matchable by a later rule.
_SUBS: list[tuple[re.Pattern[str], str]] = [
    # The "second root node" family, handled first and as a whole.
    #
    # mxml interpolates a raw buffer into this message, and for a declaration
    # node that buffer can itself contain angle brackets and spaces, e.g.
    # "<!DOCTYPE v [<b> cannot be a second root node after <a> on line 1.".
    # The general element rule below cannot collapse such a prefix, so each
    # distinct DOCTYPE body would become its own "template". That mattered
    # little when diversity was a reported statistic; it matters a lot now that
    # the loop is SCORED on reaching templates no earlier iteration reached,
    # because inflation would reward the generator for noise.
    #
    # The trailing marker is still captured on both sides, keeping the four
    # genuinely distinct call sites (element / comment / PI / CDATA) apart.
    (re.compile(r"^.*?(-->|\]\]>|\?>|>) cannot be a second root node after "
                r".*?(-->|\]\]>|\?>|>) on line"),
     r"<%s\1 cannot be a second root node after <%s\2 on line"),
    # Hex literals, e.g. "Bad control character 0x01 ...". Before the bare-number
    # rule so 0x1f does not lose its hex digits.
    (re.compile(r"0x[0-9a-fA-F]+"), "0x%x"),
    # A quoted slot whose content is itself a single quote. mxml interpolates the
    # offending character, so when that character is an apostrophe the message
    # contains three consecutive quotes. The general quoted-string rule below
    # would match the empty pair and leave a stray quote behind, producing a
    # second bogus template for the same code site.
    (re.compile(r"'{3}"), "'%s'"),
    # All quoted slots collapse to one placeholder, without distinguishing
    # single-char from multi-char content. The harness escapes control bytes, so
    # one site can emit both (saw 'n') and (saw '\n'); splitting %c from %s
    # would count those as two templates for a single branch. No mxml template
    # becomes ambiguous once the surrounding text is kept.
    (re.compile(r"'[^']*'"), "'%s'"),
    # Closing-tag names, before the general element form.
    (re.compile(r"</[^<>]*>"), "</%s>"),
    # Element names in angle brackets.
    #
    # Non-greedy, and the trailing marker is CAPTURED and preserved. mxml has
    # four separate call sites differing only by that marker:
    #     <%s>    cannot be a second root node ...   (element)
    #     <%s-->  cannot be a second root node ...   (comment)
    #     <%s?>   cannot be a second root node ...   (processing instruction)
    #     <%s]]>  cannot be a second root node ...   (CDATA)
    # A greedy match would consume "b--" from "<b-->" and stop on the bare ">",
    # collapsing all four into one template and under-counting branches reached.
    #
    # The (?!/) lookahead prevents this rule re-matching the "</%s>" written by
    # the previous rule and rewriting it to "<%s>", which would merge the
    # open-tag and close-tag slots.
    (re.compile(r"<(?!/)[^<>]*?(-->|\]\]>|\?>|/>|>)"), r"<%s\1"),
    # Bare slots: mxml interpolates some values with no quotes or brackets
    # around them, so none of the rules above match them. Left unhandled, one
    # code site produces a separate template per element name, which inflates
    # the distinct-template count several-fold.
    #
    # Anchored on the surrounding literal text rather than written as one
    # generic rule, because a bare \S+ with no anchor would swallow real words
    # and merge genuinely different templates. The mxml templates carrying a
    # bare slot are:
    #     Bad %s value '%s' in parent <%s> on line %d.
    #     Bare < in element %s on line %d.
    #     Duplicate attribute '%s' in element %s on line %d.
    #     Expected '>' after '%c' for element %s, but got '%c' on line %d.
    #     Missing value for attribute '%s' in element %s on line %d.
    #     Unable to add value node of type %s to parent <%s> on line %d.
    (re.compile(r"\bin element \S+ on line\b"), "in element %s on line"),
    (re.compile(r"\bfor element \S+, but got\b"), "for element %s, but got"),
    (re.compile(r"\bof type \S+ to parent\b"), "of type %s to parent"),
    (re.compile(r"\bBad \S+ value\b"), "Bad %s value"),
    # Bare numbers last, so line numbers become %d without eating hex digits.
    (re.compile(r"\b\d+\b"), "%d"),
]


# mxml formats every diagnostic with vsnprintf into a char[1024], so a message
# that fills the buffer arrives as exactly 1023 bytes with its tail cut off.
_MXML_MSG_BYTES = 1023
_TRUNCATED = "<truncated at mxml's 1024-byte message buffer>"


def normalize(message: str) -> str:
    """Collapse one diagnostic to its format-string template."""
    out = message.strip()
    if len(out.encode("utf-8", "surrogatepass")) >= _MXML_MSG_BYTES:
        # The descriptive part of the message was pushed out of the buffer, so
        # there is nothing left to identify which call site emitted it.
        return _TRUNCATED
    for pattern, repl in _SUBS:
        out = pattern.sub(repl, out)
    return out


def histogram(messages: list[str]) -> dict[str, int]:
    """Count normalised templates, most frequent first."""
    counts: dict[str, int] = {}
    for m in messages:
        t = normalize(m)
        counts[t] = counts.get(t, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))
