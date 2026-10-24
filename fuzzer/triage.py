"""Crash triage: parse sanitizer reports, normalise them, group by root cause.

A crash signature is a hash of the normalised top frames plus the bug type.
Grouping by signature is what decides whether a run found one bug or several, so
each normalisation choice below trades a false-merge risk against a false-split
risk.

A raw AddressSanitizer report looks like this:

    ==1343184==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50c0...
    READ of size 8 at 0x50c0000000f8 thread T0
        #0 0x635aab575d88 in index_sort /abs/path/build/asan/mxml-index.c:394
        #1 0x635aab576103 in index_sort /abs/path/build/asan/mxml-index.c:415
        #2 0x635aab576d33 in mxmlIndexNew /abs/path/build/asan/mxml-index.c:268
        #3 0x635aab56b184 in main /abs/path/harness/harness.c:138

Normalisation choices:

1. **The bug type is part of the signature.** A heap-buffer-overflow READ and a
   WRITE at the same location are different defects with different severity, so
   they must not merge. Type and access direction are both kept.

2. **Addresses, PC values and absolute paths are discarded.** They vary between
   runs (ASLR) and between machines (build directory), so keeping them would
   split one bug into as many signatures as there were runs.

3. **Line numbers are discarded, file basenames are kept.** Line numbers move
   with any edit or optimisation change. Basenames are retained so that two
   same-named `static` helpers in different translation units do not merge. The
   cost is that two distinct bugs inside one function collapse together; the
   full normalised trace is stored alongside the signature so a human can split
   them back apart.

4. **Frames outside the target are dropped.** Sanitizer interceptors (`__asan_`,
   `__interceptor_`), libc entry frames and harness frames carry no information
   about which bug this is. Dropping them also stops an interceptor frame such
   as `__interceptor_strlen` becoming the top frame and merging every
   string-function crash into one bucket.

5. **Repeated frames are collapsed to first-occurrence order.** A recursive
   function appears many times in one trace, so hashing the raw top-N frames
   would produce a different signature per recursion depth and report one bug as
   many. Taking the first N distinct function names also handles mutual
   recursion (A,B,A,B,A -> A,B), which a consecutive-duplicate collapse misses.

6. **Timeouts group by input shape, not by stack.** A hang produces no sanitizer
   report and no stack, so there is nothing to hash. One bucket for all timeouts
   would hide different hangs; a bucket each would report one hang as hundreds.
   They are keyed on the structural productions of the triggering input, which
   is the only evidence available.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

SIGNATURE_FRAMES = 5

_RE_ASAN_ERROR = re.compile(
    r"ERROR:\s+(AddressSanitizer|LeakSanitizer):\s+([a-zA-Z0-9_-]+)")
_RE_UBSAN_ERROR = re.compile(r"runtime error:\s+(.+?)(?:\n|$)")
_RE_ACCESS = re.compile(r"^\s*(READ|WRITE) of size (\d+)", re.M)
_RE_FRAME = re.compile(
    r"^\s*#(\d+)\s+0x[0-9a-f]+\s+in\s+(\S+)\s*(?:([^\s:]+):(\d+)|\((.*?)\))?",
    re.M)

# Frames that identify the plumbing rather than the defect.
_DROP_PREFIXES = ("__asan", "__ubsan", "__lsan", "__interceptor", "__sanitizer")
_DROP_EXACT = frozenset({
    "main", "_start", "__libc_start_main", "__libc_start_call_main",
    "__libc_start_main_impl",
})
_DROP_FILES = frozenset({"harness.c"})

# Frames identified by their SOURCE FILE rather than function name. Leak reports
# begin in the allocator interceptor, whose function is plainly `calloc` or
# `strdup` and so slips past the name-prefix filter above. Without this a leak
# signature reads "calloc@asan_malloc_linux.cpp" and every leak in the library
# collapses into one bucket, hiding which mxml code actually leaked.
_DROP_FILE_PAT = re.compile(
    r"^(asan_|ubsan_|lsan_|tsan_|sanitizer_)|^libc-start\.c$|^libc_start_call_main\.h$")


@dataclass
class Frame:
    func: str
    file: str | None = None

    def normalized(self) -> str:
        return f"{self.func}@{self.file}" if self.file else self.func


@dataclass
class CrashReport:
    tool: str = "unknown"          # AddressSanitizer / UndefinedBehaviorSanitizer
    bug_type: str = "unknown"      # heap-buffer-overflow, SEGV, signed-integer-overflow
    access: str | None = None      # READ / WRITE
    frames: list[Frame] = field(default_factory=list)
    raw: str = ""

    @property
    def signature_frames(self) -> list[str]:
        """First N DISTINCT normalised frames; see normalisation choice 5."""
        out: list[str] = []
        seen: set[str] = set()
        for fr in self.frames:
            key = fr.normalized()
            if key in seen:
                continue
            seen.add(key)
            out.append(key)
            if len(out) == SIGNATURE_FRAMES:
                break
        return out

    @property
    def label(self) -> str:
        parts = [self.bug_type]
        if self.access:
            parts.append(self.access)
        top = self.signature_frames[0] if self.signature_frames else "no-frames"
        parts.append(top)
        return " ".join(parts)

    @property
    def signature(self) -> str:
        material = "|".join([self.bug_type, self.access or "-", *self.signature_frames])
        return hashlib.sha256(material.encode()).hexdigest()[:12]

    def to_json(self) -> dict:
        return {
            "signature": self.signature,
            "label": self.label,
            "tool": self.tool,
            "bug_type": self.bug_type,
            "access": self.access,
            "frames": self.signature_frames,
            "all_frames": [f.normalized() for f in self.frames],
        }


def _keep(func: str, fname: str | None) -> bool:
    if func in _DROP_EXACT:
        return False
    if any(func.startswith(p) for p in _DROP_PREFIXES):
        return False
    if fname and fname in _DROP_FILES:
        return False
    if fname and _DROP_FILE_PAT.search(fname):
        return False
    return True


def parse_report(stderr: str) -> CrashReport | None:
    """Extract a structured crash report from sanitizer output, or None."""
    if not stderr:
        return None

    rep = CrashReport(raw=stderr)

    m = _RE_ASAN_ERROR.search(stderr)
    if m:
        rep.tool = m.group(1)
        # LeakSanitizer's banner is "detected memory leaks", so the generic
        # capture yields the useless word "detected". Name the class properly.
        rep.bug_type = "memory-leak" if m.group(1) == "LeakSanitizer" else m.group(2)
    else:
        m = _RE_UBSAN_ERROR.search(stderr)
        if not m:
            return None
        rep.tool = "UndefinedBehaviorSanitizer"
        # Reduce "signed integer overflow: 2147483647 + 1 cannot be ..." to a
        # stable kind, since the operand values differ per input.
        rep.bug_type = re.sub(r"[^a-z ]", "", m.group(1).split(":")[0].strip().lower()
                              ).strip().replace(" ", "-") or "runtime-error"

    ma = _RE_ACCESS.search(stderr)
    if ma:
        rep.access = ma.group(1)

    # Only the first stack in the report describes where the fault happened.
    # Later stacks ("allocated by thread T0 here") describe the object's origin
    # and would otherwise be concatenated into the signature.
    seen_first_stack = False
    for fm in _RE_FRAME.finditer(stderr):
        idx = int(fm.group(1))
        if idx == 0:
            if seen_first_stack:
                break
            seen_first_stack = True
        func = fm.group(2)
        fname = fm.group(3)
        if fname:
            fname = fname.rsplit("/", 1)[-1]
        if _keep(func, fname):
            rep.frames.append(Frame(func=func, file=fname))

    return rep


def timeout_signature(productions: list[str]) -> str:
    """Signature for a hang, keyed on input structure; see choice 6."""
    material = "timeout|" + ",".join(sorted(productions))
    return hashlib.sha256(material.encode()).hexdigest()[:12]


def group(crashes: list[dict]) -> dict[str, dict]:
    """Group crash records by signature.

    Each record needs at least {"sha", "stderr"} and optionally
    {"outcome", "productions"}.
    """
    out: dict[str, dict] = {}
    for c in crashes:
        if c.get("outcome") == "timeout":
            sig = timeout_signature(c.get("productions", []))
            label = "timeout (hang)"
            rep_json = None
        else:
            rep = parse_report(c.get("stderr", ""))
            if rep is None:
                signal_name = c.get("signal") or str(c.get("rc", "unknown"))
                sig = f"unparsed-{signal_name}"
                label = f"crash with no sanitizer report ({signal_name})"
                rep_json = None
            else:
                sig, label, rep_json = rep.signature, rep.label, rep.to_json()

        bucket = out.setdefault(sig, {
            "signature": sig, "label": label, "count": 0,
            "inputs": [], "report": rep_json,
        })
        bucket["count"] += 1
        if c.get("sha") and c["sha"] not in bucket["inputs"]:
            bucket["inputs"].append(c["sha"])
    return out
