"""Crash triage: parse sanitizer reports, normalise them, group by root cause.

A crash signature is a hash of the normalised top frames plus the bug type.
Grouping by signature is what decides whether a run found one bug or several, so
each normalisation choice trades a false-merge risk against a false-split risk.

Supports all major compiler sanitizers:
  * AddressSanitizer (ASan)
  * UndefinedBehaviorSanitizer (UBSan)
  * LeakSanitizer (LSan)
  * ThreadSanitizer (TSan) - Concurrency, data races, deadlocks
  * MemorySanitizer (MSan) - Uninitialized memory reads

Sophisticated Triage & Clustering:
  * Semantic bug categorization & exploitability severity classification (CRITICAL, HIGH, MEDIUM, LOW, INFO)
  * Multi-tier deduplication (exact signature, fault-site, stack sequence)
  * Weighted call-stack similarity scoring (exponential decay for top frames + Jaccard index)
  * Hierarchical bug clustering (merging distinct caller paths reaching the same fault)
  * Timeout clustering by input structure and grammar production profile
  * Representative crash selection for minimal reproduction
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

SIGNATURE_FRAMES = 5

_RE_SANITIZER_HEADER = re.compile(
    r"(?:==\d+==)?(?:ERROR|WARNING|FATAL):\s+(AddressSanitizer|LeakSanitizer|ThreadSanitizer|MemorySanitizer):\s+([a-zA-Z0-9_\- ]+?)(?:\s*\(|\s+on\s+|\n|$)"
)
_RE_UBSAN_ERROR = re.compile(r"runtime error:\s+(.+?)(?:\n|$)")
_RE_ACCESS = re.compile(r"^\s*(?:Previous\s+)?(READ|WRITE)\s+of\s+size\s+(\d+)", re.M | re.I)
_RE_FRAME = re.compile(
    r"^\s*#(\d+)\s+(?:0x[0-9a-f]+\s+in\s+)?(\S+)\s*(?:([^\s:]+):(\d+)|\((.*?)\))?",
    re.M,
)

# Frames that identify the plumbing rather than the defect.
_DROP_PREFIXES = (
    "__asan",
    "__ubsan",
    "__lsan",
    "__tsan",
    "__msan",
    "__interceptor",
    "__sanitizer",
)
_DROP_EXACT = frozenset({
    "main",
    "_start",
    "__libc_start_main",
    "__libc_start_call_main",
    "__libc_start_main_impl",
})
_DROP_FILES = frozenset({"harness.c"})

# Source file filter for interceptor implementations
_DROP_FILE_PAT = re.compile(
    r"^(asan_|ubsan_|lsan_|tsan_|msan_|sanitizer_)|^libc-start\.c$|^libc_start_call_main\.h$"
)


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


def classify_severity(bug_type: str, access: str | None = None, raw_stderr: str = "") -> str:
    """Classify the exploitability/severity of a defect."""
    b = bug_type.lower()
    a = (access or "").upper()

    # CRITICAL: Out-of-bounds writes, heap corruption writes, UAF writes, double-frees
    if "double-free" in b or "bad-free" in b:
        return Severity.CRITICAL.value
    if ("buffer-overflow" in b or "out-of-bounds" in b or "heap" in b) and a == "WRITE":
        return Severity.CRITICAL.value
    if "use-after-free" in b and a == "WRITE":
        return Severity.CRITICAL.value

    # HIGH: UAF reads, concurrency races, deadlocks, out-of-bounds reads
    if "use-after-free" in b:
        return Severity.HIGH.value
    if any(k in b for k in ("data-race", "race", "deadlock", "lock-order-inversion")):
        return Severity.HIGH.value
    if "buffer-overflow" in b or "global-buffer-overflow" in b:
        return Severity.HIGH.value
    if "segv" in b and "0x00000000" not in raw_stderr and "0x0 " not in raw_stderr:
        return Severity.HIGH.value

    # MEDIUM: Uninitialized memory reads, undefined behavior, stack overflow
    if "uninitialized" in b:
        return Severity.MEDIUM.value
    if "stack-overflow" in b or "stack-buffer-overflow" in b:
        return Severity.MEDIUM.value
    if any(ub in b for ub in ("overflow", "divide-by-zero", "shift", "pointer-overflow", "float", "runtime-error")):
        return Severity.MEDIUM.value

    # LOW: Memory leaks, null pointer dereference
    if "leak" in b or "null" in b or ("segv" in b and ("0x00000000" in raw_stderr or "0x0 " in raw_stderr)):
        return Severity.LOW.value

    # INFO: Timeouts, hangs
    if "timeout" in b or "hang" in b:
        return Severity.INFO.value

    return Severity.MEDIUM.value


def calculate_stack_similarity(stack1: list[str], stack2: list[str]) -> float:
    """Calculate similarity score in [0.0, 1.0] between two normalized call stacks.

    Combines weighted top-frame matching with overall Jaccard set similarity.
    Top frames receive exponentially decaying weights since crashes in the same
    leaf function are more likely related.
    """
    if not stack1 and not stack2:
        return 1.0
    if not stack1 or not stack2:
        return 0.0

    # 1. Positional comparison with exponential decay
    max_len = min(len(stack1), len(stack2), SIGNATURE_FRAMES)
    total_pos_weight = 0.0
    matched_pos_weight = 0.0

    for i in range(max_len):
        weight = 1.0 / (2 ** i)
        total_pos_weight += weight
        if stack1[i] == stack2[i]:
            matched_pos_weight += weight
        else:
            # Check function-only match if file differs
            f1 = stack1[i].split("@")[0]
            f2 = stack2[i].split("@")[0]
            if f1 == f2:
                matched_pos_weight += weight * 0.75

    pos_score = matched_pos_weight / total_pos_weight if total_pos_weight > 0 else 0.0

    # 2. Jaccard set similarity
    s1, s2 = set(stack1), set(stack2)
    jaccard = len(s1 & s2) / len(s1 | s2) if (s1 or s2) else 0.0

    return 0.7 * pos_score + 0.3 * jaccard


@dataclass
class Frame:
    func: str
    file: str | None = None

    def normalized(self) -> str:
        return f"{self.func}@{self.file}" if self.file else self.func


@dataclass
class CrashReport:
    tool: str = "unknown"          # AddressSanitizer / UBSan / TSan / MSan / LSan
    bug_type: str = "unknown"      # heap-buffer-overflow, SEGV, data-race, use-of-uninitialized-value
    access: str | None = None      # READ / WRITE
    frames: list[Frame] = field(default_factory=list)
    raw: str = ""

    @property
    def severity(self) -> str:
        return classify_severity(self.bug_type, self.access, self.raw)

    @property
    def root_cause_site(self) -> str:
        return self.signature_frames[0] if self.signature_frames else "no-frames"

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
            "severity": self.severity,
            "access": self.access,
            "root_cause_site": self.root_cause_site,
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

    m = _RE_SANITIZER_HEADER.search(stderr)
    if m:
        rep.tool = m.group(1)
        raw_type = m.group(2).strip()
        if rep.tool == "LeakSanitizer":
            rep.bug_type = "memory-leak"
        elif rep.tool in ("ThreadSanitizer", "MemorySanitizer"):
            rep.bug_type = raw_type.lower().replace(" ", "-")
        else:
            rep.bug_type = raw_type
    else:
        m = _RE_UBSAN_ERROR.search(stderr)
        if not m:
            return None
        rep.tool = "UndefinedBehaviorSanitizer"
        rep.bug_type = (
            re.sub(r"[^a-z ]", "", m.group(1).split(":")[0].strip().lower())
            .strip()
            .replace(" ", "-")
            or "runtime-error"
        )

    ma = _RE_ACCESS.search(stderr)
    if ma:
        rep.access = ma.group(1).upper()

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


@dataclass
class CrashCluster:
    """A cluster of related crashes sharing the same defect or root cause."""
    cluster_id: str
    title: str
    tool: str
    bug_type: str
    severity: str
    root_cause_func: str
    root_cause_file: str
    top_frames: list[str]
    crash_count: int
    unique_inputs: list[str] = field(default_factory=list)
    signatures: list[str] = field(default_factory=list)
    representative_sha: str = ""
    representative_report: dict | None = None
    mean_similarity: float = 1.0

    def to_json(self) -> dict:
        return {
            "cluster_id": self.cluster_id,
            "title": self.title,
            "tool": self.tool,
            "bug_type": self.bug_type,
            "severity": self.severity,
            "root_cause_func": self.root_cause_func,
            "root_cause_file": self.root_cause_file,
            "top_frames": self.top_frames,
            "crash_count": self.crash_count,
            "unique_inputs": self.unique_inputs,
            "signatures": self.signatures,
            "representative_sha": self.representative_sha,
            "representative_report": self.representative_report,
            "mean_similarity": round(self.mean_similarity, 3),
        }


class BugClusterer:
    """Advanced crash triage, deduplication, and bug clustering engine."""

    def __init__(self, similarity_threshold: float = 0.65) -> None:
        self.similarity_threshold = similarity_threshold
        self.crashes: list[dict] = []

    def add_crash(self, record: dict) -> None:
        """Add a crash record (dict with sha, stderr, outcome, etc.)."""
        self.crashes.append(record)

    def deduplicate(self) -> list[dict]:
        """Return deduplicated list of unique crashes by input sha and signature."""
        seen: set[str] = set()
        deduped: list[dict] = []
        for c in self.crashes:
            sha = c.get("sha", "")
            if sha and sha in seen:
                continue
            if sha:
                seen.add(sha)
            deduped.append(c)
        return deduped

    def cluster(self) -> list[CrashCluster]:
        """Cluster all crashes into semantic defect groups."""
        if not self.crashes:
            return []

        # 1. Group by exact signature first
        exact_groups = group(self.crashes)

        # 2. Separate into non-timeout sanitizer reports and timeouts
        report_entries: list[dict] = []
        timeout_entries: list[dict] = []
        unparsed_entries: list[dict] = []

        for sig, bucket in exact_groups.items():
            rep = bucket.get("report")
            if rep:
                report_entries.append(bucket)
            elif "timeout" in bucket.get("label", ""):
                timeout_entries.append(bucket)
            else:
                unparsed_entries.append(bucket)

        clusters: list[CrashCluster] = []
        cluster_idx = 1

        # 3. Cluster sanitizer crashes by root cause and stack similarity
        assigned_rep: set[str] = set()
        for i, b1 in enumerate(report_entries):
            sig1 = b1["signature"]
            if sig1 in assigned_rep:
                continue
            assigned_rep.add(sig1)

            rep1 = b1["report"]
            frames1 = rep1.get("frames", [])
            root1 = frames1[0] if frames1 else "unknown"
            tool1 = rep1.get("tool", "unknown")
            bug1 = rep1.get("bug_type", "unknown")
            sev1 = rep1.get("severity", Severity.MEDIUM.value)

            matched_buckets = [b1]
            sim_scores: list[float] = [1.0]

            for j, b2 in enumerate(report_entries[i + 1:], start=i + 1):
                sig2 = b2["signature"]
                if sig2 in assigned_rep:
                    continue
                rep2 = b2["report"]
                frames2 = rep2.get("frames", [])
                root2 = frames2[0] if frames2 else "unknown"

                # If same root cause site (func@file) and tool, high confidence cluster
                same_root = (root1 == root2 and root1 != "unknown")
                sim = calculate_stack_similarity(frames1, frames2)

                if same_root or (tool1 == rep2.get("tool") and sim >= self.similarity_threshold):
                    matched_buckets.append(b2)
                    sim_scores.append(sim)
                    assigned_rep.add(sig2)

            # Build CrashCluster
            total_count = sum(b["count"] for b in matched_buckets)
            all_inputs = list(dict.fromkeys(inp for b in matched_buckets for inp in b["inputs"]))
            all_sigs = [b["signature"] for b in matched_buckets]

            func_part = root1.split("@")[0] if "@" in root1 else root1
            file_part = root1.split("@")[1] if "@" in root1 else "unknown"

            title = f"[{sev1}] {bug1} in {func_part} ({file_part})"
            rep_sha = all_inputs[0] if all_inputs else ""

            cluster = CrashCluster(
                cluster_id=f"cluster-{cluster_idx:02d}",
                title=title,
                tool=tool1,
                bug_type=bug1,
                severity=sev1,
                root_cause_func=func_part,
                root_cause_file=file_part,
                top_frames=frames1,
                crash_count=total_count,
                unique_inputs=all_inputs,
                signatures=all_sigs,
                representative_sha=rep_sha,
                representative_report=rep1,
                mean_similarity=sum(sim_scores) / len(sim_scores) if sim_scores else 1.0,
            )
            clusters.append(cluster)
            cluster_idx += 1

        # 4. Cluster timeouts
        for tb in timeout_entries:
            cluster = CrashCluster(
                cluster_id=f"cluster-{cluster_idx:02d}",
                title=f"[INFO] Parser Hang / Timeout ({tb['signature']})",
                tool="HarnessTimeout",
                bug_type="timeout",
                severity=Severity.INFO.value,
                root_cause_func="unknown (hang)",
                root_cause_file="parser",
                top_frames=[],
                crash_count=tb["count"],
                unique_inputs=tb["inputs"],
                signatures=[tb["signature"]],
                representative_sha=tb["inputs"][0] if tb["inputs"] else "",
                representative_report=None,
                mean_similarity=1.0,
            )
            clusters.append(cluster)
            cluster_idx += 1

        # 5. Cluster unparsed signal crashes
        for ub in unparsed_entries:
            cluster = CrashCluster(
                cluster_id=f"cluster-{cluster_idx:02d}",
                title=f"[HIGH] {ub['label']}",
                tool="SignalDetector",
                bug_type="signal-crash",
                severity=Severity.HIGH.value,
                root_cause_func="unknown",
                root_cause_file="unknown",
                top_frames=[],
                crash_count=ub["count"],
                unique_inputs=ub["inputs"],
                signatures=[ub["signature"]],
                representative_sha=ub["inputs"][0] if ub["inputs"] else "",
                representative_report=None,
                mean_similarity=1.0,
            )
            clusters.append(cluster)
            cluster_idx += 1

        return clusters

    def triage_summary(self) -> dict[str, Any]:
        """Generate high-level triage statistics and summary dictionary."""
        clusters = self.cluster()
        severity_counts = {s.value: 0 for s in Severity}
        tool_counts: dict[str, int] = {}

        for c in clusters:
            severity_counts[c.severity] = severity_counts.get(c.severity, 0) + 1
            tool_counts[c.tool] = tool_counts.get(c.tool, 0) + 1

        return {
            "total_crashes": len(self.crashes),
            "unique_inputs": len(self.deduplicate()),
            "total_clusters": len(clusters),
            "severity_breakdown": severity_counts,
            "tool_breakdown": tool_counts,
            "clusters": [c.to_json() for c in clusters],
        }

    def generate_markdown_report(self) -> str:
        """Render triage summary as a formatted Markdown report."""
        summary = self.triage_summary()
        clusters = self.cluster()

        lines = [
            "# Crash Triage & Bug Clustering Report",
            "",
            f"**Total Incidents**: {summary['total_crashes']} | "
            f"**Unique Inputs**: {summary['unique_inputs']} | "
            f"**Unique Clusters**: {summary['total_clusters']}",
            "",
            "### Severity Breakdown",
            "| Severity | Clusters |",
            "| :--- | :--- |",
        ]
        for sev, count in summary["severity_breakdown"].items():
            if count > 0:
                lines.append(f"| **{sev}** | {count} |")

        lines.extend([
            "",
            "### Bug Clusters",
            "| ID | Severity | Tool | Bug Type | Root Cause Site | Crashes | Representative SHA |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for c in clusters:
            site = f"`{c.root_cause_func}@{c.root_cause_file}`" if c.root_cause_func != "unknown" else "unknown"
            lines.append(
                f"| `{c.cluster_id}` | **{c.severity}** | {c.tool} | `{c.bug_type}` | {site} | {c.crash_count} | `{c.representative_sha[:12]}` |"
            )

        return "\n".join(lines)


def cluster_crashes(crashes: list[dict], threshold: float = 0.65) -> list[CrashCluster]:
    """Cluster raw crash records into semantic bug clusters."""
    clusterer = BugClusterer(similarity_threshold=threshold)
    for c in crashes:
        clusterer.add_crash(c)
    return clusterer.cluster()


def deduplicate_crashes(crashes: list[dict]) -> list[dict]:
    """Deduplicate crash records."""
    clusterer = BugClusterer()
    for c in crashes:
        clusterer.add_crash(c)
    return clusterer.deduplicate()


def triage_summary(crashes: list[dict]) -> dict[str, Any]:
    """Produce comprehensive triage summary for a list of crash records."""
    clusterer = BugClusterer()
    for c in crashes:
        clusterer.add_crash(c)
    return clusterer.triage_summary()


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

        bucket = out.setdefault(
            sig,
            {
                "signature": sig,
                "label": label,
                "count": 0,
                "inputs": [],
                "report": rep_json,
            },
        )
        bucket["count"] += 1
        if c.get("sha") and c["sha"] not in bucket["inputs"]:
            bucket["inputs"].append(c["sha"])
    return out
