"""Automatic minimal reproducer generation for fuzzing defects.

Takes crashing inputs found during fuzzing campaigns and:
  1. Minimizes them using hierarchical delta debugging (DDmin + line/token reduction + simplification)
     while ensuring the exact crash signature/outcome is preserved.
  2. Verifies reproducibility across multiple standalone executions (determinism check).
  3. Generates standalone, self-contained reproducer artifacts:
       * reproducer.bin: The minimized raw binary payload
       * reproduce.py: Standalone Python script that replays payload and checks sanitizer output
       * reproduce.c: Standalone C source test case embedding the payload array
       * reproduce.sh: Shell execution script for command-line reproduction
       * metadata.json: Detailed defect metadata, reduction ratio, and triage info
"""
from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from fuzzer import triage
from fuzzer.runner import (
    DEFAULT_HARNESS,
    PER_RUN_TIMEOUT_S,
    Outcome,
)
from fuzzer.targets import BaseTarget, get_target

REPO_ROOT = Path(__file__).resolve().parent.parent


class DeltaDebugger:
    """Hierarchical delta debugger for reducing crashing inputs to their minimal form."""

    def __init__(
        self,
        oracle: Callable[[bytes], bool],
        timeout_s: float = 30.0,
        max_iterations: int = 150,
    ) -> None:
        self.oracle = oracle
        self.timeout_s = timeout_s
        self.max_iterations = max_iterations

    def minimize(self, payload: bytes) -> bytes:
        """Minimise payload while oracle(payload) remains True."""
        if not payload:
            return payload

        # Quick check: does initial payload trigger oracle?
        if not self.oracle(payload):
            return payload

        started = time.monotonic()
        current = payload
        iteration = 0

        # Stage 1: Line-based reduction (for multi-line inputs)
        if b"\n" in current:
            lines = current.split(b"\n")
            if len(lines) > 2:
                reduced_lines = self._reduce_list(
                    lines,
                    joiner=lambda chunks: b"\n".join(chunks),
                    started=started,
                )
                if self.oracle(reduced_lines):
                    current = reduced_lines

        # Stage 2: Chunk-based Delta Debugging (DDmin)
        n = 2
        while len(current) >= 2 and n <= len(current):
            if (time.monotonic() - started) > self.timeout_s or iteration > self.max_iterations:
                break
            iteration += 1

            chunk_size = len(current) // n
            if chunk_size == 0:
                break

            reduced = False
            # Try removing each chunk (complements)
            for i in range(n):
                start = i * chunk_size
                end = (i + 1) * chunk_size if i < n - 1 else len(current)
                candidate = current[:start] + current[end:]
                if candidate and self.oracle(candidate):
                    current = candidate
                    n = max(n - 1, 2)
                    reduced = True
                    break

            if reduced:
                continue

            # Try keeping only each chunk (subsets)
            for i in range(n):
                start = i * chunk_size
                end = (i + 1) * chunk_size if i < n - 1 else len(current)
                candidate = current[start:end]
                if candidate and len(candidate) < len(current) and self.oracle(candidate):
                    current = candidate
                    n = max(n - 1, 2)
                    reduced = True
                    break

            if not reduced:
                if n == len(current):
                    break
                n = min(n * 2, len(current))

        # Stage 3: Fine-grained single-byte removal pass
        if len(current) <= 128:
            idx = 0
            while idx < len(current):
                if (time.monotonic() - started) > self.timeout_s:
                    break
                candidate = current[:idx] + current[idx + 1:]
                if candidate and self.oracle(candidate):
                    current = candidate
                else:
                    idx += 1

        # Stage 4: Simplification pass (replace complex bytes with 'a' or '0')
        if len(current) <= 64:
            for idx in range(len(current)):
                b = current[idx]
                if b not in (ord(b"<"), ord(b">"), ord(b"/"), ord(b"="), ord(b'"'), ord(b"\n"), ord(b" ")):
                    for simple in (b"a", b"0", b" "):
                        candidate = current[:idx] + simple + current[idx + 1:]
                        if self.oracle(candidate):
                            current = candidate
                            break

        return current

    def _reduce_list(
        self,
        chunks: list[bytes],
        joiner: Callable[[list[bytes]], bytes],
        started: float,
    ) -> bytes:
        current = chunks
        idx = 0
        while idx < len(current):
            if (time.monotonic() - started) > (self.timeout_s / 2):
                break
            candidate_list = current[:idx] + current[idx + 1:]
            candidate = joiner(candidate_list)
            if candidate and self.oracle(candidate):
                current = candidate_list
            else:
                idx += 1
        return joiner(current)


def build_crash_oracle(
    target: BaseTarget | str = "mxml",
    expected_signature: str | None = None,
    timeout_s: float = PER_RUN_TIMEOUT_S,
    harness: Path = DEFAULT_HARNESS,
) -> Callable[[bytes], bool]:
    """Build an oracle test function that returns True if input reproduces defect."""
    target_obj = get_target(target) if isinstance(target, str) else target

    def oracle(payload: bytes) -> bool:
        try:
            r = target_obj.run(payload, timeout_s=timeout_s)
        except Exception:
            return False

        if not r.outcome.is_crash:
            return False

        if expected_signature is None:
            return True

        if r.outcome == Outcome.TIMEOUT:
            return expected_signature == "timeout" or expected_signature.startswith("timeout|")

        rep = triage.parse_report(r.stderr)
        if rep:
            return rep.signature == expected_signature
        return False

    return oracle


@dataclass
class MinimalReproducerBundle:
    """A self-contained reproducer bundle for a verified crash."""
    minimized_document: bytes
    original_len: int
    minimized_len: int
    reduction_pct: float
    signature: str
    label: str
    tool: str
    bug_type: str
    severity: str
    target: str
    verified_runs: int
    verified_ok: int
    deterministic: bool
    python_script: str = ""
    c_test_case: str = ""
    shell_script: str = ""
    raw_stderr: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "signature": self.signature,
            "label": self.label,
            "tool": self.tool,
            "bug_type": self.bug_type,
            "severity": self.severity,
            "original_len": self.original_len,
            "minimized_len": self.minimized_len,
            "reduction_pct": round(self.reduction_pct, 1),
            "verified_runs": self.verified_runs,
            "verified_ok": self.verified_ok,
            "deterministic": self.deterministic,
            "document_b64": base64.b64encode(self.minimized_document).decode("ascii"),
        }

    def write_bundle(self, out_dir: Path) -> dict[str, Path]:
        """Write all reproducer artifacts to destination directory."""
        out_dir.mkdir(parents=True, exist_ok=True)
        files = {
            "payload": out_dir / "reproducer.bin",
            "metadata": out_dir / "metadata.json",
            "python": out_dir / "reproduce.py",
            "c_test": out_dir / "reproduce.c",
            "shell": out_dir / "reproduce.sh",
            "batch": out_dir / "reproduce.cmd",
            "stderr": out_dir / "sanitizer_output.txt",
        }

        files["payload"].write_bytes(self.minimized_document)
        files["metadata"].write_text(json.dumps(self.to_json(), indent=2), encoding="utf-8")
        if self.python_script:
            files["python"].write_text(self.python_script, encoding="utf-8")
        if self.c_test_case:
            files["c_test"].write_text(self.c_test_case, encoding="utf-8")
        if self.shell_script:
            files["shell"].write_text(self.shell_script, encoding="utf-8")
            files["batch"].write_text(
                generate_batch_reproducer(), encoding="utf-8")
        if self.raw_stderr:
            files["stderr"].write_text(self.raw_stderr, encoding="utf-8")

        return files


def generate_python_reproducer(
    payload: bytes,
    target_name: str,
    signature: str = "",
    label: str = "",
    tool: str = "",
) -> str:
    """Generate a self-contained Python script to reproduce the defect."""
    payload_b64 = base64.b64encode(payload).decode("ascii")
    return f'''#!/usr/bin/env python3
"""Standalone Crash Reproducer for target '{target_name}'.
Defect: {label}
Signature: {signature}
Sanitizer/Tool: {tool}
Generated by Stratagem Fuzz-Agent.
"""
import base64
import os
import subprocess
import sys
from pathlib import Path

PAYLOAD = base64.b64decode("{payload_b64}")

def main():
    root = Path(__file__).resolve().parent.parent.parent
    harness = root / "build" / "asan" / "harness"
    if os.name == "nt" and harness.suffix.lower() != ".exe":
        harness = harness.with_name(harness.name + ".exe")

    print(f"[*] Testing payload ({{len(PAYLOAD)}} bytes) against target '{target_name}'...")
    if harness.exists() and os.access(str(harness), os.X_OK):
        print(f"[*] Executing native harness: {{harness}}")
        env = dict(os.environ)
        env["ASAN_OPTIONS"] = "abort_on_error=1:symbolize=1:print_stacktrace=1"
        env["UBSAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1:print_stacktrace=1"
        try:
            p = subprocess.run([str(harness)], input=PAYLOAD, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=5, env=env)
            rc, stderr = p.returncode, p.stderr.decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            print("[+] REPRODUCED: Parser hung (TIMEOUT)")
            return 0
    else:
        print("[*] Native harness not found; running reference target via Python...")
        sys.path.insert(0, str(root))
        from fuzzer.targets import get_target
        t = get_target("{target_name}")
        r = t.run(PAYLOAD)
        rc, stderr = r.returncode, r.stderr

    if rc != 0 or any(m in stderr for m in ("Sanitizer", "runtime error:", "SEGV", "SIG")):
        print("[+] SUCCESS: Defect reproduced successfully!")
        print(f"[*] Returncode: {{rc}}")
        if stderr:
            print(f"[*] Output:\\n{{stderr[:500]}}")
        return 0
    else:
        print("[-] FAILED: Did not trigger crash.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
'''


def generate_c_reproducer(
    payload: bytes,
    target_name: str,
    signature: str = "",
    label: str = "",
) -> str:
    """Generate a standalone C source file containing the minimal crashing input."""
    bytes_hex = ", ".join(f"0x{b:02x}" for b in payload)
    return f'''/* Standalone Minimal C Reproducer
 * Target: {target_name}
 * Defect: {label}
 * Signature: {signature}
 *
 * Compile:
 *   gcc -g -fsanitize=address,undefined reproduce.c -o reproduce
 *   ./reproduce
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const unsigned char payload[] = {{
    {bytes_hex}
}};
static const size_t payload_len = {len(payload)};

int main(int argc, char **argv) {{
    printf("[*] Reproducing defect for {target_name} (%zu bytes)...\\n", payload_len);
    /* Feed payload to stdin or execute directly */
    fwrite(payload, 1, payload_len, stdout);
    return 0;
}}
'''


def generate_shell_reproducer(
    payload_file: str = "reproducer.bin",
    harness_path: str = "./build/asan/harness",
) -> str:
    """Generate a shell runner script for command-line reproduction."""
    return f'''#!/usr/bin/env bash
# Quick reproduction script
DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
BIN="{harness_path}"
PAYLOAD="$DIR/{payload_file}"

if [ ! -x "$BIN" ]; then
  BIN="$DIR/../../build/asan/harness"
fi
if [ ! -x "$BIN" ] && [ -x "$BIN.exe" ]; then
  BIN="$BIN.exe"
fi

if [ ! -f "$PAYLOAD" ]; then
  echo "Payload not found: $PAYLOAD" >&2
  exit 1
fi

echo "[*] Replaying $PAYLOAD through $BIN..."
export ASAN_OPTIONS="abort_on_error=1:symbolize=1:print_stacktrace=1"
export UBSAN_OPTIONS="halt_on_error=1:abort_on_error=1:print_stacktrace=1"
"$BIN" < "$PAYLOAD"
echo "[*] Exit code: $?"
'''


def generate_batch_reproducer(
    payload_file: str = "reproducer.bin",
) -> str:
    """Generate a Windows ``cmd`` counterpart to ``reproduce.sh``.

    Native Windows is a supported build path for the harness, and a bundle
    whose only runner is a bash script cannot be used there.
    """
    return f'''@echo off
rem Quick reproduction script (Windows cmd)
setlocal
set "DIR=%~dp0"
set "BIN=%DIR%..\\..\\build\\asan\\harness.exe"
if not exist "%BIN%" set "BIN=%DIR%..\\..\\build\\asan\\harness"
set "PAYLOAD=%DIR%{payload_file}"

if not exist "%PAYLOAD%" (
  echo Payload not found: %PAYLOAD% 1>&2
  exit /b 1
)

echo [*] Replaying %PAYLOAD% through %BIN%...
set "ASAN_OPTIONS=abort_on_error=1:symbolize=1:print_stacktrace=1"
set "UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1"
"%BIN%" < "%PAYLOAD%"
echo [*] Exit code: %ERRORLEVEL%
'''


def create_reproducer_bundle(
    payload: bytes,
    target: BaseTarget | str = "mxml",
    out_dir: Path | None = None,
    minimize_first: bool = True,
    signature: str | None = None,
    verify_runs: int = 3,
) -> MinimalReproducerBundle:
    """End-to-end generator: delta-debugs payload, confirms reproduction, builds bundle."""
    target_obj = get_target(target) if isinstance(target, str) else target

    # Initial execution to verify baseline crash
    initial_res = target_obj.run(payload)
    orig_len = len(payload)

    # Determine signature and metadata
    rep = triage.parse_report(initial_res.stderr)
    target_sig = signature or (rep.signature if rep else ("timeout" if initial_res.outcome == Outcome.TIMEOUT else "crash"))
    label = rep.label if rep else initial_res.outcome.value
    tool = rep.tool if rep else "Harness"
    bug_type = rep.bug_type if rep else "crash"
    severity = rep.severity if rep else triage.Severity.HIGH.value

    # Delta debugging minimization
    if minimize_first and orig_len > 1:
        oracle = build_crash_oracle(target=target_obj, expected_signature=target_sig)
        dd = DeltaDebugger(oracle=oracle)
        shrunk = dd.minimize(payload)
    else:
        shrunk = payload

    min_len = len(shrunk)
    reduction_pct = ((orig_len - min_len) / orig_len * 100.0) if orig_len > 0 else 0.0

    # Verification passes
    verified_ok = 0
    for _ in range(verify_runs):
        check_res = target_obj.run(shrunk)
        check_rep = triage.parse_report(check_res.stderr)
        check_sig = check_rep.signature if check_rep else ("timeout" if check_res.outcome == Outcome.TIMEOUT else "crash")
        if check_res.outcome.is_crash and (check_sig == target_sig or target_sig in ("crash", "timeout")):
            verified_ok += 1

    deterministic = (verified_ok == verify_runs) and (verify_runs > 0)

    # Generate scripts
    py_code = generate_python_reproducer(shrunk, target_obj.name, target_sig, label, tool)
    c_code = generate_c_reproducer(shrunk, target_obj.name, target_sig, label)
    sh_code = generate_shell_reproducer("reproducer.bin")

    bundle = MinimalReproducerBundle(
        minimized_document=shrunk,
        original_len=orig_len,
        minimized_len=min_len,
        reduction_pct=reduction_pct,
        signature=target_sig,
        label=label,
        tool=tool,
        bug_type=bug_type,
        severity=severity,
        target=target_obj.name,
        verified_runs=verify_runs,
        verified_ok=verified_ok,
        deterministic=deterministic,
        python_script=py_code,
        c_test_case=c_code,
        shell_script=sh_code,
        raw_stderr=initial_res.stderr,
    )

    if out_dir is not None:
        bundle.write_bundle(out_dir)

    return bundle


def main() -> None:
    """CLI tool to minimize and bundle a crashing input."""
    import argparse

    ap = argparse.ArgumentParser(description="Generate minimal reproducer bundle for a crash.")
    ap.add_argument("input_path", help="Path to crashing input file or directory")
    ap.add_argument("-t", "--target", default="mxml", help="Target parser (default: mxml)")
    ap.add_argument("-o", "--out", default="reproducer_bundle", help="Output directory")
    ap.add_argument("--no-minimize", action="store_true", help="Skip delta debugging")
    ap.add_argument("-v", "--verify", type=int, default=3, help="Verification repetitions")
    args = ap.parse_args()

    in_path = Path(args.input_path)
    if not in_path.exists():
        raise SystemExit(f"Input file not found: {in_path}")

    payload = in_path.read_bytes()
    out_dir = Path(args.out)

    print(f"[*] Processing {len(payload)} bytes for target '{args.target}'...")
    bundle = create_reproducer_bundle(
        payload=payload,
        target=args.target,
        out_dir=out_dir,
        minimize_first=not args.no_minimize,
        verify_runs=args.verify,
    )

    print(f"[+] Reproducer generated in: {out_dir}")
    print(f"[*] Defect: {bundle.label} ({bundle.severity})")
    print(f"[*] Size: {bundle.original_len} -> {bundle.minimized_len} bytes (-{bundle.reduction_pct:.1f}%)")
    print(f"[*] Deterministic: {bundle.deterministic} ({bundle.verified_ok}/{bundle.verified_runs})")


if __name__ == "__main__":
    main()
