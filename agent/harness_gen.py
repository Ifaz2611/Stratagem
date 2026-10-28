"""Generate a target-specific fuzzing harness with an LLM, then check it.

Every target in the registry needs a driver that reads stdin, calls the parser,
turns its diagnostics into `DIAG<TAB>...` lines, and returns the exit status the
campaign layer interprets. For the built-in targets those drivers already
exist. This module is for the next target: a parser with a header and a grammar
but no hand-written harness yet.

The generated code is never trusted blindly. Before it is written as
`harness.c` it must pass a structural gate:

  * it defines `main`
  * it reads stdin
  * it emits `DIAG<TAB>` lines
  * it uses the target's required headers
  * it can return each of the four documented exit statuses
  * it does not call out to a shell, spawn a process, or open a socket
  * its delimiters balance

With `--compile` it is also compiled with the same sanitizer flags the project
uses. A harness that does not compile is reported, not silently substituted.

Usage::

    python -m agent.harness_gen --target expat --backend openai \\
        --model gpt-5 --compile

The source and a build script land in ``harness/generated/<target>/``. Pass
``--use-generated-harness`` to ``agent.loop`` to run against the binary.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent import env as envmod
from agent import llm

REPO_ROOT = Path(__file__).resolve().parent.parent
PROMPTS = REPO_ROOT / "agent" / "prompts"
GENERATED_ROOT = REPO_ROOT / "harness" / "generated"
DEFAULT_MAX_REPAIRS = 2
MAX_SOURCE_BYTES = 60_000

_FORBIDDEN = re.compile(
    r"\b(system|popen|execl|execle|execlp|execv|execvp|execve|fork|"
    r"socket|connect|fopen|freopen|remove|unlink)\s*\("
)

_PROTOCOL_EXAMPLE = r"""#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    size_t cap = 4096, len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) return 2;
    for (;;) {
        if (len == cap) {
            cap *= 2;
            unsigned char *grown = realloc(buf, cap);
            if (!grown) { free(buf); return 2; }
            buf = grown;
        }
        size_t n = fread(buf + len, 1, cap - len, stdin);
        len += n;
        if (n == 0) break;
    }

    /* Call the target parser here. Record every diagnostic it reports. */
    int diagnostics = 0;
    const char *message = NULL;

    if (message) {
        printf("DIAG\t%s\n", message);
        diagnostics++;
    }

    free(buf);
    if (diagnostics) return 3;
    return 0;
}
"""


def _sha(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


@dataclass
class HarnessSpec:
    target_name: str
    language: str
    category: str
    description: str
    headers: tuple[str, ...] = ()
    link_flags: tuple[str, ...] = ()
    grammar_text: str = ""
    grammar_file: str = ""

    @classmethod
    def from_target(cls, target: Any) -> "HarnessSpec":
        grammar_file = getattr(target, "grammar_file", None)
        grammar_text = ""
        if grammar_file:
            try:
                p = Path(grammar_file)
                if p.exists():
                    grammar_text = p.read_text(encoding="utf-8", errors="replace")[:6000]
            except OSError:
                grammar_text = ""
        return cls(
            target_name=str(getattr(target, "name", "unknown")),
            language=str(getattr(target, "harness_language", "c") or "c"),
            category=str(getattr(target, "category", "unknown")),
            description=str(getattr(target, "description", "")),
            headers=tuple(getattr(target, "harness_headers", ()) or ()),
            link_flags=tuple(getattr(target, "harness_link_flags", ()) or ()),
            grammar_text=grammar_text,
            grammar_file=str(grammar_file) if grammar_file else "",
        )

    @property
    def extension(self) -> str:
        return "cpp" if self.language.lower() in ("cpp", "c++") else "c"

    def to_json(self) -> dict:
        return {
            "target": self.target_name,
            "language": self.language,
            "category": self.category,
            "description": self.description,
            "headers": list(self.headers),
            "link_flags": list(self.link_flags),
            "grammar_file": self.grammar_file,
            "grammar_sha256": _sha(self.grammar_text) if self.grammar_text else None,
        }


@dataclass
class HarnessValidation:
    ok: bool
    stage: str = "ok"
    error: str = ""
    code: str = ""
    checks: dict[str, bool] = field(default_factory=dict)

    def feedback(self) -> str:
        failed = [name for name, ok in self.checks.items() if not ok]
        detail = ""
        if self.error:
            detail = f"\n\n{self.error}"
        if failed:
            detail += "\n\nFailed checks: " + ", ".join(failed)
        return ("The harness was rejected by the structural gate." + detail +
                "\n\nFix the harness and resend exactly one fenced code block.")


@dataclass
class HarnessArtifact:
    target: str
    source_path: Path | None
    binary_path: Path | None
    validation: HarnessValidation
    attempts: int
    model: str = ""
    compile_error: str = ""

    def to_json(self) -> dict:
        return {
            "target": self.target,
            "source_path": str(self.source_path) if self.source_path else None,
            "binary_path": str(self.binary_path) if self.binary_path else None,
            "attempts": self.attempts,
            "model": self.model,
            "validation": {
                "ok": self.validation.ok,
                "stage": self.validation.stage,
                "error": self.validation.error,
                "checks": self.validation.checks,
            },
            "compile_error": self.compile_error,
        }


_FENCE = re.compile(r"```(?:c|cpp|c\+\+)\s*\n(.*?)```", re.S)
_ANY_FENCE = re.compile(r"```[a-zA-Z0-9_+-]*\s*\n(.*?)```", re.S)


def extract_harness_code(text: str) -> str | None:
    """Pull the C/C++ block out of a response, preferring one with main()."""
    blocks = _FENCE.findall(text or "")
    if not blocks:
        blocks = _ANY_FENCE.findall(text or "")
    if not blocks:
        body = (text or "").strip()
        return body + "\n" if re.search(r"\bmain\s*\(", body) else None
    for b in blocks:
        if re.search(r"\bmain\s*\(", b):
            return b.strip() + "\n"
    return blocks[0].strip() + "\n"


def _strip_literals(code: str) -> str:
    """Remove comments and string/char literals so delimiter counting is sane."""
    out = []
    i = 0
    n = len(code)
    while i < n:
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = code.find("\n", i)
            if j == -1:
                break
            i = j
            continue
        if c == "/" and nxt == "*":
            j = code.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue
        if c in ("'", '"'):
            quote = c
            i += 1
            while i < n:
                if code[i] == "\\":
                    i += 2
                    continue
                if code[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _delimiters_balanced(code: str) -> tuple[bool, str]:
    pairs = {")": "(", "]": "[", "}": "{"}
    stack = []
    stripped = _strip_literals(code)
    for ch in stripped:
        if ch in "([{":
            stack.append(ch)
        elif ch in ")]}":
            if not stack or stack[-1] != pairs[ch]:
                return False, f"unbalanced delimiter {ch!r}"
            stack.pop()
    if stack:
        return False, "unclosed delimiters: " + "".join(stack[-8:])
    return True, ""


def validate_harness_code(code: str, spec: HarnessSpec) -> HarnessValidation:
    checks: dict[str, bool] = {}
    checks["non_empty"] = bool(code and code.strip())
    checks["size"] = len(code.encode("utf-8", "replace")) <= MAX_SOURCE_BYTES
    checks["main"] = bool(re.search(r"\bmain\s*\(", code))
    checks["stdin"] = bool(re.search(
        r"\b(?:fread|fgets|getchar|read)\s*\(|\bstdin\b|\bSTDIN_FILENO\b|std::cin",
        code))
    checks["diagnostics"] = ("DIAG\\t" in code) or ("DIAG\t" in code)
    returns = set(re.findall(r"\b(?:return|exit)\s*\(\s*([0-3])\s*\)", code))
    returns |= set(re.findall(r"\breturn\s+([0-3])\s*;", code))
    checks["exit_0"] = "0" in returns
    checks["exit_1"] = "1" in returns
    checks["exit_2"] = "2" in returns
    checks["exit_3"] = "3" in returns
    checks["headers"] = all(h in code for h in spec.headers) if spec.headers else True
    checks["no_forbidden_calls"] = not _FORBIDDEN.search(code)
    balanced, balance_error = _delimiters_balanced(code)
    checks["balanced"] = balanced

    failed = [k for k, v in checks.items() if not v]
    if not failed:
        return HarnessValidation(True, "ok", code=code, checks=checks)
    stage = "structure"
    if not checks["non_empty"]:
        stage = "empty"
    elif not checks["main"]:
        stage = "main"
    elif not checks["balanced"]:
        stage = "syntax"
    elif not checks["headers"]:
        stage = "headers"
    elif not checks["no_forbidden_calls"]:
        stage = "sandbox"
    return HarnessValidation(False, stage, error=balance_error,
                             code=code, checks=checks)


def _compiler_for(language: str) -> str | None:
    if language.lower() in ("cpp", "c++"):
        candidates = ("c++", "g++", "clang++")
    else:
        candidates = ("cc", "gcc", "clang")
    for name in candidates:
        found = shutil.which(name)
        if found:
            return found
    return None


def compile_harness(source_path: Path, binary_path: Path, spec: HarnessSpec,
                    include_dirs: tuple[str, ...] = ()) -> tuple[bool, str]:
    """Compile with the project's sanitizer flags. Returns (ok, error)."""
    compiler = _compiler_for(spec.language)
    if not compiler:
        return False, ("no C/C++ compiler on PATH (looked for "
                       "cc/gcc/clang/c++/g++/clang++)")
    binary_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        compiler,
        "-g", "-O1", "-fno-omit-frame-pointer",
        "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
        str(source_path), "-o", str(binary_path),
    ]
    for d in include_dirs:
        cmd.insert(1, f"-I{d}")
    cmd.extend(spec.link_flags)
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=180)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"compiler failed to run: {exc}"
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace")[-2500:]
        return False, err or f"compiler exited {proc.returncode}"
    return True, ""


def _binary_name(target: str) -> str:
    suffix = ".exe" if os.name == "nt" else ""
    return f"harness{suffix}"


def _build_script(spec: HarnessSpec, source_name: str) -> str:
    compiler = "c++" if spec.language.lower() in ("cpp", "c++") else "cc"
    flags = " ".join(spec.link_flags)
    return (
        "#!/usr/bin/env bash\n"
        "# Generated by agent/harness_gen.py. Builds with the same sanitizers\n"
        "# the campaign loop expects; without them a crash is recorded as clean.\n"
        "set -euo pipefail\n"
        'cd "$(dirname "${BASH_SOURCE[0]}")"\n'
        f"{compiler} -g -O1 -fno-omit-frame-pointer \\\n"
        f"  -fsanitize=address,undefined -fno-sanitize-recover=all \\\n"
        f"  {source_name} -o harness {flags}\n"
        'echo "[harness] wrote $(pwd)/harness"\n'
    )


class HarnessGenerator:
    """Drive an LLM through generate -> validate -> repair for one target."""

    def __init__(self, backend: Any, transcript_dir: Path | str,
                 max_repairs: int = DEFAULT_MAX_REPAIRS) -> None:
        self.backend = backend
        self.transcript_dir = Path(transcript_dir)
        self.max_repairs = max(0, int(max_repairs))
        self.system = (PROMPTS / "harness_system.md").read_text(encoding="utf-8")
        self.template = (PROMPTS / "harness.md").read_text(encoding="utf-8")
        self._call_seq = 0

    def _prompt(self, spec: HarnessSpec) -> str:
        return (self.template
                .replace("{target_name}", spec.target_name)
                .replace("{target_category}", spec.category)
                .replace("{target_description}", spec.description)
                .replace("{language}", spec.language)
                .replace("{headers}", ", ".join(spec.headers) or "(none)")
                .replace("{link_flags}", " ".join(spec.link_flags) or "(none)")
                .replace("{grammar_text}", spec.grammar_text or "(no grammar file available)")
                .replace("{protocol_example}", _PROTOCOL_EXAMPLE))

    def _record(self, tag: str, user: str, response: llm.LLMResponse | None,
                error: str = "") -> None:
        self._call_seq += 1
        d = self.transcript_dir / f"call-{self._call_seq}"
        d.mkdir(parents=True, exist_ok=True)
        (d / "system.md").write_text(self.system, encoding="utf-8")
        (d / "user.md").write_text(user, encoding="utf-8")
        meta = {"tag": tag, "call": self._call_seq}
        (d / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        if response is not None:
            rec = response.to_json()
            rec.update(meta)
            (d / "response.json").write_text(json.dumps(rec, indent=2), encoding="utf-8")
        else:
            (d / "error.json").write_text(json.dumps({"error": error}, indent=2),
                                          encoding="utf-8")

    def generate(self, target_name: str, out_dir: Path | str,
                 compile: bool = False,
                 include_dirs: tuple[str, ...] = ()) -> HarnessArtifact:
        from fuzzer.targets import get_target
        target = get_target(target_name)
        spec = HarnessSpec.from_target(target)
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        prompt = self._prompt(spec)
        validation = HarnessValidation(False, "empty", error="no response")
        model = ""
        attempt = 0

        while attempt <= self.max_repairs:
            attempt += 1
            tag = "harness" if attempt == 1 else f"harness-repair{attempt - 1}"
            try:
                response = self.backend.complete(self.system, prompt)
            except llm.LLMError as exc:
                self._record(tag, prompt, None, str(exc))
                return HarnessArtifact(spec.target_name, None, None,
                                       HarnessValidation(False, "transport",
                                                         error=str(exc)),
                                       attempts=attempt, model=model)
            model = response.model or model
            self._record(tag, prompt, response)
            code = extract_harness_code(response.text)
            if code is None:
                validation = HarnessValidation(
                    False, "extract",
                    error="response contained no C/C++ code block", checks={})
            else:
                validation = validate_harness_code(code, spec)
            if validation.ok:
                break
            if attempt > self.max_repairs:
                break
            prompt = (self._prompt(spec) + "\n\n---\n\n" +
                      validation.feedback())

        (out / "harness_spec.json").write_text(
            json.dumps(spec.to_json(), indent=2), encoding="utf-8")
        result = HarnessArtifact(
            target=spec.target_name,
            source_path=None,
            binary_path=None,
            validation=validation,
            attempts=attempt,
            model=model,
        )
        if not validation.ok:
            rejected = out / f"harness.rejected.{spec.extension}"
            rejected.write_text(validation.code or "", encoding="utf-8")
            (out / "harness_result.json").write_text(
                json.dumps(result.to_json(), indent=2), encoding="utf-8")
            return result

        source_path = out / f"harness.{spec.extension}"
        source_path.write_text(validation.code, encoding="utf-8")
        (out / "build.sh").write_text(_build_script(spec, source_path.name),
                                      encoding="utf-8")
        result.source_path = source_path

        if compile:
            binary_path = out / _binary_name(spec.target_name)
            ok, err = compile_harness(source_path, binary_path, spec, include_dirs)
            if ok:
                result.binary_path = binary_path
            else:
                result.compile_error = err

        (out / "harness_result.json").write_text(
            json.dumps(result.to_json(), indent=2), encoding="utf-8")
        return result


def find_generated_harness(target: Any,
                           root: Path | str = GENERATED_ROOT) -> Path | None:
    """Return a built generated harness binary for target, if one exists."""
    name = str(getattr(target, "name", target))
    directory = Path(root) / name
    for candidate in (directory / _binary_name(name), directory / "harness"):
        if candidate.exists() and os.access(str(candidate), os.X_OK):
            return candidate
    return None


def build_generated_harness(target: Any, root: Path | str = GENERATED_ROOT,
                            include_dirs: tuple[str, ...] = ()) -> Path | None:
    """Compile an existing generated source. Returns the binary on success."""
    name = str(getattr(target, "name", target))
    directory = Path(root) / name
    spec = HarnessSpec.from_target(target)
    source = directory / f"harness.{spec.extension}"
    if not source.exists():
        return None
    binary = directory / _binary_name(name)
    ok, err = compile_harness(source, binary, spec, include_dirs)
    if not ok:
        last = err.splitlines()[-1] if err.splitlines() else "unknown error"
        print(f"    [harness] compile failed for {name}: {last[:160]}")
        return None
    return binary


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Generate and validate a target-specific fuzzing harness.")
    ap.add_argument("--target", required=False, default="mxml",
                    help="registered target name")
    ap.add_argument("--backend", choices=("cli", "openai", "replay"), default=None,
                    help="default comes from LLM_BACKEND in .env, else replay")
    ap.add_argument("--model", default=None, help="model override")
    ap.add_argument("--base-url", default=None,
                    help="OpenAI-compatible endpoint; default OPENAI_BASE_URL")
    ap.add_argument("--run-id", default=None, help="transcript directory name")
    ap.add_argument("--out", default=None,
                    help="output directory (default: harness/generated/<target>)")
    ap.add_argument("--transcript-dir", default=None,
                    help="where prompts/responses are recorded")
    ap.add_argument("--max-repairs", type=int, default=DEFAULT_MAX_REPAIRS)
    ap.add_argument("--compile", action="store_true",
                    help="also compile with ASan+UBSan")
    ap.add_argument("--include-dir", action="append", default=[],
                    help="extra -I directory for compilation (repeatable)")
    ap.add_argument("--list-targets", action="store_true")
    args = ap.parse_args()

    envmod.load_env()

    if args.list_targets:
        from fuzzer.targets import list_targets
        for name, target in sorted(list_targets().items()):
            print(f"{name:12} {target.category:9} {target.description}")
        return

    backend_kind = args.backend or os.environ.get("LLM_BACKEND") or "replay"
    run_id = args.run_id or f"harness-{args.target}"
    out = Path(args.out) if args.out else GENERATED_ROOT / args.target
    transcript = (Path(args.transcript_dir) if args.transcript_dir
                  else REPO_ROOT / "runs" / run_id / "harness" / "transcript")

    kw = {}
    if args.model:
        kw["model"] = args.model
    if args.base_url:
        kw["base_url"] = args.base_url
    if backend_kind == "replay":
        kw["transcript_dir"] = transcript
        kw.pop("base_url", None)
    backend = llm.make_backend(backend_kind, **kw)
    generator = HarnessGenerator(backend, transcript, args.max_repairs)
    result = generator.generate(args.target, out, compile=args.compile,
                                include_dirs=tuple(args.include_dir))

    print(f"target      : {result.target}")
    print(f"attempts    : {result.attempts}")
    print(f"validation  : {'ok' if result.validation.ok else 'FAILED at ' + result.validation.stage}")
    if result.validation.error:
        print(f"error       : {result.validation.error}")
    if result.source_path:
        print(f"source      : {result.source_path}")
    if result.binary_path:
        print(f"binary      : {result.binary_path}")
    elif result.compile_error:
        print("compile     : FAILED")
        print(result.compile_error[-1200:])
    raise SystemExit(0 if result.validation.ok else 1)


if __name__ == "__main__":
    main()
