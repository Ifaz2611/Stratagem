"""Compile strategy modules to bytecode and load them without reparsing.

The agent loop writes a new ``fuzzer/strategies/gen_iterN.py`` before every
campaign, and the campaign, the ensemble screen and the validation gate each
load it. Importing a module normally re-reads and re-compiles its source every
time the process has not already imported it. At 500 examples per iteration
that parse is small, but it is paid repeatedly and it is pure overhead: the
source has already been syntax-checked by the gate.

This loader makes the compile step explicit:

  * source is hashed, compiled once, and the code object is cached on disk;
  * later loads read and validate the bytecode instead of the source;
  * a fresh module object is still created for every load, so module-level
    state (counters, caches, random state) resets exactly as ``importlib.reload``
    did. That matters for reproducibility: two campaigns that load the same
    strategy must start from the same state.

The cache format is deliberately not Python's ``.pyc``. Those files are keyed
on mtime and are loaded by the import machinery; generated strategies are
overwritten in place and must not leave a stale module in ``sys.modules``. A
content-addressed file under ``runs/.bytecode`` is independent of mtime, of the
import cache, and of whatever the previous iteration wrote.

No third-party dependency, no network, and nothing here is on the replay path
that could change which documents a strategy draws.
"""
from __future__ import annotations

import hashlib
import json
import marshal
import os
import re
import sys
import threading
import time
import types
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fuzzer.platform_compat import replace_file

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_STRATEGY_DIR = REPO_ROOT / "fuzzer" / "strategies"
DEFAULT_CACHE_DIR = REPO_ROOT / "runs" / ".bytecode"

_MAGIC = b"STRATAGEM-STRATEGY\x00"
_FORMAT = 1
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Bounded so a long-lived loop that generates hundreds of strategies does not
# keep every code object alive; the disk cache is the real store.
_MAX_CODE_CACHE = 64


class StrategyError(RuntimeError):
    """A strategy module is missing, malformed, or cannot be loaded."""


@dataclass
class LoadedStrategy:
    """One freshly executed strategy module plus its cache provenance."""

    name: str
    module: types.ModuleType
    source_path: Path
    code_path: Path | None
    from_cache: bool
    compile_ms: float

    def documents(self) -> Any:
        """Return the module's document strategy, with a clear error if absent."""
        fn = getattr(self.module, "documents", None)
        if not callable(fn):
            raise StrategyError(
                f"strategy {self.name!r} does not define a callable documents()")
        return fn()


def _cache_tag() -> str:
    tag = getattr(sys.implementation, "cache_tag", None) or "py"
    return f"{tag}-{sys.flags.optimize}"


def _module_name(name: str) -> str:
    return f"fuzzer.strategies.{name}"


class StrategyLoader:
    """Content-addressed bytecode cache for strategy modules.

    Parameters are injectable so tests (and callers with a vendored strategy
    tree) can point the loader at a temporary directory.
    """

    def __init__(
        self,
        strategies_dir: Path | str | None = None,
        cache_dir: Path | str | None = None,
    ) -> None:
        self.strategies_dir = Path(strategies_dir or DEFAULT_STRATEGY_DIR)
        env_cache = os.environ.get("STRATAGEM_BYTECODE_CACHE")
        self.cache_dir = Path(cache_dir or env_cache or DEFAULT_CACHE_DIR)
        self._lock = threading.Lock()
        self._codes: OrderedDict[tuple[str, str], types.CodeType] = OrderedDict()
        self._stats: dict[str, Any] = {
            "loads": 0,
            "compiled": 0,
            "cache_hits": 0,
            "executions": 0,
            "failures": 0,
            "source_bytes": 0,
            "code_bytes": 0,
        }

    # ------------------------------------------------------------- resolution
    def canonical_name(self, name: str) -> str:
        """Extract canonical strategy identifier from name or module path."""
        raw = str(name).strip()
        if raw.startswith("fuzzer.strategies."):
            raw = raw[len("fuzzer.strategies."):]
        if raw.endswith(".py"):
            raw = raw[:-3]
        if not _NAME_RE.match(raw):
            raise StrategyError(
                f"invalid strategy name {name!r}; expected a Python identifier")
        return raw

    def resolve(self, name: str) -> Path:
        """Map a strategy name to its source, rejecting path traversal."""
        cname = self.canonical_name(name)
        path = self.strategies_dir / f"{cname}.py"
        if not path.is_file():
            raise StrategyError(
                f"strategy {cname!r} not found at {path}")
        return path

    def _source_digest(self, path: Path) -> tuple[str, bytes]:
        data = path.read_bytes()
        return hashlib.sha256(data).hexdigest(), data

    def _cache_path(self, name: str, digest: str) -> Path:
        return self.cache_dir / f"{name}-{digest[:24]}-{_cache_tag()}.pyc"

    # ------------------------------------------------------------ compilation
    def _compile(self, name: str, path: Path, digest: str,
                 source: bytes) -> tuple[types.CodeType, Path, bool, float]:
        started = time.perf_counter()
        cached = self._read_code_cache(name, digest)
        if cached is not None:
            elapsed = (time.perf_counter() - started) * 1000.0
            self._stats["cache_hits"] += 1
            return cached, self._cache_path(name, digest), True, elapsed

        filename = str(path)
        try:
            source_text = source.decode("utf-8")
            code = compile(source_text, filename, "exec", dont_inherit=True)
        except (SyntaxError, UnicodeDecodeError) as exc:
            self._stats["failures"] += 1
            raise StrategyError(
                f"strategy {name!r} does not compile: {type(exc).__name__}: {exc}"
            ) from exc

        cache_path = self._cache_path(name, digest)
        body = marshal.dumps(code)
        meta = {
            "format": _FORMAT,
            "python": list(sys.version_info[:2]),
            "cache_tag": _cache_tag(),
            "source": digest,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "code_bytes": len(body),
        }
        header = json.dumps(meta, sort_keys=True).encode("utf-8")
        payload = _MAGIC + header + b"\n" + body
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = cache_path.with_name(
                f".{cache_path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
            tmp.write_bytes(payload)
            replace_file(tmp, cache_path)
        except OSError:
            # A read-only checkout still gets the in-memory cache; losing the
            # disk cache must not prevent the strategy from running.
            pass

        self._codes[(name, digest)] = code
        while len(self._codes) > _MAX_CODE_CACHE:
            self._codes.popitem(last=False)
        self._stats["compiled"] += 1
        self._stats["source_bytes"] += len(source)
        self._stats["code_bytes"] += len(body)
        elapsed = (time.perf_counter() - started) * 1000.0
        return code, cache_path, False, elapsed

    def _read_code_cache(self, name: str, digest: str) -> types.CodeType | None:
        key = (name, digest)
        code = self._codes.get(key)
        if code is not None:
            self._codes.move_to_end(key)
            return code

        path = self._cache_path(name, digest)
        if not path.is_file():
            return None
        try:
            raw = path.read_bytes()
        except OSError:
            return None
        if not raw.startswith(_MAGIC):
            return None
        header, sep, body = raw[len(_MAGIC):].partition(b"\n")
        if not sep:
            return None
        try:
            meta = json.loads(header.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if (meta.get("format") != _FORMAT
                or meta.get("source") != digest
                or meta.get("cache_tag") != _cache_tag()
                or meta.get("python") != list(sys.version_info[:2])):
            return None
        if meta.get("body_sha256") != hashlib.sha256(body).hexdigest():
            return None
        try:
            code = marshal.loads(body)
        except (EOFError, ValueError, TypeError):
            return None
        if not isinstance(code, types.CodeType):
            return None
        self._codes[key] = code
        while len(self._codes) > _MAX_CODE_CACHE:
            self._codes.popitem(last=False)
        return code

    # ----------------------------------------------------------------- loading
    def load(self, name: str, *, force: bool = False) -> LoadedStrategy:
        """Load ``name`` as a fresh module, using cached bytecode when valid."""
        cname = self.canonical_name(name)
        path = self.resolve(name)
        digest, source = self._source_digest(path)
        with self._lock:
            self._stats["loads"] += 1
            if force:
                self._codes.pop((cname, digest), None)
            try:
                code, code_path, from_cache, compile_ms = self._compile(
                    cname, path, digest, source)
            except StrategyError:
                raise
            except Exception as exc:
                self._stats["failures"] += 1
                raise StrategyError(
                    f"could not load strategy {cname!r}: "
                    f"{type(exc).__name__}: {exc}") from exc

            module = types.ModuleType(_module_name(cname))
            module.__file__ = str(path)
            module.__package__ = "fuzzer.strategies"
            module.__loader__ = None
            try:
                exec(code, module.__dict__)
            except Exception as exc:
                self._stats["failures"] += 1
                raise StrategyError(
                    f"strategy {cname!r} failed while importing: "
                    f"{type(exc).__name__}: {exc}") from exc
            self._stats["executions"] += 1

        return LoadedStrategy(
            name=cname, module=module, source_path=path, code_path=code_path,
            from_cache=from_cache, compile_ms=round(compile_ms, 3),
        )

    def load_documents(self, name: str, *, force: bool = False
                       ) -> tuple[Any, LoadedStrategy]:
        """Load a strategy and return ``(documents(), LoadedStrategy)``."""
        loaded = self.load(name, force=force)
        return loaded.documents(), loaded

    # ------------------------------------------------------------------ stats
    def stats(self) -> dict[str, Any]:
        with self._lock:
            found = sum(1 for p in self.cache_dir.glob("*.pyc")) \
                if self.cache_dir.exists() else 0
            return {
                **self._stats,
                "batch_cache_entries": len(self._codes),
                "disk_cache_entries": found,
                "cache_dir": str(self.cache_dir),
            }

    def reset_stats(self) -> None:
        with self._lock:
            for key in ("loads", "compiled", "cache_hits", "executions",
                        "failures", "source_bytes", "code_bytes"):
                self._stats[key] = 0

    def clear(self) -> None:
        """Drop in-memory code and every disk entry this loader knows."""
        with self._lock:
            self._codes.clear()
            if self.cache_dir.exists():
                for p in self.cache_dir.glob("*.pyc"):
                    try:
                        p.unlink()
                    except OSError:
                        pass


_DEFAULT_LOADER: StrategyLoader | None = None
_DEFAULT_LOCK = threading.Lock()


def get_default_loader() -> StrategyLoader:
    """Return the process-wide loader, creating it against the repo roots."""
    global _DEFAULT_LOADER
    if _DEFAULT_LOADER is None:
        with _DEFAULT_LOCK:
            if _DEFAULT_LOADER is None:
                _DEFAULT_LOADER = StrategyLoader()
    return _DEFAULT_LOADER


def load_strategy(name: str, *, force: bool = False) -> tuple[Any, LoadedStrategy]:
    """Convenience wrapper used by the campaign runner."""
    return get_default_loader().load_documents(name, force=force)


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        prog="python -m fuzzer.strategy_loader",
        description="Warm or inspect the strategy bytecode cache.")
    ap.add_argument("names", nargs="*", help="strategy module names to compile")
    ap.add_argument("--list", action="store_true",
                    help="list strategy modules in the strategy directory")
    ap.add_argument("--cache-dir", default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--clear", action="store_true")
    args = ap.parse_args(argv)

    loader = StrategyLoader(cache_dir=args.cache_dir)
    if args.clear:
        loader.clear()
    names = list(args.names)
    if args.list:
        names = sorted(p.stem for p in loader.strategies_dir.glob("*.py")
                       if p.name != "__init__.py")
    results = []
    try:
        for name in names:
            loaded = loader.load(name)
            results.append({
                "name": name,
                "from_cache": loaded.from_cache,
                "compile_ms": loaded.compile_ms,
                "code_path": str(loaded.code_path) if loaded.code_path else None,
            })
    except StrategyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    stats = loader.stats()
    if args.json:
        print(json.dumps({"strategies": results, "stats": stats}, indent=2))
    else:
        for row in results:
            source = "cache" if row["from_cache"] else "compiled"
            print(f"{row['name']:<24} {source:<8} {row['compile_ms']:.2f} ms")
        print(f"cache: {stats['disk_cache_entries']} entries under "
              f"{stats['cache_dir']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
