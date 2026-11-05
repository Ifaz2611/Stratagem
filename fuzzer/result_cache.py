"""Deterministic result cache for harness executions.

A grammar strategy can produce the same document in two iterations, a resume
can replay a batch that was already measured, and a distributed shard can be
re-run after a worker dies. Spawning the sanitizer binary again for an input
whose bytes, target, flags and timeout are unchanged produces the same answer
and costs another process launch.

This module is an opt-in SQLite cache keyed on that full execution context:

    schema version + target name/class + harness fingerprint
    + extra arguments + timeout + slow threshold + sanitizer configuration
    + SHA-256 of the input bytes

The harness fingerprint includes the binary's path, size and nanosecond mtime,
so rebuilding the target invalidates every entry without a manual purge. The
cache only stores outcomes that are meaningful for a deterministic target:
crashes, accepted inputs and well-formed rejections. Timeouts and harness
errors are never cached because they can be symptoms of machine load or of a
broken invocation rather than of the input.

Caching is off by default. It is only sound when the target and strategy are
declared deterministic, and a cached crash deliberately suppresses a fresh
reproduction, so the caller must ask for it with ``--cache-results``.

All database failures are contained: a missing, locked or corrupt cache turns
into a miss and a counter, never into a failed campaign.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable, Iterator

from fuzzer.runner import Outcome, RunResult

SCHEMA_VERSION = 1
DEFAULT_MAX_ENTRIES = 200_000
# Outcomes whose value is a property of the input, not of the machine's mood.
CACHEABLE_OUTCOMES = frozenset({
    Outcome.PARSED_CLEAN.value,
    Outcome.PARSED_DIAG.value,
    Outcome.REJECTED.value,
    Outcome.CRASH.value,
})


def _fingerprint(path: Path | str | None) -> dict[str, Any] | None:
    if path is None:
        return None
    p = Path(path)
    try:
        st = p.stat()
    except OSError:
        return {"path": str(p), "missing": True}
    return {
        "path": str(p.resolve()),
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
    }


class ResultCache:
    """SQLite-backed cache of :class:`RunResult` objects.

    One connection per worker thread is kept open for the life of the cache.
    Harness execution costs milliseconds to seconds, so opening, PRAGMA-ing
    and closing the database for every payload turned the cache into a
    bottleneck in high-throughput campaigns. WAL journal mode keeps the
    single writer from blocking the concurrent readers in the thread pool
    used by ``fuzzer.parallel``. Each worker closes its own handle with
    :meth:`close`; a campaign does this when it finishes, and a thread that
    exits without closing has its handle collected with the thread.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        max_entries: int | None = DEFAULT_MAX_ENTRIES,
        ttl_s: float | None = None,
        enabled: bool = True,
    ) -> None:
        self.path = Path(path)
        self.max_entries = max_entries
        self.ttl_s = ttl_s
        self.enabled = bool(enabled)
        self.hits = 0
        self.misses = 0
        self.stores = 0
        self.evictions = 0
        self.errors = 0
        self._last_error: str | None = None
        self._local = threading.local()
        if self.enabled:
            self._init()

    # --------------------------------------------------------------- lifecycle
    @property
    def _connection(self) -> sqlite3.Connection:
        """This thread's open connection, creating it on first use.

        SQLite handles must not cross threads, so the connection is stored in
        thread-local storage: a campaign running in one thread gets exactly
        one handle for all of its payloads, and a parallel worker gets its
        own. The PRAGMAs are applied once per handle instead of once per
        payload.
        """
        conn = getattr(self._local, "conn", None)
        if conn is None:
            try:
                conn = sqlite3.connect(str(self.path), timeout=5.0)
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
                conn.execute("PRAGMA busy_timeout=5000")
            except sqlite3.Error as exc:
                self._fail(exc)
                raise sqlite3.OperationalError(
                    self._last_error or "result cache is disabled") from exc
            self._local.conn = conn
        return conn

    @contextlib.contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        """A committed transaction on this thread's persistent connection."""
        conn = self._connection
        with conn:
            yield conn

    def _init(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._session() as conn:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS results ("
                    " key TEXT PRIMARY KEY,"
                    " value TEXT NOT NULL,"
                    " created REAL NOT NULL,"
                    " hits INTEGER NOT NULL DEFAULT 0)")
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS results_created "
                    "ON results(created)")
        except (OSError, sqlite3.Error) as exc:
            self._fail(exc)

    def _fail(self, exc: BaseException) -> None:
        self.errors += 1
        self._last_error = f"{type(exc).__name__}: {exc}"
        self.enabled = False

    def close(self) -> None:
        """Close this thread's connection.

        Campaigns call this when they finish so the database file is released
        promptly; on Windows an open handle blocks deletion of the containing
        directory. Other workers' handles close when their threads end.
        """
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            self._local.conn = None
            try:
                conn.close()
            except sqlite3.Error:
                pass

    # -------------------------------------------------------------------- key
    def context(
        self,
        target: Any,
        *,
        harness: Path | str | None = None,
        extra_args: Iterable[str] = (),
        timeout_s: float = 5.0,
        slow_threshold_s: float | None = None,
        sanitizers: Iterable[str] | None = None,
        sanitizer_env: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Build the reusable, payload-independent half of a cache key."""
        target_harness = harness
        if target_harness is None:
            target_harness = (
                getattr(target, "resolved_harness_binary", None)
                or getattr(target, "harness_binary", None)
            )
        return {
            "v": SCHEMA_VERSION,
            "target": getattr(target, "name", str(target)),
            "target_class": (f"{type(target).__module__}."
                             f"{type(target).__qualname__}"),
            "harness": _fingerprint(target_harness),
            "extra_args": [str(a) for a in extra_args],
            "timeout_s": float(timeout_s),
            "slow_threshold_s": (None if slow_threshold_s is None
                                 else float(slow_threshold_s)),
            "sanitizers": sorted(str(s) for s in (sanitizers or ())),
            "sanitizer_env": sorted((sanitizer_env or {}).items()),
        }

    @staticmethod
    def key(context: dict[str, Any], payload: bytes) -> str:
        """Hash the execution context and payload into a stable key."""
        header = json.dumps(context, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(header.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(payload)
        return digest.hexdigest()

    # ------------------------------------------------------------------ access
    def get(self, key: str) -> RunResult | None:
        if not self.enabled:
            return None
        now = time.time()
        try:
            with self._session() as conn:
                row = conn.execute(
                    "SELECT value, created FROM results WHERE key = ?",
                    (key,)).fetchone()
                if row is None:
                    self.misses += 1
                    return None
                value, created = row
                if self.ttl_s is not None and now - float(created) > self.ttl_s:
                    conn.execute("DELETE FROM results WHERE key = ?", (key,))
                    self.misses += 1
                    return None
                conn.execute(
                    "UPDATE results SET hits = hits + 1 WHERE key = ?", (key,))
        except (OSError, sqlite3.Error) as exc:
            self._fail(exc)
            return None

        try:
            data = json.loads(value)
            result = RunResult.from_json(data)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            self.errors += 1
            self._last_error = f"corrupt cache entry: {type(exc).__name__}: {exc}"
            self.misses += 1
            return None
        result.cached = True
        self.hits += 1
        return result

    def put(self, key: str, result: RunResult) -> bool:
        """Store a cacheable result. Returns True if it was written."""
        if not self.enabled or result.outcome.value not in CACHEABLE_OUTCOMES:
            return False
        data = result.to_json()
        # to_json() truncates the SHA for the human-readable log; keep the full
        # digest so a cache hit still names the exact input.
        data["input_sha256"] = result.input_sha256
        if result.slow_threshold_s is not None:
            data["slow_threshold_s"] = result.slow_threshold_s
        try:
            payload = json.dumps(data, separators=(",", ":"))
            with self._session() as conn:
                conn.execute(
                    "INSERT INTO results(key, value, created, hits) "
                    "VALUES (?, ?, ?, 0) "
                    "ON CONFLICT(key) DO UPDATE SET "
                    "value = excluded.value, created = excluded.created",
                    (key, payload, time.time()))
            self.stores += 1
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            self._fail(exc)
            return False
        if self.stores % 256 == 0:
            self.prune()
        return True

    # ------------------------------------------------------------------ admin
    def prune(self, max_entries: int | None = None) -> int:
        """Drop the oldest entries until the cache is under the limit."""
        if not self.enabled:
            return 0
        limit = self.max_entries if max_entries is None else max_entries
        if limit is None or limit < 0:
            return 0
        try:
            with self._session() as conn:
                count = int(conn.execute(
                    "SELECT COUNT(*) FROM results").fetchone()[0])
                excess = count - limit
                if excess <= 0:
                    return 0
                # Remove in batches: a pathological limit should not hold the
                # write lock for one statement per row.
                removed = conn.execute(
                    "DELETE FROM results WHERE key IN ("
                    " SELECT key FROM results ORDER BY created ASC, key ASC"
                    " LIMIT ?)", (excess,)).rowcount
        except (OSError, sqlite3.Error) as exc:
            self._fail(exc)
            return 0
        self.evictions += max(0, removed)
        return max(0, removed)

    def clear(self) -> None:
        if not self.enabled:
            return
        try:
            with self._session() as conn:
                conn.execute("DELETE FROM results")
        except (OSError, sqlite3.Error) as exc:
            self._fail(exc)

    def entries(self) -> int:
        if not self.enabled:
            return 0
        try:
            with self._session() as conn:
                return int(conn.execute(
                    "SELECT COUNT(*) FROM results").fetchone()[0])
        except (OSError, sqlite3.Error) as exc:
            self._fail(exc)
            return 0

    def stats(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "path": str(self.path),
            "hits": self.hits,
            "misses": self.misses,
            "stores": self.stores,
            "evictions": self.evictions,
            "errors": self.errors,
            "entries": self.entries() if self.enabled else 0,
            "max_entries": self.max_entries,
            "ttl_s": self.ttl_s,
            "last_error": self._last_error,
        }


def cache_enabled_by_env() -> bool:
    """Allow operators to enable the cache without changing a command line."""
    return os.environ.get("STRATAGEM_RESULT_CACHE", "").strip().lower() in (
        "1", "true", "yes", "on")
