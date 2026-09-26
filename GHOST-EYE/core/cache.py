"""
core/cache.py — small TTL cache so re-runs skip expensive, unchanged work
(crt.sh lookups, passive enumeration, DNS resolution, URL history).

Deliberately its own SQLite file (data/cache.db), separate from the asset
database in db.py, so cache churn never touches the historical asset data
that diffing depends on.

v2.1 fixes:
  - `@cached(...)` captured `enabled` at import time, so `cache.enabled: false`
    in config.yaml could not turn off the decorated functions (tools.crtsh) —
    only the hand-rolled cache calls in pipeline.py honoured it. The decorator
    now consults a module-level switch at call time; set_enabled() flips it.
  - a failed crt.sh lookup returns [], which was then cached for six hours.
    One transient 5xx meant zero certificate-transparency data for the rest of
    the day. Empty results are no longer stored (override with
    cache_empty=True where an empty answer is genuinely meaningful).
  - WAL + busy_timeout: several pipeline phases write cache entries from
    worker threads at once, which could raise "database is locked".
  - functools.wraps, so decorated tools keep their name/docstring (the test
    suite patches tools by name).
  - schema is applied once per process instead of on every connection.
"""

import functools
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

CACHE_PATH = Path(__file__).parent.parent / "data" / "cache.db"

_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS cache (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    expires_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cache_expiry ON cache(expires_at);
"""

_MISS = object()
_enabled = True
_schema_lock = threading.Lock()
_schema_done = False


def set_enabled(flag: bool):
    """Called once from the pipeline after config is merged."""
    global _enabled
    _enabled = bool(flag)


def is_enabled() -> bool:
    return _enabled


@contextmanager
def _conn():
    global _schema_done
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(CACHE_PATH, timeout=10)
    try:
        with _schema_lock:
            if not _schema_done:
                conn.executescript(_SCHEMA)
                _schema_done = True
        yield conn
        conn.commit()
    finally:
        conn.close()


def get(key: str, default=None):
    try:
        with _conn() as c:
            row = c.execute("SELECT value, expires_at FROM cache WHERE key=?", (key,)).fetchone()
    except sqlite3.Error as e:  # a broken cache must never fail the run
        return default
    if not row:
        return default
    value, expires_at = row
    if expires_at < time.time():
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def set(key: str, value, ttl_seconds: int, cache_empty: bool = False):
    """
    Store a value under `key` for `ttl_seconds`.

    Falsy values (empty list/dict/None) are skipped by default: in this
    pipeline an empty result almost always means "the tool was missing or the
    request failed", and caching that poisons every run inside the TTL window.
    """
    if value in (None, [], {}, "") and not cache_empty:
        return
    expires_at = time.time() + ttl_seconds
    payload = json.dumps(value, default=str)
    try:
        with _conn() as c:
            c.execute(
                "INSERT INTO cache (key, value, expires_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, expires_at=excluded.expires_at",
                (key, payload, expires_at),
            )
    except sqlite3.Error:
        pass


def cached(namespace: str, ttl_seconds: int, enabled: bool = True, cache_empty: bool = False):
    """
    Decorator: cache a function's return value keyed on namespace + args.
    Accepts the legacy `enabled` keyword for tests and the newer runtime switch,
    so `cache.enabled: false` and explicit `enabled=False` both work.

        @cached("crtsh", ttl_seconds=21600)
        def crtsh(domain): ...
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if not enabled or not _enabled:
                return fn(*args, **kwargs)
            key = namespace + ":" + json.dumps([args, kwargs], sort_keys=True, default=str)
            hit = get(key, default=_MISS)
            if hit is not _MISS:
                return hit
            result = fn(*args, **kwargs)
            set(key, result, ttl_seconds, cache_empty=cache_empty)
            return result
        wrapper.__wrapped__ = fn
        return wrapper
    return decorator


def purge_expired() -> int:
    """Housekeeping; returns rows removed. Cheap enough to call at run start."""
    try:
        with _conn() as c:
            cur = c.execute("DELETE FROM cache WHERE expires_at < ?", (time.time(),))
            return cur.rowcount or 0
    except sqlite3.Error:
        return 0


def clear(namespace: str | None = None) -> int:
    """Drop everything, or just one namespace (e.g. clear('crtsh'))."""
    try:
        with _conn() as c:
            if namespace:
                cur = c.execute("DELETE FROM cache WHERE key LIKE ?", (namespace + ":%",))
            else:
                cur = c.execute("DELETE FROM cache")
            return cur.rowcount or 0
    except sqlite3.Error:
        return 0
