"""
core/cache.py — small TTL cache so re-runs skip expensive, unchanged work
(crt.sh lookups, passive enumeration, DNS resolution, URL history).

Deliberately its own SQLite file (data/cache.db), separate from the asset
database in db.py, so cache churn never touches the historical asset data
that diffing depends on.
"""

import json
import sqlite3
import time
from pathlib import Path
from contextlib import contextmanager

CACHE_PATH = Path(__file__).parent.parent / "data" / "cache.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    expires_at  REAL NOT NULL
);
"""


@contextmanager
def _conn():
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(CACHE_PATH, timeout=10)
    try:
        conn.executescript(_SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def get(key: str, default=None):
    with _conn() as c:
        row = c.execute("SELECT value, expires_at FROM cache WHERE key=?", (key,)).fetchone()
    if not row:
        return default
    value, expires_at = row
    if expires_at < time.time():
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def set(key: str, value, ttl_seconds: int):
    expires_at = time.time() + ttl_seconds
    payload = json.dumps(value, default=str)
    with _conn() as c:
        c.execute(
            "INSERT INTO cache (key, value, expires_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, expires_at=excluded.expires_at",
            (key, payload, expires_at),
        )


def cached(namespace: str, ttl_seconds: int, enabled: bool = True):
    """
    Decorator: cache a function's return value keyed on namespace + args.
    Usage:
        @cached("crtsh", ttl_seconds=21600)
        def crtsh(domain): ...
    """
    def decorator(fn):
        def wrapper(*args, **kwargs):
            if not enabled:
                return fn(*args, **kwargs)
            key = namespace + ":" + json.dumps([args, kwargs], sort_keys=True, default=str)
            hit = get(key, default=_MISS)
            if hit is not _MISS:
                return hit
            result = fn(*args, **kwargs)
            set(key, result, ttl_seconds)
            return result
        wrapper.__wrapped__ = fn
        return wrapper
    return decorator


_MISS = object()


def purge_expired():
    with _conn() as c:
        c.execute("DELETE FROM cache WHERE expires_at < ?", (time.time(),))
