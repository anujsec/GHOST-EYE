"""
db.py — persistence + diffing layer.

v2 changes from the original:
  - FIXED a real diffing bug: `assets` only ever stored the *current* state
    of each asset (UNIQUE org/table_name/asset_key), with `run_id` meaning
    "last run that touched this row". That makes it impossible to
    reconstruct what the *previous* run actually looked like once an asset
    has been touched more than twice — diff_since_last was comparing the
    current snapshot against itself in some cases. Fixed by adding an
    append-only `history` table: one immutable row per (asset, run), which
    is what diffing is actually computed from now. `assets` remains as a
    fast "current state" table for direct queries (e.g. "everything on
    WordPress right now").
  - Batched upserts via SQLite's `INSERT ... ON CONFLICT DO UPDATE` instead
    of a per-row SELECT-then-branch loop.
  - WAL journal mode + busy_timeout so concurrent phases writing to the DB
    don't stall each other.
  - Indexes on the columns diffing and lookups actually filter on.
"""

import sqlite3
import json
import time
from pathlib import Path
from contextlib import contextmanager

DB_PATH = Path(__file__).parent / "data" / "recon.db"

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS runs (
    run_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    org         TEXT NOT NULL,
    layer       TEXT NOT NULL,
    started_at  REAL NOT NULL,
    finished_at REAL
);

CREATE TABLE IF NOT EXISTS assets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    org         TEXT NOT NULL,
    table_name  TEXT NOT NULL,
    asset_key   TEXT NOT NULL,
    attrs       TEXT NOT NULL,
    run_id      INTEGER NOT NULL,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1,
    UNIQUE(org, table_name, asset_key)
);

CREATE TABLE IF NOT EXISTS history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    org         TEXT NOT NULL,
    table_name  TEXT NOT NULL,
    asset_key   TEXT NOT NULL,
    run_id      INTEGER NOT NULL,
    attrs       TEXT NOT NULL,
    recorded_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assets_lookup   ON assets(org, table_name, active);
CREATE INDEX IF NOT EXISTS idx_history_run     ON history(org, table_name, run_id);
CREATE INDEX IF NOT EXISTS idx_history_key     ON history(org, table_name, asset_key);
CREATE INDEX IF NOT EXISTS idx_runs_org_layer  ON runs(org, layer, run_id);
"""


@contextmanager
def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def start_run(org: str, layer: str) -> int:
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO runs (org, layer, started_at) VALUES (?, ?, ?)",
            (org, layer, time.time()),
        )
        return cur.lastrowid


def finish_run(run_id: int):
    with get_db() as conn:
        conn.execute("UPDATE runs SET finished_at = ? WHERE run_id = ?", (time.time(), run_id))


def upsert_assets(org: str, table_name: str, run_id: int, items: dict):
    """
    items: { asset_key: {attr dict} }

    Writes:
      1. one immutable history row per item for this run (source of truth for diffing)
      2. a batched upsert into `assets` (current-state table, for direct queries)
      3. marks any previously-active asset in this table not present in `items`
         this run as inactive (batched, via a temp table — not a per-row loop)
    """
    now = time.time()
    # column order must match the INSERT below exactly: org, table_name, asset_key, run_id, attrs, recorded_at
    rows = [(org, table_name, key, run_id, json.dumps(attrs, sort_keys=True, default=str), now)
            for key, attrs in items.items()]

    with get_db() as conn:
        if rows:
            conn.executemany(
                "INSERT INTO history (org, table_name, asset_key, run_id, attrs, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                rows,
            )
            conn.executemany(
                """INSERT INTO assets (org, table_name, asset_key, attrs, run_id, first_seen, last_seen, active)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 1)
                   ON CONFLICT(org, table_name, asset_key) DO UPDATE SET
                       attrs=excluded.attrs,
                       run_id=excluded.run_id,
                       last_seen=excluded.last_seen,
                       active=1""",
                [(org, table_name, key, json.dumps(attrs, sort_keys=True, default=str), run_id, now, now)
                 for key, attrs in items.items()],
            )

        # batched inactive-marking: anything active in this table that wasn't touched this run
        conn.execute("CREATE TEMP TABLE IF NOT EXISTS _touched (asset_key TEXT PRIMARY KEY)")
        conn.execute("DELETE FROM _touched")
        if items:
            conn.executemany("INSERT OR IGNORE INTO _touched (asset_key) VALUES (?)",
                              [(k,) for k in items.keys()])
        conn.execute(
            """UPDATE assets SET active=0
               WHERE org=? AND table_name=? AND active=1
                 AND asset_key NOT IN (SELECT asset_key FROM _touched)""",
            (org, table_name),
        )
        conn.execute("DROP TABLE IF EXISTS _touched")


def diff_since_last(org: str, table_name: str, run_id: int):
    """
    Compares the history rows written for `run_id` against the history rows
    written for the most recent *earlier* run that touched this
    (org, table_name) — giving a correct point-in-time diff regardless of
    how many times individual assets were updated in between.
    """
    with get_db() as conn:
        prev_run_row = conn.execute(
            """SELECT DISTINCT run_id FROM history
               WHERE org=? AND table_name=? AND run_id < ?
               ORDER BY run_id DESC LIMIT 1""",
            (org, table_name, run_id),
        ).fetchone()

        current = {
            r["asset_key"]: json.loads(r["attrs"])
            for r in conn.execute(
                "SELECT asset_key, attrs FROM history WHERE org=? AND table_name=? AND run_id=?",
                (org, table_name, run_id),
            ).fetchall()
        }

        if not prev_run_row:
            return {"new": list(current.items()), "removed": [], "changed": []}

        prev_run_id = prev_run_row["run_id"]
        previous = {
            r["asset_key"]: json.loads(r["attrs"])
            for r in conn.execute(
                "SELECT asset_key, attrs FROM history WHERE org=? AND table_name=? AND run_id=?",
                (org, table_name, prev_run_id),
            ).fetchall()
        }

    new = [(k, v) for k, v in current.items() if k not in previous]
    removed = [(k, v) for k, v in previous.items() if k not in current]
    changed = [(k, previous[k], current[k]) for k in current if k in previous and previous[k] != current[k]]

    return {"new": new, "removed": removed, "changed": changed}


def get_active_assets(org: str, table_name: str) -> dict:
    """Current-state read, e.g. for querying 'everything on WordPress right now'."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT asset_key, attrs FROM assets WHERE org=? AND table_name=? AND active=1",
            (org, table_name),
        ).fetchall()
    return {r["asset_key"]: json.loads(r["attrs"]) for r in rows}


def prune_history(org: str, older_than_days: int = 90, vacuum: bool = True):
    """
    Optional retention control — history is append-only and will grow otherwise.

    The DELETE implicitly opens a transaction (sqlite3's default
    isolation_level=""), and SQLite refuses to VACUUM inside one, so the old
    version raised every time it was called. VACUUM now gets its own
    autocommit connection.
    """
    cutoff = time.time() - older_than_days * 86400
    with get_db() as conn:
        conn.execute("DELETE FROM history WHERE org=? AND recorded_at < ?", (org, cutoff))
    if vacuum:
        conn = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
        try:
            conn.execute("VACUUM")
        finally:
            conn.close()
